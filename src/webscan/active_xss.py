"""Sonda única e inerte para observar reflexão de um parâmetro em laboratório."""

import re
import secrets
import time
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from webscan.config import ScanConfig
from webscan.http_client import TargetScopeError, validate_target_scope, validate_target_url

_PARAMETER_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")


class ActiveProbeError(ValueError):
	"""A sonda ativa não pôde continuar dentro dos limites definidos."""


class ResponseTooLarge(ActiveProbeError):
	"""A resposta excedeu o limite de bytes da análise ativa."""


@dataclass(frozen=True, slots=True)
class ReflectionResult:
	"""Evidência resumida de reflexão; não representa XSS confirmado."""

	requested_url: str
	parameter: str
	marker: str
	status_code: int
	content_type: str
	reflection_count: int
	context: str | None

	@property
	def reflected(self) -> bool:
		return self.reflection_count > 0


def _build_probe_url(url: str, parameter: str, marker: str) -> str:
	parsed = urlsplit(url)
	# Envia somente o parâmetro de teste; não retransmite outros valores da query,
	# que podem conter tokens ou dados privados.
	return urlunsplit(parsed._replace(query=urlencode([(parameter, marker)])))


def _safe_context(body: str, marker: str, radius: int = 48) -> str | None:
	position = body.find(marker)
	if position < 0:
		return None
	start = max(0, position - radius)
	end = min(len(body), position + len(marker) + radius)
	context = body[start:end]
	return "".join(
		character if ord(character) >= 32 and ord(character) != 127 else " "
		for character in context
	)


def probe_reflection(
	url: str,
	parameter: str,
	config: ScanConfig | None = None,
	*,
	transport: httpx.BaseTransport | None = None,
	allow_loopback: bool = False,
) -> ReflectionResult:
	"""Envia um único marcador alfanumérico em GET e observa se a resposta o reflete.

	A sonda ativa exige ``allow_loopback=True`` e nunca segue redirects. Em produção,
	valida que o hostname resolva exclusivamente para loopback. Um transporte mock
	serve apenas aos testes unitários e não realiza qualquer conexão de rede.
	"""
	if not allow_loopback:
		raise TargetScopeError("A sonda ativa está habilitada somente com --lab em loopback.")
	if not _PARAMETER_PATTERN.fullmatch(parameter):
		raise ActiveProbeError("Nome de parâmetro inválido; use 1–64 letras, números, ponto, hífen ou _.")

	settings = config or ScanConfig()
	if settings.max_response_bytes < 1:
		raise ActiveProbeError("max_response_bytes precisa ser maior que zero.")
	if settings.active_probe_delay_seconds > 0:
		time.sleep(settings.active_probe_delay_seconds)

	target = validate_target_url(url)
	if transport is None:
		host = urlsplit(target).hostname
		try:
			address = ip_address(host or "")
		except ValueError as exc:
			raise TargetScopeError(
				"A sonda ativa exige IP loopback literal (127.0.0.1 ou ::1); hostnames não são aceitos."
			) from exc
		if not address.is_loopback:
			raise TargetScopeError("A sonda ativa aceita somente IPs loopback literais.")
		validate_target_scope(target, allow_loopback=True)

	alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	marker = "".join(secrets.choice(alphabet) for _ in range(20))
	probe_url = _build_probe_url(target, parameter, marker)

	with httpx.Client(
		timeout=settings.timeout_seconds,
		follow_redirects=False,
		verify=True,
		trust_env=False,
		transport=transport,
		headers={
			"User-Agent": "WebScan/0.1 (passive authorized scanner)",
			"Accept-Encoding": "identity",
		},
	) as client, client.stream("GET", probe_url) as response:
		if 300 <= response.status_code < 400:
			raise ActiveProbeError("A sonda foi interrompida: a resposta indicou redirect, que não será seguido.")

		content_encoding = response.headers.get("content-encoding", "identity").casefold()
		if content_encoding not in {"", "identity"}:
			raise ActiveProbeError("A resposta comprimida foi recusada para respeitar o limite de bytes.")

		content_length = response.headers.get("content-length")
		if content_length and content_length.isdigit() and int(content_length) > settings.max_response_bytes:
			raise ResponseTooLarge("A resposta excede o limite configurado; análise interrompida.")

		body = bytearray()
		if response.is_stream_consumed:
			# MockTransport pode materializar respostas antes de entregá-las; ainda
			# validamos o tamanho, enquanto respostas reais seguem em streaming.
			content = response.content
			if len(content) > settings.max_response_bytes:
				raise ResponseTooLarge("A resposta excede o limite configurado; análise interrompida.")
			body.extend(content)
		else:
			for chunk in response.iter_raw():
				if len(body) + len(chunk) > settings.max_response_bytes:
					raise ResponseTooLarge("A resposta excede o limite configurado; análise interrompida.")
				body.extend(chunk)

		encoding = response.encoding or "utf-8"
		decoded_body = bytes(body).decode(encoding, errors="replace")
		count = decoded_body.count(marker)
		return ReflectionResult(
			requested_url=urlunsplit(urlsplit(target)._replace(query="")),
			parameter=parameter,
			marker=marker,
			status_code=response.status_code,
			content_type=response.headers.get("content-type", ""),
			reflection_count=count,
			context=_safe_context(decoded_body, marker) if count else None,
		)