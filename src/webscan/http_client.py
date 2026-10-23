"""Requisição HTTP única, passiva, para uma URL de alvo autorizada."""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

from webscan.config import ScanConfig
from webscan.models import CookieAttributes

RELEVANT_HEADERS = (
	"content-type",
	"server",
	"x-powered-by",
	"strict-transport-security",
	"content-security-policy",
	"x-content-type-options",
	"x-frame-options",
	"referrer-policy",
)


class TargetUrlError(ValueError):
	"""A URL não tem um formato aceito pelo scanner."""


class TargetScopeError(ValueError):
	"""O destino não é permitido pela política de rede configurada."""


@dataclass(frozen=True, slots=True)
class ResponseSummary:
	"""Metadados da resposta sem armazenar o corpo ou valores de cookies."""

	requested_url: str
	status_code: int
	http_version: str
	headers: dict[str, str]
	cookies: tuple[CookieAttributes, ...]

	@property
	def cookie_count(self) -> int:
		return len(self.cookies)


def validate_target_url(url: str) -> str:
	"""Valida uma URL HTTP(S) e retorna a forma normalizada para a requisição."""
	candidate = url.strip()
	if not candidate or any(character.isspace() or ord(character) < 32 for character in candidate):
		raise TargetUrlError("Informe uma URL sem espaços ou caracteres de controle.")

	try:
		parsed = urlsplit(candidate)
		# Acessar port também valida que a porta é numérica e está no intervalo permitido.
		_ = parsed.port
	except ValueError as exc:
		raise TargetUrlError("A URL ou a porta informada é inválida.") from exc

	if parsed.scheme.lower() not in {"http", "https"}:
		raise TargetUrlError("Esquema inválido: use somente http:// ou https://.")
	if not parsed.hostname:
		raise TargetUrlError("A URL precisa incluir um hostname.")
	if parsed.username is not None or parsed.password is not None:
		raise TargetUrlError("URLs com usuário ou senha embutidos não são aceitas.")
	if parsed.fragment:
		raise TargetUrlError("Remova o fragmento (#...) da URL; ele não é enviado ao servidor.")

	try:
		parsed.hostname.encode("idna")
	except UnicodeError as exc:
		raise TargetUrlError("O hostname informado é inválido.") from exc

	return urlunsplit(parsed._replace(scheme=parsed.scheme.lower()))


def display_url(url: str) -> str:
	"""Oculta query string, que pode conter tokens ou outros dados sensíveis."""
	parsed = urlsplit(url)
	return urlunsplit(parsed._replace(query="", fragment=""))


def _cookie_attributes(raw_cookie: str) -> CookieAttributes:
	"""Extrai somente flags, descartando nome e valor do cabeçalho Set-Cookie."""
	parts = [part.strip() for part in raw_cookie.split(";")]
	name = parts[0].partition("=")[0].strip().casefold() if parts else ""
	attributes: dict[str, str | None] = {}
	for part in parts[1:]:
		attribute, separator, value = part.partition("=")
		attributes[attribute.strip().casefold()] = value.strip() if separator else None

	session_markers = ("session", "sess", "auth", "token", "sid", "jwt", "login")
	return CookieAttributes(
		secure="secure" in attributes,
		http_only="httponly" in attributes,
		same_site=attributes.get("samesite"),
		session_like=any(marker in name for marker in session_markers),
	)


def validate_target_scope(url: str, *, allow_loopback: bool = False) -> None:
	"""Permite destinos públicos; modo laboratório restringe a loopback.

	A resolução prévia reduz erros de escopo, mas não evita sozinha DNS rebinding.
	Use também firewall/restrição de saída; este CLI não deve virar serviço público.
	"""
	host = urlsplit(url).hostname
	if host is None:
		raise TargetScopeError("Não foi possível determinar o hostname do alvo.")

	try:
		try:
			addresses = {ipaddress.ip_address(host)}
		except ValueError:
			port = urlsplit(url).port or (443 if urlsplit(url).scheme == "https" else 80)
			addresses = {
				ipaddress.ip_address(info[4][0].split("%", 1)[0])
				for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
			}
	except (OSError, ValueError) as exc:
		raise TargetScopeError("Não foi possível resolver o destino com segurança.") from exc

	if not addresses:
		raise TargetScopeError("O hostname não resolveu para nenhum endereço IP.")
	if allow_loopback:
		if not all(address.is_loopback for address in addresses):
			raise TargetScopeError("O modo laboratório aceita somente destinos loopback (localhost).")
	elif not all(address.is_global for address in addresses):
		raise TargetScopeError(
			"Destino não público bloqueado. Para um laboratório local, use --lab; "
			"redes internas não são aceitas."
		)


def inspect_url(
	url: str,
	config: ScanConfig | None = None,
	*,
	transport: httpx.BaseTransport | None = None,
	allow_loopback: bool = False,
) -> ResponseSummary:
	"""Faz somente GET, não segue redirects e não lê o corpo da resposta.

	``transport`` existe para testes com HTTPX MockTransport; no uso normal, a
	conexão usa o transporte padrão do HTTPX e sua validação TLS habilitada.
	"""
	settings = config or ScanConfig()
	target = validate_target_url(url)
	# MockTransport não abre conexões de rede e permite testes determinísticos.
	if transport is None:
		validate_target_scope(target, allow_loopback=allow_loopback)

	with httpx.Client(
		timeout=settings.timeout_seconds,
		follow_redirects=False,
		verify=True,
		trust_env=False,
		transport=transport,
		headers={"User-Agent": "WebScan/0.1 (passive authorized scanner)"},
	) as client, client.stream("GET", target) as response:
		headers = {
			name: response.headers[name]
			for name in RELEVANT_HEADERS
			if name in response.headers
		}
		location = response.headers.get("location")
		if location:
			headers["location"] = display_url(location)

		return ResponseSummary(
			requested_url=display_url(target),
			status_code=response.status_code,
			http_version=response.http_version,
			headers=headers,
			cookies=tuple(
				_cookie_attributes(cookie)
				for cookie in response.headers.get_list("set-cookie")
			),
		)
