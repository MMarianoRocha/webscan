"""Verificações passivas, contextuais e conservadoras de cabeçalhos HTTP."""

from urllib.parse import urlsplit

from webscan.http_client import ResponseSummary
from webscan.models import Finding


def _finding(check_id: str, title: str, evidence: str, explanation: str, recommendation: str) -> Finding:
	return Finding(
		check_id=check_id,
		title=title,
		severity="low",
		evidence=evidence,
		explanation=explanation,
		recommendation=recommendation,
		confidence="medium",
	)


def _has_frame_ancestors(csp: str) -> bool:
	for directive in csp.split(";"):
		name = directive.strip().split(maxsplit=1)
		if name and name[0].casefold() == "frame-ancestors":
			return True
	return False


def check_headers(response: ResponseSummary) -> tuple[Finding, ...]:
	"""Verifica presença/configuração básica, sem afirmar que a aplicação é vulnerável."""
	findings: list[Finding] = []
	headers = {name.casefold(): value.strip() for name, value in response.headers.items()}
	is_https = urlsplit(response.requested_url).scheme.casefold() == "https"
	content_type = headers.get("content-type", "").casefold()
	is_html = "text/html" in content_type or "application/xhtml+xml" in content_type

	if is_https:
		hsts = headers.get("strict-transport-security")
		if not hsts:
			findings.append(
				_finding(
					"header-hsts-missing",
					"HSTS não observado",
					"Strict-Transport-Security ausente na resposta HTTPS.",
					"HSTS instrui navegadores a preferirem HTTPS em acessos futuros; a aplicabilidade depende do domínio e da implantação.",
					"Avalie configurar HSTS após confirmar HTTPS consistente para o domínio e subdomínios pertinentes.",
				)
			)
		elif not any(
			part.strip().casefold().startswith("max-age=")
			and part.partition("=")[2].strip().isdigit()
			and int(part.partition("=")[2].strip()) > 0
			for part in hsts.split(";")
		):
			findings.append(
				_finding(
					"header-hsts-max-age",
					"HSTS sem max-age positivo reconhecido",
					f"Strict-Transport-Security: {hsts}",
					"Sem um max-age positivo, o navegador pode não manter a política HSTS.",
					"Revise a sintaxe e o período adequado à implantação antes de alterar a política.",
				)
			)

	if is_html:
		csp = headers.get("content-security-policy", "")
		if not csp:
			findings.append(
				_finding(
					"header-csp-missing",
					"CSP não observada em resposta HTML",
					"Content-Security-Policy ausente.",
					"Uma CSP bem planejada pode limitar fontes de conteúdo e reduzir impacto de algumas classes de injeção; sua ausência não confirma XSS.",
					"Avalie uma política compatível com a aplicação, inicialmente em modo de relatório quando apropriado.",
				)
			)

		if "x-content-type-options" not in headers or headers["x-content-type-options"].casefold() != "nosniff":
			findings.append(
				_finding(
					"header-nosniff-missing",
					"X-Content-Type-Options nosniff não observado",
					headers.get("x-content-type-options", "X-Content-Type-Options ausente."),
					"nosniff ajuda a impedir que navegadores interpretem conteúdo como um tipo diferente do declarado.",
					"Avalie enviar X-Content-Type-Options: nosniff e definir Content-Type corretamente.",
				)
			)

		frame_protected = _has_frame_ancestors(csp) or headers.get("x-frame-options", "").casefold() in {
			"deny",
			"sameorigin",
		}
		if not frame_protected:
			findings.append(
				_finding(
					"header-framing-policy-missing",
					"Política contra framing não observada",
					"CSP frame-ancestors e X-Frame-Options efetivo não observados.",
					"Respostas HTML que podem ser incorporadas por outros sites podem estar expostas a clickjacking, dependendo da funcionalidade.",
					"Avalie CSP frame-ancestors; X-Frame-Options pode servir como compatibilidade adicional.",
				)
			)

		referrer_policy = headers.get("referrer-policy", "")
		valid_referrer_tokens = {
			"no-referrer",
			"no-referrer-when-downgrade",
			"same-origin",
			"origin",
			"strict-origin",
			"origin-when-cross-origin",
			"strict-origin-when-cross-origin",
			"unsafe-url",
		}
		if not referrer_policy:
			findings.append(
				_finding(
					"header-referrer-policy-missing",
					"Referrer-Policy não observada",
					"Referrer-Policy ausente em resposta HTML.",
					"A política controla quanto da URL de origem o navegador compartilha ao navegar para outros destinos.",
					"Avalie definir uma política explícita adequada ao produto, como strict-origin-when-cross-origin.",
				)
			)
		elif not any(token.strip().casefold() in valid_referrer_tokens for token in referrer_policy.split(",")):
			findings.append(
				_finding(
					"header-referrer-policy-value",
					"Referrer-Policy sem valor reconhecido",
					f"Referrer-Policy: {referrer_policy}",
					"O valor observado não corresponde a uma diretiva reconhecida pelo scanner.",
					"Revise a sintaxe e selecione uma política compatível com os requisitos de privacidade.",
				)
			)

	return tuple(findings)
