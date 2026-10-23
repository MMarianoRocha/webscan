"""Verificações passivas de flags de cookies sem expor seus valores."""

from urllib.parse import urlsplit

from webscan.http_client import ResponseSummary
from webscan.models import Finding


def check_cookies(response: ResponseSummary) -> tuple[Finding, ...]:
	"""Sinaliza flags ausentes com severidade baixa e sem nomes/valores de cookie."""
	if not response.cookies:
		return ()

	findings: list[Finding] = []
	if urlsplit(response.requested_url).scheme.casefold() == "https":
		missing_secure = sum(not cookie.secure for cookie in response.cookies)
		if missing_secure:
			findings.append(
				Finding(
					check_id="cookie-secure-missing",
					title="Cookie(s) sem atributo Secure",
					severity="low",
					evidence=f"{missing_secure} de {len(response.cookies)} cookie(s) sem Secure; nomes e valores omitidos.",
					explanation="Sem Secure, o navegador pode enviar o cookie por uma conexão HTTP não criptografada em determinados cenários.",
					recommendation="Avalie Secure para cookies que não precisem ser enviados por HTTP.",
					confidence="medium",
				)
			)

	session_cookies = [cookie for cookie in response.cookies if cookie.session_like]
	if session_cookies:
		missing_http_only = sum(not cookie.http_only for cookie in session_cookies)
		if missing_http_only:
			findings.append(
				Finding(
					check_id="cookie-httponly-missing",
					title="Cookie possivelmente relacionado a sessão sem HttpOnly",
					severity="low",
					evidence=f"{missing_http_only} cookie(s) com nome sugestivo de sessão sem HttpOnly; nomes e valores omitidos.",
					explanation="HttpOnly impede acesso direto ao cookie por APIs de script no navegador; a classificação pelo nome é apenas heurística.",
					recommendation="Confirme se o cookie contém estado de autenticação e, se não precisar ser acessível por script, configure HttpOnly.",
					confidence="low",
				)
			)

		invalid_same_site = sum(
			cookie.same_site is None
			or cookie.same_site.casefold() not in {"strict", "lax", "none"}
			for cookie in session_cookies
		)
		if invalid_same_site:
			findings.append(
				Finding(
					check_id="cookie-samesite-missing",
					title="Cookie possivelmente relacionado a sessão sem SameSite reconhecido",
					severity="low",
					evidence=f"{invalid_same_site} cookie(s) com nome sugestivo de sessão sem SameSite reconhecido; nomes e valores omitidos.",
					explanation="SameSite influencia o envio de cookies em contextos cross-site; a necessidade e o valor adequado dependem do fluxo da aplicação.",
					recommendation="Revise o fluxo de autenticação e defina Strict, Lax ou None; SameSite=None exige Secure em navegadores modernos.",
					confidence="low",
				)
			)

	return tuple(findings)
