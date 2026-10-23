import httpx

from webscan.checks.cookies import check_cookies
from webscan.http_client import inspect_url


def test_cookie_findings_are_aggregated_and_never_retain_cookie_values() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=[
                ("Content-Type", "text/html"),
                ("Set-Cookie", "session_id=super-secret; Path=/"),
                ("Set-Cookie", "theme=dark; Secure; HttpOnly; SameSite=Lax"),
            ],
        )

    result = inspect_url(
        "https://site.test/",
        transport=httpx.MockTransport(handler),
    )
    findings = check_cookies(result)
    identifiers = {finding.check_id for finding in findings}

    assert result.cookie_count == 2
    assert identifiers == {
        "cookie-secure-missing",
        "cookie-httponly-missing",
        "cookie-samesite-missing",
    }
    assert "super-secret" not in repr(result)
    assert "session_id" not in repr(result)
    assert all("nomes e valores omitidos" in finding.evidence for finding in findings)


def test_secure_cookie_on_http_is_not_misreported_as_missing_secure() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=[("Set-Cookie", "session=redacted; Secure; HttpOnly; SameSite=Strict")],
        )

    result = inspect_url("http://site.test/", transport=httpx.MockTransport(handler))

    assert check_cookies(result) == ()


def test_non_session_cookie_is_not_flagged_for_http_only_or_samesite() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=[("Set-Cookie", "language=pt-BR; Secure")],
        )

    result = inspect_url("https://site.test/", transport=httpx.MockTransport(handler))
    identifiers = {finding.check_id for finding in check_cookies(result)}

    assert identifiers == set()
