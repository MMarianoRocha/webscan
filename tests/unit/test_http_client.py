import httpx
import pytest

from webscan.http_client import TargetUrlError, inspect_url, validate_target_url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.test/resource",
        "https:///missing-host",
        "https://user:password@example.test/",
        "https://example.test:invalid/",
        "https://example.test:70000/",
        "https://example.test/path with spaces",
        "https://example.test/#fragment",
    ],
)
def test_validate_target_url_rejects_unsupported_or_ambiguous_urls(url: str) -> None:
    with pytest.raises(TargetUrlError):
        validate_target_url(url)


def test_validate_target_url_accepts_http_and_https() -> None:
    assert validate_target_url("https://example.test/path") == "https://example.test/path"
    assert validate_target_url("http://localhost:8000/") == "http://localhost:8000/"


def test_inspect_url_uses_one_get_and_does_not_follow_redirects() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers=[
                ("Location", "https://outside.example/login?token=secret"),
                ("Content-Security-Policy", "default-src 'self'"),
                ("Set-Cookie", "session=secret; HttpOnly"),
                ("Set-Cookie", "preference=dark; SameSite=Lax"),
            ],
            content=b"response body is intentionally not returned",
        )

    result = inspect_url(
        "https://authorized.example/check?token=private",
        transport=httpx.MockTransport(handler),
    )

    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].headers["user-agent"].startswith("WebScan/")
    assert result.status_code == 302
    assert result.requested_url == "https://authorized.example/check"
    assert result.headers["content-security-policy"] == "default-src 'self'"
    assert result.headers["location"] == "https://outside.example/login"
    assert result.cookie_count == 2
    assert "secret" not in repr(result)


def test_inspect_url_rejects_invalid_url_before_transport() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        pytest.fail("Não deveria ocorrer requisição para URL inválida")

    with pytest.raises(TargetUrlError):
        inspect_url("javascript:alert(1)", transport=httpx.MockTransport(handler))
