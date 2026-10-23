from urllib.parse import parse_qs

import httpx
import pytest

from webscan.active_xss import ActiveProbeError, ResponseTooLarge, probe_reflection
from webscan.config import ScanConfig
from webscan.http_client import TargetScopeError


def config(**overrides: object) -> ScanConfig:
    values: dict[str, object] = {"active_probe_delay_seconds": 0.0}
    values.update(overrides)
    return ScanConfig(**values)  # type: ignore[arg-type]


def test_reflection_probe_sends_one_inert_parameter_and_returns_bounded_context() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        query = parse_qs(request.url.query.decode())
        marker = query["q"][0]
        assert set(query) == {"q"}
        assert marker.isalnum()
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            content=f"<p>Você buscou: {marker}</p>".encode(),
        )

    result = probe_reflection(
        "http://127.0.0.1:8000/search?keep=value",
        "q",
        config(),
        transport=httpx.MockTransport(handler),
        allow_loopback=True,
    )

    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].headers["accept-encoding"] == "identity"
    assert result.reflected is True
    assert result.reflection_count == 1
    assert result.parameter == "q"
    assert result.context is not None and result.marker in result.context
    assert result.requested_url == "http://127.0.0.1:8000/search"
    assert "keep=value" not in repr(result)


def test_reflection_probe_reports_unobserved_marker_without_context() -> None:
    result = probe_reflection(
        "http://localhost:8000/search",
        "term",
        config(),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, text="No match")),
        allow_loopback=True,
    )

    assert result.reflected is False
    assert result.reflection_count == 0
    assert result.context is None


def test_active_probe_requires_explicit_lab_scope() -> None:
    with pytest.raises(TargetScopeError, match="somente com --lab"):
        probe_reflection(
            "https://public.example/search",
            "q",
            config(),
            transport=httpx.MockTransport(lambda _: httpx.Response(200)),
        )


def test_active_probe_real_transport_requires_literal_loopback_ip() -> None:
    with pytest.raises(TargetScopeError, match="IP loopback literal"):
        probe_reflection(
            "http://localhost:8000/search",
            "q",
            config(),
            allow_loopback=True,
        )


def test_active_probe_rejects_bad_parameter_before_request() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        pytest.fail("Não deveria enviar requisição para parâmetro inválido")

    with pytest.raises(ActiveProbeError, match="Nome de parâmetro inválido"):
        probe_reflection(
            "http://127.0.0.1/search",
            "q&admin=true",
            config(),
            transport=httpx.MockTransport(handler),
            allow_loopback=True,
        )


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"Location": "/other"}),
        httpx.Response(200, headers={"Content-Length": "20"}, content=b"x"),
    ],
)
def test_active_probe_stops_on_redirect_compression_or_declared_oversize(
    response: httpx.Response,
) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return response

    with pytest.raises(ActiveProbeError):
        probe_reflection(
            "http://127.0.0.1/search",
            "q",
            config(max_response_bytes=10),
            transport=httpx.MockTransport(handler),
            allow_loopback=True,
        )


def test_active_probe_rejects_compressed_response() -> None:
    response = httpx.Response(
        200,
        headers={"Content-Encoding": "gzip"},
        stream=httpx.ByteStream(b"compressed"),
    )

    with pytest.raises(ActiveProbeError, match="comprimida"):
        probe_reflection(
            "http://127.0.0.1/search",
            "q",
            config(),
            transport=httpx.MockTransport(lambda _: response),
            allow_loopback=True,
        )


def test_active_probe_enforces_streamed_body_limit_without_content_length() -> None:
    response = httpx.Response(
        200,
        headers={"Content-Type": "text/html"},
        stream=httpx.ByteStream(b"x" * 20),
    )

    with pytest.raises(ResponseTooLarge, match="excede o limite"):
        probe_reflection(
            "http://127.0.0.1/search",
            "q",
            config(max_response_bytes=10),
            transport=httpx.MockTransport(lambda _: response),
            allow_loopback=True,
        )
