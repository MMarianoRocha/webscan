from typer.testing import CliRunner

from webscan.active_xss import ReflectionResult
from webscan.cli import app
from webscan.http_client import ResponseSummary

runner = CliRunner()


def test_active_xss_requires_lab_mode_before_any_request() -> None:
    result = runner.invoke(app, ["scan", "http://127.0.0.1:8000/", "--active-xss", "--param", "q"])

    assert result.exit_code == 2
    assert "exige --lab" in result.stdout


def test_active_xss_requires_parameter() -> None:
    result = runner.invoke(app, ["scan", "http://127.0.0.1:8000/", "--lab", "--active-xss"])

    assert result.exit_code == 2
    assert "Informe --param" in result.stdout


def test_param_cannot_be_used_without_active_option() -> None:
    result = runner.invoke(app, ["scan", "http://127.0.0.1:8000/", "--param", "q"])

    assert result.exit_code == 2
    assert "só pode ser usado" in result.stdout


def test_active_probe_runs_after_passive_scan_even_without_passive_findings(monkeypatch) -> None:
    passive = ResponseSummary(
        requested_url="http://127.0.0.1:8000/",
        status_code=200,
        http_version="HTTP/1.1",
        headers={"content-type": "application/json"},
        cookies=(),
    )
    active = ReflectionResult(
        requested_url="http://127.0.0.1:8000/search",
        parameter="q",
        marker="Abc12345678901234567",
        status_code=200,
        content_type="text/html",
        reflection_count=1,
        context="<p>marker echoed</p>",
    )
    monkeypatch.setattr("webscan.cli.inspect_url", lambda *_args, **_kwargs: passive)
    monkeypatch.setattr("webscan.cli.probe_reflection", lambda *_args, **_kwargs: active)

    result = runner.invoke(
        app,
        ["scan", "http://127.0.0.1:8000/", "--lab", "--active-xss", "--param", "q"],
    )

    assert result.exit_code == 0
    assert "Nenhum sinal das regras implementadas" in result.stdout
    assert "marcador refletido" in result.stdout
    assert "não confirma XSS" in result.stdout
