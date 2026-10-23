"""Interface de linha de comando do WebScan."""

import httpx
import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from webscan.active_xss import ActiveProbeError, probe_reflection
from webscan.checks.cookies import check_cookies
from webscan.checks.headers import check_headers
from webscan.config import ScanConfig
from webscan.http_client import (
    TargetScopeError,
    TargetUrlError,
    display_url,
    inspect_url,
)

app = typer.Typer(
    name="webscan",
    help="Scanner web passivo para sistemas autorizados e ambientes de laboratório.",
    no_args_is_help=True,
)
console = Console()


def _safe_text(value: str) -> Text:
    """Evita interpretar markup e remove controles de terminal de conteúdo remoto."""
    cleaned = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else " "
        for character in value
    )
    return Text(cleaned)


@app.callback()
def main() -> None:
    """Ferramenta educacional de análise passiva para alvos autorizados."""


@app.command()
def scan(
    url: str = typer.Argument(..., help="URL do alvo autorizado (http:// ou https://)."),
    lab: bool = typer.Option(
        False,
        "--lab",
        help="Permite somente destinos loopback, como 127.0.0.1 ou localhost.",
    ),
    active_xss: bool = typer.Option(
        False,
        "--active-xss",
        help="Envia uma única sonda inerte; exige --lab, IP loopback literal e --param.",
    ),
    param: str | None = typer.Option(
        None,
        "--param",
        help="Nome de um único parâmetro de query para a sonda ativa.",
    ),
) -> None:
    """Consulta uma URL e reporta sinais passivos; sonda ativa é opcional."""
    if active_xss and not lab:
        console.print("[red]A sonda ativa exige --lab e um alvo loopback.[/red]")
        raise typer.Exit(code=2)
    if active_xss and not param:
        console.print("[red]Informe --param com o nome de um único parâmetro.[/red]")
        raise typer.Exit(code=2)
    if param and not active_xss:
        console.print("[red]--param só pode ser usado junto com --active-xss.[/red]")
        raise typer.Exit(code=2)

    console.print(
        "[yellow]Aviso:[/yellow] use somente em alvo próprio, laboratório ou sistema autorizado."
    )

    try:
        result = inspect_url(url, ScanConfig(), allow_loopback=lab)
    except TargetUrlError as exc:
        console.print(f"[red]URL inválida:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except TargetScopeError as exc:
        console.print(f"[red]Destino bloqueado pela política de escopo:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except httpx.HTTPError as exc:
        # Não exibir a exceção completa: ela pode conter a URL e sua query string.
        console.print(f"[red]Falha na requisição:[/red] {type(exc).__name__}")
        raise typer.Exit(code=1) from exc

    console.print(f"Alvo consultado: {result.requested_url}")
    console.print(f"Status: {result.status_code} | HTTP: {result.http_version}")
    console.print("Redirects: não seguidos")
    if lab:
        console.print("Modo laboratório: destino limitado a loopback.")

    table = Table(title="Cabeçalhos observados")
    table.add_column("Cabeçalho")
    table.add_column("Valor")
    if result.headers:
        for name, value in result.headers.items():
            safe_value = display_url(value) if name == "location" else value
            table.add_row(_safe_text(name), _safe_text(safe_value))
    else:
        table.add_row("—", "Nenhum cabeçalho selecionado foi encontrado.")
    table.add_row("set-cookie", f"{result.cookie_count} cookie(s); valores omitidos")
    console.print(table)

    findings = (*check_headers(result), *check_cookies(result))
    if not findings:
        console.print("\nNenhum sinal das regras implementadas foi observado.")
    else:
        findings_table = Table(title="Sinais para revisão (não confirmam vulnerabilidades)")
        findings_table.add_column("Severidade")
        findings_table.add_column("Verificação")
        findings_table.add_column("Evidência")
        findings_table.add_column("Recomendação")
        for finding in findings:
            findings_table.add_row(
                _safe_text(finding.severity),
                _safe_text(finding.title),
                _safe_text(finding.evidence),
                _safe_text(finding.recommendation),
            )
        console.print()
        console.print(findings_table)
        console.print(
            "[dim]As regras são passivas e contextuais. Revise cada achado; resultados não substituem análise manual.[/dim]"
        )

    if active_xss and param:
        if 300 <= result.status_code < 400:
            console.print("[yellow]Sonda ativa ignorada:[/yellow] a resposta inicial é redirect.")
            return
        console.print(
            "[yellow]Sonda ativa:[/yellow] será enviada uma única requisição GET com marcador inerte; redirects não serão seguidos."
        )
        try:
            reflection = probe_reflection(
                url,
                param,
                ScanConfig(),
                allow_loopback=True,
            )
        except (ActiveProbeError, TargetUrlError, TargetScopeError) as exc:
            console.print(f"[red]Sonda interrompida:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        except httpx.HTTPError as exc:
            console.print(f"[red]Falha na sonda:[/red] {type(exc).__name__}")
            raise typer.Exit(code=1) from exc

        status = "marcador refletido" if reflection.reflected else "marcador não observado"
        console.print(
            f"Resultado da sonda: {_safe_text(status)}; parâmetro {_safe_text(reflection.parameter)}; "
            f"ocorrências: {reflection.reflection_count}; status HTTP: {reflection.status_code}."
        )
        if reflection.context:
            console.print(f"Contexto sanitizado: {_safe_text(reflection.context)}")
        console.print(
            "[dim]Reflexão não confirma XSS. Revise manualmente o contexto e o encoding da resposta.[/dim]"
        )
