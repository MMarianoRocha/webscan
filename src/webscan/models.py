"""Modelos compartilhados entre verificações e relatórios."""

from dataclasses import dataclass
from typing import Literal

Severity = Literal["info", "low", "medium", "high"]


@dataclass(frozen=True, slots=True)
class Finding:
    """Um sinal observado; não implica confirmação automática de vulnerabilidade."""

    check_id: str
    title: str
    severity: Severity
    evidence: str
    explanation: str
    recommendation: str
    confidence: Literal["low", "medium", "high"] = "medium"


@dataclass(frozen=True, slots=True)
class CookieAttributes:
    """Atributos observáveis de um cookie, sem nome ou valor."""

    secure: bool
    http_only: bool
    same_site: str | None
    session_like: bool


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Resultado resumido de uma execução do scanner."""

    target: str
    status_code: int | None
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...] = ()
