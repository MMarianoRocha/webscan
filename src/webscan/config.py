"""Opções e limites da execução do scanner."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Limites conservadores para uma execução passiva."""

    timeout_seconds: float = 5.0
    max_response_bytes: int = 1_000_000
    max_requests: int = 1
    requests_per_second: float = 1.0
    follow_redirects: bool = False
