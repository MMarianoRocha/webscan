from webscan.models import Finding, ScanResult


def test_scan_result_holds_findings_and_limitations() -> None:
    finding = Finding(
        check_id="header-csp",
        title="CSP ausente",
        severity="low",
        evidence="Content-Security-Policy não observado",
        explanation="A resposta não apresentou uma política CSP.",
        recommendation="Revise e configure uma CSP adequada à aplicação.",
    )

    result = ScanResult(
        target="https://lab.example",
        status_code=200,
        findings=(finding,),
        limitations=("Análise passiva; não confirma explorabilidade.",),
    )

    assert result.findings[0].check_id == "header-csp"
    assert result.limitations
