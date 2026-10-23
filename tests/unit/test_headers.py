from webscan.checks.headers import check_headers
from webscan.http_client import ResponseSummary


def response(
    url: str = "https://site.test/",
    headers: dict[str, str] | None = None,
) -> ResponseSummary:
    return ResponseSummary(
        requested_url=url,
        status_code=200,
        http_version="HTTP/1.1",
        headers=headers or {},
        cookies=(),
    )


def test_html_without_security_headers_reports_low_severity_signals() -> None:
    findings = check_headers(response(headers={"content-type": "text/html; charset=utf-8"}))

    assert {finding.check_id for finding in findings} == {
        "header-hsts-missing",
        "header-csp-missing",
        "header-nosniff-missing",
        "header-framing-policy-missing",
        "header-referrer-policy-missing",
    }
    assert all(finding.severity == "low" for finding in findings)
    assert all(finding.explanation and finding.recommendation for finding in findings)


def test_headers_with_valid_policies_do_not_report_missing_findings() -> None:
    findings = check_headers(
        response(
            headers={
                "content-type": "text/html",
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
            }
        )
    )

    assert findings == ()


def test_http_api_does_not_require_https_or_html_only_headers() -> None:
    findings = check_headers(
        response(
            url="http://api.site.test/v1/health",
            headers={"content-type": "application/json"},
        )
    )

    assert findings == ()


def test_frame_ancestors_is_parsed_case_insensitively() -> None:
    findings = check_headers(
        response(
            headers={
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'; FRAME-ANCESTORS 'self'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "same-origin",
                "strict-transport-security": "max-age=60",
            }
        )
    )

    assert "header-framing-policy-missing" not in {finding.check_id for finding in findings}
