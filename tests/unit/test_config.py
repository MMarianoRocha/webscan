from webscan.config import ScanConfig


def test_defaults_are_conservative() -> None:
    config = ScanConfig()

    assert config.max_requests == 1
    assert config.follow_redirects is False
    assert config.timeout_seconds > 0
    assert config.max_response_bytes > 0
