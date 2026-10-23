import socket

import pytest

from webscan.http_client import TargetScopeError, validate_target_scope


def _address_info(address: str) -> list[tuple]:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]


def test_public_address_is_allowed_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: _address_info("93.184.216.34"))

    validate_target_scope("https://site.test/")


def test_private_destination_is_rejected_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: _address_info("10.0.0.8"))

    with pytest.raises(TargetScopeError, match="não público"):
        validate_target_scope("https://site.test/")


def test_lab_mode_accepts_only_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: _address_info("127.0.0.1"))

    validate_target_scope("http://localhost:3000/", allow_loopback=True)

    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: _address_info("192.168.1.5"))
    with pytest.raises(TargetScopeError, match="somente destinos loopback"):
        validate_target_scope("http://lab.test/", allow_loopback=True)


def test_dns_failure_is_a_scope_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_resolution(*_args: object, **_kwargs: object) -> None:
        raise socket.gaierror("lookup failed")

    monkeypatch.setattr(socket, "getaddrinfo", fail_resolution)

    with pytest.raises(TargetScopeError, match="resolver"):
        validate_target_scope("https://unresolved.test/")
