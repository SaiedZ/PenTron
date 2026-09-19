"""
Pre-flight target safety tests — tools.py::check_target_safety refuses to
start a scan whose target resolves to a private/loopback/link-local/
reserved address, since a domain's DNS can be repointed at internal
infrastructure at any time. A literal IP typed directly is always
allowed — that's an explicit operator choice, not a DNS record someone
else controls.
"""
import socket

import tools


def _fake_resolve(ip: str):
    return lambda host, *a, **kw: [(None, None, None, None, (ip, 0))]


def test_literal_ip_is_always_allowed():
    assert tools.check_target_safety("8.8.8.8") is None


def test_domain_resolving_to_public_ip_is_allowed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_resolve("93.184.216.34"))
    assert tools.check_target_safety("example.com") is None


def test_domain_resolving_to_private_ip_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_resolve("10.0.0.5"))
    result = tools.check_target_safety("evil-dns.example")
    assert result is not None
    assert "BLOCKED" in result
    assert "10.0.0.5" in result


def test_domain_resolving_to_loopback_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_resolve("127.0.0.1"))
    result = tools.check_target_safety("evil-dns.example")
    assert result is not None
    assert "BLOCKED" in result


def test_domain_resolving_to_link_local_is_blocked(monkeypatch):
    # 169.254.169.254 — the canonical cloud-metadata address
    monkeypatch.setattr(socket, "getaddrinfo", _fake_resolve("169.254.169.254"))
    result = tools.check_target_safety("evil-dns.example")
    assert result is not None
    assert "BLOCKED" in result


def test_unresolvable_domain_is_allowed_through(monkeypatch):
    def raise_gaierror(*a, **kw):
        raise socket.gaierror("unresolvable")

    monkeypatch.setattr(socket, "getaddrinfo", raise_gaierror)
    assert tools.check_target_safety("nonexistent.invalid") is None
