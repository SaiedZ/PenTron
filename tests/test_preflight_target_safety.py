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


def test_domain_resolving_to_loopback_via_ipv6_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_resolve("::1"))
    result = tools.check_target_safety("evil-dns.example")
    assert result is not None
    assert "BLOCKED" in result


def test_domain_resolving_to_ipv6_unique_local_is_blocked(monkeypatch):
    # fc00::/7 — IPv6's equivalent of RFC1918 private space
    monkeypatch.setattr(socket, "getaddrinfo", _fake_resolve("fc00::1"))
    result = tools.check_target_safety("evil-dns.example")
    assert result is not None
    assert "BLOCKED" in result


def test_partial_dns_poisoning_one_private_ip_among_several_is_blocked(monkeypatch):
    # A domain with multiple A/AAAA records where only ONE resolves
    # internally — e.g. a rebinding attempt hoping a scanner only checks
    # the first result. ALL resolved IPs must be inspected, not just one.
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, *a, **kw: [
            (None, None, None, None, ("93.184.216.34", 0)),  # legitimate public IP
            (None, None, None, None, ("10.0.0.5", 0)),        # smuggled private IP
        ],
    )
    result = tools.check_target_safety("mixed-records.example")
    assert result is not None
    assert "BLOCKED" in result
    assert "10.0.0.5" in result
    assert "93.184.216.34" not in result  # only the unsafe IP(s) are called out


def test_literal_loopback_ip_bypasses_the_check_by_design():
    # Intentional: an IP typed directly by the operator is a conscious
    # choice (e.g. testing your own machine), not a DNS record someone
    # else controls — this must stay allowed, unlike the same address
    # reached via a domain's DNS (see test_domain_resolving_to_loopback_*).
    assert tools.check_target_safety("127.0.0.1") is None


def test_classic_ip_obfuscation_via_domain_resolution_is_still_caught(monkeypatch):
    # Decimal/hex/octal-encoded IPs aren't valid literal IPs (ipaddress.ip_address
    # rejects them), so they fall into the DNS-resolution branch same as any
    # hostname — and the OS resolver normalizes them to a real IP before we
    # ever see them, so classic SSRF numeric-IP obfuscation doesn't bypass this.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_resolve("127.0.0.1"))
    result = tools.check_target_safety("2130706433")  # decimal for 127.0.0.1
    assert result is not None
    assert "BLOCKED" in result
