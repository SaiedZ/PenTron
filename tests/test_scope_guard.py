"""
Scope guard tests — the AI controls the full [TOOL:] command line, so
every dispatched call must stay bound to the operator-declared session
target. These pin down a real bug found live: a scan against clubs.ma
had all 27 of its AI-issued tool calls incorrectly blocked because of
two parsing gaps (whitespace-split breaking quoted flag values, and no
allowance for the target's own resolved IP) — see tools.py's
run_tool_by_command / _extract_positional_tokens / _resolved_ips.
"""
import socket

import pytest

import tools


@pytest.fixture(autouse=True)
def _clear_resolved_ips_cache():
    tools._resolved_ips.cache_clear()
    yield
    tools._resolved_ips.cache_clear()


def _capture_execution(monkeypatch):
    """Replace run_tool with a recorder — if the guard should have blocked
    a call, nothing should ever land here."""
    calls = []
    monkeypatch.setattr(tools, "run_tool", lambda parts, **kw: calls.append(parts) or "OK")
    return calls


class TestAllowsLegitimateCalls:
    def test_quoted_header_value_is_one_token_not_a_fake_target(self, monkeypatch):
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command(
            'curl -I -H "Host: clubs.ma" https://clubs.ma', "clubs.ma"
        )
        assert calls, f"expected execution, got: {result}"

    def test_curl_write_out_format_string_is_not_a_fake_target(self, monkeypatch):
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command(
            'curl -s -o /dev/null -w "%{http_code}" -H "Host: clubs.ma" https://clubs.ma',
            "clubs.ma",
        )
        assert calls, f"expected execution, got: {result}"

    def test_nmap_against_targets_own_resolved_ip_is_allowed(self, monkeypatch):
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda host, *a, **kw: [(None, None, None, None, ("51.255.203.205", 0))],
        )
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command("nmap -sV 51.255.203.205", "clubs.ma")
        assert calls, f"expected execution, got: {result}"

    def test_nmap_with_output_file_flag_still_matches(self, monkeypatch):
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command("nmap -sV clubs.ma -oX /tmp/nmap.xml", "clubs.ma")
        assert calls, f"expected execution, got: {result}"

    def test_case_insensitive_target_match(self, monkeypatch):
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command("whois CLUBS.MA", "clubs.ma")
        assert calls, f"expected execution, got: {result}"


class TestBlocksRealViolations:
    def test_different_host_entirely_is_blocked(self, monkeypatch):
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command("nmap -sV 10.0.0.9", "target.com")
        assert not calls
        assert "BLOCKED" in result

    def test_smuggled_second_target_is_blocked(self, monkeypatch):
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command("nmap target.com 10.0.0.5", "target.com")
        assert not calls
        assert "BLOCKED" in result

    def test_ip_unrelated_to_target_is_blocked(self, monkeypatch):
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda host, *a, **kw: [(None, None, None, None, ("1.2.3.4", 0))],
        )
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command("nmap -sV 93.184.216.34", "clubs.ma")
        assert not calls
        assert "BLOCKED" in result

    def test_disallowed_tool_is_rejected(self, monkeypatch):
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command("rm -rf /", "clubs.ma")
        assert not calls
        assert "BLOCKED" in result

    def test_unresolvable_target_has_no_ip_bypass(self, monkeypatch):
        def raise_gaierror(*a, **kw):
            raise socket.gaierror("unresolvable")

        monkeypatch.setattr(socket, "getaddrinfo", raise_gaierror)
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command("nmap -sV 1.2.3.4", "clubs.ma")
        assert not calls
        assert "BLOCKED" in result

    def test_empty_command_is_rejected(self):
        result = tools.run_tool_by_command("   ", "clubs.ma")
        assert "Empty command" in result

    def test_unbalanced_quotes_fail_closed_not_open(self, monkeypatch):
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command('curl -H "Host: clubs.ma clubs.ma', "clubs.ma")
        assert not calls
        assert "Could not parse" in result

    def test_subdomain_is_not_automatically_in_scope(self, monkeypatch):
        # Intentional: engagement scope is exact-match. A subdomain sharing a
        # suffix with the target is a different host until the operator
        # explicitly declares it as the session target.
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command("curl -I www.clubs.ma", "clubs.ma")
        assert not calls
        assert "BLOCKED" in result

    def test_subdomain_in_allowed_set_is_permitted(self, monkeypatch):
        # Discovery level 2 explicitly opts a subdomain into scope for this
        # scan — see tools.discover_subdomains / run_tool_calls's
        # allowed_subdomains threading.
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command(
            "curl -I mail.clubs.ma", "clubs.ma",
            allowed_subdomains=frozenset({"mail.clubs.ma"}),
        )
        assert calls, f"expected execution, got: {result}"

    def test_subdomain_not_in_allowed_set_still_blocked(self, monkeypatch):
        # Only subdomains discover_subdomains() actually found are permitted —
        # the AI can't name an arbitrary host and have it accepted.
        calls = _capture_execution(monkeypatch)
        result = tools.run_tool_by_command(
            "curl -I evil.clubs.ma", "clubs.ma",
            allowed_subdomains=frozenset({"mail.clubs.ma"}),
        )
        assert not calls
        assert "BLOCKED" in result
