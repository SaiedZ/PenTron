"""
WAF detection — tools.py::run_waf_detect wraps wafw00f, stripping the ANSI
color codes it always emits (even without a tty) so the report stays clean
for both the terminal and the AI's context.
"""

from pentron import tools


def test_ansi_color_codes_are_stripped(monkeypatch):
    monkeypatch.setattr(
        tools.base,
        "run_tool",
        lambda *a, **kw: (
            "[+] The site \x1b[1;94mhttps://clubs.ma\x1b[0m is behind "
            "\x1b[1;96mCloudflare\x1b[0m WAF."
        ),
    )
    result = tools.run_waf_detect("clubs.ma")
    assert "\x1b" not in result
    assert "is behind Cloudflare WAF" in result


def test_checks_both_http_and_https(monkeypatch):
    seen = {}

    def _fake_run_tool(command, **kw):
        seen["command"] = command
        return "[-] No WAF detected by the generic detection"

    monkeypatch.setattr(tools.base, "run_tool", _fake_run_tool)
    tools.run_waf_detect("clubs.ma")
    assert "http://clubs.ma" in seen["command"]
    assert "https://clubs.ma" in seen["command"]


def test_wafw00f_is_dispatchable_and_scope_checked(monkeypatch):
    calls = []
    monkeypatch.setattr(
        tools.base, "run_tool", lambda parts, **kw: calls.append(parts) or "OK"
    )
    result = tools.run_tool_by_command("wafw00f https://clubs.ma", "clubs.ma")
    assert calls, f"expected execution, got: {result}"


def test_wafw00f_against_wrong_target_is_blocked(monkeypatch):
    calls = []
    monkeypatch.setattr(
        tools.base, "run_tool", lambda parts, **kw: calls.append(parts) or "OK"
    )
    result = tools.run_tool_by_command("wafw00f https://evil.com", "clubs.ma")
    assert not calls
    assert "BLOCKED" in result
