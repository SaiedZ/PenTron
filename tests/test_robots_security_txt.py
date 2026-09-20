"""
robots.txt / security.txt recon — tools.py::run_robots_and_security_txt.
robots.txt sometimes leaks paths an admin doesn't want indexed; security.txt
(RFC 9116) signals whether the target has a documented vulnerability-
disclosure process. Checked at the standard /.well-known/ path first, with
a fallback to the legacy root path some sites still use instead.
"""

from pentron import tools
from pentron.tools import robots_security_txt


def test_https_success_does_not_fall_back_to_http(monkeypatch):
    calls = []

    def _fake_run_tool(command, **kw):
        calls.append(command)
        url = command[-1]
        if "robots.txt" in url:
            return "User-agent: *\nDisallow: /admin\n[HTTP 200]"
        if ".well-known/security.txt" in url:
            return "Contact: mailto:security@example.com\n[HTTP 200]"
        return "[HTTP 404]"

    monkeypatch.setattr(tools.base, "run_tool", _fake_run_tool)
    result = tools.run_robots_and_security_txt("example.com")

    assert all(cmd[-1].startswith("https://") for cmd in calls)
    assert "Disallow: /admin" in result
    assert "security@example.com" in result
    assert "legacy /security.txt" not in result


def test_https_failure_falls_back_to_http(monkeypatch):
    def _fake_run_tool(command, **kw):
        url = command[-1]
        if url.startswith("https://"):
            return (
                "curl: (7) Failed to connect to example.com "
                "port 443: Connection refused"
            )
        if "robots.txt" in url:
            return "User-agent: *\n[HTTP 200]"
        return "[HTTP 404]"

    monkeypatch.setattr(tools.base, "run_tool", _fake_run_tool)
    result = tools.run_robots_and_security_txt("example.com")
    assert "http://example.com/robots.txt" in result or "User-agent: *" in result


def test_security_txt_missing_at_wellknown_falls_back_to_legacy_path(monkeypatch):
    calls = []

    def _fake_run_tool(command, **kw):
        calls.append(command[-1])
        url = command[-1]
        if "robots.txt" in url:
            return "[HTTP 404]"
        if ".well-known/security.txt" in url:
            return "[HTTP 404]"
        if url.endswith("/security.txt"):
            return "Contact: mailto:security@example.com\n[HTTP 200]"
        return "[HTTP 404]"

    monkeypatch.setattr(tools.base, "run_tool", _fake_run_tool)
    result = tools.run_robots_and_security_txt("example.com")

    assert any(u.endswith("/.well-known/security.txt") for u in calls)
    assert any(u.endswith("/security.txt") and ".well-known" not in u for u in calls)
    assert "legacy /security.txt" in result
    assert "security@example.com" in result


def test_output_is_capped_in_length(monkeypatch):
    huge = "A" * 10_000

    def _fake_run_tool(command, **kw):
        return huge + "\n[HTTP 200]"

    monkeypatch.setattr(tools.base, "run_tool", _fake_run_tool)
    result = robots_security_txt._fetch_text_file("https://example.com", "/robots.txt")
    assert len(result) <= robots_security_txt._MAX_TEXT_FILE_CHARS
