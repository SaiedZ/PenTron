"""
SSRF guard tests — curl's automatic redirect-following is replaced with a
manual single-hop check (tools.py::_fetch_headers_guarded) so a redirect
can't bounce recon requests onto localhost/cloud metadata/internal
services and leak their headers into the AI's context.
"""

from pentron import tools
from pentron.tools import http_headers


def test_same_host_standard_port_redirect_is_followed(monkeypatch):
    responses = iter(
        [
            "HTTP/1.1 301 Moved Permanently\nLocation: https://clubs.ma/",
            "HTTP/2 200\nserver: nginx",
        ]
    )
    monkeypatch.setattr(tools.base, "run_tool", lambda *a, **kw: next(responses))
    result = http_headers._fetch_headers_guarded("http://clubs.ma", "clubs.ma")
    assert "Followed same-host redirect" in result
    assert "200" in result


def test_same_host_relative_redirect_is_followed(monkeypatch):
    responses = iter(
        [
            "HTTP/1.1 302 Found\nLocation: /login",
            "HTTP/1.1 200 OK\nserver: nginx",
        ]
    )
    monkeypatch.setattr(tools.base, "run_tool", lambda *a, **kw: next(responses))
    result = http_headers._fetch_headers_guarded("http://clubs.ma", "clubs.ma")
    assert "Followed same-host redirect" in result


def test_cross_host_redirect_is_blocked_not_followed(monkeypatch):
    monkeypatch.setattr(
        tools.base,
        "run_tool",
        lambda *a, **kw: "HTTP/1.1 302 Found\nLocation: https://evil.com/steal",
    )
    result = http_headers._fetch_headers_guarded("http://clubs.ma", "clubs.ma")
    assert "Redirect to different host blocked" in result
    assert "evil.com" in result


def test_same_host_nonstandard_port_redirect_is_blocked(monkeypatch):
    # e.g. a target that is itself 127.0.0.1, redirecting to 127.0.0.1:11434
    # (an internal Ollama instance) — same hostname, but not a normal
    # same-site redirect, so it must NOT be auto-followed.
    monkeypatch.setattr(
        tools.base,
        "run_tool",
        lambda *a, **kw: "HTTP/1.1 302 Found\nLocation: http://127.0.0.1:11434/",
    )
    result = http_headers._fetch_headers_guarded("http://127.0.0.1", "127.0.0.1")
    assert "Redirect to different host blocked" in result


def test_no_redirect_header_returns_response_unchanged(monkeypatch):
    monkeypatch.setattr(
        tools.base, "run_tool", lambda *a, **kw: "HTTP/1.1 200 OK\nserver: nginx"
    )
    result = http_headers._fetch_headers_guarded("http://clubs.ma", "clubs.ma")
    assert result == "HTTP/1.1 200 OK\nserver: nginx"


def test_target_match_is_case_insensitive(monkeypatch):
    responses = iter(
        [
            "HTTP/1.1 301 Moved Permanently\nLocation: https://CLUBS.MA/",
            "HTTP/2 200\nserver: nginx",
        ]
    )
    monkeypatch.setattr(tools.base, "run_tool", lambda *a, **kw: next(responses))
    result = http_headers._fetch_headers_guarded("http://clubs.ma", "clubs.ma")
    assert "Followed same-host redirect" in result
