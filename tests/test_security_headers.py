"""
HTTP security header analysis — tools.py::_analyze_security_headers enriches
the existing curl headers fetch with an explicit present/missing check for
standard security headers (HSTS, CSP, X-Frame-Options, ...). Absence is a
common misconfiguration signal, not proof of a vulnerability by itself.
"""

import tools


def test_all_headers_present_are_reported_present():
    headers = (
        "HTTP/1.1 200 OK\n"
        "Strict-Transport-Security: max-age=63072000\n"
        "Content-Security-Policy: default-src 'self'\n"
        "X-Frame-Options: DENY\n"
        "X-Content-Type-Options: nosniff\n"
        "Referrer-Policy: no-referrer\n"
        "Permissions-Policy: geolocation=()\n"
    )
    result = tools._analyze_security_headers(headers)
    assert "MISSING" not in result
    assert result.count("present :") == 6


def test_all_headers_missing_are_flagged():
    headers = "HTTP/1.1 200 OK\nServer: nginx\n"
    result = tools._analyze_security_headers(headers)
    assert "present :" not in result
    assert result.count("MISSING") == 6
    assert "strict-transport-security" in result
    assert "content-security-policy" in result


def test_partial_headers_are_individually_flagged():
    headers = "HTTP/1.1 200 OK\nX-Frame-Options: SAMEORIGIN\nX-Content-Type-Options: nosniff\n"
    result = tools._analyze_security_headers(headers)
    assert "present : x-frame-options" in result
    assert "present : x-content-type-options" in result
    assert "MISSING : strict-transport-security" in result
    assert "MISSING : content-security-policy" in result


def test_no_response_is_not_reported_as_all_missing():
    # A connection failure (curl stderr, timeout, etc.) must not be
    # misrepresented as "every security header is missing" — that would
    # imply a real response was inspected when none was.
    no_response = "[!] Timed out after 10s: curl -sI http://clubs.ma"
    result = tools._analyze_security_headers(no_response)
    assert "MISSING" not in result
    assert "Could not check" in result


def test_case_insensitive_header_matching():
    headers = "http/1.1 200 ok\nstrict-transport-security: max-age=1\n"
    result = tools._analyze_security_headers(headers)
    assert "present : strict-transport-security" in result
