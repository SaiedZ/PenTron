"""
Email-security DNS checks in tools.py::run_dig — SPF/DMARC/DKIM absence is
a real spoofing/phishing risk for a domain, not just a DNS curiosity, so
run_dig reports their presence/absence alongside the plain A/MX/NS/TXT dump.
"""

from pentron import tools


def _fake_run_tool(responses):
    def _run(command, **kw):
        joined = " ".join(command)
        for key, value in responses.items():
            if key in joined:
                return value
        return ""

    return _run


def test_spf_and_dmarc_present_are_reported_as_present(monkeypatch):
    monkeypatch.setattr(
        tools,
        "run_tool",
        _fake_run_tool(
            {
                "_dmarc.example.com": '"v=DMARC1; p=reject"',
                "default._domainkey.example.com": "",
                "TXT example.com": '"v=spf1 include:_spf.example.com ~all"',
            }
        ),
    )
    result = tools.run_dig("example.com")
    assert "[Email security — SPF]: present" in result
    assert "[Email security — DMARC]: present" in result


def test_spf_and_dmarc_absent_are_flagged_missing(monkeypatch):
    monkeypatch.setattr(
        tools,
        "run_tool",
        _fake_run_tool(
            {
                "_dmarc.example.com": "",
                "default._domainkey.example.com": "",
                "TXT example.com": "",
            }
        ),
    )
    result = tools.run_dig("example.com")
    assert "[Email security — SPF]: MISSING" in result
    assert "[Email security — DMARC]: MISSING" in result


def test_dkim_found_under_default_selector(monkeypatch):
    monkeypatch.setattr(
        tools,
        "run_tool",
        _fake_run_tool(
            {
                "default._domainkey.example.com": '"v=DKIM1; k=rsa; p=MIGfMA0..."',
                "TXT example.com": "",
                "_dmarc.example.com": "",
            }
        ),
    )
    result = tools.run_dig("example.com")
    assert "[Email security — DKIM]: found under selector 'default'" in result


def test_dkim_absent_under_default_selector_notes_other_selectors_possible(monkeypatch):
    monkeypatch.setattr(
        tools,
        "run_tool",
        _fake_run_tool(
            {
                "default._domainkey.example.com": "",
                "TXT example.com": "",
                "_dmarc.example.com": "",
            }
        ),
    )
    result = tools.run_dig("example.com")
    assert "not found under selector 'default'" in result
    assert "may still exist under another selector" in result


def test_dkim_lookup_error_is_treated_as_not_found_not_a_crash(monkeypatch):
    monkeypatch.setattr(
        tools,
        "run_tool",
        _fake_run_tool(
            {
                "default._domainkey.example.com": "[!] Timed out after 15s: dig",
                "TXT example.com": "",
                "_dmarc.example.com": "",
            }
        ),
    )
    result = tools.run_dig("example.com")
    assert "not found under selector 'default'" in result
