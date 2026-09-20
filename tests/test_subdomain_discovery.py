"""
Subdomain discovery tests — tools.py::discover_subdomains has 3 operator-
selectable levels (settings.subdomain_discovery_level):
  0 disabled — no discovery, no scope change.
  1 passive  — crt.sh (certificate transparency) only, informative in the
               report, scope guard stays exact-match.
  2 active   — crt.sh + subfinder; results ALSO become valid scope-guard
               targets for this scan (see run_tool_by_command's
               allowed_subdomains param).
"""

from pentron import tools


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_level_0_is_disabled_and_never_calls_out(monkeypatch):
    def _boom(*a, **kw):
        raise AssertionError("level 0 must not make any network call")

    monkeypatch.setattr(tools.subdomains.requests, "get", _boom)
    monkeypatch.setattr(tools.base, "run_tool", _boom)

    text, allowed = tools.discover_subdomains("clubs.ma", 0)
    assert text == ""
    assert allowed == frozenset()


def test_level_1_passive_queries_crtsh_only(monkeypatch):
    monkeypatch.setattr(
        tools.subdomains.requests,
        "get",
        lambda *a, **kw: _FakeResponse(
            [
                {"name_value": "mail.clubs.ma\n*.dev.clubs.ma"},
                {"name_value": "clubs.ma"},  # apex itself — must be excluded
            ]
        ),
    )
    monkeypatch.setattr(
        tools.base,
        "run_tool",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("level 1 must not run subfinder")
        ),
    )

    text, allowed = tools.discover_subdomains("clubs.ma", 1)
    assert "mail.clubs.ma" in text
    assert "dev.clubs.ma" in text
    assert "clubs.ma" not in text.replace("mail.clubs.ma", "").replace(
        "dev.clubs.ma", ""
    )
    # passive-only: informative, but scope guard is NOT widened
    assert allowed == frozenset()


def test_level_2_active_merges_sources_and_widens_scope(monkeypatch):
    monkeypatch.setattr(
        tools.subdomains.requests,
        "get",
        lambda *a, **kw: _FakeResponse([{"name_value": "mail.clubs.ma"}]),
    )
    monkeypatch.setattr(
        tools.base,
        "run_tool",
        lambda command, **kw: "mail.clubs.ma\nstaging.clubs.ma\n",
    )

    text, allowed = tools.discover_subdomains("clubs.ma", 2)
    assert "mail.clubs.ma" in text
    assert "staging.clubs.ma" in text
    assert allowed == frozenset({"mail.clubs.ma", "staging.clubs.ma"})


def test_no_results_is_reported_not_silently_empty(monkeypatch):
    monkeypatch.setattr(
        tools.subdomains.requests, "get", lambda *a, **kw: _FakeResponse([])
    )
    text, allowed = tools.discover_subdomains("clubs.ma", 1)
    assert "none found" in text
    assert allowed == frozenset()


def test_crtsh_failure_degrades_to_empty_not_a_crash(monkeypatch):
    def _raise(*a, **kw):
        raise Exception("network error")

    monkeypatch.setattr(tools.subdomains.requests, "get", _raise)
    text, allowed = tools.discover_subdomains("clubs.ma", 1)
    assert "none found" in text
    assert allowed == frozenset()


def test_subfinder_failure_falls_back_to_passive_results_only(monkeypatch):
    monkeypatch.setattr(
        tools.subdomains.requests,
        "get",
        lambda *a, **kw: _FakeResponse([{"name_value": "mail.clubs.ma"}]),
    )
    monkeypatch.setattr(
        tools.base, "run_tool", lambda *a, **kw: "[!] Tool not found: subfinder"
    )

    text, allowed = tools.discover_subdomains("clubs.ma", 2)
    assert "mail.clubs.ma" in text
    assert allowed == frozenset({"mail.clubs.ma"})
