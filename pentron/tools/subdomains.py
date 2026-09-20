"""Subdomain discovery (3 configurable levels) — not part of TOOLS_MENU, since
it's a scope-widening step rather than a directly user-selectable tool."""

import requests

from . import base


def _discover_subdomains_passive(target: str) -> list:
    """
    Query crt.sh (certificate transparency logs) for hostnames ever issued
    a TLS cert under this domain. A single request to a public third-party
    service — zero traffic to the target itself.
    """
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{target}", "output": "json"},
            timeout=20,
        )
        resp.raise_for_status()
        entries = resp.json()
    except Exception:
        return []

    target_lower = target.lower()
    found = set()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name.endswith(target_lower) and name != target_lower:
                found.add(name)
    return sorted(found)


def _discover_subdomains_active(target: str) -> list:
    """
    subfinder — aggregates many passive sources plus live DNS resolution,
    surfacing subdomains that never had a public certificate (so crt.sh
    alone would miss them). More thorough than the passive-only pass, and
    generates DNS traffic in the process.
    """
    output = base.run_tool(["subfinder", "-d", target, "-silent"], timeout=90)
    if output.startswith("[!]"):
        return []

    target_lower = target.lower()
    found = set()
    for line in output.splitlines():
        name = line.strip().lower()
        if name.endswith(target_lower) and name != target_lower:
            found.add(name)
    return sorted(found)


def discover_subdomains(target: str, level: int) -> tuple:
    """
    Runs the configured subdomain discovery level and returns
    (report_text, allowed_subdomains).

    Level 0 — disabled: no discovery, no scope change.
    Level 1 — passive: crt.sh only. Results are informative (added to the
      report the AI reads) but do NOT loosen the scope guard — the AI still
      can't dispatch tool calls against them.
    Level 2 — active: crt.sh + subfinder. Results ALSO become valid targets
      for the scope guard (see run_tool_by_command's allowed_subdomains),
      so the AI can follow up with nmap/whatweb/etc. on what it finds.
    """
    if level <= 0:
        return "", frozenset()

    found = set(_discover_subdomains_passive(target))
    if level >= 2:
        found.update(_discover_subdomains_active(target))

    if not found:
        mode = "active" if level >= 2 else "passive"
        return f"[*] Subdomain discovery ({mode}): none found.\n", frozenset()

    mode = "active" if level >= 2 else "passive"
    lines = [f"[*] Subdomain discovery ({mode}): {len(found)} found"]
    lines += [f"  - {name}" for name in sorted(found)]
    text = "\n".join(lines) + "\n"

    allowed = frozenset(found) if level >= 2 else frozenset()
    return text, allowed
