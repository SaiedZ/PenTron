"""
AI-facing dispatch for the free-text [TOOL:] commands the LLM emits.

Every dispatched call is scope-guarded back to the operator-declared
session target before it reaches base.run_tool() — the LLM controls the
rest of the command line, including the target, and the recon text it
reasons over (banners, headers, page bodies) can itself be
attacker-influenced.
"""

import ipaddress
import shlex
import socket
from functools import lru_cache
from urllib.parse import urlparse

from . import base, registry


def _resolve_host(token: str) -> str:
    """Best-effort hostname extraction from a raw command-line token."""
    if "://" in token:
        return (urlparse(token).hostname or "").lower()
    return token.split("/")[0].split(":")[0].lower()


# Flags (across nmap/curl/whatweb/dig/nikto/sslscan/testssl) known to take a
# following value, so that value never gets mistaken for a positional target
# argument — e.g. "-p 80,443" must skip "80,443", not treat it as the
# command's target.
_VALUE_FLAGS = {
    "-p",
    "-T",
    "-o",
    "-oN",
    "-oX",
    "-oG",
    "-oA",
    "-A",
    "-H",
    "-d",
    "-X",
    "-e",
    "-a",
    "-U",
    "--top-ports",
    "--connect-timeout",
    "--max-time",
    "--host-timeout",
    "--min-rate",
    "--max-rate",
    "--script",
    "--warnings",
    "--mode",
    "--openssl-timeout",
    "--openssl",
    "--proxy",
    "-w",
    "--write-out",
    "-b",
    "-c",
    "-D",
    "-x",
    "--data-raw",
    "--referer",
}


def _extract_positional_tokens(parts: list) -> list:
    """
    Best-effort split of a command's arguments into positional (non-flag)
    tokens — skips boolean flags (-sV, --open, -k, +short, ...) and the
    value belonging to a known value-taking flag, so a flag's value never
    gets mistaken for the target argument.
    """
    positional = []
    skip_next = False
    for token in parts:
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-") or token.startswith("+"):
            if token in _VALUE_FLAGS:
                skip_next = True
            continue
        positional.append(token)
    return positional


@lru_cache(maxsize=32)
def _resolved_ips(hostname: str) -> frozenset:
    """The session target's own resolved IPs — cached since the agentic loop
    can dispatch many calls per scan and this is the same lookup every time."""
    try:
        return frozenset(info[4][0] for info in socket.getaddrinfo(hostname, None))
    except socket.gaierror:
        return frozenset()


def run_tool_by_command(
    command_str: str, session_target: str, allowed_subdomains: frozenset = frozenset()
) -> str:
    try:
        # shlex, not .split() — a quoted argument like -H "Host: x.com" is
        # ONE token, not two; splitting on whitespace breaks both the actual
        # subprocess argv AND the scope check below (the quoted value's
        # second word would wrongly look like a mismatched positional arg).
        parts = shlex.split(command_str.strip())
    except ValueError as e:
        return f"[!] Could not parse command ({e}): {command_str}"
    if not parts:
        return "[!] Empty command."

    # allowlist only — reject anything not in the list
    tool = parts[0].lower().split("/")[-1]  # handles /bin/nmap etc
    allowed = registry.allowed_commands()
    if tool not in allowed:
        return f"[!] BLOCKED: tool '{parts[0]}' is not permitted. Allowed: {allowed}"

    # scope guard — the LLM controls the rest of the command line, including
    # the target, and the recon text it reasons over (banners, headers, page
    # bodies) can itself be attacker-influenced. Bind every dispatched tool
    # call back to the operator-declared session target so a scan can't be
    # pivoted onto an unauthorized host via a planted "run nmap on X" hint.
    # Every positional argument must match — not just one — so a command
    # can't smuggle a second, different target alongside the real one
    # (e.g. "nmap target.com 10.0.0.5").
    # allowed_subdomains: hosts discover_subdomains() found at discovery
    # level 2 (active) for this scan — an explicit, operator-opted-in
    # widening of scope, not automatic subdomain inclusion (see
    # test_subdomain_is_not_automatically_in_scope).
    positional = _extract_positional_tokens(parts[1:])
    target_host = session_target.lower()

    def _matches_target(token: str) -> bool:
        resolved = _resolve_host(token)
        if resolved == target_host:
            return True
        if resolved in allowed_subdomains:
            return True
        # a literal IP that the target's own hostname resolves to is still
        # the same host, not a pivot — e.g. the AI following up an nmap
        # against the IP curl/whatweb already reported for this target
        try:
            ipaddress.ip_address(resolved)
        except ValueError:
            return False
        return resolved in _resolved_ips(session_target)

    if not positional or any(not _matches_target(p) for p in positional):
        shown = ", ".join(positional) if positional else command_str
        return (
            f"[!] BLOCKED: target '{shown}' "
            f"does not match session target '{session_target}'"
        )

    return base.run_tool(parts)
