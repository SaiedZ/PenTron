#!/usr/bin/env python3
"""
METATRON - tools.py
Recon tool runners — all output returned as strings to feed into the LLM.
Tools used: nmap, whois, whatweb, curl, dig, nikto, sslscan, testssl.sh
OS: Parrot OS (all these tools are pre-installed or easily available)
"""

import ipaddress
import socket
import subprocess
import time
from urllib.parse import urlparse, urljoin


# ─────────────────────────────────────────────
# PRE-FLIGHT TARGET SAFETY CHECK
# ─────────────────────────────────────────────

def _is_unsafe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def check_target_safety(target: str) -> str:
    """
    Refuse to start a scan whose target resolves to a private/loopback/
    link-local/reserved address — before any recon tool runs. A domain's
    DNS can be changed at any time by whoever controls it, including to
    point at internal infrastructure (the operator's own machine, another
    container, cloud metadata); this is a real vector for a pentest target
    to redirect the very first recon pass onto something it shouldn't.

    A literal IP typed directly by the operator is always allowed — that's
    an explicit, conscious choice (e.g. testing your own LAN), not a DNS
    record an attacker could have altered.

    Returns an error string if the target should be refused, else None.
    """
    try:
        ipaddress.ip_address(target)
        return None
    except ValueError:
        pass  # not a literal IP — it's a hostname, resolve and check it

    try:
        resolved_ips = {info[4][0] for info in socket.getaddrinfo(target, None)}
    except socket.gaierror:
        return None  # unresolvable — not what this check is about, let the normal tool errors handle it

    unsafe = sorted(ip for ip in resolved_ips if _is_unsafe_ip(ip))
    if unsafe:
        return (
            f"[!] BLOCKED: '{target}' resolves to a private/internal address "
            f"({', '.join(unsafe)}) — refusing to scan. This can happen if the "
            f"target's DNS has been changed to point at internal infrastructure. "
            f"If this is intentional (e.g. testing your own network), enter the "
            f"IP address directly instead of the domain name."
        )
    return None


# ─────────────────────────────────────────────
# BASE RUNNER
# ─────────────────────────────────────────────

def run_tool(command: list, timeout: int = 120, retries: int = 0, retry_delay: float = 2.0) -> str:
    """
    Execute a shell command, return combined stdout + stderr as string.
    Never crashes the program — always returns something.

    Retries only on a timeout, up to `retries` extra attempts, since that's
    the one failure mode that's plausibly a transient network hiccup rather
    than a deterministic outcome (tool not found, target actually filtered,
    a completed scan) that re-running would just reproduce.
    """
    attempt = 0
    while True:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            output = result.stdout.strip()
            errors = result.stderr.strip()

            if output and errors:
                return output + "\n[STDERR]\n" + errors
            elif output:
                return output
            elif errors:
                return errors
            else:
                return "[!] Tool returned no output."

        except subprocess.TimeoutExpired:
            if attempt < retries:
                attempt += 1
                print(f"  [!] Timed out after {timeout}s, retrying ({attempt}/{retries})...")
                time.sleep(retry_delay)
                continue
            tried = f" (tried {attempt + 1}x)" if retries else ""
            return f"[!] Timed out after {timeout}s{tried}: {' '.join(command)}"
        except FileNotFoundError:
            return f"[!] Tool not found: {command[0]} — install it with: sudo apt install {command[0]}"
        except Exception as e:
            return f"[!] Unexpected error running {command[0]}: {e}"


# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────

def run_nmap(target: str, user_agent: str = None) -> str:
    """
    nmap -sV -sC -T4 --open
    -sV  : detect service versions
    -sC  : run default scripts (basic vuln checks)
    -T4  : aggressive timing (faster)
    --open : only show open ports
    user_agent is accepted but unused — nmap has no HTTP User-Agent concept;
    kept for a uniform TOOLS_MENU dispatch signature across all tools.
    """
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)


def run_whois(target: str, user_agent: str = None) -> str:
    """
    whois — domain registration, registrar, IP ownership info
    """
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=30, retries=1)


def run_whatweb(target: str, user_agent: str = None) -> str:
    """
    whatweb -a 3 — fingerprint web technologies, CMS, frameworks, headers
    -a 3 : aggression level 3 (active but not destructive)
    -U   : override the User-Agent header (default: WhatWeb's own), if set
    """
    args = ["whatweb", "-a", "3"]
    if user_agent:
        args += ["-U", user_agent]
    args.append(target)
    print(f"  [*] {' '.join(args)}")
    return run_tool(args, timeout=60)


def _extract_location(headers_text: str) -> str | None:
    """Pull the value of a Location: header out of raw curl -I output, if present."""
    for line in headers_text.splitlines():
        if line.lower().startswith("location:"):
            return line.split(":", 1)[1].strip()
    return None


def _fetch_headers_once(url: str, user_agent: str = None) -> str:
    args = ["curl", "-sI", "--max-time", "10"]
    if url.startswith("https://"):
        args.append("-k")  # ignore cert errors
    if user_agent:
        args += ["-A", user_agent]
    args.append(url)
    return run_tool(args, timeout=20, retries=1)


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _effective_port(parsed) -> int:
    return parsed.port or _DEFAULT_PORTS.get(parsed.scheme, 0)


def _fetch_headers_guarded(url: str, target: str, user_agent: str = None) -> str:
    """
    Fetch headers WITHOUT letting curl auto-follow redirects (SSRF guard).
    A redirect to the same host on a standard port (80/443) — i.e. a normal
    same-site http->https upgrade or path redirect — is followed once.
    Anything else is reported but not followed: a redirect to a different
    host, OR to a non-standard port on the *same* host (e.g. a target that
    is itself 127.0.0.1 redirecting to 127.0.0.1:11434), can otherwise
    bounce us onto localhost/cloud metadata/internal services and leak
    their headers into the recon data.
    """
    first = _fetch_headers_once(url, user_agent)
    location = _extract_location(first)
    if not location:
        return first

    resolved = urljoin(url, location)
    parsed = urlparse(resolved)
    host = (parsed.hostname or "").lower()
    port = _effective_port(parsed)

    same_host = host == target.lower()
    standard_port = port in _DEFAULT_PORTS.values()

    if same_host and standard_port:
        second = _fetch_headers_once(resolved, user_agent)
        return f"{first}\n[Followed same-host redirect to {resolved}]\n{second}"

    return f"{first}\n[!] Redirect to different host blocked: {location}"


def run_curl_headers(target: str, user_agent: str = None) -> str:
    """
    curl -sI — fetch HTTP headers only
    Reveals: server software, X-Powered-By, cookies, security headers (or lack of them)
    user_agent, if set, overrides curl's default User-Agent header.
    """
    print(f"  [*] curl -sI {'-A <custom UA> ' if user_agent else ''}http://{target}")
    output = _fetch_headers_guarded(f"http://{target}", target, user_agent)

    # also try https
    https_output = _fetch_headers_guarded(f"https://{target}", target, user_agent)

    return f"[HTTP Headers]\n{output}\n\n[HTTPS Headers]\n{https_output}"


def run_dig(target: str, user_agent: str = None) -> str:
    """
    dig — DNS records: A, MX, NS, TXT
    Useful for subdomains, mail servers, SPF/DKIM info
    user_agent is accepted but unused — DNS queries have no HTTP User-Agent
    concept; kept for a uniform TOOLS_MENU dispatch signature.
    """
    print(f"  [*] dig {target} ANY")
    a_record  = run_tool(["dig", "+short", "A",   target], timeout=15, retries=1)
    mx_record = run_tool(["dig", "+short", "MX",  target], timeout=15, retries=1)
    ns_record = run_tool(["dig", "+short", "NS",  target], timeout=15, retries=1)
    txt_record= run_tool(["dig", "+short", "TXT", target], timeout=15, retries=1)

    return (
        f"[A Records]\n{a_record}\n\n"
        f"[MX Records]\n{mx_record}\n\n"
        f"[NS Records]\n{ns_record}\n\n"
        f"[TXT Records]\n{txt_record}"
    )


def run_nikto(target: str, user_agent: str = None) -> str:
    """
    nikto -h — web server vulnerability scanner
    Checks for outdated software, dangerous files, misconfigurations
    WARNING: noisy tool, only run with permission
    -useragent, if user_agent is set, overrides nikto's default UA (which
    otherwise self-identifies as "Nikto/x.x" on every request — a classic
    WAF signature match). Deliberately NOT using nikto's own -R (random UA
    per request) — a fixed, operator-chosen UA stays traceable; a randomly
    rotating one doesn't.
    """
    args = ["nikto", "-h", target, "-nointeractive"]
    if user_agent:
        args += ["-useragent", user_agent]
    print(f"  [*] {' '.join(args)}  (this may take a while...)")
    return run_tool(args, timeout=300)


def run_sslscan(target: str, user_agent: str = None) -> str:
    """
    sslscan — enumerate supported TLS/SSL protocol versions, cipher suites,
    and certificate details for a host.
    user_agent is accepted but unused — sslscan operates at the TLS layer,
    no HTTP User-Agent involved; kept for a uniform dispatch signature.
    """
    print(f"  [*] sslscan --no-colour {target}")
    return run_tool(["sslscan", "--no-colour", target], timeout=90)


def run_testssl(target: str, user_agent: str = None) -> str:
    """
    testssl.sh — deeper TLS/SSL configuration audit: protocols, ciphers,
    known vulnerabilities (Heartbleed, POODLE, etc.), certificate issues.
    WARNING: slower and noisier than sslscan, run selectively.
    user_agent is accepted but unused — same reasoning as sslscan.
    """
    print(f"  [*] testssl --quiet --color 0 --warnings batch {target}  (this may take a while...)")
    return run_tool(["testssl", "--quiet", "--color", "0", "--warnings", "batch", target], timeout=240)


# ─────────────────────────────────────────────
# MAIN RECON PIPELINE
# ─────────────────────────────────────────────

TOOLS_MENU = {
    "1": ("nmap",         run_nmap),
    "2": ("whois",        run_whois),
    "3": ("whatweb",      run_whatweb),
    "4": ("curl headers", run_curl_headers),
    "5": ("dig DNS",      run_dig),
    "6": ("nikto",        run_nikto),
    "7": ("sslscan",      run_sslscan),
    "8": ("testssl.sh",   run_testssl),
}


_DEFAULT_RECON_TOOL_NAMES = ["nmap", "whois", "whatweb", "curl headers", "dig"]


def resolve_tool_plan(tool_keys) -> list:
    """
    Preview the ordered list of tool display names a run_selected_tools()
    call with these tool_keys will actually emit via on_progress — lets a
    caller (the web UI) show a full checklist upfront instead of only
    finding out what's left to run as each tool starts.
    """
    if tool_keys == "a":
        return list(_DEFAULT_RECON_TOOL_NAMES)
    if tool_keys == "n":
        return list(_DEFAULT_RECON_TOOL_NAMES) + ["nikto"]
    return [TOOLS_MENU[k][0] for k in tool_keys if k in TOOLS_MENU]


def run_default_recon(target: str, on_progress=None, delay: float = 0, user_agent: str = None) -> dict:
    """
    Run the standard recon pipeline (everything except nikto).
    Returns a dict of {tool_name: output_string}.
    Nikto is excluded by default — too slow/noisy for auto-run.
    on_progress(event, payload), if given, is called around each tool run
    so a caller (e.g. the web API) can surface live progress.
    delay, if > 0, is a pause (seconds) before each tool after the first —
    rate limiting so a scan doesn't hit the target with several tools back
    to back.
    user_agent, if set, overrides the HTTP User-Agent sent by curl/whatweb
    (tools that don't send one ignore it) — a fixed, operator-chosen value,
    not rotated per request.
    """
    print(f"\n[*] Starting recon on: {target}")
    print("─" * 50)

    first_call = True

    def _run(name, func):
        nonlocal first_call
        if not first_call and delay > 0:
            print(f"  [*] Waiting {delay}s before {name} (rate limiting)...")
            time.sleep(delay)
        first_call = False
        if on_progress:
            on_progress("tool_start", name)
        output = func(target, user_agent)
        if on_progress:
            on_progress("tool_done", name)
        return output

    results = {}
    results["nmap"]         = _run("nmap", run_nmap)
    results["whois"]        = _run("whois", run_whois)
    results["whatweb"]      = _run("whatweb", run_whatweb)
    results["curl_headers"] = _run("curl headers", run_curl_headers)
    results["dig"]          = _run("dig", run_dig)

    print("─" * 50)
    print("[+] Recon complete.\n")
    return results


def run_single_tool(tool_key: str, target: str) -> str:
    """Run one tool by its menu key. Used by AI tool dispatch."""
    if tool_key in TOOLS_MENU:
        name, func = TOOLS_MENU[tool_key]
        return func(target)
    return f"[!] Unknown tool key: {tool_key}"


def run_selected_tools(target: str, tool_keys, on_progress=None, delay: float = 0, user_agent: str = None) -> dict:
    """
    Pure equivalent of interactive_tool_run's dispatch logic, without the
    input()/print() coupling — used by the web API. tool_keys is either a
    list of TOOLS_MENU keys (e.g. ["1", "2", "4"]) or the literal "a" / "n"
    for the default-recon / default+nikto bundles (same shorthand the CLI
    tool picker accepts). delay, if > 0, is a pause (seconds) between tools.
    user_agent, if set, overrides the HTTP User-Agent for tools that send one.
    """
    if tool_keys == "a":
        return run_default_recon(target, on_progress=on_progress, delay=delay, user_agent=user_agent)

    if tool_keys == "n":
        results = run_default_recon(target, on_progress=on_progress, delay=delay, user_agent=user_agent)
        if delay > 0:
            time.sleep(delay)
        if on_progress:
            on_progress("tool_start", "nikto")
        results["nikto"] = run_nikto(target, user_agent)
        if on_progress:
            on_progress("tool_done", "nikto")
        return results

    results = {}
    first_call = True
    for key in tool_keys:
        if key not in TOOLS_MENU:
            continue
        if not first_call and delay > 0:
            time.sleep(delay)
        first_call = False
        name, func = TOOLS_MENU[key]
        if on_progress:
            on_progress("tool_start", name)
        results[name] = func(target, user_agent)
        if on_progress:
            on_progress("tool_done", name)
    return results


def format_recon_for_llm(results: dict) -> str:
    """
    Flatten the recon results dict into one clean string
    to paste into the LLM prompt.
    """
    output = ""
    for tool, data in results.items():
        output += f"\n{'='*50}\n"
        output += f"[ {tool.upper()} OUTPUT ]\n"
        output += f"{'='*50}\n"
        output += data.strip() + "\n"
    return output


ALLOWED_TOOLS = {"nmap", "whois", "whatweb", "curl", "dig", "nikto", "sslscan", "testssl"}


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
    "-p", "-T", "-o", "-oN", "-oX", "-oG", "-oA", "-A", "-H", "-d", "-X", "-e",
    "-a", "-U", "--top-ports", "--connect-timeout", "--max-time",
    "--host-timeout", "--min-rate", "--max-rate", "--script",
    "--warnings", "--mode", "--openssl-timeout", "--openssl", "--proxy",
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


def run_tool_by_command(command_str: str, session_target: str) -> str:
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."

    # allowlist only — reject anything not in the list
    tool = parts[0].lower().split("/")[-1]  # handles /bin/nmap etc
    if tool not in ALLOWED_TOOLS:
        return f"[!] BLOCKED: tool '{parts[0]}' is not permitted. Allowed: {ALLOWED_TOOLS}"

    # scope guard — the LLM controls the rest of the command line, including
    # the target, and the recon text it reasons over (banners, headers, page
    # bodies) can itself be attacker-influenced. Bind every dispatched tool
    # call back to the operator-declared session target so a scan can't be
    # pivoted onto an unauthorized host via a planted "run nmap on X" hint.
    # Every positional argument must match — not just one — so a command
    # can't smuggle a second, different target alongside the real one
    # (e.g. "nmap target.com 10.0.0.5").
    positional = _extract_positional_tokens(parts[1:])
    target_host = session_target.lower()
    if not positional or any(_resolve_host(p) != target_host for p in positional):
        shown = ", ".join(positional) if positional else command_str
        return (f"[!] BLOCKED: target '{shown}' "
                f"does not match session target '{session_target}'")

    return run_tool(parts)

# ─────────────────────────────────────────────
# INTERACTIVE TOOL SELECTOR (called from CLI)
# ─────────────────────────────────────────────

def interactive_tool_run(target: str, delay: float = 0, user_agent: str = None) -> str:
    """
    Let user manually pick which tools to run.
    Returns combined output string. delay, if > 0, is a pause (seconds)
    between tools — rate limiting so the target isn't hit by several tools
    back to back. user_agent, if set, overrides the HTTP User-Agent for
    tools that send one.
    """
    print("\n[ SELECT TOOLS TO RUN ]")
    for key, (name, _) in TOOLS_MENU.items():
        print(f"  [{key}] {name}")
    print("  [a] Run all (except nikto, sslscan, testssl.sh)")
    print("  [n] Run all + nikto (slow)")

    choice = input("\nChoice(s) e.g. 1 2 4 or a: ").strip().lower()

    if choice == "a":
        results = run_default_recon(target, delay=delay, user_agent=user_agent)
        return format_recon_for_llm(results)

    if choice == "n":
        results = run_default_recon(target, delay=delay, user_agent=user_agent)
        if delay > 0:
            time.sleep(delay)
        results["nikto"] = run_nikto(target, user_agent)
        return format_recon_for_llm(results)

    combined = {}
    first_call = True
    for key in choice.split():
        if key in TOOLS_MENU:
            if not first_call and delay > 0:
                time.sleep(delay)
            first_call = False
            name, func = TOOLS_MENU[key]
            print(f"\n[*] Running {name}...")
            combined[name] = func(target, user_agent)
        else:
            print(f"[!] Unknown option: {key}")

    return format_recon_for_llm(combined)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    target = input("Enter test target (IP or domain): ").strip()
    results = run_default_recon(target)
    print(format_recon_for_llm(results))
