"""Orchestration on top of the tool registry: default recon, tool selection,
tool-key resolution, and formatting the results for the LLM prompt."""

import time

from . import registry
from .dig import run_dig
from .http_headers import run_curl_headers
from .nikto import run_nikto
from .nmap import run_nmap
from .whatweb import run_whatweb
from .whois import run_whois
from .wpscan import run_wpscan, wordpress_detected


def resolve_tool_plan(tool_keys) -> list:
    """
    Preview the ordered list of tool display names a run_selected_tools()
    call with these tool_keys will actually emit via on_progress — lets a
    caller (the web UI) show a full checklist upfront instead of only
    finding out what's left to run as each tool starts.
    """
    if tool_keys == "a":
        return registry.default_tool_names()
    if tool_keys == "n":
        return registry.default_tool_names() + ["nikto"]
    return [spec.name for key in tool_keys if (spec := registry.get(key))]


def run_default_recon(
    target: str, on_progress=None, delay: float = 0, user_agent: str = None
) -> dict:
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

    # Kept explicit (not looped over registry.default_tool_names()) since
    # each call needs its own dict key/print — "curl_headers" here vs.
    # "curl headers" as the registry's display name, notably. Must stay the
    # same 5 tools as the default=True set in nmap.py/whois.py/whatweb.py/
    # http_headers.py/dig.py.
    results = {}
    results["nmap"] = _run("nmap", run_nmap)
    results["whois"] = _run("whois", run_whois)
    results["whatweb"] = _run("whatweb", run_whatweb)
    results["curl_headers"] = _run("curl headers", run_curl_headers)
    results["dig"] = _run("dig", run_dig)

    print("─" * 50)
    print("[+] Recon complete.\n")
    return results


def run_single_tool(tool_key: str, target: str) -> str:
    """Run one tool by its menu key. Used by AI tool dispatch."""
    spec = registry.get(tool_key)
    if spec:
        return spec.runner(target)
    return f"[!] Unknown tool key: {tool_key}"


def run_selected_tools(
    target: str, tool_keys, on_progress=None, delay: float = 0, user_agent: str = None
) -> dict:
    """
    Pure equivalent of interactive_tool_run's dispatch logic, without the
    input()/print() coupling — used by the web API. tool_keys is either a
    list of tool menu keys (e.g. ["1", "2", "4"]) or the literal "a" / "n"
    for the default-recon / default+nikto bundles (same shorthand the CLI
    tool picker accepts). delay, if > 0, is a pause (seconds) between tools.
    user_agent, if set, overrides the HTTP User-Agent for tools that send one.
    """
    if tool_keys == "a":
        return run_default_recon(
            target, on_progress=on_progress, delay=delay, user_agent=user_agent
        )

    if tool_keys == "n":
        results = run_default_recon(
            target, on_progress=on_progress, delay=delay, user_agent=user_agent
        )
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
    run_conditional_wpscan = False
    for key in tool_keys:
        spec = registry.get(key)
        if not spec:
            continue
        if spec.name == "wpscan":
            # WPScan must run after the other selected tools, regardless of
            # request order, because their output is its detection gate.
            run_conditional_wpscan = True
            continue
        if not first_call and delay > 0:
            time.sleep(delay)
        first_call = False
        if on_progress:
            on_progress("tool_start", spec.name)
        results[spec.name] = spec.runner(target, user_agent)
        if on_progress:
            on_progress("tool_done", spec.name)

    if run_conditional_wpscan:
        if not first_call and delay > 0:
            time.sleep(delay)
        if on_progress:
            on_progress("tool_start", "wpscan")
        results["wpscan"] = run_wpscan(
            target,
            user_agent,
            wordpress_is_detected=wordpress_detected(results),
        )
        if on_progress:
            on_progress("tool_done", "wpscan")
    return results


def format_recon_for_llm(results: dict) -> str:
    """
    Flatten the recon results dict into one clean string
    to paste into the LLM prompt.
    """
    output = ""
    for tool, data in results.items():
        output += f"\n{'=' * 50}\n"
        output += f"[ {tool.upper()} OUTPUT ]\n"
        output += f"{'=' * 50}\n"
        output += data.strip() + "\n"
    return output
