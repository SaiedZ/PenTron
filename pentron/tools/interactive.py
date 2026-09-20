"""Interactive tool selector — CLI-only (print/input), called from pentron/cli.py."""

import time

from . import registry
from .nikto import run_nikto
from .pipeline import format_recon_for_llm, run_default_recon


def interactive_tool_run(target: str, delay: float = 0, user_agent: str = None) -> str:
    """
    Let user manually pick which tools to run.
    Returns combined output string. delay, if > 0, is a pause (seconds)
    between tools — rate limiting so the target isn't hit by several tools
    back to back. user_agent, if set, overrides the HTTP User-Agent for
    tools that send one.
    """
    print("\n[ SELECT TOOLS TO RUN ]")
    for spec in registry.all_tools().values():
        print(f"  [{spec.key}] {spec.name}")
    print(
        "  [a] Run all (except nikto, sslscan, testssl.sh, wafw00f, "
        "robots/security.txt)"
    )
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
        spec = registry.get(key)
        if spec:
            if not first_call and delay > 0:
                time.sleep(delay)
            first_call = False
            print(f"\n[*] Running {spec.name}...")
            combined[spec.name] = spec.runner(target, user_agent)
        else:
            print(f"[!] Unknown option: {key}")

    return format_recon_for_llm(combined)
