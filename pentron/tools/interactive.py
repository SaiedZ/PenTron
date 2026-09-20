"""Interactive tool selector — CLI-only (print/input), called from pentron/cli.py."""

from . import registry
from .pipeline import format_recon_for_llm, run_selected_tools


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
        "robots/security.txt, wpscan)"
    )
    print("  [n] Run all + nikto (slow)")

    choice = input("\nChoice(s) e.g. 1 2 4 or a: ").strip().lower()

    if choice == "a":
        return format_recon_for_llm(
            run_selected_tools(target, "a", delay=delay, user_agent=user_agent)
        )

    if choice == "n":
        return format_recon_for_llm(
            run_selected_tools(target, "n", delay=delay, user_agent=user_agent)
        )

    keys = choice.split()
    for key in keys:
        if not registry.get(key):
            print(f"[!] Unknown option: {key}")
    return format_recon_for_llm(
        run_selected_tools(target, keys, delay=delay, user_agent=user_agent)
    )
