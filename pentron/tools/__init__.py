"""
pentron.tools — recon tool runners package.

Adding a new tool: create pentron/tools/<name>.py with a
run_<name>(target, user_agent=None) function decorated with
@register_tool(key=..., name=..., command_name=...) from
pentron.tools.registry, then add it to the import list below (for its
registration side effect). If it needs the target's IP, HTTP headers, etc.
it should read them itself; it doesn't need to touch any other file — the
menu (TOOLS_MENU) and the AI dispatch allowlist (ALLOWED_TOOLS) are derived
from the registry, not hand-maintained.

To shell out, call the generic runner as `from . import base` +
`base.run_tool(...)` — never `from .base import run_tool` — so tests can
monkeypatch the single `pentron.tools.base.run_tool` target regardless of
which tool module ends up calling it.
"""

# Imported in menu-key order (1..10) for their @register_tool side effect.
from . import (  # noqa: F401
    base,
    dig,
    dispatch,
    http_headers,
    nikto,
    nmap,
    robots_security_txt,
    sslscan,
    subdomains,
    testssl,
    waf,
    whatweb,
    whois,
    wpscan,
)
from .dig import run_dig  # noqa: F401
from .dispatch import run_tool_by_command
from .interactive import interactive_tool_run
from .pipeline import (
    format_recon_for_llm,
    resolve_tool_plan,
    run_default_recon,
    run_selected_tools,
    run_single_tool,
)
from .registry import all_tools, allowed_commands
from .robots_security_txt import run_robots_and_security_txt  # noqa: F401
from .safety import check_target_safety
from .subdomains import discover_subdomains
from .waf import run_waf_detect  # noqa: F401
from .wpscan import run_wpscan, wordpress_detected  # noqa: F401

TOOLS_MENU = {spec.key: (spec.name, spec.runner) for spec in all_tools().values()}
ALLOWED_TOOLS = allowed_commands()

__all__ = [
    "ALLOWED_TOOLS",
    "TOOLS_MENU",
    "check_target_safety",
    "discover_subdomains",
    "format_recon_for_llm",
    "interactive_tool_run",
    "resolve_tool_plan",
    "run_default_recon",
    "run_dig",
    "run_robots_and_security_txt",
    "run_selected_tools",
    "run_single_tool",
    "run_tool_by_command",
    "run_waf_detect",
    "run_wpscan",
    "wordpress_detected",
]
