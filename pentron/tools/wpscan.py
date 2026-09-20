"""Strictly bounded, conditional WPScan integration."""

import re

from . import base
from .registry import register_tool

_WORDPRESS_MARKERS = re.compile(
    r"(?:\bwordpress\b|/wp-(?:content|includes|json)(?:/|\b)|x-pingback)",
    re.IGNORECASE,
)


def wordpress_detected(results: dict[str, str]) -> bool:
    """Return true only when an earlier recon result contains WP evidence."""
    return any(_WORDPRESS_MARKERS.search(output or "") for output in results.values())


@register_tool(
    key="11",
    name="wpscan",
    command_name="wpscan",
    ai_dispatch=False,
)
def run_wpscan(
    target: str, user_agent: str = None, *, wordpress_is_detected: bool = False
) -> str:
    """Scan vulnerable plugins/themes only, after confirmed WP detection.

    The fixed argument list intentionally contains no user enumeration,
    credential, login, or brute-force options.  This runner is also excluded
    from AI command dispatch so those constraints cannot be replaced by
    model-supplied arguments.
    """
    if not wordpress_is_detected:
        return "[!] SKIPPED: WPScan requires prior WordPress detection."

    args = [
        "wpscan",
        "--url",
        target,
        "--enumerate",
        "vp,vt",
        "--plugins-detection",
        "passive",
        "--themes-detection",
        "passive",
        "--no-update",
        "--format",
        "cli-no-color",
    ]
    if user_agent:
        args += ["--user-agent", user_agent]
    print(f"  [*] WPScan conditional vulnerable plugin/theme scan: {target}")
    return base.run_tool(args, timeout=300)
