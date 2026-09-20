from . import base
from .registry import register_tool


@register_tool(key="3", name="whatweb", command_name="whatweb")
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
    return base.run_tool(args, timeout=60)
