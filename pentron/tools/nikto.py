from . import base
from .registry import register_tool


@register_tool(key="6", name="nikto", command_name="nikto")
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
    return base.run_tool(args, timeout=300)
