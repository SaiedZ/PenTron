import re

from . import base
from .registry import register_tool

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@register_tool(key="9", name="wafw00f", command_name="wafw00f")
def run_waf_detect(target: str, user_agent: str = None) -> str:
    """
    wafw00f — fingerprints whether a Web Application Firewall sits in front
    of the target. Matters for interpreting the rest of the scan: a "clean"
    nikto/nmap pass behind an active WAF doesn't mean much on its own — the
    WAF may be the thing that made it look clean.
    user_agent is accepted but unused — wafw00f sends its own fingerprinting
    probes regardless; kept for a uniform dispatch signature.
    """
    urls = [f"http://{target}", f"https://{target}"]
    print(f"  [*] wafw00f {' '.join(urls)}")
    output = base.run_tool(["wafw00f"] + urls, timeout=60)
    return _ANSI_RE.sub("", output)
