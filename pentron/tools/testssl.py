from . import base
from .registry import register_tool


@register_tool(key="8", name="testssl.sh", command_name="testssl")
def run_testssl(target: str, user_agent: str = None) -> str:
    """
    testssl.sh — deeper TLS/SSL configuration audit: protocols, ciphers,
    known vulnerabilities (Heartbleed, POODLE, etc.), certificate issues.
    WARNING: slower and noisier than sslscan, run selectively.
    user_agent is accepted but unused — same reasoning as sslscan.
    """
    print(
        f"  [*] testssl --quiet --color 0 --warnings batch {target}  "
        f"(this may take a while...)"
    )
    return base.run_tool(
        ["testssl", "--quiet", "--color", "0", "--warnings", "batch", target],
        timeout=240,
    )
