from . import base
from .registry import register_tool


@register_tool(key="7", name="sslscan", command_name="sslscan")
def run_sslscan(target: str, user_agent: str = None) -> str:
    """
    sslscan — enumerate supported TLS/SSL protocol versions, cipher suites,
    and certificate details for a host.
    user_agent is accepted but unused — sslscan operates at the TLS layer,
    no HTTP User-Agent involved; kept for a uniform dispatch signature.
    """
    print(f"  [*] sslscan --no-colour {target}")
    return base.run_tool(["sslscan", "--no-colour", target], timeout=90)
