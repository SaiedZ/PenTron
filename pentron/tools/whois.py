from . import base
from .registry import register_tool


@register_tool(key="2", name="whois", command_name="whois")
def run_whois(target: str, user_agent: str = None) -> str:
    """
    whois — domain registration, registrar, IP ownership info
    """
    print(f"  [*] whois {target}")
    return base.run_tool(["whois", target], timeout=30, retries=1)
