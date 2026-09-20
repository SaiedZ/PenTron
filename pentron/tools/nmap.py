from . import base
from .registry import register_tool


@register_tool(key="1", name="nmap", command_name="nmap")
def run_nmap(target: str, user_agent: str = None) -> str:
    """
    nmap -sV -sC -T4 --open
    -sV  : detect service versions
    -sC  : run default scripts (basic vuln checks)
    -T4  : aggressive timing (faster)
    --open : only show open ports
    user_agent is accepted but unused — nmap has no HTTP User-Agent concept;
    kept for a uniform tool-dispatch signature across all tools.
    """
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return base.run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)
