"""robots.txt / security.txt recon."""

from . import base
from .registry import register_tool

_MAX_TEXT_FILE_CHARS = 2000


def _fetch_text_file(base_url: str, path: str, user_agent: str = None) -> str:
    """
    GET a small text file (robots.txt, security.txt) and report its HTTP
    status alongside the body — capped in length since these are meant to
    be short, well-known files, not arbitrary page content.
    """
    args = ["curl", "-s", "--max-time", "10", "-w", "\n[HTTP %{http_code}]"]
    if base_url.startswith("https://"):
        args.append("-k")
    if user_agent:
        args += ["-A", user_agent]
    args.append(f"{base_url}{path}")
    output = base.run_tool(args, timeout=20, retries=1)
    return output[:_MAX_TEXT_FILE_CHARS]


@register_tool(key="10", name="robots/security.txt", command_name="curl")
def run_robots_and_security_txt(target: str, user_agent: str = None) -> str:
    """
    robots.txt sometimes leaks paths an admin doesn't want indexed (a weak
    signal, not a vulnerability by itself). security.txt (RFC 9116) tells
    you whether the target has a documented vulnerability-disclosure
    process — checked at the standard /.well-known/ path plus the legacy
    root path some sites still use instead.
    """
    scheme = "https"
    print(f"  [*] curl {scheme}://{target}/robots.txt")
    robots = _fetch_text_file(f"{scheme}://{target}", "/robots.txt", user_agent)
    if robots.startswith("curl:") or robots.startswith("[!]"):
        scheme = "http"
        print(f"  [*] curl {scheme}://{target}/robots.txt (https unreachable)")
        robots = _fetch_text_file(f"{scheme}://{target}", "/robots.txt", user_agent)

    print(f"  [*] curl {scheme}://{target}/.well-known/security.txt")
    security = _fetch_text_file(
        f"{scheme}://{target}", "/.well-known/security.txt", user_agent
    )
    if "[HTTP 200]" not in security:
        print(f"  [*] curl {scheme}://{target}/security.txt (legacy path)")
        legacy = _fetch_text_file(f"{scheme}://{target}", "/security.txt", user_agent)
        security += f"\n\n[legacy /security.txt]\n{legacy}"

    return f"[robots.txt]\n{robots}\n\n[security.txt]\n{security}"
