"""
curl headers — HTTP/HTTPS header fetch, with a manual redirect guard (SSRF
protection) and a present/missing check for standard security headers.
"""

from urllib.parse import urljoin, urlparse

from . import base
from .registry import register_tool


def _extract_location(headers_text: str) -> str | None:
    """Pull the value of a Location: header out of raw curl -I output, if present."""
    for line in headers_text.splitlines():
        if line.lower().startswith("location:"):
            return line.split(":", 1)[1].strip()
    return None


def _fetch_headers_once(url: str, user_agent: str = None) -> str:
    args = ["curl", "-sI", "--max-time", "10"]
    if url.startswith("https://"):
        args.append("-k")  # ignore cert errors
    if user_agent:
        args += ["-A", user_agent]
    args.append(url)
    return base.run_tool(args, timeout=20, retries=1)


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _effective_port(parsed) -> int:
    return parsed.port or _DEFAULT_PORTS.get(parsed.scheme, 0)


def _fetch_headers_guarded(url: str, target: str, user_agent: str = None) -> str:
    """
    Fetch headers WITHOUT letting curl auto-follow redirects (SSRF guard).
    A redirect to the same host on a standard port (80/443) — i.e. a normal
    same-site http->https upgrade or path redirect — is followed once.
    Anything else is reported but not followed: a redirect to a different
    host, OR to a non-standard port on the *same* host (e.g. a target that
    is itself 127.0.0.1 redirecting to 127.0.0.1:11434), can otherwise
    bounce us onto localhost/cloud metadata/internal services and leak
    their headers into the recon data.
    """
    first = _fetch_headers_once(url, user_agent)
    location = _extract_location(first)
    if not location:
        return first

    resolved = urljoin(url, location)
    parsed = urlparse(resolved)
    host = (parsed.hostname or "").lower()
    port = _effective_port(parsed)

    same_host = host == target.lower()
    standard_port = port in _DEFAULT_PORTS.values()

    if same_host and standard_port:
        second = _fetch_headers_once(resolved, user_agent)
        return f"{first}\n[Followed same-host redirect to {resolved}]\n{second}"

    return f"{first}\n[!] Redirect to different host blocked: {location}"


_SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS — enforces HTTPS, protects against protocol downgrade/SSL-stripping"
    ),
    "content-security-policy": (
        "CSP — restricts what scripts/resources a page can load, mitigates XSS"
    ),
    "x-frame-options": (
        "mitigates clickjacking (largely superseded by CSP frame-ancestors, "
        "but still widely checked)"
    ),
    "x-content-type-options": (
        "prevents the browser from MIME-sniffing a response away from its "
        "declared Content-Type"
    ),
    "referrer-policy": (
        "controls how much of the URL leaks to other sites via the Referer header"
    ),
    "permissions-policy": (
        "restricts access to browser features/APIs (camera, geolocation, etc.)"
    ),
}


def _analyze_security_headers(headers_text: str) -> str:
    """
    Flags standard HTTP security headers as present or missing. Absence is
    a common, easy-to-fix misconfiguration signal, not proof of a real
    vulnerability on its own — the AI should weigh it accordingly, not
    treat every missing header as a finding of equal severity.
    """
    if "http/" not in headers_text.lower():
        return "[Security headers] Could not check — no HTTP response received."

    lower = headers_text.lower()
    lines = ["[Security headers]"]
    for header, note in _SECURITY_HEADERS.items():
        if f"{header}:" in lower:
            lines.append(f"  present : {header}")
        else:
            lines.append(f"  MISSING : {header} — {note}")
    return "\n".join(lines)


@register_tool(key="4", name="curl headers", command_name="curl", default=True)
def run_curl_headers(target: str, user_agent: str = None) -> str:
    """
    curl -sI — fetch HTTP headers only
    Reveals: server software, X-Powered-By, cookies, security headers (or lack of them)
    user_agent, if set, overrides curl's default User-Agent header.
    """
    print(f"  [*] curl -sI {'-A <custom UA> ' if user_agent else ''}http://{target}")
    output = _fetch_headers_guarded(f"http://{target}", target, user_agent)

    # also try https
    https_output = _fetch_headers_guarded(f"https://{target}", target, user_agent)

    return (
        f"[HTTP Headers]\n{output}\n\n{_analyze_security_headers(output)}\n\n"
        f"[HTTPS Headers]\n{https_output}\n\n{_analyze_security_headers(https_output)}"
    )
