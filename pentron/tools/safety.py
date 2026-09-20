"""Pre-flight target safety check — run once before any recon tool starts."""

import ipaddress
import socket


def _is_unsafe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def check_target_safety(target: str) -> str:
    """
    Refuse to start a scan whose target resolves to a private/loopback/
    link-local/reserved address — before any recon tool runs. A domain's
    DNS can be changed at any time by whoever controls it, including to
    point at internal infrastructure (the operator's own machine, another
    container, cloud metadata); this is a real vector for a pentest target
    to redirect the very first recon pass onto something it shouldn't.

    A literal IP typed directly by the operator is always allowed — that's
    an explicit, conscious choice (e.g. testing your own LAN), not a DNS
    record an attacker could have altered.

    Returns an error string if the target should be refused, else None.
    """
    try:
        ipaddress.ip_address(target)
        return None
    except ValueError:
        pass  # not a literal IP — it's a hostname, resolve and check it

    try:
        resolved_ips = {info[4][0] for info in socket.getaddrinfo(target, None)}
    except socket.gaierror:
        # unresolvable — not what this check is about, let the normal tool
        # errors handle it
        return None

    unsafe = sorted(ip for ip in resolved_ips if _is_unsafe_ip(ip))
    if unsafe:
        return (
            f"[!] BLOCKED: '{target}' resolves to a private/internal address "
            f"({', '.join(unsafe)}) — refusing to scan. This can happen if the "
            f"target's DNS has been changed to point at internal infrastructure. "
            f"If this is intentional (e.g. testing your own network), enter the "
            f"IP address directly instead of the domain name."
        )
    return None
