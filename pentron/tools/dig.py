from . import base
from .registry import register_tool


@register_tool(key="5", name="dig DNS", command_name="dig")
def run_dig(target: str, user_agent: str = None) -> str:
    """
    dig — DNS records: A, MX, NS, TXT, plus a basic email-security check
    (SPF/DMARC/DKIM) — their absence is a real spoofing/phishing risk for
    the domain, not just a DNS curiosity.
    user_agent is accepted but unused — DNS queries have no HTTP User-Agent
    concept; kept for a uniform tool-dispatch signature.
    """
    print(f"  [*] dig {target} ANY")
    a_record = base.run_tool(["dig", "+short", "A", target], timeout=15, retries=1)
    mx_record = base.run_tool(["dig", "+short", "MX", target], timeout=15, retries=1)
    ns_record = base.run_tool(["dig", "+short", "NS", target], timeout=15, retries=1)
    txt_record = base.run_tool(["dig", "+short", "TXT", target], timeout=15, retries=1)

    print(f"  [*] dig _dmarc.{target} TXT")
    dmarc_record = base.run_tool(
        ["dig", "+short", "TXT", f"_dmarc.{target}"], timeout=15, retries=1
    )

    print(f"  [*] dig default._domainkey.{target} TXT")
    dkim_record = base.run_tool(
        ["dig", "+short", "TXT", f"default._domainkey.{target}"],
        timeout=15,
        retries=1,
    )

    spf_status = (
        "present"
        if "v=spf1" in txt_record.lower()
        else "MISSING — domain is not protected against sender spoofing via SPF"
    )
    dmarc_status = (
        "present"
        if "v=dmarc1" in dmarc_record.lower()
        else "MISSING — no policy telling mail servers what to do with spoofed mail"
    )
    dkim_found = bool(dkim_record.strip()) and not dkim_record.startswith("[!]")
    dkim_status = (
        "found under selector 'default'"
        if dkim_found
        else (
            "not found under selector 'default' (DKIM may still exist "
            "under another selector — this only checks the common default one)"
        )
    )

    return (
        f"[A Records]\n{a_record}\n\n"
        f"[MX Records]\n{mx_record}\n\n"
        f"[NS Records]\n{ns_record}\n\n"
        f"[TXT Records]\n{txt_record}\n\n"
        f"[Email security — SPF]: {spf_status}\n\n"
        f"[Email security — DMARC]: {dmarc_status}\n{dmarc_record}\n\n"
        f"[Email security — DKIM]: {dkim_status}\n{dkim_record}"
    )
