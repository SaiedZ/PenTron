"""
CVE citation verification tests — llm.py::verify_cve_citations flags any
CVE the model cites that never appeared in the raw recon data it was
given, since models sometimes cite a plausible-sounding but wrong CVE for
a service/version. The finding isn't dropped, just marked unverified.
"""
import llm


def test_cve_present_in_raw_scan_is_not_flagged():
    vulns = [{"description": "Apache vulnerable to CVE-2021-44228", "fix": ""}]
    raw_scan = "Server banner mentions CVE-2021-44228 in scan output"
    result = llm.verify_cve_citations(vulns, raw_scan)
    assert "[UNVERIFIED CVE" not in result[0]["description"]


def test_cve_absent_from_raw_scan_is_flagged():
    vulns = [{"description": "Log4j RCE via CVE-2021-44228", "fix": ""}]
    raw_scan = "nmap output showing only port 80 open, Apache banner, no log4j mention"
    result = llm.verify_cve_citations(vulns, raw_scan)
    assert "[UNVERIFIED CVE" in result[0]["description"]
    assert "CVE-2021-44228" in result[0]["description"]


def test_cve_only_in_fix_field_is_still_checked():
    vulns = [{"description": "SQL injection", "fix": "Patch per CVE-2099-99999"}]
    raw_scan = "no CVE mentioned anywhere"
    result = llm.verify_cve_citations(vulns, raw_scan)
    assert "[UNVERIFIED CVE" in result[0]["description"]


def test_match_is_case_insensitive():
    vulns = [{"description": "Vulnerable to cve-2021-44228", "fix": ""}]
    raw_scan = "Banner references CVE-2021-44228 explicitly"
    result = llm.verify_cve_citations(vulns, raw_scan)
    assert "[UNVERIFIED CVE" not in result[0]["description"]


def test_no_cve_mentioned_is_left_untouched():
    vulns = [{"description": "Weak TLS config", "fix": "Disable TLS 1.0"}]
    raw_scan = "sslscan output"
    result = llm.verify_cve_citations(vulns, raw_scan)
    assert result[0]["description"] == "Weak TLS config"


def test_already_flagged_vuln_is_not_double_flagged():
    vulns = [
        {
            "description": (
                "Uses CVE-9999-00000 "
                "[UNVERIFIED CVE — CVE-9999-00000 not present in scan data]"
            ),
            "fix": "",
        }
    ]
    raw_scan = "nothing relevant"
    result = llm.verify_cve_citations(vulns, raw_scan)
    assert result[0]["description"].count("[UNVERIFIED CVE") == 1


def test_multiple_vulnerabilities_checked_independently():
    vulns = [
        {"description": "CVE-2021-44228 confirmed", "fix": ""},
        {"description": "CVE-2019-00000 suspected", "fix": ""},
    ]
    raw_scan = "log shows CVE-2021-44228 triggered"
    result = llm.verify_cve_citations(vulns, raw_scan)
    assert "[UNVERIFIED CVE" not in result[0]["description"]
    assert "[UNVERIFIED CVE" in result[1]["description"]
