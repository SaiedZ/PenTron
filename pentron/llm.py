#!/usr/bin/env python3
"""
PENTRON - llm.py
Ollama interface for the configured model.
Builds prompts, handles AI responses, runs tool dispatch loop.
Default model: huihui_ai/qwen3.5-abliterated:9b (see providers.get_provider()
for how the model name is actually resolved from settings/env at runtime —
MODEL_NAME below is only used by the direct/test wrapper ask_ollama()).
"""

import json
import os
import re
from typing import Literal

import requests
from pydantic import BaseModel, Field, ValidationError

from .providers import OllamaProvider, ProviderResponse, get_provider
from .search import handle_search_dispatch
from .tools import run_tool_by_command

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "localhost:11434")
MODEL_NAME = "huihui_ai/qwen3.5-abliterated:9b"
MAX_TOKENS = 8192
MAX_TOOL_LOOPS = 9  # max times AI can call tools per session
OLLAMA_TIMEOUT = 600
SUMMARY_THRESHOLD = 4000


class VulnerabilityResult(BaseModel):
    name: str
    severity: Literal["critical", "high", "medium", "low"]
    port: str = ""
    service: str = ""
    evidence: str
    description: str
    fix: str


class ExploitSuggestion(BaseModel):
    name: str
    rationale: str
    tool: str = ""
    safe_validation: str = ""


class AnalysisResult(BaseModel):
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    short_summary: str = Field(min_length=1, max_length=1200)
    analysis_markdown: str = Field(min_length=1)
    vulnerabilities: list[VulnerabilityResult]
    exploit_suggestions: list[ExploitSuggestion]


class AnalysisIncompleteError(RuntimeError):
    def __init__(self, message: str, raw_response: str = "", tool_calls=None):
        super().__init__(message)
        self.raw_response = raw_response
        self.tool_calls = tool_calls or []


# ─────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are PENTRON, an elite AI penetration testing assistant \
running on Kali.
You are precise, technical, and direct. No fluff.

You have access to real tools. To use them, write tags in your response:

  [TOOL: nmap -sV 192.168.1.1]       → runs nmap or any CLI tool
  [SEARCH: CVE-2021-44228 exploit]   → searches the web via DuckDuckGo

Rules:
- Always analyze scan data thoroughly before suggesting exploits
- List vulnerabilities with: name, severity (critical/high/medium/low), port, service
- For each vulnerability, suggest a concrete fix
- If you need more information, use [SEARCH:] or [TOOL:]
- Be specific about CVE IDs when you know them
- Always give a final risk rating: CRITICAL / HIGH / MEDIUM / LOW
- When asking for a tool, emit only tool/search tags and a short explanation
- When analysis is complete, obey the JSON contract in the user prompt exactly
IMPORTANT RULES FOR ACCURACY:
- nmap filtered or no-response means INCONCLUSIVE not vulnerable
- Never assert a server version without seeing it in scan output
- Never infer CVEs from guessed versions
- curl timeouts and HTTP_CODE=000 mean the host is unreachable not exploitable
- ab and stress tools are not Slowloris unless confirmed
- Only assign CRITICAL if there is direct evidence of exploitability
- If evidence is weak mark severity as LOW with note: unconfirmed"""


# ─────────────────────────────────────────────
# OLLAMA API CALL
# ─────────────────────────────────────────────


def ask_ollama(messages: list) -> str:
    """Thin wrapper kept for direct/test use.

    analyse_target uses get_provider() instead.
    """
    print(f"\n[*] Sending to {MODEL_NAME}...")
    return (
        OllamaProvider(MODEL_NAME, timeout=OLLAMA_TIMEOUT)
        .send(messages, max_tokens=MAX_TOKENS)
        .text
    )


# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────


def extract_tool_calls(response: str) -> list:
    """
    Extract all [TOOL: ...] and [SEARCH: ...] tags from AI response.
    Returns list of tuples: [("TOOL", "nmap -sV x.x.x.x"), ("SEARCH", "CVE...")]
    """
    calls = []

    tool_matches = re.findall(r"\[TOOL:\s*(.+?)\]", response)
    search_matches = re.findall(r"\[SEARCH:\s*(.+?)\]", response)

    for m in tool_matches:
        calls.append(("TOOL", m.strip()))
    for m in search_matches:
        calls.append(("SEARCH", m.strip()))

    return calls


def summarize_tool_output(raw_output: str, provider=None) -> str:
    """
    Compress raw tool output into security-relevant bullet points
    before injecting into the LLM context.
    Keeps context size manageable across rounds.
    """
    if len(raw_output) < 500:
        return raw_output

    try:
        provider = provider or get_provider()
        summary = provider.send(
            [
                {
                    "role": "system",
                    "content": (
                        "You are a security data compressor. Extract only "
                        "security-relevant facts. Return maximum 15 bullet "
                        "points. Plain text only. No markdown."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Compress this tool output:\n{raw_output[:6000]}",
                },
            ],
            max_tokens=512,
            temperature=0.2,
        )
        text = summary.text
        return text if text and not text.startswith("[!]") else raw_output
    except Exception:
        return raw_output


def run_tool_calls(
    calls: list,
    session_target: str,
    provider=None,
    on_progress=None,
    allowed_subdomains: frozenset = frozenset(),
) -> tuple[str, list[dict]]:
    """
    Execute all tool/search calls and return combined results string.
    session_target binds any [TOOL:] call back to the operator-declared
    scan target — see tools.run_tool_by_command for why. allowed_subdomains
    is the (possibly empty) set discover_subdomains() found at discovery
    level 2 — the only case where a tool call against a non-session-target
    host is permitted.
    """
    if not calls:
        return "", []

    results = ""
    records = []
    for call_type, call_content in calls:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")

        if call_type == "TOOL":
            output = run_tool_by_command(
                call_content, session_target, allowed_subdomains
            )
        elif call_type == "SEARCH":
            output = handle_search_dispatch(call_content)
        else:
            output = f"[!] Unknown call type: {call_type}"

        blocked = output.strip().startswith("[!] BLOCKED:")
        if on_progress and blocked:
            on_progress(
                "call_blocked", f"{call_type}: {call_content} -> {output.strip()}"
            )

        compressed = summarize_tool_output(output.strip(), provider)
        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n"
        results += compressed + "\n"
        records.append(
            {
                "call_type": call_type,
                "command": call_content,
                "result": output.strip(),
                "blocked": blocked,
            }
        )

    return results, records


# ─────────────────────────────────────────────
# PARSER — extract structured data from AI output
# ─────────────────────────────────────────────
def _clean(line: str) -> str:
    return re.sub(r"\*+", "", line).strip()


def parse_vulnerabilities(response: str) -> list:
    """
    Parse VULN: lines from AI response into dicts.
    Returns list of vulnerability dicts ready for db.save_vulnerability()
    """
    vulns = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("VULN:"):
            vuln = {
                "vuln_name": "",
                "severity": "medium",
                "port": "",
                "service": "",
                "description": "",
                "fix": "",
            }

            # parse header line: VULN: name | SEVERITY: x | PORT: x | SERVICE: x
            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("VULN:"):
                    vuln["vuln_name"] = part.replace("VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("PORT:"):
                    vuln["port"] = part.replace("PORT:", "").strip()
                elif part.startswith("SERVICE:"):
                    vuln["service"] = part.replace("SERVICE:", "").strip()

            # look ahead for DESC: and FIX: lines
            j = i + 1
            while j < len(lines) and j <= i + 5:
                next_line = _clean(lines[j])
                if next_line.startswith(
                    ("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")
                ):
                    break
                if next_line.startswith("DESC:"):
                    vuln["description"] = next_line.replace("DESC:", "").strip()
                elif next_line.startswith("FIX:"):
                    vuln["fix"] = next_line.replace("FIX:", "").strip()
                j += 1

            if vuln["vuln_name"]:
                vulns.append(vuln)

        i += 1

    return vulns


def parse_risk_level(response: str) -> str:
    """Extract RISK_LEVEL from AI response."""
    match = re.search(
        r"RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)", response, re.IGNORECASE
    )
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    match = re.search(r"SUMMARY:\s*(.+)", response, re.IGNORECASE)
    return match.group(1).strip() if match else ""


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def verify_cve_citations(vulnerabilities: list, raw_scan: str) -> list:
    """
    Flag any CVE ID the model cited that never appeared in the actual scan
    data it was given. Models sometimes cite a plausible-sounding but wrong
    CVE for a service/version (e.g. Log4Shell for a plain Apache banner).
    The finding isn't dropped — it may still be a real, correctly-reasoned
    vulnerability — it's just marked as unverified against the raw evidence.
    """
    raw_upper = raw_scan.upper()
    for vuln in vulnerabilities:
        text = f"{vuln.get('description', '')} {vuln.get('fix', '')}"
        for cve in CVE_RE.findall(text):
            if (
                cve.upper() not in raw_upper
                and "[UNVERIFIED CVE" not in vuln["description"]
            ):
                vuln["description"] = (
                    vuln["description"]
                    + f" [UNVERIFIED CVE — {cve} not present in scan data]"
                ).strip()
    return vulnerabilities


# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────


FINAL_PROMPT = """Return the final assessment as JSON only, matching this shape:
{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "short_summary": "2-3 concise sentences",
  "analysis_markdown": "complete human-readable report",
  "vulnerabilities": [{
    "name": "...", "severity": "critical|high|medium|low",
    "port": "...", "service": "...", "evidence": "observed fact",
    "description": "...", "fix": "..."
  }],
  "exploit_suggestions": [{
    "name": "...", "rationale": "...", "tool": "...",
    "safe_validation": "..."
  }]
}
Do not wrap the JSON in a code fence. Do not invent evidence. An empty findings
array is valid. The Markdown field may use headings, lists, emphasis and code.
"""


def _response_text(response) -> str:
    return response.text if isinstance(response, ProviderResponse) else str(response)


def _condense_recon(raw_scan: str, provider) -> str:
    if len(raw_scan) <= SUMMARY_THRESHOLD:
        return raw_scan
    sections = re.split(r"(?=\n={20,}\n\[ )", raw_scan)
    condensed = []
    for section in sections:
        if not section.strip():
            continue
        if len(section) <= SUMMARY_THRESHOLD:
            condensed.append(section.strip())
        else:
            condensed.append(summarize_tool_output(section, provider))
    return "\n\n".join(condensed)


def _parse_analysis(response: ProviderResponse) -> AnalysisResult:
    if response.truncated:
        raise ValueError(f"provider stopped early ({response.finish_reason})")
    text = response.text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I)
    return AnalysisResult.model_validate(json.loads(text))


def _repair_analysis(provider, response: ProviderResponse, error: Exception):
    repair = provider.send(
        [
            {
                "role": "system",
                "content": "Repair the supplied answer into valid JSON. "
                + FINAL_PROMPT,
            },
            {
                "role": "user",
                "content": f"Validation error: {error}\n\nAnswer:\n{response.text}",
            },
        ],
        max_tokens=MAX_TOKENS,
        temperature=0.1,
    )
    return repair


def analyse_target(
    target: str,
    raw_scan: str,
    provider=None,
    on_progress=None,
    allowed_subdomains: frozenset = frozenset(),
) -> dict:
    provider = provider or get_provider()
    evidence = _condense_recon(raw_scan, provider)
    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT + "\n\n" + FINAL_PROMPT,
        },
        {
            "role": "user",
            "content": f"""TARGET: {target}

RECON EVIDENCE:
{evidence}

Analyze this target completely. Use [TOOL:] or [SEARCH:] if you need more information.
When no more tools are needed, return the final JSON assessment.""",
        },
    ]

    final_response = ProviderResponse("")
    tool_call_records = []

    for loop in range(MAX_TOOL_LOOPS):
        if on_progress:
            on_progress("ai_round_start", f"{loop + 1}/{MAX_TOOL_LOOPS}")

        response = provider.send(messages, max_tokens=MAX_TOKENS)
        if not isinstance(response, ProviderResponse):
            response = ProviderResponse(str(response))

        print(f"\n{'─' * 60}")
        print(f"[PENTRON - Round {loop + 1}]")
        print(f"{'─' * 60}")
        print(response.text)

        final_response = response

        tool_calls = extract_tool_calls(response.text)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break

        if on_progress:
            on_progress("tool_dispatch", tool_calls)

        tool_results, records = run_tool_calls(
            tool_calls, target, provider, on_progress, allowed_subdomains
        )
        tool_call_records.extend(records)

        # add assistant response and tool results as new messages
        messages.append({"role": "assistant", "content": response.text})
        messages.append(
            {
                "role": "user",
                "content": f"""[TOOL RESULTS]
{tool_results}

Continue your analysis with this new information.
If analysis is complete, return the final JSON assessment.""",
            }
        )

    try:
        parsed = _parse_analysis(final_response)
    except (ValueError, json.JSONDecodeError, ValidationError) as first_error:
        repaired = _repair_analysis(provider, final_response, first_error)
        if not isinstance(repaired, ProviderResponse):
            repaired = ProviderResponse(str(repaired))
        try:
            parsed = _parse_analysis(repaired)
            final_response = repaired
        except (ValueError, json.JSONDecodeError, ValidationError) as repair_error:
            raise AnalysisIncompleteError(
                f"AI response remained invalid after repair: {repair_error}",
                final_response.text,
                tool_call_records,
            ) from repair_error

    vulnerabilities = []
    for item in parsed.vulnerabilities:
        vuln = {
            "vuln_name": item.name,
            "severity": item.severity,
            "port": item.port,
            "service": item.service,
            "description": f"{item.description} Evidence: {item.evidence}",
            "fix": item.fix,
        }
        vulnerabilities.append(vuln)
    vulnerabilities = verify_cve_citations(vulnerabilities, raw_scan)

    return {
        "full_response": parsed.analysis_markdown,
        "vulnerabilities": vulnerabilities,
        "exploit_suggestions": [x.model_dump() for x in parsed.exploit_suggestions],
        "tool_calls": tool_call_records,
        "risk_level": parsed.risk_level,
        "summary": parsed.short_summary,
        "raw_scan": raw_scan,
    }


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ llm.py test — direct AI query ]\n")

    # test if ollama is reachable
    try:
        r = requests.get(f"http://{OLLAMA_HOST}", timeout=5)
        print("[+] Ollama is running.")
    except Exception:
        print("[!] Ollama not reachable. Run: ollama serve")
        exit(1)

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."
    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploit suggestions: {len(result['exploit_suggestions'])}")
