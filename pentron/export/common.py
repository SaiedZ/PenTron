"""Shared constants and helpers for the PDF/HTML report generators."""

import os

SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#27ae60",
    "unknown": "#7f8c8d",
}

RISK_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#27ae60",
    "UNKNOWN": "#7f8c8d",
}


def safe_filename(output_dir: str, sl_no, target: str, extension: str) -> str:
    """pentron_SL<n>_<target>.<extension> under output_dir (created if needed)."""
    os.makedirs(output_dir, exist_ok=True)
    safe = (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(".", "_")
    )
    return os.path.join(output_dir, f"pentron_SL{sl_no}_{safe}.{extension}")


def session_summary(data: dict) -> tuple:
    """(sl_no, target, date, risk, ai_summary) pulled out of the raw
    history/summary rows — the fields both report generators start from."""
    h = data["history"]
    sl = h[0]
    tgt = h[1]
    date = str(h[2])
    risk = data["summary"][4] if data["summary"] else "UNKNOWN"
    ai = data["summary"][3] if data["summary"] else ""
    return sl, tgt, date, risk, ai
