"""Shared validated AI-analysis and persistence workflow for CLI and Web."""

from . import db
from .llm import AnalysisIncompleteError, analyse_target


def analyse_and_save(
    sl_no: int,
    target: str,
    raw_scan: str,
    *,
    provider=None,
    on_progress=None,
    allowed_subdomains: frozenset = frozenset(),
) -> tuple[str, dict | None, str | None]:
    """Return (status, result, error); status is done or partial."""
    try:
        result = analyse_target(
            target,
            raw_scan,
            provider=provider,
            on_progress=on_progress,
            allowed_subdomains=allowed_subdomains,
        )
    except AnalysisIncompleteError as exc:
        error = str(exc)
        if on_progress:
            on_progress("saving_results", None)
        db.save_partial_analysis(
            sl_no, raw_scan, exc.raw_response, error, exc.tool_calls
        )
        return "partial", None, error

    if on_progress:
        on_progress("saving_results", None)
    db.save_analysis_result(sl_no, result)
    return "done", result, None
