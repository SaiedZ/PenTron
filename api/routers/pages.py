#!/usr/bin/env python3
"""
PENTRON - api/routers/pages.py
Server-rendered HTML pages (Jinja2 + HTMX). Filled in alongside the
templates under web/templates/.
"""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.templating import Jinja2Templates

from api import jobs
from api.serializers import history_to_dict, mask_api_key, session_to_dict
from pentron import db

BASE_DIR = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "web" / "templates"))

router = APIRouter(tags=["pages"])


@router.get("/")
def dashboard(request: Request):
    settings = db.get_settings()
    return templates.TemplateResponse(request, "dashboard.html", {"settings": settings})


@router.get("/scans/{sl_no}")
def scan_progress_page(request: Request, sl_no: int):
    return templates.TemplateResponse(request, "scan_progress.html", {"sl_no": sl_no})


@router.get("/scans/{sl_no}/status-fragment")
def scan_status_fragment(request: Request, sl_no: int):
    status = jobs.resolve_status(sl_no)
    if status is None:
        raise HTTPException(status_code=404, detail=f"SL# {sl_no} not found")
    return templates.TemplateResponse(
        request, "_scan_status_fragment.html", {"sl_no": sl_no, "status": status}
    )


@router.get("/history")
def history_list_page(request: Request):
    rows = [history_to_dict(row) for row in db.get_all_history()]
    return templates.TemplateResponse(request, "history_list.html", {"rows": rows})


@router.get("/history/{sl_no}")
def session_detail_page(request: Request, sl_no: int):
    data = db.get_session(sl_no)
    if not data["history"]:
        raise HTTPException(status_code=404, detail=f"SL# {sl_no} not found")
    return templates.TemplateResponse(
        request,
        "session_detail.html",
        {"sl_no": sl_no, "session": session_to_dict(data)},
    )


@router.get("/settings")
def settings_page(request: Request):
    settings = db.get_settings()
    settings["api_key_masked"] = mask_api_key(settings.get("api_key"))
    return templates.TemplateResponse(request, "settings.html", {"settings": settings})
