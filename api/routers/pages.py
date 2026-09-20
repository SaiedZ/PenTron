#!/usr/bin/env python3
"""
PENTRON - api/routers/pages.py
Server-rendered HTML pages (Jinja2 + HTMX). Filled in alongside the
templates under web/templates/.
"""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from markupsafe import Markup

from api import jobs
from api.serializers import history_to_dict, mask_api_key, session_to_dict
from pentron import db
from pentron.tools import registry as tool_registry

BASE_DIR = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "web" / "templates"))
markdown = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")


def render_safe_markdown(value: str) -> Markup:
    return Markup(markdown.render(value or ""))


templates.env.filters["safe_markdown"] = render_safe_markdown

router = APIRouter(tags=["pages"])

TOOL_DESCRIPTIONS = {
    "nmap": "Scans the target for open ports and running services",
    "whois": "Looks up who owns the domain and when it was registered",
    "whatweb": "Identifies the CMS, frameworks and technologies powering the site",
    "curl headers": "Reads HTTP response headers for server/version clues",
    "dig DNS": "Lists the domain's DNS records (mail servers, subdomains, etc.)",
    "nikto": "Scans the web server for known vulnerabilities and misconfigurations",
    "sslscan": "Checks which HTTPS/TLS versions and ciphers the server accepts",
    "testssl.sh": "In-depth HTTPS/TLS audit: certificates, ciphers, known weaknesses",
    "wafw00f": "Detects whether a web application firewall is protecting the site",
    "robots/security.txt": "Checks robots.txt/security.txt for hidden paths, contacts",
    "wpscan": "Checks WordPress plugins/themes for known flaws (if WordPress detected)",
}


@router.get("/")
def home(request: Request):
    return templates.TemplateResponse(request, "home.html")


@router.get("/new-scan")
def dashboard(request: Request):
    settings = db.get_settings()
    default_keys = tool_registry.default_keys()
    nikto = tool_registry.find_by_name("nikto")
    nikto_bundle_keys = default_keys + ([nikto.key] if nikto else [])
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "settings": settings,
            "tools": list(tool_registry.all_tools().values()),
            "tool_descriptions": TOOL_DESCRIPTIONS,
            "default_keys": default_keys,
            # pre-serialized for the JS PRESETS object — Starlette's
            # Jinja2Templates doesn't register a `tojson` filter
            "default_keys_json": json.dumps(default_keys),
            "nikto_bundle_keys_json": json.dumps(nikto_bundle_keys),
        },
    )


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
