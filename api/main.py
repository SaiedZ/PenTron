#!/usr/bin/env python3
"""
PENTRON - api/main.py
FastAPI app entry point: `uvicorn api.main:app --host 0.0.0.0 --port 8000`.
Run with a single worker — api/jobs.py's progress store is process-local.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from api.routers import exports, history, scans, settings

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"

app = FastAPI(title="PENTRON")

app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))

app.include_router(scans.router)
app.include_router(history.router)
app.include_router(exports.router)
app.include_router(settings.router)

# Page routes (dashboard/scan-progress/history/settings) are added in
# api/routers/pages.py alongside the Jinja2 templates.
from api.routers import pages  # noqa: E402
app.include_router(pages.router)
