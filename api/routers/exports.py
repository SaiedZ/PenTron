#!/usr/bin/env python3
"""
PENTRON - api/routers/exports.py
Generate a PDF/HTML report and stream it back as a download, reusing
export.py's existing export_pdf/export_html unchanged.
"""

import os

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from api.security import verify_token
from api.serializers import session_to_dict
from pentron import db
from pentron.export import (
    build_json_export,
    export_html,
    export_pdf,
    json_export_filename,
)

router = APIRouter(
    prefix="/api", tags=["exports"], dependencies=[Depends(verify_token)]
)

# Not export_menu's `~/PenTron/reports` default — that path isn't
# meaningful for a container serving a download back over HTTP.
EXPORTS_DIR = os.environ.get("PENTRON_EXPORTS_DIR", "/app/exports")


@router.get("/history/{sl_no}/export")
def export_session(
    sl_no: int,
    format: str = Query("pdf", pattern="^(pdf|html|json)$"),
    include_raw: bool = Query(False),
):
    data = db.get_session(sl_no)
    if not data["history"]:
        raise HTTPException(status_code=404, detail=f"SL# {sl_no} not found")

    if format == "json":
        session = session_to_dict(data)
        filename = json_export_filename(sl_no, session["history"]["target"])
        return JSONResponse(
            build_json_export(session, include_raw=include_raw),
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    if format == "pdf":
        path = export_pdf(data, EXPORTS_DIR)
        media_type = "application/pdf"
    else:
        path = export_html(data, EXPORTS_DIR)
        media_type = "text/html"

    return FileResponse(path, media_type=media_type, filename=os.path.basename(path))
