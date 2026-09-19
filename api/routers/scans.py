#!/usr/bin/env python3
"""
METATRON - api/routers/scans.py
Start a scan and poll its live progress.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

import db
from api import jobs
from api.scan_runner import run_scan_job
from api.schemas import ScanCreateRequest
from api.security import verify_token
from tools import check_target_safety

router = APIRouter(prefix="/api/scans", tags=["scans"], dependencies=[Depends(verify_token)])


@router.post("")
def start_scan(payload: ScanCreateRequest, background_tasks: BackgroundTasks):
    if not payload.target.strip():
        raise HTTPException(status_code=422, detail="target must not be empty")

    unsafe = check_target_safety(payload.target)
    if unsafe:
        raise HTTPException(status_code=422, detail=unsafe)

    sl_no = db.create_session(payload.target)
    jobs.create_job(sl_no)
    background_tasks.add_task(
        run_scan_job, sl_no, payload.target, payload.tools, payload.subdomain_discovery_level
    )
    return {"sl_no": sl_no}


@router.get("/{sl_no}/status")
def get_scan_status(sl_no: int):
    status = jobs.resolve_status(sl_no)
    if status is None:
        raise HTTPException(status_code=404, detail=f"SL# {sl_no} not found")
    return status
