#!/usr/bin/env python3
"""
PENTRON - api/routers/history.py
List/view/edit/delete scan sessions and their findings — thin wrappers
around db.py's existing CRUD functions.
"""

from fastapi import APIRouter, Depends, HTTPException

from api.schemas import (
    FixEditRequest,
    RiskEditRequest,
    VulnEditRequest,
)
from api.security import verify_token
from api.serializers import history_to_dict, session_to_dict
from pentron import db

router = APIRouter(
    prefix="/api", tags=["history"], dependencies=[Depends(verify_token)]
)


@router.get("/history")
def list_history():
    return [history_to_dict(row) for row in db.get_all_history()]


@router.get("/history/{sl_no}")
def get_history_detail(sl_no: int):
    data = db.get_session(sl_no)
    if not data["history"]:
        raise HTTPException(status_code=404, detail=f"SL# {sl_no} not found")
    return session_to_dict(data)


@router.patch("/vulnerabilities/{vuln_id}")
def edit_vuln(vuln_id: int, payload: VulnEditRequest):
    db.edit_vulnerability(vuln_id, payload.field, payload.value)
    return {"ok": True}


@router.patch("/fixes/{fix_id}")
def edit_fix(fix_id: int, payload: FixEditRequest):
    db.edit_fix(fix_id, payload.fix_text)
    return {"ok": True}


@router.patch("/history/{sl_no}/risk")
def edit_risk(sl_no: int, payload: RiskEditRequest):
    db.edit_summary_risk(sl_no, payload.risk)
    return {"ok": True}


@router.delete("/vulnerabilities/{vuln_id}")
def delete_vuln(vuln_id: int):
    db.delete_vulnerability(vuln_id)
    return {"ok": True}


@router.delete("/fixes/{fix_id}")
def delete_fix(fix_id: int):
    db.delete_fix(fix_id)
    return {"ok": True}


@router.delete("/history/{sl_no}")
def delete_session(sl_no: int):
    db.delete_full_session(sl_no)
    return {"ok": True}
