#!/usr/bin/env python3
"""
PENTRON - api/security.py
Optional shared-secret check. This is a single-operator local tool — no
multi-tenant auth is built. If PENTRON_API_TOKEN is set, requests must
send a matching X-API-Token header; if unset (the default), no auth is
enforced at all.
"""

import os

from fastapi import Header, HTTPException


async def verify_token(x_api_token: str = Header(default=None)) -> None:
    expected = os.environ.get("PENTRON_API_TOKEN")
    if not expected:
        return
    if x_api_token != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Token")
