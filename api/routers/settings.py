#!/usr/bin/env python3
"""
PENTRON - api/routers/settings.py
Runtime configuration screen backend: read/update the settings row,
list installed Ollama models, and a basic reachability health check.
"""

import requests
from fastapi import APIRouter, Depends

import db
from api.schemas import SettingsUpdateRequest
from api.security import verify_token
from api.serializers import mask_api_key

router = APIRouter(
    prefix="/api", tags=["settings"], dependencies=[Depends(verify_token)]
)


def _masked(settings: dict) -> dict:
    settings = dict(settings)
    settings["api_key"] = mask_api_key(settings.get("api_key"))
    return settings


@router.get("/settings")
def get_settings():
    return _masked(db.get_settings())


@router.put("/settings")
def update_settings(payload: SettingsUpdateRequest):
    fields = payload.model_dump(exclude_none=True)
    db.save_settings(**fields)
    return _masked(db.get_settings())


@router.get("/providers/ollama/models")
def list_ollama_models():
    settings = db.get_settings()
    host = settings.get("ollama_host") or "localhost:11434"
    try:
        resp = requests.get(f"http://{host}/api/tags", timeout=10)
        resp.raise_for_status()
        return [m["name"] for m in resp.json().get("models", [])]
    except Exception:
        return []


@router.get("/providers/ollama/gpu-status")
def ollama_gpu_status():
    """
    Best-effort GPU detection: GPU passthrough is set on the Ollama
    container at `docker compose up` time, which the web container has no
    way to control or introspect directly (no Docker socket access here).
    Instead, ask Ollama which processor its *currently loaded* model(s)
    are running on via /api/ps — size_vram > 0 means at least part of that
    model sits on GPU.
    """
    settings = db.get_settings()
    host = settings.get("ollama_host") or "localhost:11434"
    try:
        resp = requests.get(f"http://{host}/api/ps", timeout=5)
        resp.raise_for_status()
        models = resp.json().get("models", [])
    except Exception:
        return {"status": "unreachable", "models": []}

    if not models:
        return {"status": "unknown", "models": []}

    status = "gpu" if any(m.get("size_vram", 0) > 0 for m in models) else "cpu"
    return {
        "status": status,
        "models": [
            {
                "name": m.get("name"),
                "size": m.get("size", 0),
                "size_vram": m.get("size_vram", 0),
            }
            for m in models
        ],
    }


@router.get("/health")
def health():
    db_ok = True
    try:
        conn = db.get_connection()
        conn.close()
    except Exception:
        db_ok = False

    settings = db.get_settings()
    host = settings.get("ollama_host") or "localhost:11434"
    ollama_ok = True
    try:
        requests.get(f"http://{host}", timeout=5)
    except Exception:
        ollama_ok = False

    return {"db": db_ok, "ollama": ollama_ok}
