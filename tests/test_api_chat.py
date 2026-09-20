from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from api.routers import chat
from api.schemas import ChatRequest
from pentron.chat import ChatProviderError


def _session_data():
    return {
        "history": (7, "example.com", None, "completed"),
        "vulns": [],
        "fixes": [],
        "summary": None,
        "suggestions": [],
        "tool_calls": [],
    }


def test_chat_with_session_returns_reply_and_resynchronized_history(monkeypatch):
    provider = Mock()
    updated_history = [
        {"role": "user", "content": "Previous"},
        {"role": "user", "content": "Question"},
        {"role": "assistant", "content": "Answer"},
    ]
    send = Mock(return_value=("Answer", updated_history))

    monkeypatch.setattr(chat.db, "get_session", Mock(return_value=_session_data()))
    monkeypatch.setattr(chat, "build_seed_context", Mock(return_value="seed"))
    monkeypatch.setattr(chat, "get_provider", Mock(return_value=provider))
    monkeypatch.setattr(chat, "send_chat_message", send)

    response = chat.chat_with_session(
        7,
        ChatRequest(
            history=[{"role": "user", "content": "Previous"}],
            message="Question",
        ),
    )

    assert response.model_dump() == {
        "reply": "Answer",
        "history": updated_history,
    }
    chat.build_seed_context.assert_called_once()
    serialized_session = chat.build_seed_context.call_args.args[0]
    assert serialized_session["history"]["target"] == "example.com"
    send.assert_called_once_with(
        [{"role": "user", "content": "Previous"}],
        "seed",
        "Question",
        provider,
    )


def test_chat_with_session_returns_404_before_building_context(monkeypatch):
    monkeypatch.setattr(chat.db, "get_session", Mock(return_value={"history": None}))
    build_seed = Mock()
    monkeypatch.setattr(chat, "build_seed_context", build_seed)

    with pytest.raises(HTTPException) as exc_info:
        chat.chat_with_session(404, ChatRequest(message="Question"))

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "SL# 404 not found"
    build_seed.assert_not_called()


def test_chat_with_session_maps_provider_error_to_502(monkeypatch):
    monkeypatch.setattr(chat.db, "get_session", Mock(return_value=_session_data()))
    monkeypatch.setattr(chat, "get_provider", Mock(return_value=Mock()))
    monkeypatch.setattr(
        chat,
        "send_chat_message",
        Mock(side_effect=ChatProviderError("Provider unavailable")),
    )

    with pytest.raises(HTTPException) as exc_info:
        chat.chat_with_session(7, ChatRequest(message="Question"))

    assert exc_info.value.status_code == 502
    assert exc_info.value.detail == "Provider unavailable"


def test_chat_route_is_registered_on_application():
    from api.main import app

    assert any(
        getattr(route, "original_router", None) is chat.router for route in app.routes
    )
    route = next(
        route for route in chat.router.routes if route.path == "/api/scans/{sl_no}/chat"
    )
    assert "POST" in route.methods
