#!/usr/bin/env python3
"""Contextual chat endpoint for a single scan session."""

from fastapi import APIRouter, Depends, HTTPException

from api.schemas import ChatRequest, ChatResponse
from api.security import verify_token
from api.serializers import session_to_dict
from pentron import db
from pentron.ai.capabilities import context_policy_for
from pentron.ai.chat import ChatProviderError, load_chat_context, send_chat_message
from pentron.ai.providers import get_provider

router = APIRouter(prefix="/api", tags=["chat"], dependencies=[Depends(verify_token)])


@router.post("/scans/{sl_no}/chat", response_model=ChatResponse)
def chat_with_session(sl_no: int, payload: ChatRequest) -> ChatResponse:
    """Send one message using the compact context of an existing scan session."""
    data = db.get_session(sl_no)
    if not data["history"]:
        raise HTTPException(status_code=404, detail=f"SL# {sl_no} not found")

    session = session_to_dict(data)
    provider = get_provider()
    policy = context_policy_for(provider)
    context = load_chat_context(session, sl_no, payload.message, policy)
    seed = context.render(policy.session_context_budget)
    history = [message.model_dump() for message in payload.history]

    try:
        reply, updated_history = send_chat_message(
            history,
            seed,
            payload.message,
            provider,
        )
    except ChatProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return ChatResponse(reply=reply, history=updated_history)
