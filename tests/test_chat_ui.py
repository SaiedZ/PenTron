from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "web/templates/session_detail.html").read_text(encoding="utf-8")
SCRIPT = (ROOT / "web/static/js/session-chat.js").read_text(encoding="utf-8")


def test_session_page_contains_accessible_chat_widget():
    assert 'id="chat-toggle-btn"' in TEMPLATE
    assert 'aria-controls="chat-panel"' in TEMPLATE
    assert 'id="chat-panel"' in TEMPLATE
    assert 'data-session-id="{{ sl_no }}"' in TEMPLATE
    assert 'src="/static/js/session-chat.js"' in TEMPLATE


def test_findings_offer_discussion_without_automatic_submission():
    assert 'class="chat-finding-btn' in TEMPLATE
    assert "Help me understand and prioritize this finding:" in SCRIPT
    assert "input.value = [" in SCRIPT


def test_history_is_scoped_to_session_storage():
    assert '"pentron:chat:" + sessionId' in SCRIPT
    assert "sessionStorage.getItem(storageKey)" in SCRIPT
    assert "sessionStorage.setItem(storageKey" in SCRIPT
    assert "localStorage" not in SCRIPT


def test_chat_uses_api_and_replaces_history_with_server_version():
    assert 'apiFetch("POST", "/api/scans/" + sessionId + "/chat"' in SCRIPT
    assert "history = response.history" in SCRIPT
    assert "renderHistory();" in SCRIPT


def test_markdown_renderer_does_not_inject_html():
    assert "function renderMarkdown" in SCRIPT
    assert "document.createTextNode" in SCRIPT
    assert "textContent = code" in SCRIPT
    assert "innerHTML" not in SCRIPT
    assert "outerHTML" not in SCRIPT


def test_code_blocks_have_copy_action():
    assert 'copy.textContent = "Copy"' in SCRIPT
    assert "navigator.clipboard.writeText(code)" in SCRIPT
