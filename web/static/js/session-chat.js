/* Contextual session chat. History remains in this tab's sessionStorage. */
(function () {
  "use strict";

  var panel = document.getElementById("chat-panel");
  var toggle = document.getElementById("chat-toggle-btn");
  var close = document.getElementById("chat-close-btn");
  var messages = document.getElementById("chat-messages");
  var form = document.getElementById("chat-form");
  var input = document.getElementById("chat-input");
  var send = document.getElementById("chat-send-btn");
  var error = document.getElementById("chat-error");
  if (!panel || !toggle || !messages || !form || !input || !send) return;

  var sessionId = panel.dataset.sessionId;
  var storageKey = "pentron:chat:" + sessionId;
  var history = loadHistory();

  function loadHistory() {
    try {
      var value = JSON.parse(sessionStorage.getItem(storageKey) || "[]");
      if (!Array.isArray(value)) return [];
      return value.filter(function (item) {
        return (
          item &&
          (item.role === "user" || item.role === "assistant") &&
          typeof item.content === "string" &&
          item.content.trim()
        );
      });
    } catch (_) {
      return [];
    }
  }

  function saveHistory() {
    try {
      sessionStorage.setItem(storageKey, JSON.stringify(history));
    } catch (_) {
      showError("The conversation could not be saved in this tab.");
    }
  }

  function setOpen(open) {
    panel.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
    if (open) input.focus();
  }

  function showError(text) {
    error.textContent = text;
    error.hidden = !text;
  }

  function appendInline(parent, text) {
    var pattern = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/g;
    var cursor = 0;
    var match;
    while ((match = pattern.exec(text)) !== null) {
      parent.appendChild(document.createTextNode(text.slice(cursor, match.index)));
      var token = match[0];
      var element;
      if (token.startsWith("`")) element = document.createElement("code");
      else if (token.startsWith("**")) element = document.createElement("strong");
      else element = document.createElement("em");
      element.textContent = token.slice(token.startsWith("**") ? 2 : 1, token.startsWith("**") ? -2 : -1);
      parent.appendChild(element);
      cursor = match.index + token.length;
    }
    parent.appendChild(document.createTextNode(text.slice(cursor)));
  }

  function appendCodeBlock(parent, code, language) {
    var wrapper = document.createElement("div");
    wrapper.className = "chat-code-block";
    var bar = document.createElement("div");
    bar.className = "chat-code-bar";
    var label = document.createElement("span");
    label.textContent = language || "code";
    var copy = document.createElement("button");
    copy.type = "button";
    copy.textContent = "Copy";
    copy.addEventListener("click", function () {
      navigator.clipboard.writeText(code).then(function () {
        copy.textContent = "Copied";
        window.setTimeout(function () { copy.textContent = "Copy"; }, 1200);
      });
    });
    bar.append(label, copy);
    var pre = document.createElement("pre");
    var codeElement = document.createElement("code");
    codeElement.textContent = code;
    pre.appendChild(codeElement);
    wrapper.append(bar, pre);
    parent.appendChild(wrapper);
  }

  function renderMarkdown(container, markdown) {
    var lines = markdown.replace(/\r\n?/g, "\n").split("\n");
    var paragraph = [];
    var list = null;
    var code = null;
    var language = "";

    function flushParagraph() {
      if (!paragraph.length) return;
      var p = document.createElement("p");
      appendInline(p, paragraph.join(" "));
      container.appendChild(p);
      paragraph = [];
    }
    function flushList() { list = null; }
    function flushCode() {
      if (code === null) return;
      appendCodeBlock(container, code.join("\n"), language);
      code = null;
      language = "";
    }

    lines.forEach(function (line) {
      var fence = line.match(/^```([\w+-]*)\s*$/);
      if (fence) {
        if (code === null) {
          flushParagraph(); flushList(); code = []; language = fence[1];
        } else flushCode();
        return;
      }
      if (code !== null) { code.push(line); return; }
      var heading = line.match(/^(#{1,3})\s+(.+)$/);
      if (heading) {
        flushParagraph(); flushList();
        var h = document.createElement("h" + (heading[1].length + 2));
        appendInline(h, heading[2]); container.appendChild(h); return;
      }
      var item = line.match(/^\s*([-*]|\d+\.)\s+(.+)$/);
      if (item) {
        flushParagraph();
        var tag = item[1].endsWith(".") ? "ol" : "ul";
        if (!list || list.tagName.toLowerCase() !== tag) {
          list = document.createElement(tag); container.appendChild(list);
        }
        var li = document.createElement("li");
        appendInline(li, item[2]); list.appendChild(li); return;
      }
      flushList();
      if (!line.trim()) flushParagraph();
      else paragraph.push(line.trim());
    });
    flushCode(); flushParagraph();
  }

  function appendMessage(message) {
    var bubble = document.createElement("div");
    bubble.className = "chat-bubble chat-bubble-" + message.role;
    if (message.role === "assistant") renderMarkdown(bubble, message.content);
    else bubble.textContent = message.content;
    messages.appendChild(bubble);
    messages.scrollTop = messages.scrollHeight;
  }

  function renderHistory() {
    messages.querySelectorAll(".chat-bubble").forEach(function (bubble) {
      bubble.remove();
    });
    history.forEach(appendMessage);
  }

  renderHistory();
  toggle.addEventListener("click", function () { setOpen(panel.hidden); });
  close.addEventListener("click", function () { setOpen(false); });

  document.querySelectorAll(".chat-finding-btn").forEach(function (button) {
    button.addEventListener("click", function () {
      var d = button.dataset;
      input.value = [
        "Help me understand and prioritize this finding:",
        "Name: " + d.findingName,
        "Severity: " + d.findingSeverity,
        "Port: " + d.findingPort,
        "Service: " + d.findingService,
        "Description: " + d.findingDescription,
      ].join("\n");
      setOpen(true);
    });
  });

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    var text = input.value.trim();
    if (!text || send.disabled) return;
    showError("");
    input.value = "";
    appendMessage({ role: "user", content: text });
    send.disabled = true;
    input.disabled = true;
    try {
      var response = await apiFetch("POST", "/api/scans/" + sessionId + "/chat", {
        history: history,
        message: text,
      });
      history = response.history;
      saveHistory();
      renderHistory();
    } catch (requestError) {
      showError("Message not sent: " + requestError.message);
      input.value = text;
    } finally {
      send.disabled = false;
      input.disabled = false;
      input.focus();
    }
  });
})();
