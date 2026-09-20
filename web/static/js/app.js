/* PENTRON web UI — small helpers shared across pages. */

async function apiFetch(method, url, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(url, opts);
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const data = await resp.json();
      detail = data.detail || JSON.stringify(data);
    } catch (_) { /* ignore */ }
    throw new Error(detail);
  }
  if (resp.status === 204) return null;
  return resp.json();
}

async function confirmAndDelete(url, message, redirectUrl) {
  if (!confirm(message || "Delete this permanently?")) return;
  try {
    await apiFetch("DELETE", url);
    if (redirectUrl) window.location.assign(redirectUrl);
    else window.location.reload();
  } catch (err) {
    alert(`Delete failed: ${err.message}`);
  }
}

function toggleEdit(id) {
  document.getElementById(id).classList.toggle("hidden");
}

async function submitPatch(url, body, onDone) {
  try {
    await apiFetch("PATCH", url, body);
    if (onDone) onDone();
    else window.location.reload();
  } catch (err) {
    alert(`Update failed: ${err.message}`);
  }
}

// Shared navbar behavior: scroll-reactive shrink/blur, active link underline.
(function () {
  var nav = document.getElementById("site-nav");
  if (!nav) return;

  var SCROLL_THRESHOLD = 12;
  var ticking = false;

  function applyScrollState() {
    nav.classList.toggle("nav-scrolled", window.scrollY > SCROLL_THRESHOLD);
    ticking = false;
  }

  window.addEventListener(
    "scroll",
    function () {
      if (!ticking) {
        window.requestAnimationFrame(applyScrollState);
        ticking = true;
      }
    },
    { passive: true },
  );

  applyScrollState();

  var currentPage = document.body.getAttribute("data-page");
  if (currentPage) {
    document.querySelectorAll(".nav-link[data-nav]").forEach(function (link) {
      if (link.getAttribute("data-nav") === currentPage) {
        link.classList.add("active");
      }
    });
  }
})();
