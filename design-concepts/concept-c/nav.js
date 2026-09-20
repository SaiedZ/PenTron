// PenTron — Concept C nav behaviour (shared across all pages).
// Vanilla JS, no dependencies. Static mockup only.
document.addEventListener("DOMContentLoaded", function () {
  var nav = document.getElementById("site-nav");

  function onScroll() {
    if (window.scrollY > 24) {
      nav.classList.add("nav-scrolled");
    } else {
      nav.classList.remove("nav-scrolled");
    }
  }
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  var page = document.body.getAttribute("data-page");
  document.querySelectorAll(".nav-link").forEach(function (link) {
    if (link.getAttribute("data-page") === page) {
      link.classList.add("active");
    }
  });
});
