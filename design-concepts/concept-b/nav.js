// PenTron — concept B: shared navbar behaviour.
// 1) Marks the current page's nav link active (via filename match).
// 2) Shrinks the fixed navbar and adds a soft shadow once the page scrolls.
(function () {
  function currentFile() {
    var path = window.location.pathname.split("/").pop();
    return path && path.length ? path : "index.html";
  }

  function markActiveLink() {
    var here = currentFile();
    document.querySelectorAll("[data-nav-link]").forEach(function (link) {
      var href = link.getAttribute("href");
      if (href === here) {
        link.classList.add("nav-link-active");
      }
    });
  }

  function initScrollEffect() {
    var nav = document.getElementById("site-nav");
    if (!nav) return;

    var isScrolled = null; // force first paint

    function applyState(scrolled) {
      if (scrolled === isScrolled) return;
      isScrolled = scrolled;
      nav.classList.toggle("py-3", scrolled);
      nav.classList.toggle("py-5", !scrolled);
      nav.classList.toggle("shadow-nav", scrolled);
      nav.classList.toggle("bg-white", scrolled);
      nav.classList.toggle("bg-white/90", !scrolled);
      nav.classList.toggle("border-slate-200", scrolled);
      nav.classList.toggle("border-transparent", !scrolled);
    }

    function onScroll() {
      applyState(window.scrollY > 8);
    }

    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
  }

  document.addEventListener("DOMContentLoaded", function () {
    markActiveLink();
    initScrollEffect();
  });
})();
