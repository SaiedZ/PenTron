// PenTron concept A — shared navbar behavior.
// 1) toggles a "scrolled" state on the fixed navbar (blur + shadow + shrink)
// 2) marks the current page's nav link active (animated underline via CSS)
(function () {
  var nav = document.getElementById("site-nav");
  if (!nav) return;

  var SCROLL_THRESHOLD = 12;
  var ticking = false;

  function applyScrollState() {
    var scrolled = window.scrollY > SCROLL_THRESHOLD;
    nav.classList.toggle("nav-scrolled", scrolled);
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
