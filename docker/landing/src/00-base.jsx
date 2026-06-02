// Asset base prefix. Pages live at different depths (/, /blog/, /blog/<slug>/),
// so asset URLs need a matching number of "../" to stay relative - which is
// what lets the generated files open straight from disk (file://) as well as
// when served. We derive the prefix from this very bundle's own <script src>,
// which build.sh has already rewritten to the right depth (e.g. ../assets/app.js).
// Reading it back means the components render exactly the paths the
// pre-rendered HTML already contains, so React hydration finds no mismatch and
// never patches the live <img> back to an absolute path.
window.__VW_BASE__ = (function () {
  var src = (document.currentScript && document.currentScript.getAttribute("src")) || "assets/app.js";
  return src.replace(/assets\/app\.js$/, "");
})();

function vwAsset(name) {
  return window.__VW_BASE__ + "assets/" + name;
}
window.vwAsset = vwAsset;
