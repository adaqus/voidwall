function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/* === 00-base.jsx === */
// Asset base prefix. Pages live at different depths (/, /blog/, /blog/<slug>/),
// so asset URLs need a matching number of "../" to stay relative - which is
// what lets the generated files open straight from disk (file://) as well as
// when served. We derive the prefix from this very bundle's own <script src>,
// which build.sh has already rewritten to the right depth (e.g. ../assets/app.js).
// Reading it back means the components render exactly the paths the
// pre-rendered HTML already contains, so React hydration finds no mismatch and
// never patches the live <img> back to an absolute path.
window.__VW_BASE__ = function () {
  var src = document.currentScript && document.currentScript.getAttribute("src") || "assets/app.js";
  return src.replace(/assets\/app\.js$/, "");
}();
function vwAsset(name) {
  return window.__VW_BASE__ + "assets/" + name;
}
window.vwAsset = vwAsset;

/* === 00-icons.jsx === */
// Centralized icon registry - Lucide-aligned stroke set. currentColor only.
function Icon({
  name,
  size = 20
}) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.6,
    strokeLinecap: "round",
    strokeLinejoin: "round"
  };
  switch (name) {
    case "box":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "3.27 6.96 12 12.01 20.73 6.96"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "22.08",
        x2: "12",
        y2: "12"
      }));
    case "database":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("ellipse", {
        cx: "12",
        cy: "5",
        rx: "9",
        ry: "3"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M3 5v14a9 3 0 0 0 18 0V5"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M3 12a9 3 0 0 0 18 0"
      }));
    case "cloud":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M17.5 19a4.5 4.5 0 1 0-1.5-8.75A6 6 0 0 0 4 12.5 4 4 0 0 0 5.5 19h12z"
      }));
    case "hard-drive":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("line", {
        x1: "22",
        y1: "12",
        x2: "2",
        y2: "12"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "6",
        y1: "16",
        x2: "6.01",
        y2: "16"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "10",
        y1: "16",
        x2: "10.01",
        y2: "16"
      }));
    case "ram":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M2 7a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v1.1a2 2 0 0 0 0 3.8V17a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-5.1a2 2 0 0 0 0-3.8z"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M2 15h20"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M8 11V9"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M12 11V9"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M16 11V9"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M6 19v-3"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M10 19v-3"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M14 19v-3"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M18 19v-3"
      }));
    case "scan":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("circle", {
        cx: "11",
        cy: "11",
        r: "8"
      }), /*#__PURE__*/React.createElement("path", {
        d: "m21 21-4.35-4.35"
      }));
    case "redact":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "m12 3-1.9 5.8L4 10l5.8 1.9L12 18l1.9-6.1L20 10l-6.1-2.2z"
      }));
    case "audit":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "14 2 14 8 20 8"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "8",
        y1: "13",
        x2: "16",
        y2: "13"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "8",
        y1: "17",
        x2: "13",
        y2: "17"
      }));
    case "shield":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M12 22s-8-4.5-8-11V5l8-3 8 3v6c0 6.5-8 11-8 11z"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M12 8v4M12 16h.01"
      }));
    case "alert":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "8",
        x2: "12",
        y2: "12"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "16",
        x2: "12.01",
        y2: "16"
      }));
    case "block":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
      }), /*#__PURE__*/React.createElement("path", {
        d: "m14.5 9.5-5 5"
      }), /*#__PURE__*/React.createElement("path", {
        d: "m9.5 9.5 5 5"
      }));
    case "mask":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M9.88 9.88a3 3 0 1 0 4.24 4.24"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "2",
        y1: "2",
        x2: "22",
        y2: "22"
      }));
    case "filter":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("polygon", {
        points: "22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"
      }));
    case "sliders":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("line", {
        x1: "4",
        y1: "6",
        x2: "20",
        y2: "6"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "4",
        y1: "12",
        x2: "20",
        y2: "12"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "4",
        y1: "18",
        x2: "20",
        y2: "18"
      }), /*#__PURE__*/React.createElement("circle", {
        cx: "9",
        cy: "6",
        r: "2"
      }), /*#__PURE__*/React.createElement("circle", {
        cx: "15",
        cy: "12",
        r: "2"
      }), /*#__PURE__*/React.createElement("circle", {
        cx: "7",
        cy: "18",
        r: "2"
      }));
    case "chart":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("line", {
        x1: "18",
        y1: "20",
        x2: "18",
        y2: "10"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "20",
        x2: "12",
        y2: "4"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "6",
        y1: "20",
        x2: "6",
        y2: "14"
      }));
    case "globe":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("circle", {
        cx: "12",
        cy: "12",
        r: "10"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "2",
        y1: "12",
        x2: "22",
        y2: "12"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"
      }));
    case "smartphone":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("rect", {
        x: "7",
        y: "2",
        width: "10",
        height: "20",
        rx: "2"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "11",
        y1: "18",
        x2: "13",
        y2: "18"
      }));
    case "code":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("polyline", {
        points: "16 18 22 12 16 6"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "8 6 2 12 8 18"
      }));
    case "server":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("rect", {
        x: "2",
        y: "2",
        width: "20",
        height: "8",
        rx: "2"
      }), /*#__PURE__*/React.createElement("rect", {
        x: "2",
        y: "14",
        width: "20",
        height: "8",
        rx: "2"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "6",
        y1: "6",
        x2: "6.01",
        y2: "6"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "6",
        y1: "18",
        x2: "6.01",
        y2: "18"
      }));
    case "hexagon":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"
      }));
    case "perf":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("polyline", {
        points: "13 2 3 14 12 14 11 22 21 10 12 10 13 2"
      }));
    case "privacy":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("rect", {
        x: "3",
        y: "11",
        width: "18",
        height: "11",
        rx: "2"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M7 11V7a5 5 0 0 1 10 0v4"
      }));
    case "search":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("circle", {
        cx: "11",
        cy: "11",
        r: "8"
      }), /*#__PURE__*/React.createElement("path", {
        d: "m21 21-4.35-4.35"
      }));
    case "plus":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "5",
        x2: "12",
        y2: "19"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "5",
        y1: "12",
        x2: "19",
        y2: "12"
      }));
    case "menu":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("line", {
        x1: "3",
        y1: "6",
        x2: "21",
        y2: "6"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "3",
        y1: "12",
        x2: "21",
        y2: "12"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "3",
        y1: "18",
        x2: "21",
        y2: "18"
      }));
    case "settings":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("circle", {
        cx: "12",
        cy: "12",
        r: "3"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"
      }));
    case "user":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"
      }), /*#__PURE__*/React.createElement("circle", {
        cx: "12",
        cy: "7",
        r: "4"
      }));
    case "bell":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M13.73 21a2 2 0 0 1-3.46 0"
      }));
    case "languages":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "m5 8 6 6"
      }), /*#__PURE__*/React.createElement("path", {
        d: "m4 14 6-6 2-3"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M2 5h12"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M7 2h1"
      }), /*#__PURE__*/React.createElement("path", {
        d: "m22 22-5-10-5 10"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M14 18h6"
      }));
    case "flag":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M4 22V4a2 2 0 0 1 2-2h10l-2 5 2 5H6"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "4",
        y1: "22",
        x2: "4",
        y2: "15"
      }));
    case "dollar":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "2",
        x2: "12",
        y2: "22"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"
      }));
    case "gauge":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "m12 14 4-4"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M3.34 19a10 10 0 1 1 17.32 0"
      }));
    case "key":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("circle", {
        cx: "7.5",
        cy: "15.5",
        r: "5.5"
      }), /*#__PURE__*/React.createElement("path", {
        d: "m21 2-9.6 9.6"
      }), /*#__PURE__*/React.createElement("path", {
        d: "m15.5 7.5 3 3L22 7l-3-3"
      }));
    case "credit-card":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("rect", {
        x: "2",
        y: "5",
        width: "20",
        height: "14",
        rx: "2"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "2",
        y1: "10",
        x2: "22",
        y2: "10"
      }));
    case "mail":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("rect", {
        x: "2",
        y: "4",
        width: "20",
        height: "16",
        rx: "2"
      }), /*#__PURE__*/React.createElement("path", {
        d: "m2 7 10 6 10-6"
      }));
    case "phone":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.12.96.36 1.9.71 2.78a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.11-.45c.88.35 1.82.59 2.78.71A2 2 0 0 1 22 16.92z"
      }));
    case "id-card":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("rect", {
        x: "3",
        y: "4",
        width: "18",
        height: "16",
        rx: "2"
      }), /*#__PURE__*/React.createElement("circle", {
        cx: "9",
        cy: "11",
        r: "2"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M14 9h4"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M14 13h4"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M6 17h6"
      }));
    case "fingerprint":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M12 11c0 5 1.5 8.5 2 9"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M3.5 11c0-4.7 3.8-8.5 8.5-8.5s8.5 3.8 8.5 8.5"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M6 11v1a8 8 0 0 0 1.5 4.5"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M9 11a3 3 0 0 1 6 0v1c0 2 .5 5 2 7"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M21 13v1c0 2.5-.5 4-.5 4"
      }));
    case "globe-2":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("circle", {
        cx: "12",
        cy: "12",
        r: "10"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M2 12h20"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M12 2a14.5 14.5 0 0 1 4 10 14.5 14.5 0 0 1-4 10 14.5 14.5 0 0 1-4-10 14.5 14.5 0 0 1 4-10z"
      }));
    case "arrow-right":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("line", {
        x1: "5",
        y1: "12",
        x2: "19",
        y2: "12"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "12 5 19 12 12 19"
      }));
    case "external-link":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "15 3 21 3 21 9"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "10",
        y1: "14",
        x2: "21",
        y2: "3"
      }));
    case "github":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"
      }));
    case "play":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("polygon", {
        points: "6 3 20 12 6 21 6 3"
      }));
    case "activity":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("polyline", {
        points: "22 12 18 12 15 21 9 3 6 12 2 12"
      }));
    case "layers":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("polygon", {
        points: "12 2 2 7 12 12 22 7 12 2"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "2 17 12 22 22 17"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "2 12 12 17 22 12"
      }));
    case "check":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("polyline", {
        points: "20 6 9 17 4 12"
      }));
    case "x":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("line", {
        x1: "18",
        y1: "6",
        x2: "6",
        y2: "18"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "6",
        y1: "6",
        x2: "18",
        y2: "18"
      }));
    case "trend-up":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("polyline", {
        points: "22 7 13.5 15.5 8.5 10.5 2 17"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "16 7 22 7 22 13"
      }));
    case "wallet":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M21 12V7a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-1"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M16 12h6v4h-6a2 2 0 0 1 0-4z"
      }));
    case "file-json":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "14 2 14 8 20 8"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M10 13c-1 0-1 1-1 2s0 2 1 2"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M14 13c1 0 1 1 1 2s0 2-1 2"
      }));
    case "table":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("rect", {
        x: "3",
        y: "3",
        width: "18",
        height: "18",
        rx: "2"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "3",
        y1: "9",
        x2: "21",
        y2: "9"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "3",
        y1: "15",
        x2: "21",
        y2: "15"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "9",
        y1: "3",
        x2: "9",
        y2: "21"
      }));
    case "text":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("polyline", {
        points: "4 7 4 4 20 4 20 7"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "9",
        y1: "20",
        x2: "15",
        y2: "20"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "4",
        x2: "12",
        y2: "20"
      }));
    case "link":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"
      }));
    case "wrench":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-2.4z"
      }));
    case "zap":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("polygon", {
        points: "13 2 3 14 12 14 11 22 21 10 12 10 13 2"
      }));
    default:
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("circle", {
        cx: "12",
        cy: "12",
        r: "9"
      }));
  }
}
window.Icon = Icon;

/* === 01-nav.jsx === */
// Nav - paper surface, wall mark + wordmark on the left, links + CTA on the right.
function Nav() {
  // Anchors are written as "/#id" so they also work from subpages (e.g. the
  // blog), where the target sections don't exist on the current document.
  const links = [["Product", "/#product"], ["Detection", "/#detection"], ["Specializations", "/#specializations"], ["Formats", "/#formats"], ["Performance", "/#performance"], ["Blog", "/blog/"]];
  return /*#__PURE__*/React.createElement("header", {
    style: {
      position: "sticky",
      top: 0,
      zIndex: 50,
      background: "rgba(241,238,232,0.86)",
      backdropFilter: "blur(12px)",
      WebkitBackdropFilter: "blur(12px)",
      borderBottom: "1px solid var(--vw-paper-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "var(--max-w)",
      margin: "0 auto",
      padding: "16px var(--gutter)",
      display: "flex",
      alignItems: "center",
      gap: 32
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "/",
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 10,
      color: "var(--vw-paper-ink)",
      textDecoration: "none"
    }
  }, /*#__PURE__*/React.createElement("img", {
    src: vwAsset("logo-mark.svg"),
    width: "26",
    height: "26",
    alt: ""
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontWeight: 500,
      letterSpacing: "0.14em",
      fontSize: 15
    }
  }, "VOIDWALL")), /*#__PURE__*/React.createElement("nav", {
    style: {
      display: "flex",
      gap: 28,
      marginLeft: 24
    }
  }, links.map(([l, href]) => /*#__PURE__*/React.createElement("a", {
    key: l,
    href: href,
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 14,
      color: "var(--vw-paper-ink-2)",
      textDecoration: "none"
    }
  }, l))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginLeft: "auto",
      display: "flex",
      alignItems: "center",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "/demo",
    target: "_blank",
    rel: "noopener noreferrer",
    className: "vw-btn vw-btn--primary"
  }, "Try the live demo ", /*#__PURE__*/React.createElement(Icon, {
    name: "external-link",
    size: 14
  })), /*#__PURE__*/React.createElement("a", {
    href: "/#early-adopters",
    className: "vw-btn vw-btn--primary",
    style: {
      background: "white",
      color: "var(--vw-void)"
    }
  }, "Become early adopter ", /*#__PURE__*/React.createElement("span", {
    className: "arrow"
  }, "\u2192")))));
}
window.Nav = Nav;

/* === 02-hero.jsx === */
// Hero - paper surface, left text column, right "wall" illustration with traffic flow.

function Hero() {
  return /*#__PURE__*/React.createElement("section", {
    className: "vw-container",
    style: {
      paddingTop: 56,
      paddingBottom: 88
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)",
      gap: 48,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 8,
      marginBottom: 22
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 6,
      height: 24,
      padding: "0 10px",
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 999,
      fontFamily: "var(--vw-font-body)",
      fontSize: 11,
      letterSpacing: "0.12em",
      textTransform: "uppercase",
      color: "var(--vw-paper-ink-2)",
      background: "rgba(255,255,255,0.5)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 6,
      height: 6,
      borderRadius: 999,
      background: "var(--vw-violet-400)"
    }
  }), "Live demo available - early access")), /*#__PURE__*/React.createElement("p", {
    className: "vw-eyebrow",
    style: {
      margin: "0 0 22px"
    }
  }, "Stop privacy debt at the edge."), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontWeight: 600,
      fontSize: 60,
      lineHeight: 1.0,
      letterSpacing: "-0.025em",
      color: "var(--vw-paper-ink)",
      margin: "0 0 28px",
      textWrap: "balance",
      minHeight: 120
    }
  }, "Stop sensitive data ", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-400)"
    }
  }, "before it spreads"), "."), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 17,
      lineHeight: 1.55,
      color: "var(--vw-paper-ink-2)",
      maxWidth: 480,
      margin: "0 0 36px"
    }
  }, "Voidwall is a self-hosted PII firewall for HTTP, API, and AI traffic. It detects, redacts, or blocks personal data before it reaches LLM providers, agent tools, analytics, logs, traces, databases, storage, or third-party services."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 12,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "/demo",
    target: "_blank",
    rel: "noopener noreferrer",
    className: "vw-btn vw-btn--primary"
  }, "Try the live demo ", /*#__PURE__*/React.createElement(Icon, {
    name: "external-link",
    size: 14
  })), /*#__PURE__*/React.createElement("a", {
    href: "#early-adopters",
    className: "vw-btn vw-btn--primary",
    style: {
      background: "white",
      color: "var(--vw-void)"
    }
  }, "Become early adopter ", /*#__PURE__*/React.createElement("span", {
    className: "arrow"
  }, "\u2192")))), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      width: "100%",
      aspectRatio: "600/520"
    }
  }, /*#__PURE__*/React.createElement("img", {
    src: "assets/hero-wall.svg",
    alt: "",
    style: {
      position: "absolute",
      inset: 0,
      width: "100%",
      height: "100%"
    }
  }), /*#__PURE__*/React.createElement("img", {
    src: "assets/logo.svg",
    alt: "Voidwall",
    style: {
      position: "absolute",
      top: "0.5%",
      left: "57%",
      transform: "translateX(-50%)",
      height: 26,
      width: "auto",
      pointerEvents: "none"
    }
  }), [{
    label: "JSON",
    topPct: 170 / 520
  }, {
    label: "URL",
    topPct: 220 / 520
  }, {
    label: "CSV",
    topPct: 270 / 520
  }, {
    label: "TSV",
    topPct: 320 / 520
  }, {
    label: "Plain text",
    topPct: 370 / 520
  }].map(({
    label,
    topPct
  }) => /*#__PURE__*/React.createElement("div", {
    key: label,
    style: {
      position: "absolute",
      top: `${topPct * 100}%`,
      left: "1.5%",
      transform: "translateY(-50%)",
      pointerEvents: "none"
    }
  }, /*#__PURE__*/React.createElement(DataChip, {
    label: label
  }))), [{
    icon: "chart",
    label: "Web Analytics",
    topPct: 170 / 520
  }, {
    icon: "server",
    label: "CDPs",
    topPct: 220 / 520
  }, {
    icon: "globe",
    label: "Other third parties",
    topPct: 270 / 520
  }, {
    icon: "database",
    label: "Databases",
    topPct: 320 / 520
  }, {
    icon: "hard-drive",
    label: "Storage",
    topPct: 370 / 520
  }].map(({
    icon,
    label,
    topPct
  }) => /*#__PURE__*/React.createElement("div", {
    key: label,
    style: {
      position: "absolute",
      top: `${topPct * 100}%`,
      left: "78.3%",
      transform: "translateY(-50%)",
      pointerEvents: "none"
    }
  }, /*#__PURE__*/React.createElement(EnvItem, {
    icon: icon,
    label: label
  }))))));
}
function SpecCard({
  mark,
  name,
  tagline,
  details,
  params
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 12,
      background: "rgba(255,255,255,0.5)",
      padding: 22,
      display: "flex",
      flexDirection: "column",
      gap: 14
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 36,
      height: 36,
      borderRadius: 8,
      border: "1px solid var(--vw-paper-line)",
      background: "#fff",
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      fontFamily: "var(--vw-font-mono)",
      fontSize: 11,
      fontWeight: 600,
      letterSpacing: "0.02em",
      color: "var(--vw-paper-ink)"
    }
  }, mark), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 2
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 16,
      fontWeight: 600,
      color: "var(--vw-paper-ink)",
      letterSpacing: "-0.01em"
    }
  }, name), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 12,
      color: "var(--vw-paper-ink-3)"
    }
  }, tagline))), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 13.5,
      lineHeight: 1.55,
      color: "var(--vw-paper-ink-2)",
      margin: 0,
      textWrap: "pretty"
    }
  }, details), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: 6,
      marginTop: 2
    }
  }, params.map(p => /*#__PURE__*/React.createElement("span", {
    key: p,
    style: {
      fontFamily: "var(--vw-font-mono)",
      fontSize: 11,
      color: "var(--vw-paper-ink-2)",
      background: "var(--vw-paper-2)",
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 6,
      padding: "3px 7px"
    }
  }, p))));
}
function DataChip({
  label
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 8,
      fontFamily: "var(--vw-font-mono)",
      fontSize: 11.5,
      color: "var(--vw-paper-ink)",
      background: "rgba(255,255,255,0.75)",
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 6,
      padding: "6px 10px",
      alignSelf: "flex-start"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 6,
      height: 6,
      borderRadius: 999,
      background: "var(--vw-violet-400)"
    }
  }), label);
}
function RequestRow({
  method,
  path,
  payload
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 10,
      fontFamily: "var(--vw-font-mono)",
      fontSize: 11.5,
      color: "var(--vw-paper-ink-2)",
      background: "rgba(255,255,255,0.7)",
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 6,
      padding: "5px 9px",
      maxWidth: 260
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-500)",
      fontWeight: 600
    }
  }, method), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-paper-ink)"
    }
  }, path), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-paper-ink-3)"
    }
  }, "\xB7 "), payload.map(([k, v, sensitive], i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      color: "var(--vw-paper-ink-3)"
    }
  }, k, "=", /*#__PURE__*/React.createElement("span", {
    style: {
      color: sensitive ? "var(--vw-danger)" : "var(--vw-paper-ink-2)",
      textDecoration: sensitive ? "line-through" : "none",
      textDecorationColor: "var(--vw-danger)"
    }
  }, v))));
}
function EnvItem({
  icon,
  label
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 12,
      fontFamily: "var(--vw-font-body)",
      fontSize: 14,
      color: "var(--vw-paper-ink)",
      whiteSpace: "nowrap"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 32,
      height: 32,
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 8,
      background: "#fff",
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      color: "var(--vw-paper-ink)"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: icon,
    size: 16
  })), label);
}
window.Hero = Hero;

/* === 03-metrics.jsx === */
// Metrics strip - replaces "trusted by" since the product is pre-launch.
// Four key numbers presented as a horizontal hairline-divided row on a paper-2 band.
function Metrics() {
  const items = [["115", "", "PII types", "supported out of the box"], ["7", "", "Languages", "English, French, German, Dutch, Italian, Spanish, Polish"], ["15", "", "Countries", "USA, UK, France, Germany..."], ["2", "", "Specializations", "Google Analytics, Matomo"], ["5", "", "Formats", "JSON, URL, CSV, TSV, plain text"]];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--vw-paper-2)",
      borderTop: "1px solid var(--vw-paper-line)",
      borderBottom: "1px solid var(--vw-paper-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-container",
    style: {
      padding: "44px var(--gutter)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(5, 1fr)"
    }
  }, items.map(([n, suffix, label, sub], i) => /*#__PURE__*/React.createElement("div", {
    key: label,
    style: {
      padding: "0 28px",
      borderLeft: i === 0 ? "0" : "1px solid var(--vw-paper-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 56,
      fontWeight: 600,
      letterSpacing: "-0.03em",
      lineHeight: 1,
      color: "var(--vw-paper-ink)",
      marginBottom: 12,
      display: "flex",
      alignItems: "baseline"
    }
  }, n, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-400)"
    }
  }, suffix)), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 13,
      fontWeight: 500,
      color: "var(--vw-paper-ink)",
      marginBottom: 4
    }
  }, label), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 12,
      color: "var(--vw-paper-ink-3)"
    }
  }, sub))))));
}
window.Metrics = Metrics;

/* === 04-features.jsx === */
// Features - void surface, 4-up row separated by hairlines.
// Anchored on the four Voidwall verbs: Inspect → Enforce → Sanitize → Audit.
function Features() {
  const items = [["scan", "Scan", "Parse and scan every outgoing payload across JSON, CSV, TSV, and plain text.", "both"], ["redact", "Redact", "Replace detected PII with placeholders like [EMAIL], [US_SSN], [FR_NIR]...", "both"], ["mask", "Mask", "...or mask with configurable characters.", "both"], ["block", "Block", "Block the entire request if contains sensitive data.", "proxy"], ["alert", "Alert", "Warn when sensitive data leak is detected.", "proxy"]];
  return /*#__PURE__*/React.createElement("section", {
    id: "product",
    className: "vw-container",
    style: {
      padding: "96px var(--gutter) 60px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: 64,
      maxWidth: 720
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 48,
      fontWeight: 600,
      letterSpacing: "-0.025em",
      lineHeight: 1.02,
      color: "var(--vw-void-ink)",
      margin: 0,
      textWrap: "balance"
    }
  }, "What Voidwall does"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 16,
      lineHeight: 1.55,
      color: "var(--vw-void-ink-2)",
      margin: "20px 0 0",
      maxWidth: 600
    }
  }, "Run it two ways: inline as an ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: "var(--vw-void-ink)",
      fontWeight: 600
    }
  }, "HTTP proxy"), " that filters live traffic, or as a ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: "var(--vw-void-ink)",
      fontWeight: 600
    }
  }, "REST API"), " you call to scan and redact on demand. The tag on each card shows where it applies.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(5, 1fr)"
    }
  }, items.map(([icon, title, body, mode], i) => /*#__PURE__*/React.createElement("div", {
    key: title,
    style: {
      padding: "0 28px",
      borderLeft: i === 0 ? "0" : "1px solid var(--vw-void-line)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 44,
      height: 44,
      borderRadius: 10,
      border: "1px solid var(--vw-void-line)",
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      color: "var(--vw-violet-300)",
      marginBottom: 22
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: icon,
    size: 22
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      margin: "0 0 10px",
      flexWrap: "wrap"
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 19,
      fontWeight: 600,
      letterSpacing: "-0.015em",
      color: "var(--vw-void-ink)",
      margin: 0
    }
  }, title), /*#__PURE__*/React.createElement(ModeTag, {
    mode: mode
  })), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 14,
      lineHeight: 1.6,
      color: "var(--vw-void-ink-2)",
      margin: 0
    }
  }, body)))));
}
// Mode tag - marks whether a verb is available via both interfaces or proxy-only.
function ModeTag({
  mode
}) {
  const both = mode === "both";
  return /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      height: 18,
      padding: "0 7px",
      borderRadius: 999,
      fontFamily: "var(--vw-font-mono)",
      fontSize: 9.5,
      letterSpacing: "0.06em",
      textTransform: "uppercase",
      whiteSpace: "nowrap",
      color: "var(--vw-void-ink-2)",
      border: "1px solid var(--vw-void-ink-3)",
      background: "transparent"
    }
  }, both ? "Proxy + API" : "Proxy only");
}
window.Features = Features;

/* === 05-coverage.jsx === */
// Coverage - void surface. The breadth-of-detection story.
// 100+ PII types organized by category, plus languages + countries strip.
function Coverage() {
  const groups = [{
    title: "Identity & Contact",
    icon: "user",
    items: [["Person name", true], ["Email", true], ["Phone number", true], ["Date of birth", false], ["Geolocation", false], ["Postal address", false], ["Postcode / ZIP", false]]
  }, {
    title: "National IDs",
    icon: "flag",
    items: [["US - SSN", true], ["US - ITIN", false], ["GB - NI no.", false], ["IE - PPSN", false], ["CA - SIN", false], ["FR - NIR", true], ["FR - CNI", false], ["DE - Steuer-ID", true], ["DE - Personalausweis", false], ["AT - SVNR", false], ["CH - AHV", false], ["NL - BSN", true], ["IT - Codice Fiscale", true], ["ES - DNI", true], ["PL - PESEL", true]]
  }, {
    title: "Travel & Driving",
    icon: "globe-2",
    items: [["Passport", true], ["Driver's licence", true], ["US - Alien no.", false], ["US - USCIS receipt", false], ["VIN", false]]
  }, {
    title: "Health & Tax",
    icon: "audit",
    items: [["GB - NHS number", true], ["AU - Medicare", false], ["NZ - NHI", false], ["CA - OHIP", false], ["US - EIN", true], ["GB - UTR", false], ["AU - TFN", false], ["AU - ABN", false], ["FR - SIRET / SIREN", true], ["FR - NIF", false]]
  }, {
    title: "Financial & Crypto",
    icon: "credit-card",
    items: [["IBAN", true], ["Credit card", true], ["SWIFT / BIC", false], ["US - ABA routing", false], ["GB - Sort code", false], ["AU / CA - Bank account", false], ["Bitcoin", true], ["Ethereum", false]]
  }, {
    title: "Tech & Secrets",
    icon: "key",
    items: [["IPv4 / IPv6", true], ["MAC address", false], ["IMEI", false], ["AWS access key", true], ["AWS secret key", true], ["GitHub token", false]]
  }];
  const languages = [["EN", "English"], ["FR", "Français"], ["DE", "Deutsch"], ["NL", "Nederlands"], ["IT", "Italiano"], ["ES", "Español"], ["PL", "Polski"]];
  const countries = ["International", "United States", "Great Britain", "Australia", "New Zealand", "Canada", "Ireland", "South Africa", "France", "Germany", "Austria", "Switzerland", "Netherlands", "Italy", "Spain", "Poland"];
  return /*#__PURE__*/React.createElement("section", {
    id: "detection",
    className: "vw-container",
    style: {
      padding: "60px var(--gutter) 80px",
      borderTop: "1px solid var(--vw-void-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "minmax(0, 0.7fr) minmax(0, 1.3fr)",
      gap: 80,
      alignItems: "start"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "sticky",
      top: 100
    }
  }, /*#__PURE__*/React.createElement("p", {
    className: "vw-eyebrow",
    style: {
      margin: "0 0 18px"
    }
  }, "Detection coverage"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 44,
      fontWeight: 600,
      letterSpacing: "-0.025em",
      lineHeight: 1.02,
      color: "var(--vw-void-ink)",
      margin: "0 0 22px",
      textWrap: "balance"
    }
  }, "115 PII types.", /*#__PURE__*/React.createElement("br", null), "And growing."), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 15.5,
      lineHeight: 1.6,
      color: "var(--vw-void-ink-2)",
      margin: "0 0 28px",
      maxWidth: 400
    }
  }, "Voidwall is able to detect PII using pattern recognition, contextual analysis and validation, so it warns about real values, not just looks-like ones. Here are examples of what can be detected.", /*#__PURE__*/React.createElement("br", null), /*#__PURE__*/React.createElement("br", null), "Custom types can be added via configuration file."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 12,
      marginBottom: 28
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "vw-eyebrow vw-eyebrow--muted"
  }, "Languages"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, max-content)",
      gap: 8
    }
  }, languages.map(([code, name]) => /*#__PURE__*/React.createElement("div", {
    key: code,
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 8,
      padding: "8px 12px",
      border: "1px solid var(--vw-void-line)",
      borderRadius: 8,
      fontFamily: "var(--vw-font-mono)",
      fontSize: 12,
      color: "var(--vw-void-ink)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-300)",
      fontWeight: 600
    }
  }, code), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-void-ink-3)"
    }
  }, name)))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 4,
      height: 26,
      padding: "0 10px",
      borderRadius: 999,
      fontFamily: "var(--vw-font-body)",
      fontSize: 12,
      color: "var(--vw-violet-300)"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "plus",
    size: 12
  }), " more soon"))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "vw-eyebrow vw-eyebrow--muted"
  }, "Countries"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: 6
    }
  }, countries.map(c => /*#__PURE__*/React.createElement("span", {
    key: c,
    style: {
      display: "inline-flex",
      alignItems: "center",
      height: 26,
      padding: "0 10px",
      border: "1px solid var(--vw-void-line)",
      borderRadius: 999,
      fontFamily: "var(--vw-font-body)",
      fontSize: 12,
      color: "var(--vw-void-ink-2)",
      whiteSpace: "nowrap"
    }
  }, c)), /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 4,
      height: 26,
      padding: "0 10px",
      borderRadius: 999,
      fontFamily: "var(--vw-font-body)",
      fontSize: 12,
      color: "var(--vw-violet-300)"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "plus",
    size: 12
  }), " more soon")))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(2, 1fr)",
      gap: 16
    }
  }, groups.map(g => /*#__PURE__*/React.createElement("div", {
    key: g.title,
    style: {
      background: "var(--vw-void-2)",
      border: "1px solid var(--vw-void-line)",
      borderRadius: 14,
      padding: "20px 22px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      marginBottom: 18
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-300)",
      display: "inline-flex"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: g.icon,
    size: 18
  })), /*#__PURE__*/React.createElement("h4", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 14,
      fontWeight: 600,
      letterSpacing: "0.02em",
      textTransform: "uppercase",
      color: "var(--vw-void-ink)",
      margin: 0
    }
  }, g.title)), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: 6
    }
  }, g.items.map(([label, hot]) => /*#__PURE__*/React.createElement("span", {
    key: label,
    style: {
      display: "inline-flex",
      alignItems: "center",
      height: 28,
      padding: "0 11px",
      border: `1px solid ${hot ? "var(--vw-violet-400)" : "var(--vw-void-line)"}`,
      borderRadius: 8,
      fontFamily: "var(--vw-font-body)",
      fontSize: 12.5,
      color: hot ? "var(--vw-violet-200)" : "var(--vw-void-ink-2)",
      background: hot ? "rgba(139,125,246,0.08)" : "transparent",
      whiteSpace: "nowrap"
    }
  }, label))))))));
}
window.Coverage = Coverage;

/* === 06-analytics.jsx === */
// Analytics - void surface. GA4 + Matomo real-time scanning.
// Shows the same tracking event in raw vs. sanitized form, for each platform.
function Analytics() {
  return /*#__PURE__*/React.createElement("section", {
    id: "specializations",
    className: "vw-container",
    style: {
      padding: "80px var(--gutter) 80px",
      borderTop: "1px solid var(--vw-void-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-section-head",
    style: {
      marginBottom: 56
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("p", {
    className: "vw-eyebrow",
    style: {
      margin: "0 0 18px"
    }
  }, "Analytics, sanitized"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 44,
      fontWeight: 600,
      letterSpacing: "-0.025em",
      lineHeight: 1.02,
      color: "var(--vw-void-ink)",
      margin: 0,
      textWrap: "balance"
    }
  }, "Scan GA4 and Matomo", /*#__PURE__*/React.createElement("br", null), "traffic in real time.")), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 16,
      lineHeight: 1.55,
      color: "var(--vw-void-ink-2)",
      margin: 0,
      maxWidth: 460
    }
  }, "Front-end tracking is the leakiest path out of a product - marketing teams add events, users paste their PII to search bars, and personal data slips into Google or Matomo unnoticed. Even 20% of websites have this problem. Voidwall may be a proxy between your product and web analytics, preventing your users' personal data from leaking out.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr",
      gap: 24
    }
  }, /*#__PURE__*/React.createElement(PlatformCard, {
    name: "Google Analytics 4",
    endpoint: "POST  /g/collect",
    tag: "ga4"
  }), /*#__PURE__*/React.createElement(PlatformCard, {
    name: "Matomo",
    endpoint: "POST  /matomo.php",
    tag: "matomo"
  })), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 16,
      lineHeight: 1.55,
      color: "var(--vw-void-ink-2)",
      margin: "32px 0 0",
      maxWidth: 1120
    }
  }, "Specializations know what to scan - catching sensitive data even inside doubly-encoded payloads. They also know what ", /*#__PURE__*/React.createElement("em", null, "not"), " to scan, so the integration keeps working as intended."));
}
function PlatformCard({
  name,
  endpoint,
  tag
}) {
  const ga4Raw = [['v', '2'], ['tid', 'G-X8Q1ZRP7M2'], ['cid', '1822941715.1719583924'], ['dl', 'https://shop.acme.io/u/alex.miller@acme.io', true], ['dt', 'Order #4711 - alex.miller@acme.io', true], ['en', 'login'], ['ep.contact_phone', '+33 6 12 34 56 78', true], ['uid', 'alex.miller@acme.io', true], ['_uip', '203.0.113.42', true]];
  const ga4San = [['v', '2'], ['tid', 'G-X8Q1ZRP7M2'], ['cid', '1822941715.1719583924'], ['dl', 'https://shop.acme.io/u/[EMAIL]'], ['dt', 'Order #4711 - [EMAIL]'], ['en', 'login'], ['ep.contact_phone', '[FR_PHONE_NUMBER]'], ['uid', 'alex.miller@acme.io', false, 'by design'], ['_uip', '203.0.113.42', false, 'by design']];
  const matomoRaw = [['idsite', '17'], ['rec', '1'], ['url', 'https://shop.acme.de/?email=klaus.weber@example.de', true], ['action_name', 'Login · Acme'], ['dimension2', 'klaus.weber@example.de', true], ['_cvar', '{"1":["email","klaus.weber@example.de"]}', true], ['_id', '8b3f1a92ee44c1d2'], ['uid', 'klaus.weber@example.de', true], ['cip', '94.245.66.10', true]];
  const matomoSan = [['idsite', '17'], ['rec', '1'], ['url', 'https://shop.acme.de/?email=[EMAIL]'], ['action_name', 'Login · Acme'], ['dimension2', '[EMAIL]'], ['_cvar', '{"1":["email","[EMAIL]"]}'], ['_id', '8b3f1a92ee44c1d2'], ['uid', 'klaus.weber@example.de', false, 'by design'], ['cip', '94.245.66.10', false, 'by design']];
  const raw = tag === "ga4" ? ga4Raw : matomoRaw;
  const san = tag === "ga4" ? ga4San : matomoSan;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--vw-void-2)",
      border: "1px solid var(--vw-void-line)",
      borderRadius: 14,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "16px 20px",
      borderBottom: "1px solid var(--vw-void-line)",
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-300)",
      display: "inline-flex"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "activity",
    size: 18
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 15,
      fontWeight: 600,
      color: "var(--vw-void-ink)"
    }
  }, name)), /*#__PURE__*/React.createElement("code", {
    style: {
      fontFamily: "var(--vw-font-mono)",
      fontSize: 11.5,
      color: "var(--vw-void-ink-3)"
    }
  }, endpoint)), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr"
    }
  }, /*#__PURE__*/React.createElement(ParamColumn, {
    label: "Received",
    rows: raw
  }), /*#__PURE__*/React.createElement(ParamColumn, {
    label: "Forwarded",
    rows: san,
    sanitized: true
  })));
}
function ParamColumn({
  label,
  rows,
  sanitized
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "18px 20px",
      borderRight: sanitized ? "0" : "1px solid var(--vw-void-line)",
      background: sanitized ? "rgba(139,125,246,0.04)" : "transparent"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      marginBottom: 14,
      fontFamily: "var(--vw-font-body)",
      fontSize: 10.5,
      letterSpacing: "0.14em",
      textTransform: "uppercase",
      color: sanitized ? "var(--vw-violet-300)" : "var(--vw-void-ink-3)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 6,
      height: 6,
      borderRadius: 999,
      background: sanitized ? "var(--vw-violet-400)" : "var(--vw-danger)"
    }
  }), label), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "auto 1fr",
      rowGap: 6,
      columnGap: 12,
      fontFamily: "var(--vw-font-mono)",
      fontSize: 12
    }
  }, rows.map(([k, v, hot, tag], i) => /*#__PURE__*/React.createElement(React.Fragment, {
    key: i
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-void-ink-3)"
    }
  }, k), /*#__PURE__*/React.createElement("span", {
    style: {
      color: hot ? "var(--vw-danger)" : "var(--vw-void-ink)",
      wordBreak: "break-all"
    }
  }, v, tag && /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: 6,
      fontFamily: "var(--vw-font-body)",
      fontSize: 10,
      letterSpacing: "0.06em",
      textTransform: "uppercase",
      color: "var(--vw-success)",
      border: "1px solid rgba(56,178,122,0.4)",
      borderRadius: 3,
      padding: "0 5px"
    }
  }, tag))))));
}
window.Analytics = Analytics;

/* === 07-formats.jsx === */
// Formats - void surface. Tabbed code pane: JSON / CSV / TSV / URL / plain text.
// React state drives the active tab.
function Formats() {
  const [tab, setTab] = React.useState("json");
  const samples = {
    json: {
      label: "JSON",
      icon: "file-json",
      before: `{
  "order_id": "A-2186",
  "customer": {
    "full_name": { "value": "Sarah Dupont" },
    "phone_number": { "primary": "+33 6 12 34 56 78" },
    "national_id": { "nir": "1 85 05 78 006 084 91" }
  },
  "billing": {
    "iban": { "formatted": "FR76 3000 6000 0112 3456 7890 189" }
  }
}`,
      after: `{
  "order_id": "A-2186",
  "customer": {
    "full_name": { "value": "[PERSON_NAME]" },
    "phone_number": { "primary": "[PHONE_NUMBER]" },
    "national_id": { "nir": "[FR_NIR]" }
  },
  "billing": {
    "iban": { "formatted": "[IBAN]" }
  }
}`
    },
    csv: {
      label: "CSV",
      icon: "table",
      before: `order_id,customer_name,email,phone,iban
A-2186,Sarah Dupont,s.dupont@acme.fr,+33 6 12 34 56 78,FR76 3000 6000 0112 3456 7890 189
A-2187,Klaus Weber,klaus.w@example.de,+49 30 9876 5432,DE89 3704 0044 0532 0130 00
A-2188,Lisa Müller,lisa.m@example.ch,+41 79 123 45 67,CH93 0076 2011 6238 5295 7`,
      after: `order_id,customer_name,email,phone,iban
A-2186,[PERSON_NAME],[EMAIL],[PHONE_NUMBER],[IBAN]
A-2187,[PERSON_NAME],[EMAIL],[PHONE_NUMBER],[IBAN]
A-2188,[PERSON_NAME],[EMAIL],[CH_PHONE_NUMBER],[IBAN]`
    },
    tsv: {
      label: "TSV",
      icon: "table",
      before: `event_id\tuser_id\temail\tip\tquery
e_4471\t1822\talex@acme.io\t203.0.113.42\thotels in Berlin
e_4472\t1923\tklaus.weber@example.de\t94.245.66.10\tIdNr 65929970489
e_4473\t1924\tm.weber@example.at\t82.85.10.5\tSVNR 1238150185`,
      after: `event_id\tuser_id\temail\tip\tquery
e_4471\t1822\t[EMAIL]\t[IP_ADDRESS]\thotels in Berlin
e_4472\t1923\t[EMAIL]\t[IP_ADDRESS]\tIdNr [DE_STEUER_ID]
e_4473\t1924\t[EMAIL]\t[IP_ADDRESS]\tSVNR [AT_SVNR]`
    },
    url: {
      label: "URL",
      icon: "link",
      before: `GET /api/users/s.dupont@acme.fr/profile
GET /lookup?ssn=123-45-6789&card=4111111111111111
POST /track?uid=alex@acme.io&phone_number=555-123-4567
GET /search?user[first_name]=Sarah&user[last_name]=Dupont
GET /eth/0x1234567890abcdef1234567890abcdef12345678/balance`,
      after: `GET /api/users/[EMAIL]/profile
GET /lookup?ssn=[US_SSN]&card=[CREDIT_CARD]
POST /track?uid=[EMAIL]&phone_number=[US_PHONE_NUMBER]
GET /search?user[first_name]=Sarah&user[last_name]=[PERSON_NAME]
GET /eth/[ETHEREUM_ADDRESS]/balance`
    },
    text: {
      label: "Plain text",
      icon: "text",
      before: `Hi support,

I never received my order A-2186. My email on the account is
s.dupont@acme.fr and my phone is +33 6 12 34 56 78. I paid with
my Visa 4539 1488 0343 6467 on the 14th. Please check.

Thanks!`,
      after: `Hi support,

I never received my order A-2186. My email on the account is
[EMAIL] and my phone is [PHONE_NUMBER]. I paid with
my Visa [CREDIT_CARD] on the 14th. Please check.

Thanks!`
    }
  };
  const current = samples[tab];
  return /*#__PURE__*/React.createElement("section", {
    id: "formats",
    className: "vw-container",
    style: {
      padding: "60px var(--gutter) 80px",
      borderTop: "1px solid var(--vw-void-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-section-head",
    style: {
      marginBottom: 40
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("p", {
    className: "vw-eyebrow",
    style: {
      margin: "0 0 18px"
    }
  }, "Format-aware"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 44,
      fontWeight: 600,
      letterSpacing: "-0.025em",
      lineHeight: 1.02,
      color: "var(--vw-void-ink)",
      margin: 0,
      textWrap: "balance"
    }
  }, "Works well even with nested data.")), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 16,
      lineHeight: 1.55,
      color: "var(--vw-void-ink-2)",
      margin: 0,
      maxWidth: 460
    }
  }, "Voidwall parses the request before it scans it. Whether the payload is a nested JSON, a flat CSV, a tab-separated data, a URL packed with query parameters, or free-form text, the same matchers apply.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 4,
      marginBottom: 16,
      borderBottom: "1px solid var(--vw-void-line)"
    }
  }, Object.entries(samples).map(([key, s]) => {
    const active = tab === key;
    return /*#__PURE__*/React.createElement("button", {
      key: key,
      onClick: () => setTab(key),
      style: {
        appearance: "none",
        background: "transparent",
        cursor: "pointer",
        border: 0,
        padding: "12px 18px",
        borderBottom: `2px solid ${active ? "var(--vw-violet-400)" : "transparent"}`,
        marginBottom: -1,
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        fontFamily: "var(--vw-font-body)",
        fontSize: 13.5,
        fontWeight: 500,
        color: active ? "var(--vw-void-ink)" : "var(--vw-void-ink-2)",
        transition: "color .18s var(--vw-ease-out), border-color .18s var(--vw-ease-out)"
      }
    }, /*#__PURE__*/React.createElement(Icon, {
      name: s.icon,
      size: 16
    }), " ", s.label);
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 0,
      background: "var(--vw-void-2)",
      border: "1px solid var(--vw-void-line)",
      borderRadius: 14,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement(CodePane, {
    title: "Inbound",
    payload: current.before,
    bad: true
  }), /*#__PURE__*/React.createElement(CodePane, {
    title: "Outbound",
    payload: current.after
  })));
}
function CodePane({
  title,
  payload,
  bad
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      borderRight: bad ? "1px solid var(--vw-void-line)" : "0",
      background: bad ? "transparent" : "rgba(139,125,246,0.04)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "12px 18px",
      borderBottom: "1px solid var(--vw-void-line)",
      fontFamily: "var(--vw-font-body)",
      fontSize: 11,
      letterSpacing: "0.14em",
      textTransform: "uppercase",
      color: bad ? "var(--vw-void-ink-3)" : "var(--vw-violet-300)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 6,
      height: 6,
      borderRadius: 999,
      background: bad ? "var(--vw-danger)" : "var(--vw-violet-400)"
    }
  }), title), /*#__PURE__*/React.createElement("pre", {
    style: {
      margin: 0,
      padding: "18px 20px",
      fontFamily: "var(--vw-font-mono)",
      fontSize: 12.5,
      lineHeight: 1.6,
      color: "var(--vw-void-ink)",
      whiteSpace: "pre",
      overflow: "auto",
      minHeight: 260
    }
  }, highlight(payload, bad)));
}

// Crude highlighter - wraps sensitive runs in red, placeholders in violet.
// Longer literals must come before substrings (e.g. "Sarah Dupont" before "Sarah")
// so the alternation picks the wider match at any given position.
function highlight(text, bad) {
  if (bad) {
    const re = /(Sarah Dupont|s\.dupont@acme\.fr|\+33 6 12 34 56 78|1 85 05 78 006 084 91|FR76 3000 6000 0112 3456 7890 189|12 rue de Belleville, 75011 Paris|Klaus Weber|klaus\.w@example\.de|klaus\.weber@example\.de|\+49 30 9876 5432|DE89 3704 0044 0532 0130 00|Lisa Müller|lisa\.m@example\.ch|\+41 79 123 45 67|CH93 0076 2011 6238 5295 7|alex@acme\.io|203\.0\.113\.42|94\.245\.66\.10|m\.weber@example\.at|82\.85\.10\.5|65929970489|1238150185|4539 1488 0343 6467|123-45-6789|4111111111111111|555-123-4567|0x1234567890abcdef1234567890abcdef12345678|Dupont)/g;
    return splitWith(text, re, (m, i) => /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        color: "var(--vw-danger)",
        background: "rgba(229,86,75,0.12)",
        borderRadius: 3
      }
    }, m));
  } else {
    // Matches the proxy's TypeLabel redaction format: [SCREAMING_SNAKE_CASE].
    const re = /\[[A-Z][A-Z_]*\]/g;
    return splitWith(text, re, (m, i) => /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        color: "var(--vw-violet-300)"
      }
    }, m));
  }
}
function splitWith(text, regex, wrap) {
  const out = [];
  let last = 0;
  let m;
  let i = 0;
  regex.lastIndex = 0;
  while ((m = regex.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(wrap(m[0], i++));
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}
window.Formats = Formats;

/* === 09-performance.jsx === */
// Performance - paper-band section. Highlights latency, throughput, and cost.
// Numbers are illustrative (no benchmarks shipped yet); keep them measured and lower-case.
function Performance() {
  return /*#__PURE__*/React.createElement("section", {
    id: "performance",
    style: {
      background: "var(--vw-paper)",
      borderTop: "1px solid var(--vw-void-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-container",
    style: {
      padding: "96px var(--gutter)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "minmax(0, 0.9fr) minmax(0, 1.1fr)",
      gap: 64,
      alignItems: "end",
      marginBottom: 64
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("p", {
    className: "vw-eyebrow",
    style: {
      margin: "0 0 18px",
      color: "var(--vw-violet-500)"
    }
  }, "Performance"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 44,
      fontWeight: 600,
      letterSpacing: "-0.025em",
      lineHeight: 1.02,
      color: "var(--vw-paper-ink)",
      margin: 0,
      textWrap: "balance"
    }
  }, "Built for the", /*#__PURE__*/React.createElement("br", null), "edge of your stack.")), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 16,
      lineHeight: 1.55,
      color: "var(--vw-paper-ink-2)",
      margin: 0,
      maxWidth: 460
    }
  }, "Voidwall scales horizontally, runs in your cluster, and adds a budget you can measure in single-digit milliseconds. It's designed to be a lightweight, self-hosted service that doesn't break the bank as you grow.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: 24
    }
  }, /*#__PURE__*/React.createElement(PerfCard, {
    icon: "gauge",
    eyebrow: "Latency (p99)",
    big: "9.2",
    unit: "ms",
    sub: "added per request, payload size 10 KiB",
    chart: /*#__PURE__*/React.createElement(Bars, {
      values: [2.6, 3.9, 5.3, 9.2],
      labels: ["p50", "p75", "p95", "p99"]
    })
  }), /*#__PURE__*/React.createElement(PerfCard, {
    icon: "trend-up",
    eyebrow: "Request rate",
    big: "32k",
    unit: "req/s",
    sub: "single container, 6 logical cores, 10 KiB payload",
    chart: /*#__PURE__*/React.createElement(Bars, {
      values: [13, 22, 26, 32],
      labels: ["1c", "2c", "4c", "6c"]
    })
  }), /*#__PURE__*/React.createElement(PerfCard, {
    icon: "ram",
    eyebrow: "Memory usage max",
    big: "214",
    unit: "MiB",
    sub: "single container, 6 logical cores, 10 KiB payload"
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 56,
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: 0
    }
  }, [["scaling", "Horizontal scaling", "Stateless by design. No shared database, no coordination between containers, no dependencies to provision first."], ["server", "Ships as a single container", "Pull the image and go. Runs entirely in your environment. No payloads leave your infrastructure."], ["code", "Proxy or API - your call", "Drop it inline as a reverse or forward proxy, or call the HTTP API to scan and redact on demand. Same engine, three ways to plug in."]].map(([icon, title, body], i) => /*#__PURE__*/React.createElement("div", {
    key: title,
    style: {
      padding: "0 28px",
      borderLeft: i === 0 ? "0" : "1px solid var(--vw-paper-line)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 36,
      height: 36,
      borderRadius: 8,
      border: "1px solid var(--vw-paper-line)",
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      color: "var(--vw-paper-ink)",
      marginBottom: 16,
      background: "#fff"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: icon,
    size: 18
  })), /*#__PURE__*/React.createElement("h4", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 17,
      fontWeight: 600,
      letterSpacing: "-0.01em",
      color: "var(--vw-paper-ink)",
      margin: "0 0 8px"
    }
  }, title), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 14,
      lineHeight: 1.55,
      color: "var(--vw-paper-ink-2)",
      margin: 0
    }
  }, body))))));
}
function PerfCard({
  icon,
  eyebrow,
  big,
  unit,
  sub,
  chart
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: "#fff",
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 14,
      padding: "24px 24px 22px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      marginBottom: 22
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 11,
      letterSpacing: "0.14em",
      textTransform: "uppercase",
      color: "var(--vw-paper-ink-3)"
    }
  }, eyebrow), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-paper-ink-3)"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: icon,
    size: 16
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      gap: 6,
      fontFamily: "var(--vw-font-display)",
      fontSize: 56,
      fontWeight: 600,
      letterSpacing: "-0.03em",
      lineHeight: 1,
      color: "var(--vw-paper-ink)",
      marginBottom: 8
    }
  }, big, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 14,
      fontWeight: 500,
      letterSpacing: 0,
      color: "var(--vw-paper-ink-2)"
    }
  }, unit)), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 13,
      lineHeight: 1.5,
      color: "var(--vw-paper-ink-2)",
      margin: "0 0 18px"
    }
  }, sub), chart);
}
function Bars({
  values,
  labels
}) {
  const max = Math.max(...values);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "flex-end",
      gap: 10,
      height: 60,
      marginTop: 4
    }
  }, values.map((v, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      flex: 1,
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      height: `${v / max * 50}px`,
      background: i === values.length - 1 ? "var(--vw-violet-400)" : "var(--vw-paper-ink)",
      borderRadius: 3,
      minHeight: 6
    },
    title: values[i]
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-mono)",
      fontSize: 10,
      color: "var(--vw-paper-ink-3)"
    }
  }, labels[i]))));
}
function CostBars() {
  // Comparative: hosted DLP, self-hosted DLP-other, Voidwall.
  const rows = [["Hosted DLP API", 100, "var(--vw-paper-ink)"], ["Voidwall", 0.7, "var(--vw-violet-400)"]];
  const max = 100;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 10,
      marginTop: 4
    }
  }, rows.map(([label, v, color]) => /*#__PURE__*/React.createElement("div", {
    key: label
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      justifyContent: "space-between",
      fontFamily: "var(--vw-font-body)",
      fontSize: 11,
      color: "var(--vw-paper-ink-2)",
      marginBottom: 4
    }
  }, /*#__PURE__*/React.createElement("span", null, label), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-mono)"
    }
  }, v < 1 ? `${v}¢` : `$${(v / 100).toFixed(2)}`)), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 6,
      background: "var(--vw-paper-2)",
      borderRadius: 3,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: `${Math.max(v / max * 100, 1.2)}%`,
      height: "100%",
      background: color
    }
  })))));
}
window.Performance = Performance;

/* === 10-blog.jsx === */
// Blog - paper surface. Three teaser cards + link to the index.
// Posts come from window.POSTS (generated from src/blog/posts/*.md by build.sh).
function Blog() {
  const posts = (window.POSTS || []).slice(0, 3);
  return /*#__PURE__*/React.createElement("section", {
    id: "blog",
    style: {
      background: "var(--vw-paper)",
      borderTop: "1px solid var(--vw-paper-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-container",
    style: {
      padding: "96px var(--gutter)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "end",
      justifyContent: "space-between",
      marginBottom: 56,
      gap: 32
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("p", {
    className: "vw-eyebrow",
    style: {
      margin: "0 0 18px",
      color: "var(--vw-violet-500)"
    }
  }, "From the blog"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 44,
      fontWeight: 600,
      letterSpacing: "-0.025em",
      lineHeight: 1.02,
      color: "var(--vw-paper-ink)",
      margin: 0,
      textWrap: "balance",
      maxWidth: 560
    }
  }, "Notes from the wall.")), /*#__PURE__*/React.createElement("a", {
    href: "/blog/",
    className: "vw-btn vw-btn--ghost"
  }, "All posts ", /*#__PURE__*/React.createElement("span", {
    className: "arrow"
  }, "\u2192"))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: 24
    }
  }, posts.map((p, i) => /*#__PURE__*/React.createElement(PostCard, _extends({
    key: i
  }, p))))));
}
function PostCard({
  slug,
  tag,
  date,
  title,
  excerpt,
  read
}) {
  return /*#__PURE__*/React.createElement("a", {
    href: `/blog/${slug}/`,
    style: {
      display: "flex",
      flexDirection: "column",
      background: "#fff",
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 14,
      padding: 28,
      textDecoration: "none",
      transition: "box-shadow .18s var(--vw-ease-out), transform .18s var(--vw-ease-out)"
    },
    onMouseEnter: e => {
      e.currentTarget.style.boxShadow = "0 6px 18px -6px rgba(10,14,26,0.18)";
    },
    onMouseLeave: e => {
      e.currentTarget.style.boxShadow = "none";
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      marginBottom: 28
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      height: 22,
      padding: "0 9px",
      fontFamily: "var(--vw-font-body)",
      fontSize: 11,
      letterSpacing: "0.12em",
      textTransform: "uppercase",
      color: "var(--vw-violet-500)",
      background: "rgba(139,125,246,0.12)",
      borderRadius: 4
    }
  }, tag), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-mono)",
      fontSize: 11.5,
      color: "var(--vw-paper-ink-3)"
    }
  }, date)), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 22,
      fontWeight: 600,
      letterSpacing: "-0.02em",
      lineHeight: 1.18,
      color: "var(--vw-paper-ink)",
      margin: "0 0 14px",
      textWrap: "balance",
      minHeight: 78
    }
  }, title), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 14,
      lineHeight: 1.55,
      color: "var(--vw-paper-ink-2)",
      margin: "0 0 28px",
      textWrap: "pretty"
    }
  }, excerpt), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "auto",
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      fontFamily: "var(--vw-font-body)",
      fontSize: 13
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-paper-ink-3)"
    }
  }, read), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-500)",
      display: "inline-flex",
      alignItems: "center",
      gap: 6
    }
  }, "Read ", /*#__PURE__*/React.createElement(Icon, {
    name: "arrow-right",
    size: 14
  }))));
}
window.Blog = Blog;
window.PostCard = PostCard;

/* === 11-cta.jsx === */
// CTA - void surface. Subscription for for early access, embedded from MailerLite.
function CTA() {
  return /*#__PURE__*/React.createElement("section", {
    id: "early-adopters",
    style: {
      background: "var(--vw-void)",
      color: "var(--vw-void-ink)",
      borderTop: "1px solid var(--vw-void-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-container",
    style: {
      padding: "120px var(--gutter)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    class: "ml-embedded",
    "data-form": "GUKjOD"
  })));
}
window.CTA = CTA;

/* === 12-footer.jsx === */
// Footer - void surface. Logo and copyright only.
function Footer() {
  return /*#__PURE__*/React.createElement("footer", {
    style: {
      background: "var(--vw-void)",
      color: "var(--vw-void-ink)",
      borderTop: "1px solid var(--vw-void-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-container",
    style: {
      padding: "32px var(--gutter)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      gap: 16,
      fontFamily: "var(--vw-font-body)",
      fontSize: 12.5,
      color: "var(--vw-void-ink-3)",
      flexWrap: "wrap"
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "/",
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 10,
      color: "var(--vw-violet-300)",
      textDecoration: "none"
    }
  }, /*#__PURE__*/React.createElement("img", {
    src: vwAsset("logo-mark-light.svg"),
    width: "24",
    height: "24",
    alt: ""
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontWeight: 500,
      letterSpacing: "0.14em",
      fontSize: 15,
      color: "var(--vw-void-ink)"
    }
  }, "VOIDWALL")), /*#__PURE__*/React.createElement("span", null, "\xA9 2026 Voidwall"))));
}
window.Footer = Footer;

/* === 13-blog-index.jsx === */
// Blog index - paper surface. Full list of every post, reusing PostCard.
// Rendered at /blog/ (see the router in 15-app.jsx). Posts come from
// window.POSTS (generated from src/blog/posts/*.md by build.sh).
function BlogIndex() {
  const posts = window.POSTS || [];
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(Nav, null), /*#__PURE__*/React.createElement("main", {
    style: {
      background: "var(--vw-paper)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-container",
    style: {
      padding: "96px var(--gutter)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: 56,
      maxWidth: 720
    }
  }, /*#__PURE__*/React.createElement("p", {
    className: "vw-eyebrow",
    style: {
      margin: "0 0 18px",
      color: "var(--vw-violet-500)"
    }
  }, "Blog"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 56,
      fontWeight: 600,
      letterSpacing: "-0.025em",
      lineHeight: 1.02,
      color: "var(--vw-paper-ink)",
      margin: "0 0 20px",
      textWrap: "balance"
    }
  }, "Notes from the wall."), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 17,
      lineHeight: 1.55,
      color: "var(--vw-paper-ink-2)",
      margin: 0,
      textWrap: "pretty"
    }
  }, "Engineering notes, detection deep-dives, and what we learn watching personal data move through real systems.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: 24
    }
  }, posts.map((p, i) => /*#__PURE__*/React.createElement(PostCard, _extends({
    key: i
  }, p)))))), /*#__PURE__*/React.createElement(Footer, null));
}
window.BlogIndex = BlogIndex;

/* === 14-blog-post.jsx === */
// Single blog post - paper surface, narrow reading column. Rendered at
// /blog/<slug>/ (see the router in 15-app.jsx). The post body is pre-rendered
// HTML (markdown → HTML at build time) injected into a .vw-prose container.
function BlogPost({
  slug
}) {
  const post = (window.POSTS || []).find(p => p.slug === slug);
  if (!post) {
    return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(Nav, null), /*#__PURE__*/React.createElement("main", {
      style: {
        background: "var(--vw-paper)"
      }
    }, /*#__PURE__*/React.createElement("div", {
      className: "vw-container",
      style: {
        padding: "120px var(--gutter)",
        textAlign: "center"
      }
    }, /*#__PURE__*/React.createElement("h1", {
      style: {
        fontFamily: "var(--vw-font-display)",
        fontSize: 40,
        fontWeight: 600,
        color: "var(--vw-paper-ink)",
        margin: "0 0 16px"
      }
    }, "Post not found."), /*#__PURE__*/React.createElement("a", {
      href: "/blog/",
      className: "vw-btn vw-btn--ghost"
    }, /*#__PURE__*/React.createElement("span", {
      className: "arrow"
    }, "\u2190"), " All posts"))), /*#__PURE__*/React.createElement(Footer, null));
  }
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(Nav, null), /*#__PURE__*/React.createElement("main", {
    style: {
      background: "var(--vw-paper)"
    }
  }, /*#__PURE__*/React.createElement("article", {
    className: "vw-container",
    style: {
      maxWidth: 760,
      padding: "80px var(--gutter) 96px"
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "/blog/",
    className: "vw-btn vw-btn--ghost",
    style: {
      marginBottom: 40
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "arrow"
  }, "\u2190"), " All posts"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      marginBottom: 24
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      height: 22,
      padding: "0 9px",
      fontFamily: "var(--vw-font-body)",
      fontSize: 11,
      letterSpacing: "0.12em",
      textTransform: "uppercase",
      color: "var(--vw-violet-500)",
      background: "rgba(139,125,246,0.12)",
      borderRadius: 4
    }
  }, post.tag), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-mono)",
      fontSize: 11.5,
      color: "var(--vw-paper-ink-3)"
    }
  }, post.date), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 13,
      color: "var(--vw-paper-ink-3)"
    }
  }, "\xB7 ", post.read)), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 46,
      fontWeight: 600,
      letterSpacing: "-0.025em",
      lineHeight: 1.04,
      color: "var(--vw-paper-ink)",
      margin: "0 0 40px",
      textWrap: "balance"
    }
  }, post.title), /*#__PURE__*/React.createElement("div", {
    className: "vw-prose",
    dangerouslySetInnerHTML: {
      __html: post.html
    }
  }))), /*#__PURE__*/React.createElement(Footer, null));
}
window.BlogPost = BlogPost;

/* === 15-app.jsx === */
// Entry point - renders the landing page. The original standalone export
// used a Tweaks editor panel; the production build renders the components
// directly with a fixed headline variant.
function App() {
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(Nav, null), /*#__PURE__*/React.createElement(Hero, null), /*#__PURE__*/React.createElement(Metrics, null), /*#__PURE__*/React.createElement("div", {
    className: "void-band vw-void"
  }, /*#__PURE__*/React.createElement(Features, null), /*#__PURE__*/React.createElement(Coverage, null), /*#__PURE__*/React.createElement(Analytics, null), /*#__PURE__*/React.createElement(Formats, null)), /*#__PURE__*/React.createElement(Performance, null), /*#__PURE__*/React.createElement(Blog, null), /*#__PURE__*/React.createElement(CTA, null), /*#__PURE__*/React.createElement(Footer, null));
}

// Path-based router. Each route is pre-rendered to its own index.html by
// build.sh, so this only has to pick the view for the current page.
//
// We can't trust location.pathname directly: opened from disk (file://) it's an
// absolute filesystem path, not the site path. Instead we reconstruct the
// site-relative path from the page depth - the number of "../" in the asset
// base (set in 00-base.jsx) tells us how many trailing path segments belong to
// the site. That gives the same answer whether served or opened locally.
function Root() {
  const base = window.__VW_BASE__;
  const raw = window.location.pathname.replace(/\/index\.html$/, "/");
  let path;
  if (base.startsWith("/")) {
    // Absolute base (build-time render, or served from the site root):
    // location.pathname already is the site path.
    path = raw;
  } else {
    // Relative base (runtime, including file://): keep only the trailing
    // segments that belong to the site, one per "../" in the base.
    const depth = (base.match(/\.\.\//g) || []).length;
    const segs = raw.split("/").filter(Boolean);
    path = "/" + segs.slice(segs.length - depth).join("/");
    if (path !== "/") path += "/";
  }
  const post = path.match(/^\/blog\/([^/]+)\/$/);
  if (post) return /*#__PURE__*/React.createElement(BlogPost, {
    slug: post[1]
  });
  if (path === "/blog/") return /*#__PURE__*/React.createElement(BlogIndex, null);
  return /*#__PURE__*/React.createElement(App, null);
}
ReactDOM.hydrateRoot(document.getElementById("root"), /*#__PURE__*/React.createElement(Root, null));
