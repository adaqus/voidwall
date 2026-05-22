function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/* === 00-icons.jsx === */
// Centralized icon registry — Lucide-aligned stroke set. currentColor only.
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
    case "inspect":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("circle", {
        cx: "11",
        cy: "11",
        r: "8"
      }), /*#__PURE__*/React.createElement("path", {
        d: "m21 21-4.35-4.35"
      }));
    case "enforce":
      return /*#__PURE__*/React.createElement("svg", common, /*#__PURE__*/React.createElement("path", {
        d: "M12 22s-8-4.5-8-11V5l8-3 8 3v6c0 6.5-8 11-8 11z"
      }), /*#__PURE__*/React.createElement("path", {
        d: "m9 12 2 2 4-4"
      }));
    case "sanitize":
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
// Nav — paper surface, wall mark + wordmark on the left, links + CTA on the right.
function Nav() {
  const links = [["Product", "#product"], ["Detection", "#detection"], ["Integrations", "#integrations"], ["Performance", "#performance"], ["Blog", "#blog"]];
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
    href: "#",
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 10,
      color: "var(--vw-paper-ink)",
      textDecoration: "none"
    }
  }, /*#__PURE__*/React.createElement("img", {
    src: "assets/logo-mark.svg",
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
      gap: 16
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "https://github.com/",
    target: "_blank",
    rel: "noreferrer",
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 14,
      color: "var(--vw-paper-ink)",
      textDecoration: "none",
      display: "inline-flex",
      alignItems: "center",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "github",
    size: 16
  }), " GitHub"), /*#__PURE__*/React.createElement("a", {
    href: "#demo",
    className: "vw-btn vw-btn--primary"
  }, "Try the live demo ", /*#__PURE__*/React.createElement("span", {
    className: "arrow"
  }, "\u2192")))));
}
window.Nav = Nav;

/* === 02-hero.jsx === */
// Hero — paper surface, left text column, right "wall" illustration with traffic flow.
// Headline variants — exposed so the Tweaks panel can cycle between options.
// `lead` / `accent` are sized at the same scale; `lead` ends with a period or fragment,
// `accent` is the violet kicker on its own line.
const HEADLINE_VARIANTS = {
  "wall": {
    lead: "Stop personal data at the wall.",
    accent: "In every direction.",
    size: 68
  },
  "intercepted": {
    lead: "Personal data, intercepted at the edge of every request.",
    accent: "Inbound and outbound.",
    size: 60
  },
  "in-out": {
    lead: "Sensitive data in. Sanitized data out.",
    accent: "Nothing you can't audit in between.",
    size: 60
  },
  "performance": {
    lead: "Protects performance-demanding systems from sensitive data leaks.",
    accent: "Both in and out.",
    size: 56
  }
};
window.HEADLINE_VARIANTS = HEADLINE_VARIANTS;
function Hero({
  headlineKey = "wall"
}) {
  const h = HEADLINE_VARIANTS[headlineKey] || HEADLINE_VARIANTS["wall"];
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
  }), "Live demo available \u2014 early access")), /*#__PURE__*/React.createElement("p", {
    className: "vw-eyebrow",
    style: {
      margin: "0 0 22px"
    }
  }, "DLP proxy. Data stays protected."), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontWeight: 600,
      fontSize: h.size,
      lineHeight: 1.0,
      letterSpacing: "-0.025em",
      color: "var(--vw-paper-ink)",
      margin: "0 0 28px",
      textWrap: "balance",
      minHeight: 220
    }
  }, h.lead, " ", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-400)"
    }
  }, h.accent)), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 17,
      lineHeight: 1.55,
      color: "var(--vw-paper-ink-2)",
      maxWidth: 480,
      margin: "0 0 36px"
    }
  }, "Voidwall is an HTTP reverse proxy and HTTP API that detects, filters, and sanitizes personal data in real time. Deploy it in front of any service \u2014 applications, analytics, third-party APIs \u2014 and stop sensitive data at the edge of your environment."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 12,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "#demo",
    className: "vw-btn vw-btn--primary"
  }, "Try the live demo ", /*#__PURE__*/React.createElement("span", {
    className: "arrow"
  }, "\u2192")), /*#__PURE__*/React.createElement("a", {
    href: "#blog",
    className: "vw-btn vw-btn--ghost"
  }, "Read the blog ", /*#__PURE__*/React.createElement("span", {
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
  }))))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 56
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      justifyContent: "space-between",
      marginBottom: 18
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "vw-eyebrow"
  }, "Specializations"), /*#__PURE__*/React.createElement("a", {
    href: "#integrations",
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 13,
      color: "var(--vw-paper-ink-2)",
      textDecoration: "none"
    }
  }, "All integrations ", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-400)"
    }
  }, "\u2192"))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(2, minmax(0,1fr))",
      gap: 20
    }
  }, /*#__PURE__*/React.createElement(SpecCard, {
    mark: "GA4",
    name: "Google Analytics 4",
    tagline: "Sanitizes gtag and /collect payloads.",
    details: "Strips client_id, user_id, user properties, and resolves the IP to a /24 before the request crosses your perimeter. Works inline against measurement protocol v2 and gtag.js.",
    params: ["client_id", "user_id", "user_properties", "ip_override", "geo_*"]
  }), /*#__PURE__*/React.createElement(SpecCard, {
    mark: "Matomo",
    name: "Matomo",
    tagline: "Inspects /matomo.php and bulk tracking.",
    details: "Filters _id, uid, urlref, and custom dimensions in real time. Honours per-site policies, including PiwikPro deployments, with zero changes to the tracking snippet.",
    params: ["_id", "uid", "urlref", "dimensionN", "custom_vars"]
  }))));
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
// Metrics strip — replaces "trusted by" since the product is pre-launch.
// Four key numbers presented as a horizontal hairline-divided row on a paper-2 band.
function Metrics() {
  const items = [["80", "+", "PII types", "supported out of the box"], ["3", "", "Languages", "English, French, German"], ["11", "", "Countries", "and growing every month"], ["4", "", "Formats", "JSON, CSV, TSV, plain text"]];
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
      gridTemplateColumns: "repeat(4, 1fr)"
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
// Features — void surface, 4-up row separated by hairlines.
// Anchored on the four Voidwall verbs: Inspect → Enforce → Sanitize → Audit.
function Features() {
  const items = [["inspect", "Inspect", "Parse and scan every outgoing payload across JSON, CSV, TSV, and plain text."], ["enforce", "Enforce", "Apply policy rules per route, destination, and content type. Block or transform."], ["sanitize", "Sanitize", "Redact, hash, mask, or tokenize matched fields inline. Originals never leave."], ["audit", "Audit", "Stream structured findings to your logs. Every match is timestamped and traceable."]];
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
  }, /*#__PURE__*/React.createElement("p", {
    className: "vw-eyebrow",
    style: {
      margin: "0 0 18px"
    }
  }, "What Voidwall does"), /*#__PURE__*/React.createElement("h2", {
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
  }, "Four operations.", /*#__PURE__*/React.createElement("br", null), "One inline pass.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(4, 1fr)"
    }
  }, items.map(([icon, title, body], i) => /*#__PURE__*/React.createElement("div", {
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
  })), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 19,
      fontWeight: 600,
      letterSpacing: "-0.015em",
      color: "var(--vw-void-ink)",
      margin: "0 0 10px"
    }
  }, title), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 14,
      lineHeight: 1.6,
      color: "var(--vw-void-ink-2)",
      margin: 0
    }
  }, body)))));
}
window.Features = Features;

/* === 05-coverage.jsx === */
// Coverage — void surface. The breadth-of-detection story.
// 80+ PII types organized by category, plus languages + countries strip.
function Coverage() {
  const groups = [{
    title: "Identity",
    icon: "id-card",
    items: [["Full name", true], ["Email", true], ["Phone number", true], ["Date of birth", false], ["Passport no.", true], ["National ID", true], ["Driver's licence", false], ["Tax ID", false]]
  }, {
    title: "Financial",
    icon: "credit-card",
    items: [["IBAN", true], ["Credit card", true], ["SWIFT / BIC", false], ["Bank routing", false], ["VAT number", false], ["Crypto wallet", true], ["Account no.", false]]
  }, {
    title: "Locale-specific",
    icon: "flag",
    items: [["US — SSN", true], ["UK — NI no.", false], ["FR — NIR", true], ["FR — SIREN", false], ["DE — Steuer-ID", true], ["NL — BSN", false], ["IT — Codice Fiscale", false], ["PL — PESEL", false], ["ES — DNI", false], ["CA — SIN", false]]
  }, {
    title: "Technical",
    icon: "fingerprint",
    items: [["IPv4 / IPv6", true], ["MAC address", false], ["URL with token", false], ["JWT", true], ["API key", true], ["Cookie ID", false], ["Device fingerprint", false]]
  }];
  const languages = [["EN", "English"], ["FR", "Français"], ["DE", "Deutsch"]];
  const countries = ["United States", "United Kingdom", "France", "Germany", "Netherlands", "Italy", "Spain", "Poland", "Belgium", "Canada", "Switzerland"];
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
  }, "Over 80 PII types.", /*#__PURE__*/React.createElement("br", null), "Three languages.", /*#__PURE__*/React.createElement("br", null), "Eleven countries."), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 15.5,
      lineHeight: 1.6,
      color: "var(--vw-void-ink-2)",
      margin: "0 0 28px",
      maxWidth: 400
    }
  }, "Detectors are context-aware and locale-specific. A French NIR isn't a German Steuer-ID, even when the digits collide. Voidwall reads the field name, the values around it, and the route \u2014 then decides."), /*#__PURE__*/React.createElement("div", {
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
      display: "flex",
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
  }, name))))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "vw-eyebrow vw-eyebrow--muted"
  }, "Countries \u2014 and growing"), /*#__PURE__*/React.createElement("div", {
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
// Analytics — void surface. GA4 + Matomo real-time scanning.
// Shows the same tracking event in raw vs. sanitized form, for each platform.
function Analytics() {
  return /*#__PURE__*/React.createElement("section", {
    id: "integrations",
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
  }, "Front-end tracking is the leakiest path out of a product \u2014 marketing teams add events, developers add custom parameters, and personal data slips into Google or Matomo unnoticed. Voidwall sits in front of the collector and sanitizes every hit.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(2, 1fr)",
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
  })));
}
function PlatformCard({
  name,
  endpoint,
  tag
}) {
  const ga4Raw = [['v', '2'], ['tid', 'G-X8Q1ZRP'], ['cid', '1822941.1715'], ['uid', 'alex.miller@acme.io', true], ['ep.session_id', '6671'], ['ep.search_query', 'sarah dupont 06 12 34 56 78', true], ['ep.user_zip', '75011', true], ['uip', '203.0.113.42', true]];
  const ga4San = [['v', '2'], ['tid', 'G-X8Q1ZRP'], ['cid', '1822941.1715'], ['uid', 'sha256:a4f9…', null, 'hashed'], ['ep.session_id', '6671'], ['ep.search_query', '<name> <phone:fr>', null, 'redacted'], ['ep.user_zip', '750**', null, 'masked'], ['uip', '203.0.113.0', null, 'truncated']];
  const matomoRaw = [['idsite', '17'], ['rec', '1'], ['action_name', 'Checkout'], ['uid', 'klaus.weber@example.de', true], ['e_n', 'lead.submit'], ['cvar', '{"email":"klaus.weber@example.de"}', true], ['_id', '8b3f1a92ee44c1d2'], ['cip', '94.245.66.10', true]];
  const matomoSan = [['idsite', '17'], ['rec', '1'], ['action_name', 'Checkout'], ['uid', 'sha256:7c12…', null, 'hashed'], ['e_n', 'lead.submit'], ['cvar', '{"email":"<email>"}', null, 'redacted'], ['_id', '8b3f1a92ee44c1d2'], ['cip', '94.245.66.0', null, 'truncated']];
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
// Formats — void surface. Tabbed code pane: JSON / CSV / TSV / plain text.
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
    "name": "Sarah Dupont",
    "email": "s.dupont@acme.fr",
    "phone": "+33 6 12 34 56 78",
    "nir": "2 85 04 75 116 042 89"
  },
  "billing_iban": "FR76 3000 4012 3456 7890 1234 567",
  "notes": "Address: 12 rue de Belleville, 75011 Paris"
}`,
      after: `{
  "order_id": "A-2186",
  "customer": {
    "name": "<name>",
    "email": "<email>",
    "phone": "<phone:fr>",
    "nir": "<fr.nir>"
  },
  "billing_iban": "<iban>",
  "notes": "Address: <address:fr>"
}`
    },
    csv: {
      label: "CSV",
      icon: "table",
      before: `order_id,customer_name,email,phone,iban,country
A-2186,Sarah Dupont,s.dupont@acme.fr,+33 6 12 34 56 78,FR76 3000 4012 3456 7890 1234 567,FR
A-2187,Klaus Weber,klaus.w@example.de,+49 30 9876 5432,DE89 3704 0044 0532 0130 00,DE
A-2188,Anna Rossi,a.rossi@example.it,+39 320 555 11 22,IT60 X054 2811 1010 0000 0123 456,IT`,
      after: `order_id,customer_name,email,phone,iban,country
A-2186,<name>,<email>,<phone:fr>,<iban>,FR
A-2187,<name>,<email>,<phone:de>,<iban>,DE
A-2188,<name>,<email>,<phone:it>,<iban>,IT`
    },
    tsv: {
      label: "TSV",
      icon: "table",
      before: `event_id\tuser_id\temail\tip\tquery
e_4471\t1822\talex@acme.io\t203.0.113.42\thotels in Berlin
e_4472\t1923\tklaus.weber@example.de\t94.245.66.10\tbsn 1234 56 789
e_4473\t1924\ta.rossi@example.it\t82.85.10.5\tcodice fiscale RSSMRA`,
      after: `event_id\tuser_id\temail\tip\tquery
e_4471\tsha256:b1…\t<email>\t203.0.113.0\thotels in Berlin
e_4472\tsha256:7c…\t<email>\t94.245.66.0\t<nl.bsn>
e_4473\tsha256:9a…\t<email>\t82.85.10.0\t<it.codice_fiscale>`
    },
    text: {
      label: "Plain text",
      icon: "text",
      before: `Hi support,

I never received my order A-2186. My email on the account is
s.dupont@acme.fr and my phone is +33 6 12 34 56 78. I paid with
my Visa 4539 1488 0343 6467 on the 14th. Please check.

— Sarah`,
      after: `Hi support,

I never received my order A-2186. My email on the account is
<email> and my phone is <phone:fr>. I paid with
my Visa <credit_card> on the 14th. Please check.

— <name>`
    }
  };
  const current = samples[tab];
  return /*#__PURE__*/React.createElement("section", {
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
  }, "Four payload formats.", /*#__PURE__*/React.createElement("br", null), "Same rules.")), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 16,
      lineHeight: 1.55,
      color: "var(--vw-void-ink-2)",
      margin: 0,
      maxWidth: 460
    }
  }, "Voidwall parses the body before it scans it. Whether the payload is a nested JSON document, a flat CSV upload, a tab-separated tracking hit, or free-form text in a support message, the same matchers apply.")), /*#__PURE__*/React.createElement("div", {
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

// Crude highlighter — wraps sensitive runs in red, placeholders in violet.
function highlight(text, bad) {
  if (bad) {
    const re = /(Sarah Dupont|s\.dupont@acme\.fr|\+33 6 12 34 56 78|2 85 04 75 116 042 89|FR76 3000 4012 3456 7890 1234 567|Address: 12 rue de Belleville, 75011 Paris|Klaus Weber|klaus\.w@example\.de|\+49 30 9876 5432|DE89 3704 0044 0532 0130 00|Anna Rossi|a\.rossi@example\.it|\+39 320 555 11 22|IT60 X054 2811 1010 0000 0123 456|alex@acme\.io|203\.0\.113\.42|klaus\.weber@example\.de|94\.245\.66\.10|82\.85\.10\.5|bsn 1234 56 789|codice fiscale RSSMRA|4539 1488 0343 6467)/g;
    return splitWith(text, re, (m, i) => /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        color: "var(--vw-danger)",
        background: "rgba(229,86,75,0.12)",
        borderRadius: 3
      }
    }, m));
  } else {
    const re = /(<[^>]+>|sha256:[a-z0-9…]+)/g;
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

/* === 08-custom-pii.jsx === */
// CustomPII — void surface. YAML-style config + matched samples.
// Demonstrates user-defined detectors.
function CustomPII() {
  const yaml = [{
    t: "c",
    v: "# detectors/acme.yaml"
  }, {
    t: "n"
  }, {
    t: "k",
    v: "detector"
  }, {
    t: "p",
    v: ": "
  }, {
    t: "v",
    v: "acme_employee_id"
  }, {
    t: "n"
  }, {
    t: "k",
    v: "language"
  }, {
    t: "p",
    v: ": "
  }, {
    t: "v",
    v: "[en, fr, de]"
  }, {
    t: "n"
  }, {
    t: "k",
    v: "match"
  }, {
    t: "p",
    v: ":"
  }, {
    t: "n"
  }, {
    t: "p",
    v: "  "
  }, {
    t: "k",
    v: "regex"
  }, {
    t: "p",
    v: ": "
  }, {
    t: "s",
    v: "ACME-[A-Z]{2}-\\d{6}"
  }, {
    t: "n"
  }, {
    t: "p",
    v: "  "
  }, {
    t: "k",
    v: "context"
  }, {
    t: "p",
    v: ": "
  }, {
    t: "v",
    v: "[employee, badge, staff]"
  }, {
    t: "n"
  }, {
    t: "p",
    v: "  "
  }, {
    t: "k",
    v: "confidence"
  }, {
    t: "p",
    v: ": "
  }, {
    t: "v",
    v: "high"
  }, {
    t: "n"
  }, {
    t: "k",
    v: "action"
  }, {
    t: "p",
    v: ":"
  }, {
    t: "n"
  }, {
    t: "p",
    v: "  "
  }, {
    t: "k",
    v: "transform"
  }, {
    t: "p",
    v: ": "
  }, {
    t: "v",
    v: "redact"
  }, {
    t: "n"
  }, {
    t: "p",
    v: "  "
  }, {
    t: "k",
    v: "placeholder"
  }, {
    t: "p",
    v: ": "
  }, {
    t: "s",
    v: "<acme.employee>"
  }, {
    t: "n"
  }, {
    t: "k",
    v: "scope"
  }, {
    t: "p",
    v: ":"
  }, {
    t: "n"
  }, {
    t: "p",
    v: "  "
  }, {
    t: "k",
    v: "routes"
  }, {
    t: "p",
    v: ": "
  }, {
    t: "v",
    v: "[\"/api/*\", \"/g/collect\"]"
  }, {
    t: "n"
  }];
  const matched = [{
    ok: true,
    v: "ACME-NY-018442"
  }, {
    ok: true,
    v: "ACME-PR-720199"
  }, {
    ok: true,
    v: "ACME-LD-005512"
  }, {
    ok: false,
    v: "ACME-tickets-2025",
    reason: "context missing"
  }, {
    ok: false,
    v: "ACME-XX-00",
    reason: "regex mismatch"
  }];
  return /*#__PURE__*/React.createElement("section", {
    className: "vw-container",
    style: {
      padding: "60px var(--gutter) 80px",
      borderTop: "1px solid var(--vw-void-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)",
      gap: 56,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("p", {
    className: "vw-eyebrow",
    style: {
      margin: "0 0 18px"
    }
  }, "Your data, your rules"), /*#__PURE__*/React.createElement("h2", {
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
  }, "Define your own", /*#__PURE__*/React.createElement("br", null), "PII types in YAML."), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 16,
      lineHeight: 1.6,
      color: "var(--vw-void-ink-2)",
      margin: "0 0 28px",
      maxWidth: 440
    }
  }, "Every business has personal data the built-in detectors will not know: internal employee IDs, customer numbers, project codenames, partner references. Add as many user-defined matchers as you need \u2014 with regex, context keywords, confidence thresholds, and per-route scope."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 10,
      marginBottom: 28
    }
  }, ["Hot-reloaded — no restart, no redeploy.", "Composable with built-in detectors.", "Versioned alongside the rest of your config."].map(t => /*#__PURE__*/React.createElement("div", {
    key: t,
    style: {
      display: "flex",
      gap: 10,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-300)"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "check",
    size: 14
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 14,
      color: "var(--vw-void-ink)"
    }
  }, t)))), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "vw-btn vw-btn--link",
    style: {
      color: "var(--vw-violet-300)"
    }
  }, "See the matcher reference ", /*#__PURE__*/React.createElement("span", {
    className: "arrow"
  }, "\u2192"))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--vw-void-2)",
      border: "1px solid var(--vw-void-line)",
      borderRadius: 14,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "12px 16px",
      borderBottom: "1px solid var(--vw-void-line)",
      fontFamily: "var(--vw-font-mono)",
      fontSize: 12,
      color: "var(--vw-void-ink-3)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "flex",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: 999,
      background: "var(--vw-void-line)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: 999,
      background: "var(--vw-void-line)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: 999,
      background: "var(--vw-void-line)"
    }
  })), "detectors/acme.yaml"), /*#__PURE__*/React.createElement("pre", {
    style: {
      margin: 0,
      padding: "18px 20px",
      fontFamily: "var(--vw-font-mono)",
      fontSize: 12.5,
      lineHeight: 1.7,
      color: "var(--vw-void-ink)",
      whiteSpace: "pre",
      overflow: "auto"
    }
  }, yaml.map((tok, i) => {
    if (tok.t === "n") return "\n";
    if (tok.t === "c") return /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        color: "var(--vw-void-ink-3)"
      }
    }, tok.v);
    if (tok.t === "k") return /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        color: "var(--vw-violet-300)"
      }
    }, tok.v);
    if (tok.t === "s") return /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        color: "#C8A35F"
      }
    }, "\"", tok.v, "\"");
    if (tok.t === "v") return /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        color: "var(--vw-void-ink)"
      }
    }, tok.v);
    return /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        color: "var(--vw-void-ink-3)"
      }
    }, tok.v);
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 16,
      background: "var(--vw-void-2)",
      border: "1px solid var(--vw-void-line)",
      borderRadius: 14,
      padding: "16px 18px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 10.5,
      letterSpacing: "0.14em",
      textTransform: "uppercase",
      color: "var(--vw-void-ink-3)",
      marginBottom: 12
    }
  }, "Test results"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 8
    }
  }, matched.map((m, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "grid",
      gridTemplateColumns: "20px 1fr auto",
      gap: 10,
      alignItems: "center",
      fontFamily: "var(--vw-font-mono)",
      fontSize: 12.5
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: m.ok ? "var(--vw-success)" : "var(--vw-void-ink-3)"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: m.ok ? "check" : "x",
    size: 14
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-void-ink)"
    }
  }, m.v), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 11,
      color: m.ok ? "var(--vw-success)" : "var(--vw-void-ink-3)"
    }
  }, m.ok ? "match" : m.reason))))))));
}
window.CustomPII = CustomPII;

/* === 09-performance.jsx === */
// Performance — paper-band section. Highlights latency, throughput, and cost.
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
  }, "Voidwall is written to disappear behind the wire. It scales horizontally, runs in your cluster, and adds a budget you can measure in single-digit milliseconds. No external calls, no phone-home, no per-request fees.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: 24
    }
  }, /*#__PURE__*/React.createElement(PerfCard, {
    icon: "gauge",
    eyebrow: "Latency (p99)",
    big: "1.2",
    unit: "ms",
    sub: "added per request, JSON payloads under 4 KiB",
    chart: /*#__PURE__*/React.createElement(Bars, {
      values: [0.6, 0.8, 1.0, 1.1, 1.2],
      labels: ["p50", "p75", "p90", "p95", "p99"]
    })
  }), /*#__PURE__*/React.createElement(PerfCard, {
    icon: "trend-up",
    eyebrow: "Throughput",
    big: "38k",
    unit: "req/s",
    sub: "sustained per pod, four logical cores",
    chart: /*#__PURE__*/React.createElement(Bars, {
      values: [8, 16, 24, 32, 38],
      labels: ["1c", "2c", "3c", "4c", "4c+"]
    })
  }), /*#__PURE__*/React.createElement(PerfCard, {
    icon: "wallet",
    eyebrow: "Cost",
    big: "0.7",
    unit: "\xA2 / million req",
    sub: "self-hosted, commodity hardware",
    chart: /*#__PURE__*/React.createElement(CostBars, null)
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 56,
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: 0
    }
  }, [["zap", "Streaming parser", "Bodies are scanned as they arrive — no buffering large uploads in memory."], ["layers", "Horizontal scaling", "Stateless workers. Add a pod, get throughput. Drain a pod, get nothing else."], ["server", "Runs where you do", "Kubernetes, ECS, Nomad, bare metal, or a single VM. No managed plane."]].map(([icon, title, body], i) => /*#__PURE__*/React.createElement("div", {
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
      height: `${v / max * 100}%`,
      background: i === values.length - 1 ? "var(--vw-violet-400)" : "var(--vw-paper-ink)",
      borderRadius: 3,
      minHeight: 6
    }
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
// Blog — paper surface. Three teaser cards + link to the index.
function Blog() {
  const posts = [{
    tag: "Engineering",
    date: "2026-05-12",
    title: "Why we built Voidwall as a proxy, not a library.",
    excerpt: "An inline DLP layer has to survive every protocol mistake in your stack. Here is why a proxy beats an SDK once teams scale.",
    read: "8 min read"
  }, {
    tag: "Detection",
    date: "2026-04-28",
    title: "The case for locale-specific PII detectors.",
    excerpt: "A French NIR and a German Steuer-ID share digit counts but mean different things. Context-free matching is a recipe for false positives — and worse.",
    read: "6 min read"
  }, {
    tag: "Analytics",
    date: "2026-04-10",
    title: "Personal data is leaking into GA4. Here is what we found.",
    excerpt: "We instrumented twelve production properties and counted the events that carried emails, phone numbers, and IPs. The result is not pretty.",
    read: "11 min read"
  }];
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
    href: "#",
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
  tag,
  date,
  title,
  excerpt,
  read
}) {
  return /*#__PURE__*/React.createElement("a", {
    href: "#",
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

/* === 11-cta.jsx === */
// CTA — void surface. Big "Try the live demo" with a small terminal-style preview.
function CTA() {
  return /*#__PURE__*/React.createElement("section", {
    id: "demo",
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
    style: {
      display: "grid",
      gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)",
      gap: 80,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("p", {
    className: "vw-eyebrow",
    style: {
      margin: "0 0 22px",
      color: "var(--vw-violet-300)"
    }
  }, "Available now \u2014 early access"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--vw-font-display)",
      fontSize: 64,
      fontWeight: 600,
      letterSpacing: "-0.025em",
      lineHeight: 0.98,
      color: "var(--vw-void-ink)",
      margin: "0 0 24px",
      textWrap: "balance"
    }
  }, "Send a request.", /*#__PURE__*/React.createElement("br", null), "Watch it come back", /*#__PURE__*/React.createElement("br", null), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-400)"
    }
  }, "clean.")), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 17,
      lineHeight: 1.55,
      color: "var(--vw-void-ink-2)",
      margin: "0 0 36px",
      maxWidth: 460
    }
  }, "The hosted demo accepts any JSON, CSV, TSV, or text payload \u2014 or a real GA4 / Matomo tracking hit \u2014 and returns it sanitized. No signup, no email, no install."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 12,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "vw-btn vw-btn--primary"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "play",
    size: 14
  }), " Open the demo ", /*#__PURE__*/React.createElement("span", {
    className: "arrow"
  }, "\u2192")), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "vw-btn vw-btn--ghost",
    style: {
      color: "var(--vw-void-ink)"
    }
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "github",
    size: 16
  }), " View on GitHub ", /*#__PURE__*/React.createElement("span", {
    className: "arrow"
  }, "\u2192")))), /*#__PURE__*/React.createElement(Terminal, null))));
}
function Terminal() {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--vw-void-2)",
      border: "1px solid var(--vw-void-line)",
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "0 28px 60px -24px rgba(139,125,246,0.35)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "12px 16px",
      borderBottom: "1px solid var(--vw-void-line)",
      fontFamily: "var(--vw-font-mono)",
      fontSize: 12,
      color: "var(--vw-void-ink-3)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "flex",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 9,
      height: 9,
      borderRadius: 999,
      background: "var(--vw-void-line)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 9,
      height: 9,
      borderRadius: 999,
      background: "var(--vw-void-line)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 9,
      height: 9,
      borderRadius: 999,
      background: "var(--vw-void-line)"
    }
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      flex: 1
    }
  }, "demo.voidwall.io \u2014 curl")), /*#__PURE__*/React.createElement("pre", {
    style: {
      margin: 0,
      padding: "20px 22px",
      fontFamily: "var(--vw-font-mono)",
      fontSize: 12.5,
      lineHeight: 1.6,
      color: "var(--vw-void-ink)",
      whiteSpace: "pre-wrap",
      wordBreak: "break-word"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-void-ink-3)"
    }
  }, "$ "), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-300)"
    }
  }, "curl"), " -sX POST https://demo.voidwall.io/v1/scan \\", "\n  -H 'content-type: application/json' \\", "\n  -d '{\"", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "#C8A35F"
    }
  }, "email"), "\":\"", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-danger)"
    }
  }, "s.dupont@acme.fr"), "\",\"", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "#C8A35F"
    }
  }, "phone"), "\":\"", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-danger)"
    }
  }, "+33 6 12 34 56 78"), "\"}'\n\n", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-void-ink-3)"
    }
  }, "HTTP/1.1 200 OK"), "\n", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-void-ink-3)"
    }
  }, "x-voidwall-findings: 2 matches, 0 blocked"), "\n", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-void-ink-3)"
    }
  }, "x-voidwall-latency: 0.9ms"), "\n\n", "{\n  \"", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "#C8A35F"
    }
  }, "email"), "\": \"", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-300)"
    }
  }, "<email>"), "\",\n  \"", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "#C8A35F"
    }
  }, "phone"), "\": \"", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-violet-300)"
    }
  }, "<phone:fr>"), "\"\n}"));
}
window.CTA = CTA;

/* === 12-footer.jsx === */
// Footer — void surface. Multi-column with brand, status, and link sets.
function Footer() {
  const groups = [{
    title: "Product",
    links: ["Detection coverage", "Analytics scanning", "Custom matchers", "Performance", "Live demo"]
  }, {
    title: "Resources",
    links: ["Blog", "GitHub", "Changelog", "Security", "Status"]
  }, {
    title: "Company",
    links: ["About", "Contact", "Press", "Careers"]
  }];
  return /*#__PURE__*/React.createElement("footer", {
    style: {
      background: "var(--vw-void)",
      color: "var(--vw-void-ink)",
      borderTop: "1px solid var(--vw-void-line)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-container",
    style: {
      padding: "72px var(--gutter) 32px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "minmax(0, 1.4fr) repeat(3, minmax(0, 1fr))",
      gap: 48,
      alignItems: "start"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("a", {
    href: "#",
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 10,
      color: "var(--vw-violet-300)",
      textDecoration: "none",
      marginBottom: 22
    }
  }, /*#__PURE__*/React.createElement("img", {
    src: "assets/logo-mark-light.svg",
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
  }, "VOIDWALL")), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 13.5,
      lineHeight: 1.55,
      color: "var(--vw-void-ink-2)",
      margin: "0 0 22px",
      maxWidth: 320
    }
  }, "The invisible wall between your data and the outside. Self-hosted DLP proxy for HTTP traffic."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 8,
      padding: "8px 12px",
      border: "1px solid var(--vw-void-line)",
      borderRadius: 8,
      fontFamily: "var(--vw-font-body)",
      fontSize: 12,
      color: "var(--vw-void-ink-2)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 7,
      height: 7,
      borderRadius: 999,
      background: "var(--vw-success)"
    }
  }), "Demo operational", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--vw-void-ink-3)",
      marginLeft: 6
    }
  }, "\xB7"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--vw-font-mono)",
      color: "var(--vw-void-ink-3)"
    }
  }, "v0.4.2"))), groups.map(g => /*#__PURE__*/React.createElement("div", {
    key: g.title
  }, /*#__PURE__*/React.createElement("h4", {
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 11,
      letterSpacing: "0.14em",
      textTransform: "uppercase",
      color: "var(--vw-void-ink-3)",
      margin: "0 0 16px",
      fontWeight: 500
    }
  }, g.title), /*#__PURE__*/React.createElement("ul", {
    style: {
      listStyle: "none",
      padding: 0,
      margin: 0,
      display: "flex",
      flexDirection: "column",
      gap: 10
    }
  }, g.links.map(l => /*#__PURE__*/React.createElement("li", {
    key: l
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    style: {
      fontFamily: "var(--vw-font-body)",
      fontSize: 13.5,
      color: "var(--vw-void-ink-2)",
      textDecoration: "none"
    }
  }, l))))))), /*#__PURE__*/React.createElement("hr", {
    className: "vw-rule",
    style: {
      borderTopColor: "var(--vw-void-line)",
      margin: "48px 0 22px"
    }
  }), /*#__PURE__*/React.createElement("div", {
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
  }, /*#__PURE__*/React.createElement("span", null, "\xA9 2026 Voidwall. Built in Paris and Berlin."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 20
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    style: {
      color: "var(--vw-void-ink-3)",
      textDecoration: "none"
    }
  }, "Privacy"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    style: {
      color: "var(--vw-void-ink-3)",
      textDecoration: "none"
    }
  }, "Terms"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    style: {
      color: "var(--vw-void-ink-3)",
      textDecoration: "none"
    }
  }, "Security disclosure")))));
}
window.Footer = Footer;

/* === 13-app.jsx === */
// Entry point — renders the landing page. The original standalone export
// used a Tweaks editor panel; the production build renders the components
// directly with a fixed headline variant.
function App() {
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(Nav, null), /*#__PURE__*/React.createElement(Hero, {
    headlineKey: "intercepted"
  }), /*#__PURE__*/React.createElement(Metrics, null), /*#__PURE__*/React.createElement("div", {
    className: "void-band vw-void"
  }, /*#__PURE__*/React.createElement(Features, null), /*#__PURE__*/React.createElement(Coverage, null), /*#__PURE__*/React.createElement(Analytics, null), /*#__PURE__*/React.createElement(Formats, null), /*#__PURE__*/React.createElement(CustomPII, null)), /*#__PURE__*/React.createElement(Performance, null), /*#__PURE__*/React.createElement(Blog, null), /*#__PURE__*/React.createElement(CTA, null), /*#__PURE__*/React.createElement(Footer, null));
}
ReactDOM.createRoot(document.getElementById("root")).render(/*#__PURE__*/React.createElement(App, null));
