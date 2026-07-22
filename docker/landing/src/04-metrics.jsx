// Metrics strip - replaces "trusted by" since the product is pre-launch.
// Four key numbers presented as a horizontal hairline-divided row on a paper-2 band.
function Metrics() {
  const items = [
    ["118", "", "PII types", "supported out of the box"],
    ["7",  "",  "Languages", "English, French, German, Dutch, Italian, Spanish, Polish"],
    ["15", "",  "Countries", "USA, UK, France, Germany..."],
    ["2", "",  "Specializations", "Google Analytics, Matomo"],
    ["5",  "",  "Formats",   "JSON, URL, CSV, TSV, plain text"],
  ];
  return (
    <div style={{ background: "var(--vw-paper-2)", borderTop: "1px solid var(--vw-paper-line)", borderBottom: "1px solid var(--vw-paper-line)" }}>
      <div className="vw-container" style={{ padding: "44px var(--gutter)" }}>
        <div className="r-metrics" style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)" }}>
          {items.map(([n, suffix, label, sub], i) => (
            <div key={label} style={{
              padding: "0 28px",
              borderLeft: i === 0 ? "0" : "1px solid var(--vw-paper-line)",
            }}>
              <div className="r-stat" style={{
                fontFamily: "var(--vw-font-display)",
                fontSize: 56, fontWeight: 600, letterSpacing: "-0.03em",
                lineHeight: 1, color: "var(--vw-paper-ink)",
                marginBottom: 12,
                display: "flex", alignItems: "baseline",
              }}>
                {n}<span style={{ color: "var(--vw-violet-400)" }}>{suffix}</span>
              </div>
              <div style={{
                fontFamily: "var(--vw-font-body)", fontSize: 13, fontWeight: 500,
                color: "var(--vw-paper-ink)", marginBottom: 4,
              }}>{label}</div>
              <div style={{
                fontFamily: "var(--vw-font-body)", fontSize: 12,
                color: "var(--vw-paper-ink-3)",
              }}>{sub}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
window.Metrics = Metrics;
