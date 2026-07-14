// Features - void surface, 4-up row separated by hairlines.
// Anchored on the four Voidwall verbs: Inspect → Enforce → Sanitize → Audit.
function Features() {
  const items = [
    ["scan",  "Scan",  "Parse and scan every outgoing payload across JSON, CSV, TSV, and plain text.", "both"],
    ["redact",  "Redact",  "Replace detected PII with placeholders like [EMAIL], [US_SSN], [FR_NIR]...", "both"],
    ["mask", "Mask", "...or mask with configurable characters.", "both"],
    ["block",    "Block",    "Block the entire request if contains sensitive data.", "proxy"],
    ["alert",    "Alert",    "Warn when sensitive data leak is detected.", "proxy"],
  ];
  return (
    <section id="product" className="vw-container" style={{ padding: "96px var(--gutter) 60px" }}>
      <div style={{ marginBottom: 64, maxWidth: 720 }}>
        {/* <p className="vw-eyebrow" style={{ margin: "0 0 18px" }}>What Voidwall does</p> */}
        <h2 style={{
          fontFamily: "var(--vw-font-display)", fontSize: 48, fontWeight: 600,
          letterSpacing: "-0.025em", lineHeight: 1.02,
          color: "var(--vw-void-ink)", margin: 0, textWrap: "balance",
        }}>
          What Voidwall does
        </h2>
        <p style={{
          fontFamily: "var(--vw-font-body)", fontSize: 16, lineHeight: 1.55,
          color: "var(--vw-void-ink-2)", margin: "20px 0 0", maxWidth: 600,
        }}>
          Run it two ways: inline as an <strong style={{ color: "var(--vw-void-ink)", fontWeight: 600 }}>HTTP proxy</strong> that
          filters live traffic, or as a <strong style={{ color: "var(--vw-void-ink)", fontWeight: 600 }}>REST API</strong> you
          call to scan and redact on demand. The tag on each card shows where it applies.
        </p>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)" }}>
        {items.map(([icon, title, body, mode], i) => (
          <div key={title} style={{
            padding: "0 28px",
            borderLeft: i === 0 ? "0" : "1px solid var(--vw-void-line)",
          }}>
            <span style={{
              width: 44, height: 44, borderRadius: 10,
              border: "1px solid var(--vw-void-line)",
              display: "inline-flex", alignItems: "center", justifyContent: "center",
              color: "var(--vw-violet-300)", marginBottom: 22,
            }}>
              <Icon name={icon} size={22}/>
            </span>
            <div style={{ display: "flex", alignItems: "center", gap: 8, margin: "0 0 10px", flexWrap: "wrap" }}>
              <h3 style={{
                fontFamily: "var(--vw-font-display)", fontSize: 19, fontWeight: 600,
                letterSpacing: "-0.015em", color: "var(--vw-void-ink)", margin: 0,
              }}>{title}</h3>
              <ModeTag mode={mode}/>
            </div>
            <p style={{
              fontFamily: "var(--vw-font-body)", fontSize: 14, lineHeight: 1.6,
              color: "var(--vw-void-ink-2)", margin: 0,
            }}>{body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
// Mode tag - marks whether a verb is available via both interfaces or proxy-only.
function ModeTag({ mode }) {
  const both = mode === "both";
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      height: 18, padding: "0 7px", borderRadius: 999,
      fontFamily: "var(--vw-font-mono)", fontSize: 9.5,
      letterSpacing: "0.06em", textTransform: "uppercase", whiteSpace: "nowrap",
      color: "var(--vw-void-ink-2)",
      border: "1px solid var(--vw-void-ink-3)",
      background: "transparent",
    }}>
      {both ? "Proxy + API" : "Proxy only"}
    </span>
  );
}

window.Features = Features;
