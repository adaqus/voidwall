// Features — void surface, 4-up row separated by hairlines.
// Anchored on the four Voidwall verbs: Inspect → Enforce → Sanitize → Audit.
function Features() {
  const items = [
    ["scan",  "Scan",  "Parse and scan every outgoing payload across JSON, CSV, TSV, and plain text."],
    ["redact",  "Redact",  "Replace detected PIIs with placeholers like [EMAIL], [US_SSN], [FR_NIR]..."],
    ["mask", "Mask", "...or mask with configurable characters."],
    ["block",    "Block",    "Block the entire request if contain sensitive data."],
    ["alert",    "Alert",    "Warn when sensitive data leak is detected."],
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
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)" }}>
        {items.map(([icon, title, body], i) => (
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
            <h3 style={{
              fontFamily: "var(--vw-font-display)", fontSize: 19, fontWeight: 600,
              letterSpacing: "-0.015em", color: "var(--vw-void-ink)", margin: "0 0 10px",
            }}>{title}</h3>
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
window.Features = Features;
