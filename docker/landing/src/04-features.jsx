// Features — void surface, 4-up row separated by hairlines.
// Anchored on the four Voidwall verbs: Inspect → Enforce → Sanitize → Audit.
function Features() {
  const items = [
    ["inspect",  "Inspect",  "Parse and scan every outgoing payload across JSON, CSV, TSV, and plain text."],
    ["enforce",  "Enforce",  "Apply policy rules per route, destination, and content type. Block or transform."],
    ["sanitize", "Sanitize", "Redact, hash, mask, or tokenize matched fields inline. Originals never leave."],
    ["audit",    "Audit",    "Stream structured findings to your logs. Every match is timestamped and traceable."],
  ];
  return (
    <section id="product" className="vw-container" style={{ padding: "96px var(--gutter) 60px" }}>
      <div style={{ marginBottom: 64, maxWidth: 720 }}>
        <p className="vw-eyebrow" style={{ margin: "0 0 18px" }}>What Voidwall does</p>
        <h2 style={{
          fontFamily: "var(--vw-font-display)", fontSize: 48, fontWeight: 600,
          letterSpacing: "-0.025em", lineHeight: 1.02,
          color: "var(--vw-void-ink)", margin: 0, textWrap: "balance",
        }}>
          Four operations.<br/>One inline pass.
        </h2>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)" }}>
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
