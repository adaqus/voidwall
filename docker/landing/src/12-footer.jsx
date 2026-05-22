// Footer — void surface. Multi-column with brand, status, and link sets.
function Footer() {
  const groups = [
    { title: "Product",   links: ["Detection coverage", "Analytics scanning", "Custom matchers", "Performance", "Live demo"] },
    { title: "Resources", links: ["Blog", "GitHub", "Changelog", "Security", "Status"] },
    { title: "Company",   links: ["About", "Contact", "Press", "Careers"] },
  ];

  return (
    <footer style={{ background: "var(--vw-void)", color: "var(--vw-void-ink)", borderTop: "1px solid var(--vw-void-line)" }}>
      <div className="vw-container" style={{ padding: "72px var(--gutter) 32px" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "minmax(0, 1.4fr) repeat(3, minmax(0, 1fr))",
          gap: 48, alignItems: "start",
        }}>
          <div>
            <a href="#" style={{ display: "inline-flex", alignItems: "center", gap: 10, color: "var(--vw-violet-300)", textDecoration: "none", marginBottom: 22 }}>
              <img src="assets/logo-mark-light.svg" width="24" height="24" alt=""/>
              <span style={{ fontFamily: "var(--vw-font-display)", fontWeight: 500, letterSpacing: "0.14em", fontSize: 15, color: "var(--vw-void-ink)" }}>VOIDWALL</span>
            </a>
            <p style={{
              fontFamily: "var(--vw-font-body)", fontSize: 13.5, lineHeight: 1.55,
              color: "var(--vw-void-ink-2)", margin: "0 0 22px", maxWidth: 320,
            }}>
              The invisible wall between your data and the outside. Self-hosted DLP proxy for HTTP traffic.
            </p>
            <div style={{
              display: "inline-flex", alignItems: "center", gap: 8,
              padding: "8px 12px",
              border: "1px solid var(--vw-void-line)",
              borderRadius: 8,
              fontFamily: "var(--vw-font-body)", fontSize: 12,
              color: "var(--vw-void-ink-2)",
            }}>
              <span style={{ width: 7, height: 7, borderRadius: 999, background: "var(--vw-success)" }}/>
              Demo operational
              <span style={{ color: "var(--vw-void-ink-3)", marginLeft: 6 }}>·</span>
              <span style={{ fontFamily: "var(--vw-font-mono)", color: "var(--vw-void-ink-3)" }}>v0.4.2</span>
            </div>
          </div>

          {groups.map(g => (
            <div key={g.title}>
              <h4 style={{
                fontFamily: "var(--vw-font-body)", fontSize: 11,
                letterSpacing: "0.14em", textTransform: "uppercase",
                color: "var(--vw-void-ink-3)", margin: "0 0 16px", fontWeight: 500,
              }}>{g.title}</h4>
              <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 10 }}>
                {g.links.map(l => (
                  <li key={l}>
                    <a href="#" style={{
                      fontFamily: "var(--vw-font-body)", fontSize: 13.5,
                      color: "var(--vw-void-ink-2)", textDecoration: "none",
                    }}>{l}</a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <hr className="vw-rule" style={{ borderTopColor: "var(--vw-void-line)", margin: "48px 0 22px" }}/>

        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16,
          fontFamily: "var(--vw-font-body)", fontSize: 12.5,
          color: "var(--vw-void-ink-3)", flexWrap: "wrap",
        }}>
          <span>© 2026 Voidwall. Built in Paris and Berlin.</span>
          <div style={{ display: "flex", gap: 20 }}>
            <a href="#" style={{ color: "var(--vw-void-ink-3)", textDecoration: "none" }}>Privacy</a>
            <a href="#" style={{ color: "var(--vw-void-ink-3)", textDecoration: "none" }}>Terms</a>
            <a href="#" style={{ color: "var(--vw-void-ink-3)", textDecoration: "none" }}>Security disclosure</a>
          </div>
        </div>
      </div>
    </footer>
  );
}
window.Footer = Footer;
