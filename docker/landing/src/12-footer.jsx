// Footer — void surface. Logo and copyright only.
function Footer() {
  return (
    <footer style={{ background: "var(--vw-void)", color: "var(--vw-void-ink)", borderTop: "1px solid var(--vw-void-line)" }}>
      <div className="vw-container" style={{ padding: "32px var(--gutter)" }}>
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16,
          fontFamily: "var(--vw-font-body)", fontSize: 12.5,
          color: "var(--vw-void-ink-3)", flexWrap: "wrap",
        }}>
          <a href="#" style={{ display: "inline-flex", alignItems: "center", gap: 10, color: "var(--vw-violet-300)", textDecoration: "none" }}>
            <img src="assets/logo-mark-light.svg" width="24" height="24" alt=""/>
            <span style={{ fontFamily: "var(--vw-font-display)", fontWeight: 500, letterSpacing: "0.14em", fontSize: 15, color: "var(--vw-void-ink)" }}>VOIDWALL</span>
          </a>
          <span>© 2026 Voidwall</span>
        </div>
      </div>
    </footer>
  );
}
window.Footer = Footer;
