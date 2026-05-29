// Nav — paper surface, wall mark + wordmark on the left, links + CTA on the right.
function Nav() {
  const links = [
    ["Product", "#product"],
    ["Detection", "#detection"],
    ["Specializations", "#specializations"],
    ["Formats", "#formats"],
    ["Performance", "#performance"],
    // ["Blog", "#blog"],
  ];
  return (
    <header style={{
      position: "sticky", top: 0, zIndex: 50,
      background: "rgba(241,238,232,0.86)",
      backdropFilter: "blur(12px)",
      WebkitBackdropFilter: "blur(12px)",
      borderBottom: "1px solid var(--vw-paper-line)",
    }}>
      <div style={{
        maxWidth: "var(--max-w)", margin: "0 auto",
        padding: "16px var(--gutter)",
        display: "flex", alignItems: "center", gap: 32,
      }}>
        <a href="#" style={{ display: "inline-flex", alignItems: "center", gap: 10, color: "var(--vw-paper-ink)", textDecoration: "none" }}>
          <img src="assets/logo-mark.svg" width="26" height="26" alt=""/>
          <span style={{ fontFamily: "var(--vw-font-display)", fontWeight: 500, letterSpacing: "0.14em", fontSize: 15 }}>VOIDWALL</span>
        </a>
        <nav style={{ display: "flex", gap: 28, marginLeft: 24 }}>
          {links.map(([l, href]) => (
            <a key={l} href={href} style={{
              fontFamily: "var(--vw-font-body)", fontSize: 14, color: "var(--vw-paper-ink-2)",
              textDecoration: "none",
            }}>{l}</a>
          ))}
        </nav>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
          <a href="/demo" target="_blank" rel="noopener noreferrer" className="vw-btn vw-btn--primary">
            Try the live demo <Icon name="external-link" size={14}/>
          </a>
          <a href="#early-adopters" className="vw-btn vw-btn--primary" style={{ background: "white", color: "var(--vw-void)" }}>
            Become early adopter <span className="arrow">→</span>
          </a>
        </div>
      </div>
    </header>
  );
}
window.Nav = Nav;
