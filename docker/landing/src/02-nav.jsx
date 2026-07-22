// Nav - paper surface, wall mark + wordmark on the left, links + CTA on the right.
// Below desktop widths (see .r-nav-* rules in styles.css) the links + CTAs hide
// and a hamburger toggles the dropdown panel rendered under the bar.
function Nav() {
  // Anchors are written as "/#id" so they also work from subpages (e.g. the
  // blog), where the target sections don't exist on the current document.
  const links = [
    ["Product", "/#product"],
    ["Detection", "/#detection"],
    ["Specializations", "/#specializations"],
    ["Formats", "/#formats"],
    ["Performance", "/#performance"],
    ["Blog", "/blog/"],
  ];
  const [open, setOpen] = React.useState(false);
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
        <a href="/" style={{ display: "inline-flex", alignItems: "center", gap: 10, color: "var(--vw-paper-ink)", textDecoration: "none" }}>
          <img src={vwAsset("logo-mark.svg")} width="26" height="26" alt=""/>
          <span style={{ fontFamily: "var(--vw-font-display)", fontWeight: 500, letterSpacing: "0.14em", fontSize: 15 }}>VOIDWALL</span>
        </a>
        <nav className="r-nav-links" style={{ display: "flex", gap: 28, marginLeft: 24 }}>
          {links.map(([l, href]) => (
            <a key={l} href={href} style={{
              fontFamily: "var(--vw-font-body)", fontSize: 14, color: "var(--vw-paper-ink-2)",
              textDecoration: "none",
            }}>{l}</a>
          ))}
        </nav>
        <div className="r-nav-actions" style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
          <a href="/demo" target="_blank" rel="noopener noreferrer" className="vw-btn vw-btn--primary">
            Try the live demo <Icon name="external-link" size={14}/>
          </a>
          <a href="/#early-adopters" className="vw-btn vw-btn--primary" style={{ background: "white", color: "var(--vw-void)" }}>
            Become early adopter <span className="arrow">→</span>
          </a>
        </div>
        <button
          className="r-nav-toggle"
          onClick={() => setOpen(o => !o)}
          aria-label="Toggle menu"
          aria-expanded={open}
          style={{
            display: "none", marginLeft: "auto",
            width: 40, height: 40, alignItems: "center", justifyContent: "center",
            background: "transparent", border: "1px solid var(--vw-paper-line)",
            borderRadius: 8, color: "var(--vw-paper-ink)", cursor: "pointer",
          }}
        >
          <Icon name={open ? "x" : "menu"} size={20}/>
        </button>
      </div>

      {/* Mobile dropdown - hidden by default; revealed by the .r-nav-panel rule
          when data-open is set and the viewport is below the nav breakpoint. */}
      <div className="r-nav-panel" data-open={open ? "1" : "0"} style={{
        display: "none",
        background: "var(--vw-paper)",
        borderBottom: "1px solid var(--vw-paper-line)",
        padding: "8px var(--gutter) 20px",
      }}>
        <nav style={{ display: "flex", flexDirection: "column" }}>
          {links.map(([l, href]) => (
            <a key={l} href={href} onClick={() => setOpen(false)} style={{
              padding: "12px 0", fontFamily: "var(--vw-font-body)", fontSize: 16,
              color: "var(--vw-paper-ink)", textDecoration: "none",
              borderBottom: "1px solid var(--vw-paper-line)",
            }}>{l}</a>
          ))}
        </nav>
        <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 16 }}>
          <a href="/demo" target="_blank" rel="noopener noreferrer" className="vw-btn vw-btn--primary" style={{ justifyContent: "center" }}>
            Try the live demo <Icon name="external-link" size={14}/>
          </a>
          <a href="/#early-adopters" onClick={() => setOpen(false)} className="vw-btn vw-btn--primary" style={{ background: "white", color: "var(--vw-void)", justifyContent: "center" }}>
            Become early adopter <span className="arrow">→</span>
          </a>
        </div>
      </div>
    </header>
  );
}
window.Nav = Nav;
