// Coverage — void surface. The breadth-of-detection story.
// 80+ PII types organized by category, plus languages + countries strip.
function Coverage() {
  const groups = [
    {
      title: "Identity",
      icon: "id-card",
      items: [
        ["Full name", true],
        ["Email", true],
        ["Phone number", true],
        ["Date of birth", false],
        ["Passport no.", true],
        ["National ID", true],
        ["Driver's licence", false],
        ["Tax ID", false],
      ],
    },
    {
      title: "Financial",
      icon: "credit-card",
      items: [
        ["IBAN", true],
        ["Credit card", true],
        ["SWIFT / BIC", false],
        ["Bank routing", false],
        ["VAT number", false],
        ["Crypto wallet", true],
        ["Account no.", false],
      ],
    },
    {
      title: "Locale-specific",
      icon: "flag",
      items: [
        ["US — SSN", true],
        ["UK — NI no.", false],
        ["FR — NIR", true],
        ["FR — SIREN", false],
        ["DE — Steuer-ID", true],
        ["NL — BSN", false],
        ["IT — Codice Fiscale", false],
        ["PL — PESEL", false],
        ["ES — DNI", false],
        ["CA — SIN", false],
      ],
    },
    {
      title: "Technical",
      icon: "fingerprint",
      items: [
        ["IPv4 / IPv6", true],
        ["MAC address", false],
        ["URL with token", false],
        ["JWT", true],
        ["API key", true],
        ["Cookie ID", false],
        ["Device fingerprint", false],
      ],
    },
  ];

  const languages = [
    ["EN", "English"],
    ["FR", "Français"],
    ["DE", "Deutsch"],
  ];

  const countries = [
    "United States", "United Kingdom", "France", "Germany",
    "Netherlands", "Italy", "Spain", "Poland",
    "Belgium", "Canada", "Switzerland",
  ];

  return (
    <section id="detection" className="vw-container" style={{ padding: "60px var(--gutter) 80px", borderTop: "1px solid var(--vw-void-line)" }}>
      <div style={{
        display: "grid", gridTemplateColumns: "minmax(0, 0.7fr) minmax(0, 1.3fr)",
        gap: 80, alignItems: "start",
      }}>
        <div style={{ position: "sticky", top: 100 }}>
          <p className="vw-eyebrow" style={{ margin: "0 0 18px" }}>Detection coverage</p>
          <h2 style={{
            fontFamily: "var(--vw-font-display)", fontSize: 44, fontWeight: 600,
            letterSpacing: "-0.025em", lineHeight: 1.02,
            color: "var(--vw-void-ink)", margin: "0 0 22px", textWrap: "balance",
          }}>
            Over 80 PII types.<br/>Three languages.<br/>Eleven countries.
          </h2>
          <p style={{
            fontFamily: "var(--vw-font-body)", fontSize: 15.5, lineHeight: 1.6,
            color: "var(--vw-void-ink-2)", margin: "0 0 28px", maxWidth: 400,
          }}>
            Detectors are context-aware and locale-specific. A French
            NIR isn't a German Steuer-ID, even when the digits collide.
            Voidwall reads the field name, the values around it, and
            the route — then decides.
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 28 }}>
            <span className="vw-eyebrow vw-eyebrow--muted">Languages</span>
            <div style={{ display: "flex", gap: 8 }}>
              {languages.map(([code, name]) => (
                <div key={code} style={{
                  display: "inline-flex", alignItems: "center", gap: 8,
                  padding: "8px 12px",
                  border: "1px solid var(--vw-void-line)",
                  borderRadius: 8,
                  fontFamily: "var(--vw-font-mono)", fontSize: 12,
                  color: "var(--vw-void-ink)",
                }}>
                  <span style={{ color: "var(--vw-violet-300)", fontWeight: 600 }}>{code}</span>
                  <span style={{ color: "var(--vw-void-ink-3)" }}>{name}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <span className="vw-eyebrow vw-eyebrow--muted">Countries — and growing</span>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {countries.map(c => (
                <span key={c} style={{
                  display: "inline-flex", alignItems: "center",
                  height: 26, padding: "0 10px",
                  border: "1px solid var(--vw-void-line)",
                  borderRadius: 999,
                  fontFamily: "var(--vw-font-body)", fontSize: 12,
                  color: "var(--vw-void-ink-2)",
                  whiteSpace: "nowrap",
                }}>{c}</span>
              ))}
              <span style={{
                display: "inline-flex", alignItems: "center", gap: 4,
                height: 26, padding: "0 10px",
                borderRadius: 999,
                fontFamily: "var(--vw-font-body)", fontSize: 12,
                color: "var(--vw-violet-300)",
              }}>
                <Icon name="plus" size={12}/> more soon
              </span>
            </div>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 16 }}>
          {groups.map(g => (
            <div key={g.title} style={{
              background: "var(--vw-void-2)",
              border: "1px solid var(--vw-void-line)",
              borderRadius: 14,
              padding: "20px 22px",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 18 }}>
                <span style={{ color: "var(--vw-violet-300)", display: "inline-flex" }}>
                  <Icon name={g.icon} size={18}/>
                </span>
                <h4 style={{
                  fontFamily: "var(--vw-font-display)", fontSize: 14, fontWeight: 600,
                  letterSpacing: "0.02em", textTransform: "uppercase",
                  color: "var(--vw-void-ink)", margin: 0,
                }}>{g.title}</h4>
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {g.items.map(([label, hot]) => (
                  <span key={label} style={{
                    display: "inline-flex", alignItems: "center",
                    height: 28, padding: "0 11px",
                    border: `1px solid ${hot ? "var(--vw-violet-400)" : "var(--vw-void-line)"}`,
                    borderRadius: 8,
                    fontFamily: "var(--vw-font-body)", fontSize: 12.5,
                    color: hot ? "var(--vw-violet-200)" : "var(--vw-void-ink-2)",
                    background: hot ? "rgba(139,125,246,0.08)" : "transparent",
                    whiteSpace: "nowrap",
                  }}>{label}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
window.Coverage = Coverage;
