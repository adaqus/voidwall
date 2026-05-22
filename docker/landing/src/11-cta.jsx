// CTA — void surface. Big "Try the live demo" with a small terminal-style preview.
function CTA() {
  return (
    <section id="demo" style={{ background: "var(--vw-void)", color: "var(--vw-void-ink)", borderTop: "1px solid var(--vw-void-line)" }}>
      <div className="vw-container" style={{ padding: "120px var(--gutter)" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)",
          gap: 80, alignItems: "center",
        }}>
          <div>
            <p className="vw-eyebrow" style={{ margin: "0 0 22px", color: "var(--vw-violet-300)" }}>
              Available now — early access
            </p>
            <h2 style={{
              fontFamily: "var(--vw-font-display)", fontSize: 64, fontWeight: 600,
              letterSpacing: "-0.025em", lineHeight: 0.98,
              color: "var(--vw-void-ink)", margin: "0 0 24px", textWrap: "balance",
            }}>
              Send a request.<br/>Watch it come back<br/><span style={{ color: "var(--vw-violet-400)" }}>clean.</span>
            </h2>
            <p style={{
              fontFamily: "var(--vw-font-body)", fontSize: 17, lineHeight: 1.55,
              color: "var(--vw-void-ink-2)", margin: "0 0 36px", maxWidth: 460,
            }}>
              The hosted demo accepts any JSON, CSV, TSV, or text payload — or a
              real GA4 / Matomo tracking hit — and returns it sanitized.
              No signup, no email, no install.
            </p>
            <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
              <a href="#" className="vw-btn vw-btn--primary">
                <Icon name="play" size={14}/> Open the demo <span className="arrow">→</span>
              </a>
              <a href="#" className="vw-btn vw-btn--ghost" style={{ color: "var(--vw-void-ink)" }}>
                <Icon name="github" size={16}/> View on GitHub <span className="arrow">→</span>
              </a>
            </div>
          </div>

          <Terminal/>
        </div>
      </div>
    </section>
  );
}

function Terminal() {
  return (
    <div style={{
      background: "var(--vw-void-2)",
      border: "1px solid var(--vw-void-line)",
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "0 28px 60px -24px rgba(139,125,246,0.35)",
    }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 10,
        padding: "12px 16px",
        borderBottom: "1px solid var(--vw-void-line)",
        fontFamily: "var(--vw-font-mono)", fontSize: 12,
        color: "var(--vw-void-ink-3)",
      }}>
        <span style={{ display: "flex", gap: 6 }}>
          <span style={{ width: 9, height: 9, borderRadius: 999, background: "var(--vw-void-line)" }}/>
          <span style={{ width: 9, height: 9, borderRadius: 999, background: "var(--vw-void-line)" }}/>
          <span style={{ width: 9, height: 9, borderRadius: 999, background: "var(--vw-void-line)" }}/>
        </span>
        <span style={{ flex: 1 }}>demo.voidwall.io — curl</span>
      </div>
      <pre style={{
        margin: 0, padding: "20px 22px",
        fontFamily: "var(--vw-font-mono)", fontSize: 12.5, lineHeight: 1.6,
        color: "var(--vw-void-ink)",
        whiteSpace: "pre-wrap", wordBreak: "break-word",
      }}>
        <span style={{ color: "var(--vw-void-ink-3)" }}>$ </span>
        <span style={{ color: "var(--vw-violet-300)" }}>curl</span>
        {" -sX POST https://demo.voidwall.io/v1/scan \\"}
        {"\n  -H 'content-type: application/json' \\"}
        {"\n  -d '{\""}<span style={{ color: "#C8A35F" }}>email</span>{"\":\""}
        <span style={{ color: "var(--vw-danger)" }}>s.dupont@acme.fr</span>
        {"\",\""}<span style={{ color: "#C8A35F" }}>phone</span>{"\":\""}
        <span style={{ color: "var(--vw-danger)" }}>+33 6 12 34 56 78</span>{"\"}'\n\n"}

        <span style={{ color: "var(--vw-void-ink-3)" }}>{"HTTP/1.1 200 OK"}</span>{"\n"}
        <span style={{ color: "var(--vw-void-ink-3)" }}>{"x-voidwall-findings: 2 matches, 0 blocked"}</span>{"\n"}
        <span style={{ color: "var(--vw-void-ink-3)" }}>{"x-voidwall-latency: 0.9ms"}</span>{"\n\n"}
        {"{\n  \""}<span style={{ color: "#C8A35F" }}>email</span>{"\": \""}
        <span style={{ color: "var(--vw-violet-300)" }}>{"<email>"}</span>{"\",\n  \""}
        <span style={{ color: "#C8A35F" }}>phone</span>{"\": \""}
        <span style={{ color: "var(--vw-violet-300)" }}>{"<phone:fr>"}</span>{"\"\n}"}
      </pre>
    </div>
  );
}

window.CTA = CTA;
