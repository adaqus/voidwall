// CustomPII — void surface. YAML-style config + matched samples.
// Demonstrates user-defined detectors.
function CustomPII() {
  const yaml = [
    { t: "c", v: "# detectors/acme.yaml" },
    { t: "n" },
    { t: "k", v: "detector" }, { t: "p", v: ": " }, { t: "v", v: "acme_employee_id" }, { t: "n" },
    { t: "k", v: "language" },  { t: "p", v: ": " }, { t: "v", v: "[en, fr, de]" },     { t: "n" },
    { t: "k", v: "match" },     { t: "p", v: ":" },  { t: "n" },
    { t: "p", v: "  " }, { t: "k", v: "regex" },    { t: "p", v: ": " }, { t: "s", v: "ACME-[A-Z]{2}-\\d{6}" }, { t: "n" },
    { t: "p", v: "  " }, { t: "k", v: "context" },  { t: "p", v: ": " }, { t: "v", v: "[employee, badge, staff]" }, { t: "n" },
    { t: "p", v: "  " }, { t: "k", v: "confidence" }, { t: "p", v: ": " }, { t: "v", v: "high" }, { t: "n" },
    { t: "k", v: "action" },    { t: "p", v: ":" },  { t: "n" },
    { t: "p", v: "  " }, { t: "k", v: "transform" }, { t: "p", v: ": " }, { t: "v", v: "redact" }, { t: "n" },
    { t: "p", v: "  " }, { t: "k", v: "placeholder" }, { t: "p", v: ": " }, { t: "s", v: "<acme.employee>" }, { t: "n" },
    { t: "k", v: "scope" },     { t: "p", v: ":" },  { t: "n" },
    { t: "p", v: "  " }, { t: "k", v: "routes" },   { t: "p", v: ": " }, { t: "v", v: "[\"/api/*\", \"/g/collect\"]" }, { t: "n" },
  ];

  const matched = [
    { ok: true,  v: "ACME-NY-018442" },
    { ok: true,  v: "ACME-PR-720199" },
    { ok: true,  v: "ACME-LD-005512" },
    { ok: false, v: "ACME-tickets-2025", reason: "context missing" },
    { ok: false, v: "ACME-XX-00",        reason: "regex mismatch" },
  ];

  return (
    <section className="vw-container" style={{ padding: "60px var(--gutter) 80px", borderTop: "1px solid var(--vw-void-line)" }}>
      <div style={{
        display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)",
        gap: 56, alignItems: "center",
      }}>
        <div>
          <p className="vw-eyebrow" style={{ margin: "0 0 18px" }}>Your data, your rules</p>
          <h2 style={{
            fontFamily: "var(--vw-font-display)", fontSize: 44, fontWeight: 600,
            letterSpacing: "-0.025em", lineHeight: 1.02,
            color: "var(--vw-void-ink)", margin: "0 0 22px", textWrap: "balance",
          }}>
            Define your own<br/>PII types in YAML.
          </h2>
          <p style={{
            fontFamily: "var(--vw-font-body)", fontSize: 16, lineHeight: 1.6,
            color: "var(--vw-void-ink-2)", margin: "0 0 28px", maxWidth: 440,
          }}>
            Every business has personal data the built-in detectors will not know:
            internal employee IDs, customer numbers, project codenames, partner
            references. Add as many user-defined matchers as you need — with
            regex, context keywords, confidence thresholds, and per-route scope.
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 28 }}>
            {[
              "Hot-reloaded — no restart, no redeploy.",
              "Composable with built-in detectors.",
              "Versioned alongside the rest of your config.",
            ].map(t => (
              <div key={t} style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <span style={{ color: "var(--vw-violet-300)" }}><Icon name="check" size={14}/></span>
                <span style={{ fontFamily: "var(--vw-font-body)", fontSize: 14, color: "var(--vw-void-ink)" }}>{t}</span>
              </div>
            ))}
          </div>
          <a href="#" className="vw-btn vw-btn--link" style={{ color: "var(--vw-violet-300)" }}>
            See the matcher reference <span className="arrow">→</span>
          </a>
        </div>

        <div>
          <div style={{
            background: "var(--vw-void-2)",
            border: "1px solid var(--vw-void-line)",
            borderRadius: 14,
            overflow: "hidden",
          }}>
            <div style={{
              display: "flex", alignItems: "center", gap: 10,
              padding: "12px 16px",
              borderBottom: "1px solid var(--vw-void-line)",
              fontFamily: "var(--vw-font-mono)", fontSize: 12,
              color: "var(--vw-void-ink-3)",
            }}>
              <span style={{ display: "flex", gap: 6 }}>
                <span style={{ width: 8, height: 8, borderRadius: 999, background: "var(--vw-void-line)" }}/>
                <span style={{ width: 8, height: 8, borderRadius: 999, background: "var(--vw-void-line)" }}/>
                <span style={{ width: 8, height: 8, borderRadius: 999, background: "var(--vw-void-line)" }}/>
              </span>
              detectors/acme.yaml
            </div>
            <pre style={{
              margin: 0, padding: "18px 20px",
              fontFamily: "var(--vw-font-mono)", fontSize: 12.5, lineHeight: 1.7,
              color: "var(--vw-void-ink)",
              whiteSpace: "pre",
              overflow: "auto",
            }}>
              {yaml.map((tok, i) => {
                if (tok.t === "n") return "\n";
                if (tok.t === "c") return <span key={i} style={{ color: "var(--vw-void-ink-3)" }}>{tok.v}</span>;
                if (tok.t === "k") return <span key={i} style={{ color: "var(--vw-violet-300)" }}>{tok.v}</span>;
                if (tok.t === "s") return <span key={i} style={{ color: "#C8A35F" }}>"{tok.v}"</span>;
                if (tok.t === "v") return <span key={i} style={{ color: "var(--vw-void-ink)" }}>{tok.v}</span>;
                return <span key={i} style={{ color: "var(--vw-void-ink-3)" }}>{tok.v}</span>;
              })}
            </pre>
          </div>

          <div style={{
            marginTop: 16,
            background: "var(--vw-void-2)",
            border: "1px solid var(--vw-void-line)",
            borderRadius: 14,
            padding: "16px 18px",
          }}>
            <div style={{
              fontFamily: "var(--vw-font-body)", fontSize: 10.5,
              letterSpacing: "0.14em", textTransform: "uppercase",
              color: "var(--vw-void-ink-3)", marginBottom: 12,
            }}>Test results</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {matched.map((m, i) => (
                <div key={i} style={{
                  display: "grid", gridTemplateColumns: "20px 1fr auto",
                  gap: 10, alignItems: "center",
                  fontFamily: "var(--vw-font-mono)", fontSize: 12.5,
                }}>
                  <span style={{ color: m.ok ? "var(--vw-success)" : "var(--vw-void-ink-3)" }}>
                    <Icon name={m.ok ? "check" : "x"} size={14}/>
                  </span>
                  <span style={{ color: "var(--vw-void-ink)" }}>{m.v}</span>
                  <span style={{
                    fontFamily: "var(--vw-font-body)", fontSize: 11,
                    color: m.ok ? "var(--vw-success)" : "var(--vw-void-ink-3)",
                  }}>{m.ok ? "match" : m.reason}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
window.CustomPII = CustomPII;
