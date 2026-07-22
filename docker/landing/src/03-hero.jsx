// Hero - paper surface, left text column, right "wall" illustration with traffic flow.

function Hero() {
  return (
    <section className="vw-container" style={{ paddingTop: 56, paddingBottom: 88 }}>
      <div className="r-hero" style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 48, alignItems: "center" }}>
        {/* Left */}
        <div>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, marginBottom: 22 }}>
            <span style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              height: 24, padding: "0 10px",
              border: "1px solid var(--vw-paper-line)",
              borderRadius: 999,
              fontFamily: "var(--vw-font-body)", fontSize: 11,
              letterSpacing: "0.12em", textTransform: "uppercase",
              color: "var(--vw-paper-ink-2)",
              background: "rgba(255,255,255,0.5)",
            }}>
              <span style={{ width: 6, height: 6, borderRadius: 999, background: "var(--vw-violet-400)" }}/>
              Live demo available - early access
            </span>
          </div>
          <h1 className="r-hero-h1" style={{
            fontFamily: "var(--vw-font-display)",
            fontWeight: 600, fontSize: 60, lineHeight: 1.0,
            letterSpacing: "-0.025em",
            color: "var(--vw-paper-ink)",
            margin: "0 0 28px",
            textWrap: "balance",
            minHeight: 120,
          }}>
            <span style={{ color: "var(--vw-violet-400)" }}>Ultra-fast</span> PII detection inside your infrastructure
          </h1>
          <p style={{
            fontFamily: "var(--vw-font-body)", fontSize: 17, lineHeight: 1.55,
            color: "var(--vw-paper-ink-2)", maxWidth: 480,
            margin: "0 0 24px",
          }}>
            Voidwall is a self-hosted HTTP proxy and API that detects PII across HTTP, API, and AI traffic.
          </p>
          <ul style={{
            listStyle: "none", margin: "0 0 36px", padding: 0,
            display: "flex", flexDirection: "column", gap: 12, maxWidth: 480,
          }}>
            {[
              "Predictable infrastructure costs",
              "Single-digit millisecond latency (P99)",
              "Scales to thousands of PII types",
              "Add custom PII types without retraining models",
            ].map((point) => (
              <li key={point} style={{
                display: "flex", alignItems: "center", gap: 10,
                fontFamily: "var(--vw-font-body)", fontSize: 16, lineHeight: 1.4,
                color: "var(--vw-paper-ink)",
              }}>
                <span style={{
                  flex: "0 0 auto", display: "inline-flex", alignItems: "center", justifyContent: "center",
                  color: "var(--vw-violet-400)",
                }}>
                  <Icon name="check" size={18}/>
                </span>
                {point}
              </li>
            ))}
          </ul>
          <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
            <a href="/demo" target="_blank" rel="noopener noreferrer" className="vw-btn vw-btn--primary">
              Try the live demo <Icon name="external-link" size={14}/>
            </a>
            <a href="#early-adopters" className="vw-btn vw-btn--primary" style={{ background: "white", color: "var(--vw-void)" }}>
              Become early adopter <span className="arrow">→</span>
            </a>
          </div>
        </div>

        {/* Right - wall illustration + traffic flow */}
        <div className="r-hero-art" style={{ position: "relative", width: "100%", aspectRatio: "600/520" }}>
          <img src="assets/hero-wall.svg" alt="" style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }}/>

          {/* Voidwall logo - centered on the vertical axis of the wall below (wall center ≈ 57% across 600px viewBox) */}
          <img src="assets/logo.svg" alt="Voidwall" style={{
            position: "absolute",
            top: "0.5%",
            left: "57%",
            transform: "translateX(-50%)",
            height: 26,
            width: "auto",
            pointerEvents: "none",
          }}/>

          {/* Sample data crossing the wall - y% matches line origins in hero-wall.svg (viewBox 600×520) */}
          {[
            { label: "JSON",       topPct: 170 / 520 },
            { label: "URL",        topPct: 220 / 520 },
            { label: "CSV",        topPct: 270 / 520 },
            { label: "TSV",        topPct: 320 / 520 },
            { label: "Plain text", topPct: 370 / 520 },
          ].map(({ label, topPct }) => (
            <div key={label} style={{
              position: "absolute",
              top: `${topPct * 100}%`,
              left: "1.5%",
              transform: "translateY(-50%)",
              pointerEvents: "none",
            }}>
              <DataChip label={label}/>
            </div>
          ))}

          {/* Env list - protected side (right of the wall). Y% matches outgoing lines in hero-wall.svg. */}
          {[
            { icon: "box",     label: "LLMs",                 topPct: 160 / 520 },
            { icon: "wrench",  label: "Agents",               topPct: 204 / 520 },
            { icon: "chart",   label: "Web Analytics",        topPct: 248 / 520 },
            { icon: "server",  label: "CDPs",                 topPct: 292 / 520 },
            { icon: "audit",   label: "Logs",                 topPct: 336 / 520 },
            { icon: "globe",   label: "Other third parties",  topPct: 380 / 520 },
          ].map(({ icon, label, topPct }) => (
            <div key={label} style={{
              position: "absolute",
              top: `${topPct * 100}%`,
              left: "78.3%",
              transform: "translateY(-50%)",
              pointerEvents: "none",
            }}>
              <EnvItem icon={icon} label={label}/>
            </div>
          ))}
        </div>
      </div>

      {/* Tracker-specific specializations - surfaces the two flagship integrations */}
      {/* <div style={{ marginTop: 56 }}>
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 18 }}>
          <span className="vw-eyebrow">Specializations</span>
          <a href="#integrations" style={{
            fontFamily: "var(--vw-font-body)", fontSize: 13,
            color: "var(--vw-paper-ink-2)", textDecoration: "none",
          }}>All integrations <span style={{ color: "var(--vw-violet-400)" }}>→</span></a>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0,1fr))", gap: 20 }}>
          <SpecCard
            mark="GA4"
            name="Google Analytics 4"
            tagline="Sanitizes gtag and /collect payloads."
            details="Strips client_id, user_id, user properties, and resolves the IP to a /24 before the request crosses your perimeter. Works inline against measurement protocol v2 and gtag.js."
            params={["client_id", "user_id", "user_properties", "ip_override", "geo_*"]}
          />
          <SpecCard
            mark="Matomo"
            name="Matomo"
            tagline="Inspects /matomo.php and bulk tracking."
            details="Filters _id, uid, urlref, and custom dimensions in real time. Honours per-site policies, including PiwikPro deployments, with zero changes to the tracking snippet."
            params={["_id", "uid", "urlref", "dimensionN", "custom_vars"]}
          />
        </div>
      </div> */}
    </section>
  );
}

function SpecCard({ mark, name, tagline, details, params }) {
  return (
    <div style={{
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 12,
      background: "rgba(255,255,255,0.5)",
      padding: 22,
      display: "flex", flexDirection: "column", gap: 14,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{
          width: 36, height: 36, borderRadius: 8,
          border: "1px solid var(--vw-paper-line)",
          background: "#fff",
          display: "inline-flex", alignItems: "center", justifyContent: "center",
          fontFamily: "var(--vw-font-mono)", fontSize: 11, fontWeight: 600,
          letterSpacing: "0.02em",
          color: "var(--vw-paper-ink)",
        }}>{mark}</span>
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <span style={{
            fontFamily: "var(--vw-font-display)", fontSize: 16, fontWeight: 600,
            color: "var(--vw-paper-ink)", letterSpacing: "-0.01em",
          }}>{name}</span>
          <span style={{
            fontFamily: "var(--vw-font-body)", fontSize: 12,
            color: "var(--vw-paper-ink-3)",
          }}>{tagline}</span>
        </div>
      </div>
      <p style={{
        fontFamily: "var(--vw-font-body)", fontSize: 13.5, lineHeight: 1.55,
        color: "var(--vw-paper-ink-2)", margin: 0,
        textWrap: "pretty",
      }}>{details}</p>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 2 }}>
        {params.map(p => (
          <span key={p} style={{
            fontFamily: "var(--vw-font-mono)", fontSize: 11,
            color: "var(--vw-paper-ink-2)",
            background: "var(--vw-paper-2)",
            border: "1px solid var(--vw-paper-line)",
            borderRadius: 6,
            padding: "3px 7px",
          }}>{p}</span>
        ))}
      </div>
    </div>
  );
}

function DataChip({ label }) {
  return (
    <div style={{
      display: "inline-flex", alignItems: "center", gap: 8,
      fontFamily: "var(--vw-font-mono)", fontSize: 11.5,
      color: "var(--vw-paper-ink)",
      background: "rgba(255,255,255,0.75)",
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 6,
      padding: "6px 10px",
      alignSelf: "flex-start",
    }}>
      <span style={{
        width: 6, height: 6, borderRadius: 999,
        background: "var(--vw-violet-400)",
      }}/>
      {label}
    </div>
  );
}

function RequestRow({ method, path, payload }) {
  return (
    <div style={{
      display: "inline-flex", alignItems: "center", gap: 10,
      fontFamily: "var(--vw-font-mono)", fontSize: 11.5,
      color: "var(--vw-paper-ink-2)",
      background: "rgba(255,255,255,0.7)",
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 6,
      padding: "5px 9px",
      maxWidth: 260,
    }}>
      <span style={{ color: "var(--vw-violet-500)", fontWeight: 600 }}>{method}</span>
      <span style={{ color: "var(--vw-paper-ink)" }}>{path}</span>
      <span style={{ color: "var(--vw-paper-ink-3)" }}>· </span>
      {payload.map(([k, v, sensitive], i) => (
        <span key={i} style={{ color: "var(--vw-paper-ink-3)" }}>
          {k}=<span style={{
            color: sensitive ? "var(--vw-danger)" : "var(--vw-paper-ink-2)",
            textDecoration: sensitive ? "line-through" : "none",
            textDecorationColor: "var(--vw-danger)",
          }}>{v}</span>
        </span>
      ))}
    </div>
  );
}

function EnvItem({ icon, label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, fontFamily: "var(--vw-font-body)", fontSize: 14, color: "var(--vw-paper-ink)", whiteSpace: "nowrap" }}>
      <span style={{
        width: 32, height: 32, border: "1px solid var(--vw-paper-line)", borderRadius: 8,
        background: "#fff", display: "inline-flex", alignItems: "center", justifyContent: "center",
        color: "var(--vw-paper-ink)",
      }}>
        <Icon name={icon} size={16}/>
      </span>
      {label}
    </div>
  );
}

window.Hero = Hero;
