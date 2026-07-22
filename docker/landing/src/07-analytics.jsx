// Analytics - void surface. GA4 + Matomo real-time scanning.
// Shows the same tracking event in raw vs. sanitized form, for each platform.
function Analytics() {
  return (
    <section id="specializations" className="vw-container" style={{ padding: "80px var(--gutter) 80px", borderTop: "1px solid var(--vw-void-line)" }}>
      <div className="vw-section-head" style={{ marginBottom: 56 }}>
        <div>
          <p className="vw-eyebrow" style={{ margin: "0 0 18px" }}>Analytics, sanitized</p>
          <h2 className="r-section-h2" style={{
            fontFamily: "var(--vw-font-display)", fontSize: 44, fontWeight: 600,
            letterSpacing: "-0.025em", lineHeight: 1.02,
            color: "var(--vw-void-ink)", margin: 0, textWrap: "balance",
          }}>
            Scan GA4 and Matomo<br/>traffic in real time.
          </h2>
        </div>
        <p style={{
          fontFamily: "var(--vw-font-body)", fontSize: 16, lineHeight: 1.55,
          color: "var(--vw-void-ink-2)", margin: 0, maxWidth: 460,
        }}>
          Front-end tracking is the leakiest path out of a product -
          marketing teams add events, users paste their PII to search bars,
          and personal data slips into Google or Matomo unnoticed. Even 20% of websites
          have this problem. Voidwall may be a proxy between your product and web analytics,
          preventing your users' personal data from leaking out.
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 24 }}>
        <PlatformCard
          name="Google Analytics 4"
          endpoint="POST  /g/collect"
          tag="ga4"
        />
        <PlatformCard
          name="Matomo"
          endpoint="POST  /matomo.php"
          tag="matomo"
        />
      </div>

      <p style={{
        fontFamily: "var(--vw-font-body)", fontSize: 16, lineHeight: 1.55,
        color: "var(--vw-void-ink-2)", margin: "32px 0 0", maxWidth: 1120,
      }}>
        Specializations know what to scan - catching sensitive data even
        inside doubly-encoded payloads. They also know what <em>not</em> to
        scan, so the integration keeps working as intended.
      </p>
    </section>
  );
}

function PlatformCard({ name, endpoint, tag }) {
  const ga4Raw = [
    ['v', '2'],
    ['tid', 'G-X8Q1ZRP7M2'],
    ['cid', '1822941715.1719583924'],
    ['dl', 'https://shop.acme.io/u/alex.miller@acme.io', true],
    ['dt', 'Order #4711 - alex.miller@acme.io', true],
    ['en', 'login'],
    ['ep.contact_phone', '+33 6 12 34 56 78', true],
    ['uid', 'alex.miller@acme.io', true],
    ['_uip', '203.0.113.42', true],
  ];
  const ga4San = [
    ['v', '2'],
    ['tid', 'G-X8Q1ZRP7M2'],
    ['cid', '1822941715.1719583924'],
    ['dl', 'https://shop.acme.io/u/[EMAIL]'],
    ['dt', 'Order #4711 - [EMAIL]'],
    ['en', 'login'],
    ['ep.contact_phone', '[FR_PHONE_NUMBER]'],
    ['uid', 'alex.miller@acme.io', false, 'by design'],
    ['_uip', '203.0.113.42', false, 'by design'],
  ];
  const matomoRaw = [
    ['idsite', '17'],
    ['rec', '1'],
    ['url', 'https://shop.acme.de/?email=klaus.weber@example.de', true],
    ['action_name', 'Login · Acme'],
    ['dimension2', 'klaus.weber@example.de', true],
    ['_cvar', '{"1":["email","klaus.weber@example.de"]}', true],
    ['_id', '8b3f1a92ee44c1d2'],
    ['uid', 'klaus.weber@example.de', true],
    ['cip', '94.245.66.10', true],
  ];
  const matomoSan = [
    ['idsite', '17'],
    ['rec', '1'],
    ['url', 'https://shop.acme.de/?email=[EMAIL]'],
    ['action_name', 'Login · Acme'],
    ['dimension2', '[EMAIL]'],
    ['_cvar', '{"1":["email","[EMAIL]"]}'],
    ['_id', '8b3f1a92ee44c1d2'],
    ['uid', 'klaus.weber@example.de', false, 'by design'],
    ['cip', '94.245.66.10', false, 'by design'],
  ];

  const raw = tag === "ga4" ? ga4Raw : matomoRaw;
  const san = tag === "ga4" ? ga4San : matomoSan;

  return (
    <div style={{
      background: "var(--vw-void-2)",
      border: "1px solid var(--vw-void-line)",
      borderRadius: 14,
      overflow: "hidden",
    }}>
      <div style={{
        padding: "16px 20px",
        borderBottom: "1px solid var(--vw-void-line)",
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ color: "var(--vw-violet-300)", display: "inline-flex" }}>
            <Icon name="activity" size={18}/>
          </span>
          <span style={{
            fontFamily: "var(--vw-font-display)", fontSize: 15, fontWeight: 600,
            color: "var(--vw-void-ink)",
          }}>{name}</span>
        </div>
        <code style={{
          fontFamily: "var(--vw-font-mono)", fontSize: 11.5,
          color: "var(--vw-void-ink-3)",
        }}>{endpoint}</code>
      </div>

      <div className="r-params" style={{ display: "grid", gridTemplateColumns: "1fr 1fr" }}>
        <ParamColumn label="Received" rows={raw}/>
        <ParamColumn label="Forwarded" rows={san} sanitized/>
      </div>
    </div>
  );
}

function ParamColumn({ label, rows, sanitized }) {
  return (
    <div style={{
      padding: "18px 20px",
      borderRight: sanitized ? "0" : "1px solid var(--vw-void-line)",
      background: sanitized ? "rgba(139,125,246,0.04)" : "transparent",
    }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 8, marginBottom: 14,
        fontFamily: "var(--vw-font-body)", fontSize: 10.5,
        letterSpacing: "0.14em", textTransform: "uppercase",
        color: sanitized ? "var(--vw-violet-300)" : "var(--vw-void-ink-3)",
      }}>
        <span style={{
          width: 6, height: 6, borderRadius: 999,
          background: sanitized ? "var(--vw-violet-400)" : "var(--vw-danger)",
        }}/>
        {label}
      </div>
      <div style={{
        display: "grid", gridTemplateColumns: "auto 1fr",
        rowGap: 6, columnGap: 12,
        fontFamily: "var(--vw-font-mono)", fontSize: 12,
      }}>
        {rows.map(([k, v, hot, tag], i) => (
          <React.Fragment key={i}>
            <span style={{ color: "var(--vw-void-ink-3)" }}>{k}</span>
            <span style={{
              color: hot ? "var(--vw-danger)" : "var(--vw-void-ink)",
              wordBreak: "break-all",
            }}>
              {v}
              {tag && (
                <span style={{
                  marginLeft: 6,
                  fontFamily: "var(--vw-font-body)",
                  fontSize: 10, letterSpacing: "0.06em", textTransform: "uppercase",
                  color: "var(--vw-success)",
                  border: "1px solid rgba(56,178,122,0.4)",
                  borderRadius: 3, padding: "0 5px",
                }}>{tag}</span>
              )}
            </span>
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

window.Analytics = Analytics;
