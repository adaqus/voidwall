// Formats — void surface. Tabbed code pane: JSON / CSV / TSV / plain text.
// React state drives the active tab.
function Formats() {
  const [tab, setTab] = React.useState("json");

  const samples = {
    json: {
      label: "JSON",
      icon: "file-json",
      before:
`{
  "order_id": "A-2186",
  "customer": {
    "name": "Sarah Dupont",
    "email": "s.dupont@acme.fr",
    "phone": "+33 6 12 34 56 78",
    "nir": "2 85 04 75 116 042 89"
  },
  "billing_iban": "FR76 3000 4012 3456 7890 1234 567",
  "notes": "Address: 12 rue de Belleville, 75011 Paris"
}`,
      after:
`{
  "order_id": "A-2186",
  "customer": {
    "name": "<name>",
    "email": "<email>",
    "phone": "<phone:fr>",
    "nir": "<fr.nir>"
  },
  "billing_iban": "<iban>",
  "notes": "Address: <address:fr>"
}`,
    },
    csv: {
      label: "CSV",
      icon: "table",
      before:
`order_id,customer_name,email,phone,iban,country
A-2186,Sarah Dupont,s.dupont@acme.fr,+33 6 12 34 56 78,FR76 3000 4012 3456 7890 1234 567,FR
A-2187,Klaus Weber,klaus.w@example.de,+49 30 9876 5432,DE89 3704 0044 0532 0130 00,DE
A-2188,Anna Rossi,a.rossi@example.it,+39 320 555 11 22,IT60 X054 2811 1010 0000 0123 456,IT`,
      after:
`order_id,customer_name,email,phone,iban,country
A-2186,<name>,<email>,<phone:fr>,<iban>,FR
A-2187,<name>,<email>,<phone:de>,<iban>,DE
A-2188,<name>,<email>,<phone:it>,<iban>,IT`,
    },
    tsv: {
      label: "TSV",
      icon: "table",
      before:
`event_id\tuser_id\temail\tip\tquery
e_4471\t1822\talex@acme.io\t203.0.113.42\thotels in Berlin
e_4472\t1923\tklaus.weber@example.de\t94.245.66.10\tbsn 1234 56 789
e_4473\t1924\ta.rossi@example.it\t82.85.10.5\tcodice fiscale RSSMRA`,
      after:
`event_id\tuser_id\temail\tip\tquery
e_4471\tsha256:b1…\t<email>\t203.0.113.0\thotels in Berlin
e_4472\tsha256:7c…\t<email>\t94.245.66.0\t<nl.bsn>
e_4473\tsha256:9a…\t<email>\t82.85.10.0\t<it.codice_fiscale>`,
    },
    text: {
      label: "Plain text",
      icon: "text",
      before:
`Hi support,

I never received my order A-2186. My email on the account is
s.dupont@acme.fr and my phone is +33 6 12 34 56 78. I paid with
my Visa 4539 1488 0343 6467 on the 14th. Please check.

— Sarah`,
      after:
`Hi support,

I never received my order A-2186. My email on the account is
<email> and my phone is <phone:fr>. I paid with
my Visa <credit_card> on the 14th. Please check.

— <name>`,
    },
  };

  const current = samples[tab];

  return (
    <section className="vw-container" style={{ padding: "60px var(--gutter) 80px", borderTop: "1px solid var(--vw-void-line)" }}>
      <div className="vw-section-head" style={{ marginBottom: 40 }}>
        <div>
          <p className="vw-eyebrow" style={{ margin: "0 0 18px" }}>Format-aware</p>
          <h2 style={{
            fontFamily: "var(--vw-font-display)", fontSize: 44, fontWeight: 600,
            letterSpacing: "-0.025em", lineHeight: 1.02,
            color: "var(--vw-void-ink)", margin: 0, textWrap: "balance",
          }}>
            Four payload formats.<br/>Same rules.
          </h2>
        </div>
        <p style={{
          fontFamily: "var(--vw-font-body)", fontSize: 16, lineHeight: 1.55,
          color: "var(--vw-void-ink-2)", margin: 0, maxWidth: 460,
        }}>
          Voidwall parses the body before it scans it. Whether the
          payload is a nested JSON document, a flat CSV upload, a
          tab-separated tracking hit, or free-form text in a support
          message, the same matchers apply.
        </p>
      </div>

      {/* Tabs */}
      <div style={{
        display: "flex", gap: 4, marginBottom: 16,
        borderBottom: "1px solid var(--vw-void-line)",
      }}>
        {Object.entries(samples).map(([key, s]) => {
          const active = tab === key;
          return (
            <button
              key={key}
              onClick={() => setTab(key)}
              style={{
                appearance: "none", background: "transparent", cursor: "pointer",
                border: 0,
                padding: "12px 18px",
                borderBottom: `2px solid ${active ? "var(--vw-violet-400)" : "transparent"}`,
                marginBottom: -1,
                display: "inline-flex", alignItems: "center", gap: 8,
                fontFamily: "var(--vw-font-body)", fontSize: 13.5, fontWeight: 500,
                color: active ? "var(--vw-void-ink)" : "var(--vw-void-ink-2)",
                transition: "color .18s var(--vw-ease-out), border-color .18s var(--vw-ease-out)",
              }}
            >
              <Icon name={s.icon} size={16}/> {s.label}
            </button>
          );
        })}
      </div>

      <div style={{
        display: "grid", gridTemplateColumns: "1fr 1fr",
        gap: 0,
        background: "var(--vw-void-2)",
        border: "1px solid var(--vw-void-line)",
        borderRadius: 14,
        overflow: "hidden",
      }}>
        <CodePane title="Inbound" payload={current.before} bad/>
        <CodePane title="Outbound" payload={current.after}/>
      </div>
    </section>
  );
}

function CodePane({ title, payload, bad }) {
  return (
    <div style={{
      borderRight: bad ? "1px solid var(--vw-void-line)" : "0",
      background: bad ? "transparent" : "rgba(139,125,246,0.04)",
    }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 8,
        padding: "12px 18px",
        borderBottom: "1px solid var(--vw-void-line)",
        fontFamily: "var(--vw-font-body)", fontSize: 11,
        letterSpacing: "0.14em", textTransform: "uppercase",
        color: bad ? "var(--vw-void-ink-3)" : "var(--vw-violet-300)",
      }}>
        <span style={{
          width: 6, height: 6, borderRadius: 999,
          background: bad ? "var(--vw-danger)" : "var(--vw-violet-400)",
        }}/>
        {title}
      </div>
      <pre style={{
        margin: 0, padding: "18px 20px",
        fontFamily: "var(--vw-font-mono)", fontSize: 12.5, lineHeight: 1.6,
        color: "var(--vw-void-ink)",
        whiteSpace: "pre",
        overflow: "auto",
        minHeight: 260,
      }}>{highlight(payload, bad)}</pre>
    </div>
  );
}

// Crude highlighter — wraps sensitive runs in red, placeholders in violet.
function highlight(text, bad) {
  if (bad) {
    const re = /(Sarah Dupont|s\.dupont@acme\.fr|\+33 6 12 34 56 78|2 85 04 75 116 042 89|FR76 3000 4012 3456 7890 1234 567|Address: 12 rue de Belleville, 75011 Paris|Klaus Weber|klaus\.w@example\.de|\+49 30 9876 5432|DE89 3704 0044 0532 0130 00|Anna Rossi|a\.rossi@example\.it|\+39 320 555 11 22|IT60 X054 2811 1010 0000 0123 456|alex@acme\.io|203\.0\.113\.42|klaus\.weber@example\.de|94\.245\.66\.10|82\.85\.10\.5|bsn 1234 56 789|codice fiscale RSSMRA|4539 1488 0343 6467)/g;
    return splitWith(text, re, (m, i) => (
      <span key={i} style={{ color: "var(--vw-danger)", background: "rgba(229,86,75,0.12)", borderRadius: 3 }}>{m}</span>
    ));
  } else {
    const re = /(<[^>]+>|sha256:[a-z0-9…]+)/g;
    return splitWith(text, re, (m, i) => (
      <span key={i} style={{ color: "var(--vw-violet-300)" }}>{m}</span>
    ));
  }
}

function splitWith(text, regex, wrap) {
  const out = [];
  let last = 0;
  let m;
  let i = 0;
  regex.lastIndex = 0;
  while ((m = regex.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(wrap(m[0], i++));
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

window.Formats = Formats;
