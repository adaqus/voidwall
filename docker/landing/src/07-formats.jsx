// Formats — void surface. Tabbed code pane: JSON / CSV / TSV / URL / plain text.
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
    "full_name": { "value": "Sarah Dupont" },
    "phone_number": { "primary": "+33 6 12 34 56 78" },
    "national_id": { "nir": "1 85 05 78 006 084 91" }
  },
  "billing": {
    "iban": { "formatted": "FR76 3000 6000 0112 3456 7890 189" }
  }
}`,
      after:
`{
  "order_id": "A-2186",
  "customer": {
    "full_name": { "value": "[PERSON_NAME]" },
    "phone_number": { "primary": "[PHONE_NUMBER]" },
    "national_id": { "nir": "[FR_NIR]" }
  },
  "billing": {
    "iban": { "formatted": "[IBAN]" }
  }
}`,
    },
    csv: {
      label: "CSV",
      icon: "table",
      before:
`order_id,customer_name,email,phone,iban
A-2186,Sarah Dupont,s.dupont@acme.fr,+33 6 12 34 56 78,FR76 3000 6000 0112 3456 7890 189
A-2187,Klaus Weber,klaus.w@example.de,+49 30 9876 5432,DE89 3704 0044 0532 0130 00
A-2188,Lisa Müller,lisa.m@example.ch,+41 79 123 45 67,CH93 0076 2011 6238 5295 7`,
      after:
`order_id,customer_name,email,phone,iban
A-2186,[PERSON_NAME],[EMAIL],[PHONE_NUMBER],[IBAN]
A-2187,[PERSON_NAME],[EMAIL],[PHONE_NUMBER],[IBAN]
A-2188,[PERSON_NAME],[EMAIL],[CH_PHONE_NUMBER],[IBAN]`,
    },
    tsv: {
      label: "TSV",
      icon: "table",
      before:
`event_id\tuser_id\temail\tip\tquery
e_4471\t1822\talex@acme.io\t203.0.113.42\thotels in Berlin
e_4472\t1923\tklaus.weber@example.de\t94.245.66.10\tIdNr 65929970489
e_4473\t1924\tm.weber@example.at\t82.85.10.5\tSVNR 1238150185`,
      after:
`event_id\tuser_id\temail\tip\tquery
e_4471\t1822\t[EMAIL]\t[IP_ADDRESS]\thotels in Berlin
e_4472\t1923\t[EMAIL]\t[IP_ADDRESS]\tIdNr [DE_STEUER_ID]
e_4473\t1924\t[EMAIL]\t[IP_ADDRESS]\tSVNR [AT_SVNR]`,
    },
    url: {
      label: "URL",
      icon: "link",
      before:
`GET /api/users/s.dupont@acme.fr/profile
GET /lookup?ssn=123-45-6789&card=4111111111111111
POST /track?uid=alex@acme.io&phone_number=555-123-4567
GET /search?user[first_name]=Sarah&user[last_name]=Dupont
GET /eth/0x1234567890abcdef1234567890abcdef12345678/balance`,
      after:
`GET /api/users/[EMAIL]/profile
GET /lookup?ssn=[US_SSN]&card=[CREDIT_CARD]
POST /track?uid=[EMAIL]&phone_number=[US_PHONE_NUMBER]
GET /search?user[first_name]=Sarah&user[last_name]=[PERSON_NAME]
GET /eth/[ETHEREUM_ADDRESS]/balance`,
    },
    text: {
      label: "Plain text",
      icon: "text",
      before:
`Hi support,

I never received my order A-2186. My email on the account is
s.dupont@acme.fr and my phone is +33 6 12 34 56 78. I paid with
my Visa 4539 1488 0343 6467 on the 14th. Please check.

Thanks!`,
      after:
`Hi support,

I never received my order A-2186. My email on the account is
[EMAIL] and my phone is [PHONE_NUMBER]. I paid with
my Visa [CREDIT_CARD] on the 14th. Please check.

Thanks!`,
    },
  };

  const current = samples[tab];

  return (
    <section id="formats" className="vw-container" style={{ padding: "60px var(--gutter) 80px", borderTop: "1px solid var(--vw-void-line)" }}>
      <div className="vw-section-head" style={{ marginBottom: 40 }}>
        <div>
          <p className="vw-eyebrow" style={{ margin: "0 0 18px" }}>Format-aware</p>
          <h2 style={{
            fontFamily: "var(--vw-font-display)", fontSize: 44, fontWeight: 600,
            letterSpacing: "-0.025em", lineHeight: 1.02,
            color: "var(--vw-void-ink)", margin: 0, textWrap: "balance",
          }}>
            Works well even with nested data.
          </h2>
        </div>
        <p style={{
          fontFamily: "var(--vw-font-body)", fontSize: 16, lineHeight: 1.55,
          color: "var(--vw-void-ink-2)", margin: 0, maxWidth: 460,
        }}>
          Voidwall parses the request before it scans it. Whether
          the payload is a nested JSON, a flat CSV, a
          tab-separated data, a URL packed with query
          parameters, or free-form text, the same matchers apply.
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
// Longer literals must come before substrings (e.g. "Sarah Dupont" before "Sarah")
// so the alternation picks the wider match at any given position.
function highlight(text, bad) {
  if (bad) {
    const re = /(Sarah Dupont|s\.dupont@acme\.fr|\+33 6 12 34 56 78|1 85 05 78 006 084 91|FR76 3000 6000 0112 3456 7890 189|12 rue de Belleville, 75011 Paris|Klaus Weber|klaus\.w@example\.de|klaus\.weber@example\.de|\+49 30 9876 5432|DE89 3704 0044 0532 0130 00|Lisa Müller|lisa\.m@example\.ch|\+41 79 123 45 67|CH93 0076 2011 6238 5295 7|alex@acme\.io|203\.0\.113\.42|94\.245\.66\.10|m\.weber@example\.at|82\.85\.10\.5|65929970489|1238150185|4539 1488 0343 6467|123-45-6789|4111111111111111|555-123-4567|0x1234567890abcdef1234567890abcdef12345678|Dupont)/g;
    return splitWith(text, re, (m, i) => (
      <span key={i} style={{ color: "var(--vw-danger)", background: "rgba(229,86,75,0.12)", borderRadius: 3 }}>{m}</span>
    ));
  } else {
    // Matches the proxy's TypeLabel redaction format: [SCREAMING_SNAKE_CASE].
    const re = /\[[A-Z][A-Z_]*\]/g;
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
