// Performance — paper-band section. Highlights latency, throughput, and cost.
// Numbers are illustrative (no benchmarks shipped yet); keep them measured and lower-case.
function Performance() {
  return (
    <section id="performance" style={{ background: "var(--vw-paper)", borderTop: "1px solid var(--vw-void-line)" }}>
      <div className="vw-container" style={{ padding: "96px var(--gutter)" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "minmax(0, 0.9fr) minmax(0, 1.1fr)",
          gap: 64, alignItems: "end", marginBottom: 64,
        }}>
          <div>
            <p className="vw-eyebrow" style={{ margin: "0 0 18px", color: "var(--vw-violet-500)" }}>Performance</p>
            <h2 style={{
              fontFamily: "var(--vw-font-display)", fontSize: 44, fontWeight: 600,
              letterSpacing: "-0.025em", lineHeight: 1.02,
              color: "var(--vw-paper-ink)", margin: 0, textWrap: "balance",
            }}>
              Built for the<br/>edge of your stack.
            </h2>
          </div>
          <p style={{
            fontFamily: "var(--vw-font-body)", fontSize: 16, lineHeight: 1.55,
            color: "var(--vw-paper-ink-2)", margin: 0, maxWidth: 460,
          }}>
            Voidwall scales horizontally, runs in your cluster, and adds a budget you can
            measure in single-digit milliseconds. It's designed to be a lightweight, self-hosted service that 
            doesn't break the bank as you grow.
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 24 }}>
          <PerfCard
            icon="gauge"
            eyebrow="Latency (p99)"
            big="9.2"
            unit="ms"
            sub="added per request, payload size 10 KiB"
            chart={<Bars values={[2.6, 3.9, 5.3, 9.2]} labels={["p50", "p75", "p95", "p99"]}/>}
          />
          <PerfCard
            icon="trend-up"
            eyebrow="Request rate"
            big="32k"
            unit="req/s"
            sub="single container, 6 logical cores, 10 KiB payload"
            chart={<Bars values={[13, 22, 26, 32]} labels={["1c", "2c", "4c", "6c"]}/>}
          />
          <PerfCard
            icon="ram"
            eyebrow="Memory usage max"
            big="214"
            unit="MiB"
            sub="single container, 6 logical cores, 10 KiB payload"
          />
        </div>

        <div style={{
          marginTop: 56,
          display: "grid", gridTemplateColumns: "repeat(3, 1fr)",
          gap: 0,
        }}>
          {[
            ["scaling", "Horizontal scaling", "Stateless containers. Add a pod, get throughput. Drain a pod, get nothing else."],
            ["server", "Ships as a single container", "Pull the image and go. Runs entirely in your environment. No payloads leave your infrastructure."],
            ["code", "Proxy or API — your call", "Drop it inline as a reverse or forward proxy, or call the HTTP API to scan and redact on demand. Same engine, three ways to plug in."],
          ].map(([icon, title, body], i) => (
            <div key={title} style={{
              padding: "0 28px",
              borderLeft: i === 0 ? "0" : "1px solid var(--vw-paper-line)",
            }}>
              <span style={{
                width: 36, height: 36, borderRadius: 8,
                border: "1px solid var(--vw-paper-line)",
                display: "inline-flex", alignItems: "center", justifyContent: "center",
                color: "var(--vw-paper-ink)", marginBottom: 16, background: "#fff",
              }}>
                <Icon name={icon} size={18}/>
              </span>
              <h4 style={{
                fontFamily: "var(--vw-font-display)", fontSize: 17, fontWeight: 600,
                letterSpacing: "-0.01em", color: "var(--vw-paper-ink)", margin: "0 0 8px",
              }}>{title}</h4>
              <p style={{
                fontFamily: "var(--vw-font-body)", fontSize: 14, lineHeight: 1.55,
                color: "var(--vw-paper-ink-2)", margin: 0,
              }}>{body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function PerfCard({ icon, eyebrow, big, unit, sub, chart }) {
  return (
    <div style={{
      background: "#fff",
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 14,
      padding: "24px 24px 22px",
    }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 22 }}>
        <span style={{
          fontFamily: "var(--vw-font-body)", fontSize: 11,
          letterSpacing: "0.14em", textTransform: "uppercase",
          color: "var(--vw-paper-ink-3)",
        }}>{eyebrow}</span>
        <span style={{ color: "var(--vw-paper-ink-3)" }}>
          <Icon name={icon} size={16}/>
        </span>
      </div>
      <div style={{
        display: "flex", alignItems: "baseline", gap: 6,
        fontFamily: "var(--vw-font-display)", fontSize: 56, fontWeight: 600,
        letterSpacing: "-0.03em", lineHeight: 1,
        color: "var(--vw-paper-ink)",
        marginBottom: 8,
      }}>
        {big}
        <span style={{
          fontFamily: "var(--vw-font-body)", fontSize: 14, fontWeight: 500,
          letterSpacing: 0, color: "var(--vw-paper-ink-2)",
        }}>{unit}</span>
      </div>
      <p style={{
        fontFamily: "var(--vw-font-body)", fontSize: 13, lineHeight: 1.5,
        color: "var(--vw-paper-ink-2)", margin: "0 0 18px",
      }}>{sub}</p>
      {chart}
    </div>
  );
}

function Bars({ values, labels }) {
  const max = Math.max(...values);
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 10, height: 60, marginTop: 4 }}>
      {values.map((v, i) => (
        <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
          <div style={{
            width: "100%",
            height: `${(v / max) * 50}px`,
            background: i === values.length - 1 ? "var(--vw-violet-400)" : "var(--vw-paper-ink)",
            borderRadius: 3,
            minHeight: 6,
          }} title={values[i]} />
          <span style={{
            fontFamily: "var(--vw-font-mono)", fontSize: 10,
            color: "var(--vw-paper-ink-3)",
          }}>{labels[i]}</span>
        </div>
      ))}
    </div>
  );
}

function CostBars() {
  // Comparative: hosted DLP, self-hosted DLP-other, Voidwall.
  const rows = [
    ["Hosted DLP API", 100, "var(--vw-paper-ink)"],
    ["Voidwall",         0.7, "var(--vw-violet-400)"],
  ];
  const max = 100;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 4 }}>
      {rows.map(([label, v, color]) => (
        <div key={label}>
          <div style={{
            display: "flex", justifyContent: "space-between",
            fontFamily: "var(--vw-font-body)", fontSize: 11,
            color: "var(--vw-paper-ink-2)", marginBottom: 4,
          }}>
            <span>{label}</span>
            <span style={{ fontFamily: "var(--vw-font-mono)" }}>
              {v < 1 ? `${v}¢` : `$${(v/100).toFixed(2)}`}
            </span>
          </div>
          <div style={{ height: 6, background: "var(--vw-paper-2)", borderRadius: 3, overflow: "hidden" }}>
            <div style={{
              width: `${Math.max((v / max) * 100, 1.2)}%`,
              height: "100%", background: color,
            }}/>
          </div>
        </div>
      ))}
    </div>
  );
}

window.Performance = Performance;
