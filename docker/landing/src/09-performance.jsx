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
            Voidwall is written to disappear behind the wire. It scales
            horizontally, runs in your cluster, and adds a budget you can
            measure in single-digit milliseconds. No external calls, no
            phone-home, no per-request fees.
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 24 }}>
          <PerfCard
            icon="gauge"
            eyebrow="Latency (p99)"
            big="1.2"
            unit="ms"
            sub="added per request, JSON payloads under 4 KiB"
            chart={<Bars values={[0.6, 0.8, 1.0, 1.1, 1.2]} labels={["p50", "p75", "p90", "p95", "p99"]}/>}
          />
          <PerfCard
            icon="trend-up"
            eyebrow="Throughput"
            big="38k"
            unit="req/s"
            sub="sustained per pod, four logical cores"
            chart={<Bars values={[8, 16, 24, 32, 38]} labels={["1c", "2c", "3c", "4c", "4c+"]}/>}
          />
          <PerfCard
            icon="wallet"
            eyebrow="Cost"
            big="0.7"
            unit="¢ / million req"
            sub="self-hosted, commodity hardware"
            chart={<CostBars/>}
          />
        </div>

        <div style={{
          marginTop: 56,
          display: "grid", gridTemplateColumns: "repeat(3, 1fr)",
          gap: 0,
        }}>
          {[
            ["zap", "Streaming parser", "Bodies are scanned as they arrive — no buffering large uploads in memory."],
            ["layers", "Horizontal scaling", "Stateless workers. Add a pod, get throughput. Drain a pod, get nothing else."],
            ["server", "Runs where you do", "Kubernetes, ECS, Nomad, bare metal, or a single VM. No managed plane."],
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
            height: `${(v / max) * 100}%`,
            background: i === values.length - 1 ? "var(--vw-violet-400)" : "var(--vw-paper-ink)",
            borderRadius: 3,
            minHeight: 6,
          }}/>
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
