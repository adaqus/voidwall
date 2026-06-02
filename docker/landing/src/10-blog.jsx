// Blog — paper surface. Three teaser cards + link to the index.
// Posts come from window.POSTS (generated from src/blog/posts/*.md by build.sh).
function Blog() {
  const posts = (window.POSTS || []).slice(0, 3);

  return (
    <section id="blog" style={{ background: "var(--vw-paper)", borderTop: "1px solid var(--vw-paper-line)" }}>
      <div className="vw-container" style={{ padding: "96px var(--gutter)" }}>
        <div style={{
          display: "flex", alignItems: "end", justifyContent: "space-between",
          marginBottom: 56, gap: 32,
        }}>
          <div>
            <p className="vw-eyebrow" style={{ margin: "0 0 18px", color: "var(--vw-violet-500)" }}>From the blog</p>
            <h2 style={{
              fontFamily: "var(--vw-font-display)", fontSize: 44, fontWeight: 600,
              letterSpacing: "-0.025em", lineHeight: 1.02,
              color: "var(--vw-paper-ink)", margin: 0, textWrap: "balance", maxWidth: 560,
            }}>
              Notes from the wall.
            </h2>
          </div>
          <a href="/blog/" className="vw-btn vw-btn--ghost">All posts <span className="arrow">→</span></a>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 24 }}>
          {posts.map((p, i) => <PostCard key={i} {...p}/>)}
        </div>
      </div>
    </section>
  );
}

function PostCard({ slug, tag, date, title, excerpt, read }) {
  return (
    <a href={`/blog/${slug}/`} style={{
      display: "flex", flexDirection: "column",
      background: "#fff",
      border: "1px solid var(--vw-paper-line)",
      borderRadius: 14,
      padding: 28,
      textDecoration: "none",
      transition: "box-shadow .18s var(--vw-ease-out), transform .18s var(--vw-ease-out)",
    }}
    onMouseEnter={e => {
      e.currentTarget.style.boxShadow = "0 6px 18px -6px rgba(10,14,26,0.18)";
    }}
    onMouseLeave={e => {
      e.currentTarget.style.boxShadow = "none";
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 28 }}>
        <span style={{
          display: "inline-flex", alignItems: "center",
          height: 22, padding: "0 9px",
          fontFamily: "var(--vw-font-body)", fontSize: 11,
          letterSpacing: "0.12em", textTransform: "uppercase",
          color: "var(--vw-violet-500)",
          background: "rgba(139,125,246,0.12)",
          borderRadius: 4,
        }}>{tag}</span>
        <span style={{ fontFamily: "var(--vw-font-mono)", fontSize: 11.5, color: "var(--vw-paper-ink-3)" }}>{date}</span>
      </div>
      <h3 style={{
        fontFamily: "var(--vw-font-display)", fontSize: 22, fontWeight: 600,
        letterSpacing: "-0.02em", lineHeight: 1.18,
        color: "var(--vw-paper-ink)", margin: "0 0 14px",
        textWrap: "balance", minHeight: 78,
      }}>{title}</h3>
      <p style={{
        fontFamily: "var(--vw-font-body)", fontSize: 14, lineHeight: 1.55,
        color: "var(--vw-paper-ink-2)", margin: "0 0 28px",
        textWrap: "pretty",
      }}>{excerpt}</p>
      <div style={{
        marginTop: "auto", display: "flex", alignItems: "center", justifyContent: "space-between",
        fontFamily: "var(--vw-font-body)", fontSize: 13,
      }}>
        <span style={{ color: "var(--vw-paper-ink-3)" }}>{read}</span>
        <span style={{ color: "var(--vw-violet-500)", display: "inline-flex", alignItems: "center", gap: 6 }}>
          Read <Icon name="arrow-right" size={14}/>
        </span>
      </div>
    </a>
  );
}

window.Blog = Blog;
window.PostCard = PostCard;
