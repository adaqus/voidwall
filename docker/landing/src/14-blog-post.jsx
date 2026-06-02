// Single blog post — paper surface, narrow reading column. Rendered at
// /blog/<slug>/ (see the router in 15-app.jsx). The post body is pre-rendered
// HTML (markdown → HTML at build time) injected into a .vw-prose container.
function BlogPost({ slug }) {
  const post = (window.POSTS || []).find(p => p.slug === slug);

  if (!post) {
    return (
      <>
        <Nav/>
        <main style={{ background: "var(--vw-paper)" }}>
          <div className="vw-container" style={{ padding: "120px var(--gutter)", textAlign: "center" }}>
            <h1 style={{
              fontFamily: "var(--vw-font-display)", fontSize: 40, fontWeight: 600,
              color: "var(--vw-paper-ink)", margin: "0 0 16px",
            }}>Post not found.</h1>
            <a href="/blog/" className="vw-btn vw-btn--ghost"><span className="arrow">←</span> All posts</a>
          </div>
        </main>
        <Footer/>
      </>
    );
  }

  return (
    <>
      <Nav/>
      <main style={{ background: "var(--vw-paper)" }}>
        <article className="vw-container" style={{ maxWidth: 760, padding: "80px var(--gutter) 96px" }}>
          <a href="/blog/" className="vw-btn vw-btn--ghost" style={{ marginBottom: 40 }}>
            <span className="arrow">←</span> All posts
          </a>

          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 24 }}>
            <span style={{
              display: "inline-flex", alignItems: "center",
              height: 22, padding: "0 9px",
              fontFamily: "var(--vw-font-body)", fontSize: 11,
              letterSpacing: "0.12em", textTransform: "uppercase",
              color: "var(--vw-violet-500)",
              background: "rgba(139,125,246,0.12)",
              borderRadius: 4,
            }}>{post.tag}</span>
            <span style={{ fontFamily: "var(--vw-font-mono)", fontSize: 11.5, color: "var(--vw-paper-ink-3)" }}>{post.date}</span>
            <span style={{ fontFamily: "var(--vw-font-body)", fontSize: 13, color: "var(--vw-paper-ink-3)" }}>· {post.read}</span>
          </div>

          <h1 style={{
            fontFamily: "var(--vw-font-display)", fontSize: 46, fontWeight: 600,
            letterSpacing: "-0.025em", lineHeight: 1.04,
            color: "var(--vw-paper-ink)", margin: "0 0 40px", textWrap: "balance",
          }}>{post.title}</h1>

          <div className="vw-prose" dangerouslySetInnerHTML={{ __html: post.html }}/>
        </article>
      </main>
      <Footer/>
    </>
  );
}

window.BlogPost = BlogPost;
