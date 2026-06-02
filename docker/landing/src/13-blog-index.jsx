// Blog index — paper surface. Full list of every post, reusing PostCard.
// Rendered at /blog/ (see the router in 15-app.jsx). Posts come from
// window.POSTS (generated from src/blog/posts/*.md by build.sh).
function BlogIndex() {
  const posts = window.POSTS || [];

  return (
    <>
      <Nav/>
      <main style={{ background: "var(--vw-paper)" }}>
        <div className="vw-container" style={{ padding: "96px var(--gutter)" }}>
          <div style={{ marginBottom: 56, maxWidth: 720 }}>
            <p className="vw-eyebrow" style={{ margin: "0 0 18px", color: "var(--vw-violet-500)" }}>Blog</p>
            <h1 style={{
              fontFamily: "var(--vw-font-display)", fontSize: 56, fontWeight: 600,
              letterSpacing: "-0.025em", lineHeight: 1.02,
              color: "var(--vw-paper-ink)", margin: "0 0 20px", textWrap: "balance",
            }}>
              Notes from the wall.
            </h1>
            <p style={{
              fontFamily: "var(--vw-font-body)", fontSize: 17, lineHeight: 1.55,
              color: "var(--vw-paper-ink-2)", margin: 0, textWrap: "pretty",
            }}>
              Engineering notes, detection deep-dives, and what we learn watching
              personal data move through real systems.
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 24 }}>
            {posts.map((p, i) => <PostCard key={i} {...p}/>)}
          </div>
        </div>
      </main>
      <Footer/>
    </>
  );
}

window.BlogIndex = BlogIndex;
