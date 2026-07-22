// Single blog post - paper surface, narrow reading column. Rendered at
// /blog/<slug>/ (see the router in 15-app.jsx). The post body is pre-rendered
// HTML (markdown → HTML at build time) injected into a .vw-prose container.
function BlogPost({ slug }) {
  const post = (window.POSTS || []).find(p => p.slug === slug);
  const [zoom, setZoom] = React.useState(null);

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

          <h1 className="r-page-h1" style={{
            fontFamily: "var(--vw-font-display)", fontSize: 46, fontWeight: 600,
            letterSpacing: "-0.025em", lineHeight: 1.04,
            color: "var(--vw-paper-ink)", margin: "0 0 40px", textWrap: "balance",
          }}>{post.title}</h1>

          {/* Tap any figure to open it in the lightbox. Delegated from the
              container because the prose HTML is injected, not React-managed. */}
          <div
            className="vw-prose"
            onClick={(e) => {
              if (e.target.tagName === "IMG") {
                setZoom({ src: e.target.currentSrc || e.target.src, alt: e.target.alt });
              }
            }}
            dangerouslySetInnerHTML={{ __html: post.html }}
          />
        </article>
      </main>
      <Footer/>
      {zoom && <Lightbox src={zoom.src} alt={zoom.alt} onClose={() => setZoom(null)}/>}
    </>
  );
}

// Full-screen image zoom for blog-post figures. The image renders at up to its
// natural size and the overlay scrolls, so wide images (e.g. the example-text
// strip) can be panned for detail on small screens. Close via the button,
// a tap on the backdrop, or Escape.
function Lightbox({ src, alt, onClose }) {
  React.useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [onClose]);

  return (
    <div onClick={onClose} style={{
      position: "fixed", inset: 0, zIndex: 100,
      background: "rgba(10,14,26,0.92)",
      overflow: "auto", cursor: "zoom-out",
    }}>
      {/* inline-flex sizes to the image but stays at least viewport-sized, so
          the picture centres when it fits and both scroll edges stay reachable
          when it doesn't. */}
      <div style={{
        display: "inline-flex", minWidth: "100%", minHeight: "100%",
        boxSizing: "border-box", padding: 24,
        alignItems: "center", justifyContent: "center",
      }}>
        <img src={src} alt={alt} onClick={(e) => e.stopPropagation()} style={{
          display: "block", maxWidth: 1600, borderRadius: 8, cursor: "default",
          boxShadow: "0 24px 60px -20px rgba(0,0,0,0.6)",
        }}/>
      </div>
      <button onClick={onClose} aria-label="Close image" style={{
        position: "fixed", top: 16, right: 16, width: 40, height: 40,
        display: "inline-flex", alignItems: "center", justifyContent: "center",
        background: "rgba(244,242,238,0.14)",
        border: "1px solid rgba(244,242,238,0.28)",
        borderRadius: 8, color: "var(--vw-void-ink)", cursor: "pointer",
      }}>
        <Icon name="x" size={20}/>
      </button>
    </div>
  );
}

window.BlogPost = BlogPost;
