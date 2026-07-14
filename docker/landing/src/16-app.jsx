// Entry point - renders the landing page. The original standalone export
// used a Tweaks editor panel; the production build renders the components
// directly with a fixed headline variant.
function App() {
  return (
    <>
      <Nav/>
      <Hero/>
      <Metrics/>
      <div className="void-band vw-void">
        <Features/>
        <Coverage/>
        <Analytics/>
        <Formats/>
      </div>
      <Performance/>
      <Blog/>
      <CTA/>
      <Footer/>
    </>
  );
}

// Path-based router. Each route is pre-rendered to its own index.html by
// build.sh, so this only has to pick the view for the current page.
//
// We can't trust location.pathname directly: opened from disk (file://) it's an
// absolute filesystem path, not the site path. Instead we reconstruct the
// site-relative path from the page depth - the number of "../" in the asset
// base (set in 00-base.jsx) tells us how many trailing path segments belong to
// the site. That gives the same answer whether served or opened locally.
function Root() {
  const base = window.__VW_BASE__;
  const raw = window.location.pathname.replace(/\/index\.html$/, "/");

  let path;
  if (base.startsWith("/")) {
    // Absolute base (build-time render, or served from the site root):
    // location.pathname already is the site path.
    path = raw;
  } else {
    // Relative base (runtime, including file://): keep only the trailing
    // segments that belong to the site, one per "../" in the base.
    const depth = (base.match(/\.\.\//g) || []).length;
    const segs = raw.split("/").filter(Boolean);
    path = "/" + segs.slice(segs.length - depth).join("/");
    if (path !== "/") path += "/";
  }

  const post = path.match(/^\/blog\/([^/]+)\/$/);
  if (post) return <BlogPost slug={post[1]}/>;
  if (path === "/blog/") return <BlogIndex/>;
  if (path === "/privacy/") return <PrivacyPolicy/>;
  return <App/>;
}

ReactDOM.hydrateRoot(document.getElementById("root"), <Root/>);
