// Entry point — renders the landing page. The original standalone export
// used a Tweaks editor panel; the production build renders the components
// directly with a fixed headline variant.
function App() {
  return (
    <>
      <Nav/>
      <Hero headlineKey="intercepted"/>
      <Metrics/>
      <div className="void-band vw-void">
        <Features/>
        <Coverage/>
        <Analytics/>
        <Formats/>
        <CustomPII/>
      </div>
      <Performance/>
      <Blog/>
      <CTA/>
      <Footer/>
    </>
  );
}

ReactDOM.hydrateRoot(document.getElementById("root"), <App/>);
