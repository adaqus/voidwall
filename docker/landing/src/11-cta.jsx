// CTA - void surface. Subscription for for early access, embedded from MailerLite.
function CTA() {
  return (
    <section id="early-adopters" style={{ background: "var(--vw-void)", color: "var(--vw-void-ink)", borderTop: "1px solid var(--vw-void-line)" }}>
      <div className="vw-container" style={{ padding: "120px var(--gutter)" }}>
        <div class="ml-embedded" data-form="GUKjOD"></div>
        <p style={{
          fontFamily: "var(--vw-font-body)", fontSize: 13, lineHeight: 1.5,
          color: "var(--vw-void-ink-3)", textAlign: "center", margin: "16px auto 0", maxWidth: 480,
        }}>
          By subscribing you agree to our{" "}
          <a href="/privacy/" style={{ color: "var(--vw-violet-300)" }}>Privacy Policy</a>.
        </p>
      </div>
    </section>
  );
}

window.CTA = CTA;
