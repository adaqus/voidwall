// Privacy policy - paper surface. Static legal text rendered at /privacy/
// (see the router in 16-app.jsx and the route list in build.sh).
// Organised by processing activity; each activity lists the same compact fields.
function PrivacyPolicy() {
  const h2 = {
    fontFamily: "var(--vw-font-display)", fontSize: 22, fontWeight: 600,
    letterSpacing: "-0.015em", color: "var(--vw-paper-ink)", margin: "44px 0 12px",
  };
  const h3 = {
    fontFamily: "var(--vw-font-display)", fontSize: 18, fontWeight: 600,
    letterSpacing: "-0.01em", color: "var(--vw-paper-ink)", margin: "28px 0 10px",
  };
  const p = {
    fontFamily: "var(--vw-font-body)", fontSize: 16, lineHeight: 1.6,
    color: "var(--vw-paper-ink-2)", margin: "0 0 14px", textWrap: "pretty",
  };
  const link = { color: "var(--vw-violet-500)" };

  // One activity block: a heading and a compact field list
  // (data / purpose / legal basis / recipients / retention + optional note).
  function Activity({ title, data, purpose, basis, recipients, retention, note }) {
    const fields = [
      ["Data processed", data],
      ["Purpose", purpose],
      ["Legal basis", basis],
      ["Recipients", recipients],
      ["Retention", retention],
    ];
    if (note) fields.push(["Please note", note]);
    return (
      <>
        <h3 style={h3}>{title}</h3>
        <ul style={{ listStyle: "none", padding: 0, margin: "0 0 8px" }}>
          {fields.map(([label, value]) => (
            <li key={label} style={{ ...p, display: "flex", gap: 8, margin: "0 0 8px" }}>
              <span style={{ flex: "0 0 130px", fontWeight: 600, color: "var(--vw-paper-ink)" }}>{label}</span>
              <span style={{ flex: 1 }}>{value}</span>
            </li>
          ))}
        </ul>
      </>
    );
  }

  return (
    <>
      <Nav/>
      <main style={{ background: "var(--vw-paper)" }}>
        <div className="vw-container" style={{ padding: "96px var(--gutter)" }}>
          <div style={{ maxWidth: 760 }}>
            <p className="vw-eyebrow" style={{ margin: "0 0 18px", color: "var(--vw-violet-500)" }}>Legal</p>
            <h1 className="r-page-h1" style={{
              fontFamily: "var(--vw-font-display)", fontSize: 48, fontWeight: 600,
              letterSpacing: "-0.025em", lineHeight: 1.04,
              color: "var(--vw-paper-ink)", margin: "0 0 16px", textWrap: "balance",
            }}>
              Privacy Policy
            </h1>
            <p style={{ ...p, color: "var(--vw-paper-ink-3)", fontSize: 14 }}>Last updated: 14 July 2026</p>

            <h2 style={h2}>Who we are</h2>
            <p style={p}>
              This website (voidwall.io), including the live demo and the early-adopter
              programme, is operated by NRTW Adam Tulejko, ul. Bł. Ks. Jolanty 3/2,
              71-220 Szczecin, Poland — the data controller responsible for your personal
              data. For any question about this policy or your data, contact us at{" "}
              <a href="mailto:privacy@voidwall.io" style={link}>privacy@voidwall.io</a>.
            </p>
            <p style={p}>
              This policy is organised by activity. For each one we set out what data we
              process, why, our legal basis, who receives it, and how long we keep it.
            </p>

            <h2 style={h2}>How we process your data</h2>

            <Activity
              title="1. Early-adopter subscription"
              data="Your email address, and a record of your consent (date and time)."
              purpose="To send you early-access invitations and occasional Voidwall product updates."
              basis={<>Your consent (GDPR Art. 6(1)(a)). Providing your email is voluntary; without it you cannot join the early-adopter mailing list.</>}
              recipients="MailerLite, which stores your email and delivers our messages on our behalf."
              retention={<>We keep your email until you unsubscribe or ask us to delete it. After that we keep proof of your consent for up to 3 years (the period during which related claims may arise), and a minimal suppression-list entry for as long as necessary to make sure we do not add you again.</>}
              note={<>You can withdraw consent at any time via the unsubscribe link in any email or by contacting us. Withdrawal does not affect the lawfulness of processing carried out before you withdrew.</>}
            />

            <Activity
              title="2. Email enquiries and early-adopter correspondence"
              data="Your email address and anything you choose to include — for example your name, company, job role, use case, or message content — such as when you reply to our welcome email."
              purpose="To respond to you and to discuss possible participation in the early-adopter programme."
              basis="Our legitimate interest (GDPR Art. 6(1)(f)) in handling enquiries, and/or taking steps at your request before entering a possible agreement."
              recipients="Cloudflare (Email Routing) forwards messages sent to our addresses to Google (Gmail), where we read and reply to them. Both act on our behalf."
              retention="Until your enquiry is resolved and for up to 24 months after our last substantive exchange, then deleted."
              note="Please do not include special-category data or confidential information you would not want us to process."
            />

            <Activity
              title="3. Live demo"
              data="The payload you submit, the operation you select (scan or redaction), the content type, and related request options."
              purpose="Solely to produce the scan or redaction result you requested."
              basis="Our legitimate interest (GDPR Art. 6(1)(f)) in letting you try the product."
              recipients="Processed by our own application on Fly.io; not shared with anyone else."
              retention={<>Your payload is processed in memory and discarded once the response is returned — we do not store it. Our servers keep only operational logs (for example errors and request counts) that do not contain your payload.</>}
              note={<><strong>Do not submit real personal data, credentials, special-category data, or confidential information.</strong> Use test or sample data only.</>}
            />

            <Activity
              title="4. Website delivery, security, and technical logs"
              data="Technical data needed to serve and protect the site: IP address, request time, requested path, user agent, response status, and abuse-prevention events (rate limiting)."
              purpose="To deliver the website, keep it available and secure, and prevent abuse."
              basis="Our legitimate interest (GDPR Art. 6(1)(f)) in operating a secure, reliable service."
              recipients="Fly.io, which hosts the site on our behalf. Your IP address is read only to apply per-IP rate limiting and is held transiently in memory for that purpose; it is not written to an application database."
              retention="Operational and platform logs are kept only for a short period (no longer than 30 days) and are then deleted."
            />

            <Activity
              title="5. Aggregate website analytics"
              data="Cookieless, aggregate measurements such as page views, referrer, approximate country, and device or browser type."
              purpose="To understand traffic and improve the site."
              basis="Our legitimate interest (GDPR Art. 6(1)(f)) in measuring and improving the site."
              recipients={<>Cloudflare, which provides the Web Analytics on our behalf. When your browser sends the analytics beacon, Cloudflare also receives your IP address and user agent to process it, but Cloudflare states it does not store your IP, does not use cookies or local storage, and does not fingerprint you or track you across sites.</>}
              retention="We hold only aggregate figures, which contain no personal data."
            />

            <h2 style={h2}>Cookies</h2>
            <p style={p}>
              We use no tracking or advertising cookies, and our analytics are cookieless.
              The MailerLite signup form sets a small number of functional cookies and
              local-storage entries to operate the form — for example to keep your form
              session and to remember that you have already submitted it. They are limited
              to running the form and are not used to track you.
            </p>

            <h2 style={h2}>International transfers</h2>
            <p style={p}>
              Some of our providers are based outside the European Economic Area (EEA):
            </p>
            <ul style={{ paddingLeft: 20, margin: "0 0 14px" }}>
              <li style={{ ...p, margin: "0 0 8px" }}><strong>Fly.io</strong> (United States) — hosting — relies on the EU–US Data Privacy Framework.</li>
              <li style={{ ...p, margin: "0 0 8px" }}><strong>Cloudflare</strong> (United States) — analytics and email routing — relies on the EU–US Data Privacy Framework and, where applicable, Standard Contractual Clauses.</li>
              <li style={{ ...p, margin: "0 0 8px" }}><strong>Google</strong> (United States) — email inbox (Gmail) — relies on the EU–US Data Privacy Framework and, where applicable, Standard Contractual Clauses.</li>
              <li style={{ ...p, margin: "0 0 8px" }}><strong>MailerLite Limited</strong> (Ireland) — email — provides our email-marketing service. Where MailerLite or its sub-processors transfer personal data outside the EEA, they use Standard Contractual Clauses or another valid transfer mechanism.</li>
            </ul>
            <p style={p}>
              You can ask us for more information about these safeguards, or a copy of them,
              using the contact details above.
            </p>

            <h2 style={h2}>Automated decision-making</h2>
            <p style={p}>
              We do not use your personal data for profiling or automated decisions that
              produce legal or similarly significant effects.
            </p>

            <h2 style={h2}>Your rights</h2>
            <p style={p}>
              Where the relevant legal conditions are met, you have the right to access,
              correct, delete, or restrict processing of your data, to object to processing
              based on our legitimate interests, to data portability, and to withdraw
              consent at any time (see the subscription activity above). You can unsubscribe
              from any email using the link in its footer, or contact us at{" "}
              <a href="mailto:privacy@voidwall.io" style={link}>privacy@voidwall.io</a>.
            </p>
            <p style={p}>
              If you believe we have handled your data unlawfully, you can lodge a complaint
              with the Polish supervisory authority — the President of the Personal Data
              Protection Office (Prezes Urzędu Ochrony Danych Osobowych, UODO), ul. Stawki 2,
              00-193 Warsaw — or with the supervisory authority where you live or work.
            </p>

            <h2 style={h2}>Changes to this policy</h2>
            <p style={p}>
              We may update this policy from time to time. For minor editorial changes we
              will simply update the date at the top. For material changes — for example to
              the purposes, recipients, or legal bases — we will take reasonable steps to
              inform subscribers before the change takes effect.
            </p>
          </div>
        </div>
      </main>
      <Footer/>
    </>
  );
}

window.PrivacyPolicy = PrivacyPolicy;
