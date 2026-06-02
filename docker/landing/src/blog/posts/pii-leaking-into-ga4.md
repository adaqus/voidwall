---
title: Personal data is leaking into GA4. Here is what we found.
tag: Analytics
date: 2026-04-10
read: 11 min read
excerpt: We instrumented twelve production properties and counted the events that carried emails, phone numbers, and IPs. The result is not pretty.
---

Analytics is where personal data goes to be forgotten. Nobody *means* to send an
email address to Google Analytics — it just rides along in a URL, a form field,
or a search query that someone wired into an event parameter two years ago.

We pointed Voidwall at the outbound analytics traffic of twelve production
properties for two weeks and counted what crossed the wire.

## What we found

Across the twelve properties:

- **Nine** sent at least one event carrying an email address, usually inside a
  page path or a `search_term` parameter.
- **Five** leaked phone numbers, almost always from un-sanitised form
  submissions fired as custom events.
- **Every one** forwarded a full client IP somewhere in the request, despite
  IP anonymisation being "on."

The common thread: none of it was deliberate. It was the residue of features
shipped quickly and instrumented generously.

## Why it happens

GA4's model encourages you to attach context to events. Context is exactly where
PII hides:

1. A checkout page with the email in the URL for "convenience."
2. A site-search box whose query becomes a tracked parameter.
3. A support widget that helpfully includes the user's phone in its payload.

Each one is reasonable in isolation. Together they turn your analytics pipeline
into an uncontrolled copy of your customer database.

## What actually fixes it

You can audit event schemas by hand, but schemas drift and new events appear
weekly. The durable fix is to inspect the traffic itself, on its way out, and
redact what shouldn't leave:

- Strip emails and phone numbers from parameter values before they reach the
  collector.
- Truncate or drop client IPs at the wall, not at the vendor's mercy.
- Keep a count of what was redacted, by kind, so you can see the leak shrink.

The numbers don't have to be pretty. They have to be *visible* — and then they
have to go to zero.
