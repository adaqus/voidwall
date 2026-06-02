---
title: Why we built Voidwall as a proxy, not a library.
tag: Engineering
date: 2026-05-12
read: 8 min read
excerpt: An inline DLP layer has to survive every protocol mistake in your stack. Here is why a proxy beats an SDK once teams scale.
---

The obvious way to stop personal data from leaving your system is to check it
at the point it's produced. Import an SDK, wrap the call, scan the payload. It
works — until you have forty services, three languages, and a contractor who
shipped the one path that forgot to wrap the call.

## A library is opt-in. A proxy is not.

An SDK protects the code that remembers to use it. That sounds fine until you
count the ways data actually leaves a system: a debug log that got promoted to
an analytics sink, a webhook added in a hurry, a third-party tag a marketer
pasted into the page. None of those import your SDK.

A proxy sits on the wire. Every request that crosses it is inspected, whether
or not the author knew Voidwall existed. The default flips from *opt-in safety*
to *opt-out exposure* — and exposure now requires someone to deliberately route
around the wall.

## The protocol is the contract.

Libraries couple to your language and your framework version. A proxy couples
to HTTP, which every service already speaks. That means:

- One detection policy, enforced identically across Go, Python, and Rust.
- No redeploy of forty services to change a redaction rule.
- A single place to audit what was inspected and what was blocked.

## Where a proxy earns its keep

The hard part of inline DLP isn't matching a regex. It's doing it under load,
without becoming the thing that takes your site down. That's why the scanner
runs off the async runtime on dedicated threads, and why body buffers are
dropped the moment a scan completes. The wall has to be invisible when it
passes traffic and unmissable when it stops it.

A library can be correct. A proxy can be *unavoidable*. At scale, unavoidable
is the property that actually protects you.
