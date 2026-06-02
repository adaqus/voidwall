---
title: The case for locale-specific PII detectors.
tag: Detection
date: 2026-04-28
read: 6 min read
excerpt: A French NIR and a German Steuer-ID share digit counts but mean different things. Context-free matching is a recipe for false positives — and worse.
---

Most PII detectors are built around a comforting fiction: that a piece of
personal data looks the same everywhere. Strip the formatting and a national ID
is just digits, a phone number is just digits, an order reference is — also
just digits.

## Digits don't carry meaning. Context does.

A French NIR is fifteen digits. A German Steuer-ID is eleven. A US SSN is nine.
On their own these are just numbers that happen to fall in a length range, and
a context-free matcher will cheerfully flag an invoice total or a tracking
number as a national identifier.

The fix isn't a stricter regex. It's reading the neighbourhood:

- The label next to the value (`Steuernummer:`, `N° de sécurité sociale`).
- The checksum the format defines — a real NIR validates; a random run of
  digits usually doesn't.
- The language and country the surrounding text is written in.

## Why false positives are a real cost

A detector that over-fires trains people to ignore it. Redact the order total
as if it were a tax ID and the team turns the rule off. Now you've lost the
true positives too. Precision isn't a nicety — it's what keeps the wall
switched on.

## And the false negatives are worse

The mirror image is quieter and more dangerous. A locale you didn't model is a
locale you don't detect. A detector tuned only for US formats will wave a Polish
PESEL straight through. "We scan for PII" becomes "we scan for *American* PII,"
and nobody notices until the data is already gone.

Locale-specific detectors cost more to build — a rule, a checksum, and a
keyword set per country. But the alternative isn't a simpler detector. It's a
detector that's confidently wrong in both directions.
