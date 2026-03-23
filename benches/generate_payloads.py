#!/usr/bin/env python3
"""Generate deterministic test payloads for load testing.

Produces JSON files in benches/payloads/ with clean and PII-containing
content at various sizes: ~100 B, ~10 KB, ~1 MB.

PII kinds used (5 total):
  Hyperscan-based (2): Email, UsSsn
  KeywordContext-based (3): PersonName, DateOfBirth, GbNhsNumber
"""

import json
import os
import random

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "payloads")

# Seed for reproducibility
RNG = random.Random(42)

CLEAN_WORDS = [
    "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
    "lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing",
    "elit", "sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore",
    "et", "dolore", "magna", "aliqua", "enim", "ad", "minim", "veniam",
    "quis", "nostrud", "exercitation", "ullamco", "laboris", "nisi",
    "aliquip", "ex", "ea", "commodo", "consequat", "duis", "aute", "irure",
    "in", "reprehenderit", "voluptate", "velit", "esse", "cillum",
    "fugiat", "nulla", "pariatur", "excepteur", "sint", "occaecat",
    "cupidatat", "non", "proident", "sunt", "culpa", "qui", "officia",
    "deserunt", "mollit", "anim", "id", "est", "laborum",
]

# --- PII templates ---
# Hyperscan-based: Email, UsSsn (detected by pattern alone)
# KeywordContext-based: PersonName, DateOfBirth, GbNhsNumber (need keyword context)

PII_TEMPLATES = [
    # Email (Hyperscan)
    "Please contact john.doe@example.com for details.",
    "Send the report to jane.smith@testmail.org today.",
    "Email alice.jones@webmail.com with the update.",
    "Reach out to bob.wilson@company.net for support.",
    "Forward to charlie.brown@sample.io immediately.",
    # UsSsn (Hyperscan)
    "The SSN on file is 123-45-6789 for verification.",
    "Applicant SSN: 987-65-4321 was submitted.",
    "Records show SSN 111-22-3333 in the database.",
    "Updated SSN to 444-55-6666 per request.",
    "Verified SSN 777-88-9999 against records.",
    # PersonName (KeywordContext)
    "The applicant's name is John Smith as listed.",
    "Patient name is Jane Doe according to records.",
    "The customer called Robert Wilson confirmed.",
    "Account holder name is Alice Johnson verified.",
    "The employee named Charlie Brown was notified.",
    # DateOfBirth (KeywordContext)
    "Date of birth: 15/03/1990 confirmed on file.",
    "The patient was born on January 15, 1985.",
    "DOB recorded as 22/11/1978 in the system.",
    "Date of birth is 07/04/2001 per application.",
    "Born on March 30, 1995 as stated in records.",
    # GbNhsNumber (KeywordContext)
    "NHS number: 123 456 7890 on patient record.",
    "Patient NHS number is 943 476 5919 verified.",
    "The NHS number 401 023 2137 was confirmed.",
    "Registered NHS number: 654 321 0987 in system.",
    "NHS number 219 457 8631 linked to this case.",
]


def generate_clean_text(target_bytes: int) -> str:
    """Generate clean lorem-ipsum-like text of approximately target_bytes."""
    words = []
    current_size = 0
    while current_size < target_bytes:
        word = RNG.choice(CLEAN_WORDS)
        words.append(word)
        current_size += len(word) + 1
    return " ".join(words)


def generate_pii_text(target_bytes: int, pii_count: int) -> str:
    """Generate text with embedded PII values of approximately target_bytes.

    PII instances are distributed evenly across all 5 kinds by cycling
    through PII_TEMPLATES (5 templates per kind, 25 total).
    """
    # Pick pii_count templates, cycling through all kinds evenly
    selected = []
    for i in range(pii_count):
        selected.append(PII_TEMPLATES[i % len(PII_TEMPLATES)])

    pii_total = sum(len(t) for t in selected)
    remaining = max(0, target_bytes - pii_total)

    # Distribute clean text between PII segments
    segments = []
    gap_count = pii_count + 1
    gap_size = remaining // gap_count if gap_count > 0 else remaining

    for i in range(pii_count + 1):
        if gap_size > 0:
            segments.append(generate_clean_text(gap_size))
        if i < pii_count:
            segments.append(selected[i])

    return " ".join(segments)


def make_payload(text: str) -> str:
    """Wrap text in a JSON object."""
    return json.dumps({"data": text}, ensure_ascii=False)


def write_payload(filename: str, content: str) -> None:
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w") as f:
        f.write(content)
    size = os.path.getsize(path)
    print(f"  {filename}: {size:,} bytes")


def main() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("Generating payloads...")

    # Clean payloads (no PII)
    write_payload("clean_small.json", make_payload(generate_clean_text(80)))
    write_payload("clean_medium.json", make_payload(generate_clean_text(10_000)))
    write_payload("clean_large.json", make_payload(generate_clean_text(1_000_000)))

    # PII payloads (mix of 5 PII kinds)
    write_payload("pii_small.json", make_payload(generate_pii_text(80, 2)))
    write_payload("pii_medium.json", make_payload(generate_pii_text(10_000, 10)))
    write_payload("pii_large.json", make_payload(generate_pii_text(1_000_000, 100)))

    print("Done.")


if __name__ == "__main__":
    main()
