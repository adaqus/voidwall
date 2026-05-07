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


# --- Structured-scanning payloads -------------------------------------------

# Names cycle deterministically so the file regenerates byte-identical.
FIRST_NAMES = ["John", "Jane", "Alice", "Bob", "Charlie", "Diana", "Edward",
               "Fiona", "George", "Helen"]
LAST_NAMES = ["Doe", "Smith", "Johnson", "Brown", "Wilson", "Davis", "Miller",
              "Taylor", "Anderson", "Thomas"]
CITIES = ["New York", "London", "Paris", "Berlin", "Tokyo", "Sydney",
          "Toronto", "Dublin", "Madrid", "Rome"]


def generate_nested_json() -> str:
    """4-5 levels of nesting with KeywordContextDetector keywords mid-path
    (e.g. `request.user.phone.primary`, `accounts[i].holder.name.first`)."""

    accounts = []
    for i in range(3):
        accounts.append({
            "id": f"acct-{i + 1}",
            "holder": {
                "name": {
                    "first": FIRST_NAMES[i + 2],
                    "last": LAST_NAMES[i + 2],
                },
                "ssn": f"{100 + i:03d}-{20 + i:02d}-{3000 + i:04d}",
            },
            "address": {
                "city": CITIES[i],
                "country": "US",
            },
        })

    payload = {
        "tenant_id": "acme-corp",
        "request": {
            "metadata": {
                "trace_id": "abc-123-def-456",
                "session": {
                    "ip": "203.0.113.5",
                    "ua": "Mozilla/5.0 (X11; Linux x86_64)",
                },
            },
            "user": {
                "id": "u-9876",
                "email": "john.doe@example.com",
                "name": {
                    "first": "John",
                    "last": "Doe",
                },
                "phone": {
                    "primary": "555-123-4567",
                    "mobile": "555-987-6543",
                },
                "dob": {
                    "value": "1990-01-15",
                },
            },
            "accounts": accounts,
        },
    }
    return json.dumps(payload, ensure_ascii=False)


def generate_table_csv(rows: int = 100) -> str:
    """CSV with header row containing KeywordContext keywords (`first_name`,
    `last_name`, `phone`, `dob`) plus Hyperscan-detected columns (`email`,
    `ssn`). Generates `rows` data rows after the header."""

    header = "id,first_name,last_name,email,phone,ssn,dob,city,notes"
    lines = [header]
    for i in range(rows):
        first = FIRST_NAMES[i % len(FIRST_NAMES)]
        last = LAST_NAMES[i % len(LAST_NAMES)]
        email = f"{first.lower()}.{last.lower()}{i}@example.com"
        phone = f"555-{(100 + i) % 1000:03d}-{(1000 + i * 7) % 10000:04d}"
        ssn = f"{(100 + i) % 1000:03d}-{(20 + i) % 100:02d}-{(3000 + i * 13) % 10000:04d}"
        year = 1950 + (i % 50)
        month = (i % 12) + 1
        day = (i % 28) + 1
        dob = f"{year:04d}-{month:02d}-{day:02d}"
        city = CITIES[i % len(CITIES)]
        lines.append(
            f"{i + 1},{first},{last},{email},{phone},{ssn},{dob},{city},patient"
        )
    return "\n".join(lines) + "\n"


def generate_clean_table_csv(rows: int) -> str:
    """CSV of the same column count as `generate_table_csv` but with neutral
    column names (no PII keywords) and lorem-ipsum row data (no PII patterns).
    Used by the http_api benchmark when PII=false to compare scanner cost on
    structured but PII-free input."""

    header = "id,col_a,col_b,col_c,col_d,col_e,col_f,col_g,col_h"
    lines = [header]
    for i in range(rows):
        cells = [
            str(i + 1),
            *(RNG.choice(CLEAN_WORDS) for _ in range(8)),
        ]
        lines.append(",".join(cells))
    return "\n".join(lines) + "\n"


# Row counts chosen so the resulting files line up with the JSON size buckets:
#   small  ≈ 100 B   medium ≈ 10 KB   large ≈ 1 MB
# Each row averages ~84 bytes for the PII table and ~50 bytes for the clean
# table, so the row counts below produce comparable file sizes.
CSV_PII_ROWS = {"small": 1, "medium": 100, "large": 10_000}
CSV_CLEAN_ROWS = {"small": 1, "medium": 200, "large": 17_000}


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

    # Structured-scanning payloads (path/column context drives detection)
    write_payload("pii_nested.json", generate_nested_json())
    write_payload("pii_table.csv", generate_table_csv(100))

    # Sized CSV payloads for the http_api benchmark. The medium PII table is
    # byte-identical to pii_table.csv above; both names exist so the
    # http_api scenario can iterate small/medium/large without overloading the
    # bare pii_table.csv corpus used by structured_scanning.js.
    for size, n in CSV_PII_ROWS.items():
        write_payload(f"pii_table_{size}.csv", generate_table_csv(n))
    for size, n in CSV_CLEAN_ROWS.items():
        write_payload(f"clean_table_{size}.csv", generate_clean_table_csv(n))

    print("Done.")


if __name__ == "__main__":
    main()
