use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use pii::Scanner;

const CLEAN_TEXT: &str = "\
The quick brown fox jumps over the lazy dog. In a world filled with wonders, \
the beauty of nature never ceases to amaze those who take the time to observe. \
Mountains rise majestically above the clouds, rivers carve their paths through \
ancient valleys, and forests hum with the quiet energy of countless living things. \
Every season brings its own palette of colors: the fresh greens of spring, the \
golden warmth of summer, the fiery reds of autumn, and the pristine whites of \
winter. Through it all, the cycle of life continues its timeless rhythm, \
reminding us of the enduring power of the natural world.";

const EMAIL_TEXT: &str = "\
From: alice.johnson@example.com\n\
To: bob.smith@corporate-inc.net\n\
CC: support_team@helpdesk.org\n\
Subject: Q3 Report Review\n\n\
Hi Bob,\n\n\
Please find the Q3 report attached. I've also forwarded a copy to \
carol.white@analytics.example.com for her review. If you have any questions, \
reach out to the project lead at david.lee@corporate-inc.net.\n\n\
Best regards,\n\
Alice";

const PHONE_TEXT: &str = "\
Customer Service Log - Ticket #4821\n\n\
Called customer at (555) 123-4567 regarding their account issue. Customer \
requested a callback at 555-987-6543. Transferred to supervisor line at \
+1 (555) 246-8100. Follow-up scheduled; customer alternate number is \
555.321.7654. Case escalated to regional office at (800) 555-0199.";

const CREDIT_CARD_TEXT: &str = "\
Order Confirmation #ORD-20250115\n\n\
Thank you for your purchase! Your order has been placed successfully.\n\
Payment method: Visa ending in 1111\n\
Full card number on file: 4111 1111 1111 1111\n\
Billing amount: $249.99\n\n\
A second payment of $50.00 was charged to card 5500 0000 0000 0004.\n\
Please retain this confirmation for your records.";

const SSN_TEXT: &str = "\
Employee Records Update — Q1 2025\n\n\
Please verify the following SSNs for payroll processing:\n\
- John Smith: 123-45-6789\n\
- Maria Garcia: 234-56-7890\n\
- Robert Johnson: 345-67-8901\n\
All employees must confirm their records by end of month.\n\
Contact HR at extension 4200 for corrections.";

const NINO_TEXT: &str = "\
UK Employee Onboarding — National Insurance Numbers\n\n\
New starters this quarter:\n\
- Emma Thompson: AB 12 34 56 C\n\
- James Wilson: CE345678A\n\
- Sarah Davies: HJ 78 90 12 B\n\
Please ensure all NINOs are registered with HMRC before the first payroll run.\n\
Contact the payroll team for any discrepancies.";

const IBAN_TEXT: &str = "\
International Wire Transfer Instructions\n\n\
Beneficiary: Acme GmbH\n\
IBAN: DE89 3704 0044 0532 0130 00\n\
BIC: COBADEFFXXX\n\n\
Secondary account:\n\
IBAN: GB29 NWBK 6016 1331 9268 19\n\
Please reference invoice #INV-2025-0042 in the payment description.\n\
Processing time is typically 1-3 business days for SEPA transfers.";

const PASSPORT_TEXT: &str = "\
Travel Authorization Request\n\n\
Passenger: Jane Doe\n\
Passport Number: 123456789\n\
Nationality: US\n\
Expiry: 2028-06-15\n\n\
Co-traveler: John Doe\n\
Passport Number: 987654321\n\
Nationality: US\n\
Expiry: 2029-03-20\n\
Please submit copies of all passport bio pages to the travel desk.";

const IP_TEXT: &str = "\
Server Incident Report — 2025-01-15\n\n\
Affected systems:\n\
- Web server: 192.168.1.100\n\
- Database: 10.0.0.42\n\
- Load balancer: 172.16.0.1\n\
- IPv6 gateway: 2001:0db8:85a3:0000:0000:8a2e:0370:7334\n\n\
Unauthorized access detected from 203.0.113.55 at 14:23 UTC.\n\
All traffic from the source IP has been blocked at the firewall.";

const MIXED_PII_TEXT: &str = "\
SUPPORT TICKET #ST-2025-0842\n\
Priority: High\n\
Created: 2025-01-15 09:23:41 UTC\n\n\
Customer Information:\n\
  Name: Jane Doe\n\
  Email: jane.doe@personalmail.com\n\
  Phone: (555) 234-5678\n\
  Alternate Phone: 555-876-5432\n\n\
Issue Description:\n\
Customer reports unauthorized transaction on credit card 4111 1111 1111 1111. \
The charge of $1,247.83 appeared on January 14th from an unrecognized merchant. \
Customer has been a member since 2019 and has no prior disputes on record.\n\n\
Agent Notes (2025-01-15 09:45:00):\n\
Contacted fraud department at fraud-alerts@bank-security.example.com. \
Initiated chargeback process. Customer provided backup card \
5500 0000 0000 0004 for future billing. Supervisor notified at \
sup.martinez@internal.example.net. Customer will receive status update \
at jane.doe@personalmail.com within 48 hours.\n\n\
Escalation Contact: +1 (800) 555-0147\n\n\
Customer Identity Verification:\n\
  SSN on file: 123-45-6789\n\
  UK NINO (dual citizen): AB 12 34 56 C\n\
  Passport Number: 123456789\n\
  Bank IBAN: GB29 NWBK 6016 1331 9268 19\n\n\
Resolution Timeline:\n\
The investigation team has been briefed. Preliminary review indicates the \
transaction originated from overseas IP address 203.0.113.55. The security team has \
flagged the merchant account for further analysis. All relevant transaction \
logs have been preserved for the investigation. The customer's account has \
been temporarily secured with enhanced monitoring. A follow-up call is \
scheduled for January 17th to provide an update on the investigation status. \
The compliance team has been notified per regulatory requirements.\n\n\
Additional documentation has been requested from the merchant's acquiring \
bank. Internal case reference: FRD-2025-00342. The customer expressed \
satisfaction with the initial response time and the steps taken to secure \
their account. No further action required at this time pending investigation \
results. End of ticket notes.\n";

fn make_long_clean_text() -> String {
    CLEAN_TEXT.repeat(20)
}

// Measures bytes/second throughput of mark_piis across different input sizes
// and content types: PII-free text (~500B), mixed PII (~2KB), and long clean text (~10KB).
fn throughput_mark_piis(c: &mut Criterion) {
    let scanner = Scanner::new();
    let long_clean = make_long_clean_text();

    let mut group = c.benchmark_group("throughput");

    let inputs: &[(&str, &str)] = &[
        ("clean_500b", CLEAN_TEXT),
        ("mixed_2kb", MIXED_PII_TEXT),
        ("clean_10kb", &long_clean),
    ];

    for (name, text) in inputs {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(BenchmarkId::new("mark_piis", name), text, |b, input| {
            b.iter(|| scanner.mark_piis(input));
        });
    }

    group.finish();
}

// Measures bytes/second throughput of has_piis across the same input sizes.
// Shows the speed of short-circuit detection (stops at first match) at scale.
fn throughput_has_piis(c: &mut Criterion) {
    let scanner = Scanner::new();
    let long_clean = make_long_clean_text();

    let mut group = c.benchmark_group("throughput_has_piis");

    let inputs: &[(&str, &str)] = &[
        ("clean_500b", CLEAN_TEXT),
        ("mixed_2kb", MIXED_PII_TEXT),
        ("clean_10kb", &long_clean),
    ];

    for (name, text) in inputs {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(BenchmarkId::new("has_piis", name), text, |b, input| {
            b.iter(|| scanner.has_piis(input));
        });
    }

    group.finish();
}

// Compares short-circuit has_piis (stops at first match) vs full mark_piis
// (extracts all matches) on the same mixed-PII input to quantify the
// early-exit advantage.
fn has_piis_vs_mark_piis(c: &mut Criterion) {
    let scanner = Scanner::new();

    let mut group = c.benchmark_group("has_piis_vs_mark_piis");

    group.bench_function("has_piis", |b| {
        b.iter(|| scanner.has_piis(MIXED_PII_TEXT));
    });

    group.bench_function("mark_piis", |b| {
        b.iter(|| scanner.mark_piis(MIXED_PII_TEXT));
    });

    group.finish();
}

// Isolates each PII type by running mark_piis on text containing only that
// type. Shows the relative cost of each PII kind's regex + validation.
fn per_pii_kind(c: &mut Criterion) {
    let scanner = Scanner::new();

    let mut group = c.benchmark_group("per_pii_kind");

    group.bench_function("email", |b| {
        b.iter(|| scanner.mark_piis(EMAIL_TEXT));
    });

    group.bench_function("phone", |b| {
        b.iter(|| scanner.mark_piis(PHONE_TEXT));
    });

    group.bench_function("credit_card", |b| {
        b.iter(|| scanner.mark_piis(CREDIT_CARD_TEXT));
    });

    group.bench_function("ssn", |b| {
        b.iter(|| scanner.mark_piis(SSN_TEXT));
    });

    group.bench_function("nino", |b| {
        b.iter(|| scanner.mark_piis(NINO_TEXT));
    });

    group.bench_function("iban", |b| {
        b.iter(|| scanner.mark_piis(IBAN_TEXT));
    });

    group.bench_function("passport", |b| {
        b.iter(|| scanner.mark_piis(PASSPORT_TEXT));
    });

    group.bench_function("ip_address", |b| {
        b.iter(|| scanner.mark_piis(IP_TEXT));
    });

    group.finish();
}

// Measures the baseline cost of scanning PII-free text where no patterns
// match. Shows the fixed overhead of running all regexes with zero results.
fn clean_text_overhead(c: &mut Criterion) {
    let scanner = Scanner::new();

    let mut group = c.benchmark_group("clean_text_overhead");

    group.bench_function("has_piis", |b| {
        b.iter(|| scanner.has_piis(CLEAN_TEXT));
    });

    group.bench_function("mark_piis", |b| {
        b.iter(|| scanner.mark_piis(CLEAN_TEXT));
    });

    group.finish();
}

criterion_group!(
    benches,
    throughput_mark_piis,
    throughput_has_piis,
    has_piis_vs_mark_piis,
    per_pii_kind,
    clean_text_overhead
);
criterion_main!(benches);
