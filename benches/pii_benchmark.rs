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
Resolution Timeline:\n\
The investigation team has been briefed. Preliminary review indicates the \
transaction originated from an overseas IP address. The security team has \
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

fn throughput(c: &mut Criterion) {
    let scanner = Scanner::new();
    let long_clean = make_long_clean_text();

    let mut group = c.benchmark_group("throughput");

    let inputs: &[(&str, &str)] = &[("clean_500b", CLEAN_TEXT), ("mixed_2kb", MIXED_PII_TEXT)];

    for (name, text) in inputs {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(BenchmarkId::new("mark_piis", name), text, |b, input| {
            b.iter(|| scanner.mark_piis(input));
        });
    }

    group.throughput(Throughput::Bytes(long_clean.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("mark_piis", "clean_10kb"),
        &long_clean.as_str(),
        |b, input| {
            b.iter(|| scanner.mark_piis(input));
        },
    );

    group.finish();
}

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

fn per_detector(c: &mut Criterion) {
    let scanner = Scanner::new();

    let mut group = c.benchmark_group("per_detector");

    group.bench_function("email", |b| {
        b.iter(|| scanner.mark_piis(EMAIL_TEXT));
    });

    group.bench_function("phone", |b| {
        b.iter(|| scanner.mark_piis(PHONE_TEXT));
    });

    group.bench_function("credit_card", |b| {
        b.iter(|| scanner.mark_piis(CREDIT_CARD_TEXT));
    });

    group.finish();
}

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
    throughput,
    has_piis_vs_mark_piis,
    per_detector,
    clean_text_overhead
);
criterion_main!(benches);
