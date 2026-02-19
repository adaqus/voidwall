use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use pii::{RedactWith, Scanner};

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
Called customer at phone (555) 123-4567 regarding their account issue. Customer \
requested a callback number 555-987-6543. Transferred to supervisor telephone \
+1 (555) 246-8100. Follow-up scheduled; customer alternate phone \
555.321.7654. Case escalated to regional office tel (800) 555-0199.";

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

const ITIN_TEXT: &str = "\
IRS Individual Taxpayer Identification Numbers — Batch Verification\n\n\
The following ITINs require validation before processing:\n\
- Applicant A: 912-70-1234\n\
- Applicant B: 900-94-5678\n\
- Applicant C: 923-86-4321\n\
Please verify all ITINs against the IRS database before issuing refunds.\n\
Contact the ITIN unit at extension 7200 for discrepancies.";

const SIN_TEXT: &str = "\
Canada Revenue Agency — SIN Verification Report\n\n\
Employee social insurance numbers for payroll registration:\n\
- Marie Tremblay: 130-692-544\n\
- James Chen: 130 692 544\n\
- Sophie Martin: 468-277-138\n\
All SINs must be validated before the first pay period.\n\
Contact HR for any corrections needed.";

const PPSN_TEXT: &str = "\
Revenue Commissioners — PPSN Records\n\n\
New registrations this quarter:\n\
- Sean Murphy: 1234567T\n\
- Aoife Kelly: 1234567TW\n\
- Padraig O'Brien: 7654321M\n\
All PPSNs must be verified before tax credits are applied.\n\
Contact the local Revenue office for queries.";

const SA_ID_TEXT: &str = "\
Department of Home Affairs — Identity Verification\n\n\
The following South African ID numbers need validation:\n\
- Thabo Mbeki: SA ID number: 8001015009087\n\
- Naledi Zulu: identity number: 9506150089081\n\
Please ensure all ID numbers are registered in the population register.\n\
Contact the nearest Home Affairs office for amendments.";

const MAC_TEXT: &str = "\
Network Device Inventory — Building A, Floor 3\n\n\
Registered MAC addresses:\n\
- Workstation 1: 00:1A:2B:3C:4D:5E\n\
- Workstation 2: AA-BB-CC-DD-EE-FF\n\
- Cisco Switch: 001A.2B3C.4D5E\n\
- Access Point: ff:ee:dd:cc:bb:aa\n\
All devices must be registered in the asset management system.";

const UK_DL_TEXT: &str = "\
DVLA — Driving Licence Verification\n\n\
Licence numbers for identity check:\n\
- Mr Jones: JONES901157A99Y1\n\
- Ms Smith: SMITH856107B92X3\n\
Please verify all licence numbers against DVLA records.\n\
Contact the DVLA helpline for any discrepancies.";

const VIN_TEXT: &str = "\
Vehicle Registration Database — Monthly Audit\n\n\
The following VINs require verification:\n\
- Honda Civic: 1HGBH41JXMN109186\n\
- Toyota Camry: 4T1BF1FK5CU638859\n\
- Ford F-150: 1FTFW1ET0DFC10312\n\
All VINs must be cross-referenced with manufacturer records.";

const TFN_TEXT: &str = "\
Australian Taxation Office — TFN Verification\n\n\
The following tax file numbers require validation:\n\
- Employee A: TFN: 123 456 782\n\
- Employee B: Tax file number: 876 543 210\n\
Please ensure all TFNs are registered before payroll processing.\n\
Contact the ATO helpline for discrepancies.";

const NZ_IRD_TEXT: &str = "\
Inland Revenue Department — IRD Number Verification\n\n\
The following IRD numbers need validation:\n\
- Taxpayer A: IRD number: 49-091-857\n\
- Taxpayer B: IRD: 136-410-133\n\
All IRD numbers must be verified before tax returns are processed.\n\
Contact the IRD helpline for any corrections.";

const NHS_TEXT: &str = "\
National Health Service — Patient Records\n\n\
Patient NHS numbers for verification:\n\
- Patient A: NHS number: 943 476 5919\n\
- Patient B: NHS: 401 023 2137\n\
Please verify all NHS numbers against the spine database.\n\
Contact the NHS helpdesk for discrepancies.";

const MEDICARE_TEXT: &str = "\
Medicare Australia — Card Verification\n\n\
Medicare numbers for processing:\n\
- Member A: Medicare number: 2123 45670 1\n\
- Member B: Medicare card: 3987 65432 1\n\
All Medicare numbers must be verified before claims are processed.\n\
Contact Medicare for any issues.";

const US_PASSPORT_NEW_TEXT: &str = "\
US Department of State — Passport Records\n\n\
New format passport numbers for verification:\n\
- Applicant A: Passport number: A12345678\n\
- Applicant B: US passport: X98765432\n\
All passport numbers must be verified against State Department records.\n\
Contact the passport agency for corrections.";

const SWIFT_BIC_TEXT: &str = "\
International Banking — SWIFT Code Directory\n\n\
Bank routing codes for wire transfers:\n\
- Deutsche Bank: SWIFT code: DEUTDEFF\n\
- HSBC London: BIC: HSBCGB2LXXX\n\
All SWIFT/BIC codes must be verified before transfers are initiated.\n\
Contact the correspondent banking team for queries.";

const EIN_TEXT: &str = "\
IRS — Employer Identification Number Records\n\n\
Business EINs for tax filing:\n\
- Acme Corp: EIN: 12-3456789\n\
- Widget Inc: Employer identification number: 20-1234567\n\
All EINs must be verified before quarterly filings are submitted.\n\
Contact the IRS business helpline for corrections.";

const IMEI_TEXT: &str = "\
Mobile Device Management — IMEI Registry\n\n\
Device IMEI numbers for inventory:\n\
- iPhone 15: IMEI: 490154203237518\n\
- Samsung S24: IMEI number: 35-209900-176148-1\n\
All IMEI numbers must be registered in the device management system.\n\
Contact IT support for any discrepancies.";

const UTR_TEXT: &str = "\
HMRC — Unique Taxpayer Reference Verification\n\n\
Self Assessment UTR numbers for tax filing:\n\
- Taxpayer A: UTR: 5555555555\n\
- Taxpayer B: Self assessment UTR: 1000000103\n\
All UTRs must be verified before tax returns are submitted.\n\
Contact HMRC for any discrepancies.";

const ABA_TEXT: &str = "\
US Banking — ABA Routing Number Verification\n\n\
Bank routing numbers for wire transfers:\n\
- JPMorgan Chase: Routing number: 021000021\n\
- Bank of America: ABA routing number: 026009593\n\
All routing numbers must be verified before transfers are initiated.\n\
Contact the bank for any corrections.";

const SORT_CODE_TEXT: &str = "\
UK Banking — Sort Code Directory\n\n\
Branch sort codes for account verification:\n\
- Barclays: Sort code: 20-00-00\n\
- HSBC: Bank sort code: 40-47-84\n\
All sort codes must be verified against BACS records.\n\
Contact the branch for any discrepancies.";

const GEOLOCATION_TEXT: &str = "\
Location Tracking Report — Fleet Management\n\n\
Vehicle positions at last check-in:\n\
- Truck A: GPS coordinates: 40.7128,-74.0060\n\
- Truck B: coordinates: -33.8688, 151.2093\n\
- Truck C: lat/long: 51.5074,-0.1278\n\
All GPS coordinates must be logged in the tracking system.\n\
Contact dispatch for any discrepancies.";

const A_NUMBER_TEXT: &str = "\
USCIS — Alien Registration Number Verification\n\n\
Immigration case records:\n\
- Applicant A: Alien number: A012345678\n\
- Applicant B: USCIS number: A98765432\n\
- Applicant C: Green card number: A1234567\n\
All A-Numbers must be verified against USCIS records.\n\
Contact the local USCIS field office for corrections.";

const USCIS_RECEIPT_TEXT: &str = "\
USCIS — Receipt Number Tracking\n\n\
Pending immigration cases:\n\
- Case A: USCIS receipt number: SRC2190000001\n\
- Case B: Receipt number: EAC2180050234\n\
- Case C: I-797 receipt: WAC2200100567\n\
All receipt numbers must be tracked in the case management system.\n\
Contact USCIS customer service for status updates.";

const US_DL_TEXT: &str = "\
US Department of Motor Vehicles — License Verification\n\n\
Driver's license numbers for identity check:\n\
- California: Driver's license: B1234568\n\
- Florida: DL number: W123456789012\n\
- Illinois: Driver's license number: S530-4000-0001\n\
- Ohio: License number: AB123456\n\
All license numbers must be verified against DMV records.\n\
Contact the issuing state DMV for any discrepancies.";

const NZ_NHI_TEXT: &str = "\
New Zealand Ministry of Health — NHI Verification\n\n\
Patient NHI numbers for records:\n\
- Patient A: NHI: DAB8745\n\
- Patient B: National health index: ZAC5361\n\
All NHI numbers must be verified against the NHI register.\n\
Contact the Ministry of Health for any corrections.";

const NZ_DL_TEXT: &str = "\
New Zealand Transport Agency — Licence Verification\n\n\
Driver licence numbers for identity check:\n\
- Driver A: Licence number: AB123456\n\
- Driver B: Driver licence: CD789012\n\
All licence numbers must be verified against NZTA records.\n\
Contact the nearest NZTA office for any discrepancies.";

const IE_DRIVER_TEXT: &str = "\
Road Safety Authority — Irish Driver Number Verification\n\n\
Driver numbers for licence check:\n\
- Driver A: Driver number: 123456789\n\
- Driver B: Driving licence: 987654321\n\
All driver numbers must be verified against RSA records.\n\
Contact the NDLS for any corrections.";

const ZA_TRN_TEXT: &str = "\
South African Revenue Service — Tax Reference Verification\n\n\
Tax reference numbers for filing:\n\
- Taxpayer A: Tax reference: 0123456789\n\
- Taxpayer B: SARS: 9876543210\n\
All tax reference numbers must be verified before filing.\n\
Contact SARS for any discrepancies.";

const CA_OHIP_TEXT: &str = "\
Ontario Ministry of Health — OHIP Verification\n\n\
Health card numbers for registration:\n\
- Patient A: OHIP: 1234567897\n\
- Patient B: Health card: 9876543219\n\
All OHIP numbers must be verified before claims are processed.\n\
Contact ServiceOntario for any corrections.";

// Realistic support ticket containing the 5 most common US PII types:
// email, phone, credit card, SSN, IP address. Used for a focused
// throughput benchmark that reflects everyday US proxy traffic.
const US_COMMON_PII_TEXT: &str = "\
CUSTOMER SERVICE RECORD #CS-2025-1138\n\
Date: 2025-01-15\n\n\
Customer Information:\n\
  Name: Michael Turner\n\
  Email: m.turner@example.com\n\
  Phone: (555) 867-5309\n\
  Alternate contact: 555-234-7890\n\n\
Account Activity:\n\
Customer called about a disputed charge on their Visa card. \
The card number on file is 4111 1111 1111 1111. A second charge was \
also flagged on card 5500 0000 0000 0004.\n\n\
Identity Verification:\n\
  SSN provided: 123-45-6789\n\n\
Technical Notes:\n\
Login attempt flagged from IP address 203.0.113.55. \
A second access attempt originated from 198.51.100.42 within the same session. \
Both IPs have been logged for security review.\n\n\
Agent assigned: sarah.jones@support.example.com\n\
Escalation email: fraud-team@bank.example.com\n\n\
Case Status: Open — awaiting customer callback at (555) 867-5309.";

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
results.\n\n\
Extended Verification Records:\n\
  ITIN (US tax filing): 912-70-1234\n\
  Canada SIN: 130-692-544\n\
  Ireland PPSN: 1234567T\n\
  South Africa ID: 8001015009087\n\
  Device MAC address: 00:1A:2B:3C:4D:5E\n\
  UK Driving Licence: JONES901157A99Y1\n\
  Vehicle VIN: 1HGBH41JXMN109186\n\n\
Tier 2 Verification Records:\n\
  TFN: 123 456 782\n\
  IRD number: 49-091-857\n\
  NHS number: 943 476 5919\n\
  Medicare number: 2123 45670 1\n\
  Passport number: A12345678\n\
  SWIFT code: DEUTDEFF\n\
  EIN: 12-3456789\n\
  IMEI: 490154203237518\n\n\
Tier 3 Verification Records:\n\
  UTR: 5555555555\n\
  Routing number: 021000021\n\
  Sort code: 20-00-00\n\
  GPS coordinates: 40.7128,-74.0060\n\
  Driver's license: B1234568\n\
  Alien number: A012345678\n\
  USCIS receipt number: SRC2190000001\n\n\
Tier 4 Verification Records:\n\
  NHI: DAB8745\n\
  Licence number: AB123456\n\
  Driver number: 123456789\n\
  Tax reference: 0123456789\n\
  OHIP: 1234567897\n\n\
End of ticket notes.\n";

fn make_long_clean_text() -> String {
    CLEAN_TEXT.repeat(20)
}

// Measures bytes/second throughput of mark_piis across different input sizes
// and content types: PII-free text (~500B), mixed PII (~2KB), and long clean text (~10KB).
fn throughput_mark_piis(c: &mut Criterion) {
    let scanner = Scanner::new().unwrap();
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
    let scanner = Scanner::new().unwrap();
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

// Measures bytes/second throughput of mark_piis and has_piis on a realistic
// US support-ticket containing only the 5 most common US PII types
// (email, phone, credit card, SSN, IP address). More representative of
// everyday proxy traffic than the exhaustive MIXED_PII_TEXT fixture.
fn throughput_us_common_pii(c: &mut Criterion) {
    let scanner = Scanner::new().unwrap();

    let mut group = c.benchmark_group("throughput_us_common_pii");
    group.throughput(Throughput::Bytes(US_COMMON_PII_TEXT.len() as u64));

    group.bench_function("mark_piis", |b| {
        b.iter(|| scanner.mark_piis(US_COMMON_PII_TEXT));
    });

    group.bench_function("has_piis", |b| {
        b.iter(|| scanner.has_piis(US_COMMON_PII_TEXT));
    });

    group.finish();
}

// Compares short-circuit has_piis (stops at first match) vs full mark_piis
// (extracts all matches) on the same mixed-PII input to quantify the
// early-exit advantage.
fn has_piis_vs_mark_piis(c: &mut Criterion) {
    let scanner = Scanner::new().unwrap();

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
    let scanner = Scanner::new().unwrap();

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

    group.bench_function("itin", |b| {
        b.iter(|| scanner.mark_piis(ITIN_TEXT));
    });

    group.bench_function("sin", |b| {
        b.iter(|| scanner.mark_piis(SIN_TEXT));
    });

    group.bench_function("ppsn", |b| {
        b.iter(|| scanner.mark_piis(PPSN_TEXT));
    });

    group.bench_function("sa_id", |b| {
        b.iter(|| scanner.mark_piis(SA_ID_TEXT));
    });

    group.bench_function("mac_address", |b| {
        b.iter(|| scanner.mark_piis(MAC_TEXT));
    });

    group.bench_function("uk_driving_licence", |b| {
        b.iter(|| scanner.mark_piis(UK_DL_TEXT));
    });

    group.bench_function("vin", |b| {
        b.iter(|| scanner.mark_piis(VIN_TEXT));
    });

    group.bench_function("australia_tfn", |b| {
        b.iter(|| scanner.mark_piis(TFN_TEXT));
    });

    group.bench_function("nz_ird", |b| {
        b.iter(|| scanner.mark_piis(NZ_IRD_TEXT));
    });

    group.bench_function("nhs_number", |b| {
        b.iter(|| scanner.mark_piis(NHS_TEXT));
    });

    group.bench_function("au_medicare", |b| {
        b.iter(|| scanner.mark_piis(MEDICARE_TEXT));
    });

    group.bench_function("us_passport_new", |b| {
        b.iter(|| scanner.mark_piis(US_PASSPORT_NEW_TEXT));
    });

    group.bench_function("swift_bic", |b| {
        b.iter(|| scanner.mark_piis(SWIFT_BIC_TEXT));
    });

    group.bench_function("ein", |b| {
        b.iter(|| scanner.mark_piis(EIN_TEXT));
    });

    group.bench_function("imei", |b| {
        b.iter(|| scanner.mark_piis(IMEI_TEXT));
    });

    group.bench_function("uk_utr", |b| {
        b.iter(|| scanner.mark_piis(UTR_TEXT));
    });

    group.bench_function("us_aba_routing", |b| {
        b.iter(|| scanner.mark_piis(ABA_TEXT));
    });

    group.bench_function("uk_sort_code", |b| {
        b.iter(|| scanner.mark_piis(SORT_CODE_TEXT));
    });

    group.bench_function("precise_geolocation", |b| {
        b.iter(|| scanner.mark_piis(GEOLOCATION_TEXT));
    });

    group.bench_function("us_drivers_license", |b| {
        b.iter(|| scanner.mark_piis(US_DL_TEXT));
    });

    group.bench_function("alien_number", |b| {
        b.iter(|| scanner.mark_piis(A_NUMBER_TEXT));
    });

    group.bench_function("uscis_receipt", |b| {
        b.iter(|| scanner.mark_piis(USCIS_RECEIPT_TEXT));
    });

    group.bench_function("nz_nhi", |b| {
        b.iter(|| scanner.mark_piis(NZ_NHI_TEXT));
    });

    group.bench_function("nz_driver_licence", |b| {
        b.iter(|| scanner.mark_piis(NZ_DL_TEXT));
    });

    group.bench_function("ie_driver_number", |b| {
        b.iter(|| scanner.mark_piis(IE_DRIVER_TEXT));
    });

    group.bench_function("za_tax_reference", |b| {
        b.iter(|| scanner.mark_piis(ZA_TRN_TEXT));
    });

    group.bench_function("ca_ohip", |b| {
        b.iter(|| scanner.mark_piis(CA_OHIP_TEXT));
    });

    group.finish();
}

// Measures the baseline cost of scanning PII-free text where no patterns
// match. Shows the fixed overhead of running all regexes with zero results.
fn clean_text_overhead(c: &mut Criterion) {
    let scanner = Scanner::new().unwrap();

    let mut group = c.benchmark_group("clean_text_overhead");

    group.bench_function("has_piis", |b| {
        b.iter(|| scanner.has_piis(CLEAN_TEXT));
    });

    group.bench_function("mark_piis", |b| {
        b.iter(|| scanner.mark_piis(CLEAN_TEXT));
    });

    group.finish();
}

fn redaction_throughput(c: &mut Criterion) {
    let scanner = Scanner::new().unwrap();

    let mut group = c.benchmark_group("redaction");
    group.throughput(Throughput::Bytes(MIXED_PII_TEXT.len() as u64));

    group.bench_function("char_mask_mixed", |b| {
        b.iter(|| {
            let mut input = String::from(MIXED_PII_TEXT);
            scanner.redact(&mut input, &RedactWith::Char('*'));
        });
    });

    group.bench_function("type_label_mixed", |b| {
        b.iter(|| {
            let mut input = String::from(MIXED_PII_TEXT);
            scanner.redact(&mut input, &RedactWith::TypeLabel);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    throughput_mark_piis,
    throughput_has_piis,
    throughput_us_common_pii,
    has_piis_vs_mark_piis,
    per_pii_kind,
    clean_text_overhead,
    redaction_throughput
);
criterion_main!(benches);
