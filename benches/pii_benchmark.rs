use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use pii::detector::Detector;
use pii::hyperscan_detector::HyperscanDetector;
use pii::keyword_context_detector::KeywordContextDetector;
use pii::{Language, PiiKind, Scanner};
use std::collections::HashSet;

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

const GB_PHONE_TEXT: &str = "\
UK Customer Service Record — Call Log\n\n\
Customer: Sarah Jenkins\n\
Phone: +44 7911 123456\n\
Alternate: 07700 900234\n\
Case opened after customer called regarding account access issues.\n\
Follow-up scheduled at phone 020 7946 0958.\n\
Contact agent at ext. 4200 for case updates.";

const AU_PHONE_TEXT: &str = "\
Australia Customer Service — Ticket #AU-4821\n\n\
Customer: James Nguyen\n\
Phone: +61 4 1234 5678\n\
Alternate: 04 9876 5432\n\
Customer called regarding a billing dispute.\n\
Transferred to billing team at tel 02 9876 5432.\n\
Callback scheduled for business hours.";

const NZ_PHONE_TEXT: &str = "\
New Zealand Support Ticket — NZ-1234\n\n\
Customer: Aroha Williams\n\
Phone: +64 2 123 4567\n\
Alternate: 09 876 5432\n\
Customer reported connectivity issues.\n\
Technical support callback at phone 04 987 6543.";

const IE_PHONE_TEXT: &str = "\
Irish Customer Service — Ticket #IE-0023\n\n\
Customer: Ciarán O'Brien\n\
Phone: +353 87 123 4567\n\
Alternate: 086 987 6543\n\
Case escalated to senior support at telephone 01 234 5678.";

const ZA_PHONE_TEXT: &str = "\
South Africa Customer Support — Ticket #ZA-0782\n\n\
Customer: Thabo Nkosi\n\
Phone: +27 71 123 4567\n\
Alternate: 082 987 6543\n\
Customer queried account statement.\n\
Escalation contact: tel 011 234 5678.";

const ZA_PASSPORT_TEXT: &str = "\
South Africa Home Affairs — Passport Verification\n\n\
Travellers requiring passport verification:\n\
- Traveller A: South African passport: 123456789\n\
- Traveller B: SA passport: 987654321\n\
All passports must be verified against Home Affairs records.\n\
Contact the nearest office for discrepancies.";

const ZA_DL_TEXT: &str = "\
South Africa Road Traffic — Driver's Licence Verification\n\n\
Drivers requiring licence verification:\n\
- Driver A: Driver's licence: 8001015009087\n\
- Driver B: Driving licence: 9506150089081\n\
All driver's licences must be verified before renewal.\n\
Contact the licensing department for corrections.";

const US_ZA_POSTAL_TEXT: &str = "\
Postal Code Verification — Cross-border directory\n\n\
Addresses requiring postal code verification:\n\
- South Africa A: Postal code: 0001\n\
- South Africa B: Zip code: 8001\n\
- United States A: ZIP code: 90210\n\
- United States B: zip: 10001-1234\n\
- United States C: postal code: 20500\n\
All postal codes must be verified against SAPO and USPS records.\n\
Contact the post office for any issues.";

const IE_EIRCODE_TEXT: &str = "\
Ireland Customer Address Verification — Q1 2026\n\n\
Records requiring Eircode validation:\n\
- Customer A: D02 X285\n\
- Customer B: T12 N5CY\n\
- Customer C: D6W FD93\n\
- Customer D: F92 AB12\n\
- Customer E: D02X285\n\
All Eircodes must be verified against An Post records before dispatch.";

const AWS_ACCESS_KEY_TEXT: &str = "\
AWS Infrastructure Audit — Q1 2025\n\n\
Rotated credentials detected in CI pipeline logs:\n\
- Service account A: AKIAIOSFODNN7EXAMPLE\n\
- Service account B: AKIAI44QH8DHBEXAMPLE\n\
All access keys must be rotated within 90 days per security policy.\n\
Contact the security team to revoke compromised credentials.";

const GITHUB_TOKEN_TEXT: &str = "\
GitHub Actions Workflow — Token Audit\n\n\
Personal access tokens found in repository history:\n\
- Developer A: gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12\n\
- Developer B: ghp_XYZabcdefghijklmnopqrstuvwxyz012345\n\
All tokens must be revoked and regenerated immediately.\n\
Review secret scanning alerts in the GitHub repository settings.";

const AWS_SECRET_KEY_TEXT: &str = "\
AWS Secrets Rotation — Security Notice\n\n\
The following secret access keys require immediate rotation:\n\
- Account A: AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
- Account B: secret_access_key: abcdefghijklmnopqrstuvwxyz0123456789ABCD\n\
Please update all affected services and rotate keys in IAM immediately.\n\
Contact DevOps for assistance with the rotation procedure.";

const GB_PASSPORT_TEXT: &str = "\
UK Border Control — Passenger Verification\n\n\
Passengers requiring identity verification:\n\
- Passenger A: British passport: 123456789\n\
- Passenger B: UK passport: 987654321\n\
All passports must be verified against UKBA records before boarding.\n\
Contact border control for any discrepancies.";

const AU_PASSPORT_TEXT: &str = "\
Australian Border Force — Passenger Records\n\n\
Passengers processed at international arrivals:\n\
- Traveller A: Australian passport: A1234567\n\
- Traveller B: Passport number: B7654321\n\
All passport numbers must be scanned and verified.\n\
Contact the ABF helpdesk for any issues.";

const CA_PASSPORT_TEXT: &str = "\
Canada Border Services Agency — Entry Records\n\n\
Travellers processed at the port of entry:\n\
- Traveller A: Canadian passport: AB123456\n\
- Traveller B: Passport number: XY987654\n\
All documents must be verified against CBSA records.\n\
Contact CBSA for discrepancies.";

const NZ_PASSPORT_TEXT: &str = "\
New Zealand Customs — Arrival Records\n\n\
Arriving passengers:\n\
- Passenger A: New Zealand passport: NZ123456\n\
- Passenger B: NZ passport: L1234567\n\
All passports verified against NZCS records.\n\
Contact customs for queries.";

const IE_PASSPORT_TEXT: &str = "\
Irish Naturalisation and Immigration Service — Records\n\n\
Applications processed:\n\
- Applicant A: Irish passport: AB1234567\n\
- Applicant B: Ireland passport: CD7654321\n\
All passports verified against INIS records.\n\
Contact INIS for corrections.";

const DOB_TEXT: &str = "\
HR System — Employee Date of Birth Verification\n\n\
The following records require DOB confirmation:\n\
- Employee A: Date of birth: 15/03/1985\n\
- Employee B: DOB: 1990-07-22\n\
- Employee C: Born on: 01-01-1978\n\
All records must be verified against original documents.\n\
Contact HR for any discrepancies.";

const GB_POSTCODE_TEXT: &str = "\
UK Address Verification — Batch Process\n\n\
Addresses requiring postcode validation:\n\
- Record A: London, SW1A 1AA\n\
- Record B: Manchester, M1 1AE\n\
- Record C: Edinburgh, EH1 1YZ\n\
All postcodes must be validated against Royal Mail PAF.\n\
Contact the address team for corrections.";

const CA_POSTAL_CODE_TEXT: &str = "\
Canada Post — Address Verification\n\n\
Delivery records requiring postal code check:\n\
- Record A: Toronto, M5V 3L9\n\
- Record B: Ottawa, K1A 0B1\n\
- Record C: Vancouver, V6B 2W9\n\
All postal codes verified against Canada Post database.\n\
Contact the delivery team for corrections.";

const BITCOIN_ADDRESS_TEXT: &str = "\
Cryptocurrency Audit — Wallet Inventory\n\n\
Bitcoin wallets flagged for review:\n\
- Wallet A: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n\
- Wallet B: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy\n\
All wallet addresses must be verified against transaction records.\n\
Contact the compliance team for further investigation.";

const ETHEREUM_ADDRESS_TEXT: &str = "\
DeFi Platform — Account Review\n\n\
Ethereum wallets requiring KYC verification:\n\
- Account A: 0x1234567890abcdef1234567890abcdef12345678\n\
- Account B: 0xAbCdEf1234567890AbCdEf1234567890AbCdEf12\n\
All addresses must be linked to verified identities.\n\
Contact the compliance team for KYC escalation.";

const AU_BANK_ACCOUNT_TEXT: &str = "\
Australian Banking — BSB Verification\n\n\
Bank accounts flagged for validation:\n\
- Account A: BSB: 012-345 Account: 123456789\n\
- Account B: BSB number: 082-001\n\
All BSB numbers must be validated against APCA records.\n\
Contact the bank for any discrepancies.";

const CA_BANK_ACCOUNT_TEXT: &str = "\
Canadian Banking — Account Verification\n\n\
Bank transit records requiring validation:\n\
- Account A: Transit number: 00100 001 1234567\n\
- Account B: Chequing account: 9876543210\n\
All transit and institution numbers must be verified.\n\
Contact the bank for corrections.";

const FR_NIR_TEXT: &str = "\
Caisse Primaire d'Assurance Maladie — Vérification des Assurés\n\n\
Dossiers à vérifier avant traitement :\n\
- Assuré A : numéro de sécurité sociale : 1 85 05 78 006 084 91\n\
- Assuré B : numéro sécu : 2 84 11 75 012 345 20\n\
Tous les numéros doivent être vérifiés avant le remboursement.\n\
Contactez la CPAM pour toute correction.";

const FR_SIRET_TEXT: &str = "\
Chambre de Commerce — Vérification des Entreprises\n\n\
Entreprises enregistrées ce trimestre :\n\
- Entreprise A : SIRET : 73282932000074\n\
- Entreprise B : numéro SIRET : 44306184100047\n\
Tous les numéros SIRET doivent être vérifiés au registre.\n\
Contactez le greffe pour toute correction.";

const FR_PHONE_TEXT: &str = "\
Service Client — Fiche d'Appel\n\n\
Client : Jean Dupont\n\
Téléphone : 06 12 34 56 78\n\
Autre contact : portable : +33 7 98 76 54 32\n\
Le client a appelé concernant une facturation.\n\
Rappel prévu à téléphone : 01 23 45 67 89.";

const FR_MIXED_TEXT: &str = "\
DOSSIER CLIENT #FR-2025-0042\n\
Priorité : Haute\n\
Créé : 2025-01-15 09:23:41 UTC\n\n\
Informations Client :\n\
  Nom : Marie Dubois\n\
  Téléphone : 06 12 34 56 78\n\
  Code postal : 75008\n\n\
Vérification d'Identité :\n\
  Numéro de sécurité sociale : 1 85 05 78 006 084 91\n\
  Carte d'identité : 123456789012\n\
  Passeport français : 05AB12345\n\
  Permis de conduire : 987654321012\n\
  Numéro fiscal : 0123456789012\n\n\
Entreprise :\n\
  SIRET : 73282932000074\n\
  SIREN : 732829320\n\n\
Informations Bancaires :\n\
  Code SWIFT : BNPAFRPP\n\
  Numéro IMEI : 490154203237518\n\n\
Date de naissance : 15 mars 1990\n\
Coordonnées GPS : 48.8566,2.3522\n\n\
Fin des notes du dossier.\n";

// Realistic French support ticket containing the 5 most common France PII
// types: email, phone, NIR (sécurité sociale), postal code, and SIRET.
// More representative of everyday French-language proxy traffic than the
// exhaustive FR_MIXED_TEXT fixture.
const FR_COMMON_PII_TEXT: &str = "\
FICHE DE SUIVI — SERVICE CLIENT\n\
Dossier : #CLI-2025-0317\n\
Date : 2025-03-15\n\n\
Informations Client :\n\
  Nom : Sophie Martin\n\
  E-mail : s.martin@example.fr\n\
  Téléphone : 06 12 34 56 78\n\
  Autre contact : portable : +33 7 98 76 54 32\n\n\
Vérification d'Identité :\n\
  Numéro de sécurité sociale : 2 84 11 75 012 345 20\n\n\
Adresse :\n\
  12 rue de la Paix\n\
  Code postal : 75002\n\
  Paris, France\n\n\
Entreprise associée :\n\
  Raison sociale : Dupont & Fils SARL\n\
  SIRET : 73282932000074\n\n\
Notes :\n\
La cliente a contacté le service au sujet d'une erreur de facturation.\n\
Un second e-mail a été envoyé à comptabilite@dupont-fils.example.fr.\n\
Rappel prévu à téléphone : 01 23 45 67 89.\n\n\
Statut : En cours — en attente de rappel client.";

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

const PERSON_NAME_TEXT: &str = "\
Hospital Admissions — Patient Registry\n\n\
Patients admitted this week:\n\
- Patient A: Patient name: John Smith\n\
- Patient B: Full name: María García-López\n\
- Patient C: Nom complet: Jean-Pierre Dubois\n\
- Patient D: Nachname: Müller, Vorname: Hans\n\
All patient names must be verified against identity documents.\n\
Contact the admissions desk for corrections.";

const AU_DL_TEXT: &str = "\
Transport for NSW — Driver Licence Verification\n\n\
Drivers requiring licence verification:\n\
- Driver A: Australian driver's licence: 12345678\n\
- Driver B: Aus driver's license: 1234567890\n\
All driver's licences must be verified before renewal.\n\
Contact the licensing department for corrections.";

const AU_ABN_TEXT: &str = "\
Australian Business Register — ABN Verification\n\n\
Businesses requiring ABN verification:\n\
- Business A: ABN: 51 824 753 556\n\
- Business B: Australian business number: 33 051 775 556\n\
All ABNs must be verified before registration.\n\
Contact the ABR for corrections.";

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
Tier 5 Verification Records:\n\
  GB phone: +44 7911 123456\n\
  AU phone: +61 4 1234 5678\n\
  NZ phone: +64 2 123 4567\n\
  IE phone: +353 87 123 4567\n\
  ZA phone: +27 71 123 4567\n\
  AWS access key: AKIAIOSFODNN7EXAMPLE\n\
  GitHub token: gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12\n\
  AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
  South African passport: 123456789\n\
  Driver's licence: 8001015009087\n\
  Postal code: 0001\n\
  US ZIP: 90210-1234\n\
  IE Eircode: D02 X285\n\
  British passport: 123456789\n\
  Australian passport: A1234567\n\
  Canadian passport: AB123456\n\
  New Zealand passport: NZ123456\n\
  Irish passport: AB1234567\n\
  Date of birth: 15/03/1985\n\
  GB postcode: SW1A 1AA\n\
  CA postal code: M5V 3L9\n\
  Bitcoin wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n\
  Ethereum wallet: 0x1234567890abcdef1234567890abcdef12345678\n\
  BSB: 012-345\n\
  Transit number: 00100 001 1234567\n\
  Australian driver's licence: 12345678\n\
  ABN: 51 824 753 556\n\n\
Tier 6 France Verification Records:\n\
  Numéro de sécurité sociale: 1 85 05 78 006 084 91\n\
  SIRET: 73282932000074\n\
  SIREN: 732829320\n\
  Passeport français: 05AB12345\n\
  Carte d'identité: 123456789012\n\
  Permis de conduire: 987654321012\n\
  Téléphone: 06 12 34 56 78\n\
  Code postal: 75008\n\
  Numéro fiscal: 0123456789012\n\
  Adresse: 15 rue de la Paix, 75002 Paris\n\
  BP: 1234, 75008 Paris\n\n\
Tier 7 Germany/Austria/Switzerland Verification Records:\n\
  Steuer-ID: 65929970489\n\
  Personalausweis: L01X00T471\n\
  Rufnummer: +49 30 12345678\n\
  Postleitzahl: 10115\n\
  SVNR: 1238150185\n\
  AHV-Nummer: 756.1234.5678.97\n\
  Geburtsdatum: 15 März 1990\n\
  Reisepass: 123456789\n\
  Anschrift: Musterstraße 42, 10115 Berlin\n\
  Postfach: 1234, 10557 Berlin\n\
  Packstation: 109, 01099 Dresden\n\
  Wohnadresse: Schillerstraße 10, 1010 Wien\n\
  Postfach: 789, 5020 Salzburg\n\
  Lieferadresse: Bahnhofstrasse 1, 8001 Zürich\n\
  Postfach: 567, 6000 Luzern\n\n\
Tier 8 Person Names:\n\
  Full name: Jane Doe\n\
  Nom complet: Jean-Pierre Dupont\n\
  Nachname: Müller\n\n\
End of ticket notes.\n";

const DE_STEUER_ID_TEXT: &str = "\
Bundeszentralamt für Steuern — Steuerliche Identifikation\n\n\
Die folgenden Steuer-IDs müssen überprüft werden:\n\
- Steuerpflichtiger A: Steuer-ID: 65929970489\n\
- Steuerpflichtiger B: Steueridentifikationsnummer: 86095742719\n\
Alle Steuer-IDs müssen vor der Steuererklärung verifiziert werden.\n\
Kontaktieren Sie das Finanzamt bei Unstimmigkeiten.";

const DE_PHONE_TEXT: &str = "\
Kundendienst — Anrufprotokoll\n\n\
Kunde: Hans Müller\n\
Rufnummer: +49 30 12345678\n\
Alternativ: Handynummer: +49 151 12345678\n\
Der Kunde rief bezüglich einer Rechnungsfrage an.\n\
Rückruf geplant an Telefonnummer: +49 89 98765432.";

const AT_SVNR_TEXT: &str = "\
Österreichische Sozialversicherung — Versichertendaten\n\n\
Versicherte zur Überprüfung:\n\
- Versicherter A: SVNR: 1238150185\n\
- Versicherter B: Sozialversicherungsnummer: 1233250689\n\
Alle Versicherungsnummern müssen verifiziert werden.\n\
Kontaktieren Sie die zuständige Kasse bei Fragen.";

const CH_AHV_TEXT: &str = "\
Schweizerische Ausgleichskasse — AHV-Nummern\n\n\
Zu überprüfende Versicherte:\n\
- Versicherter A: AHV-Nummer: 756.1234.5678.97\n\
- Versicherter B: Versichertennummer: 756.5432.1098.73\n\
Alle AHV-Nummern müssen im Register verifiziert werden.\n\
Kontaktieren Sie die Ausgleichskasse bei Korrekturen.";

const DE_MIXED_TEXT: &str = "\
KUNDENDOSSIER #DE-2025-0042\n\
Priorität: Hoch\n\
Erstellt: 2025-01-15 09:23:41 UTC\n\n\
Kundeninformationen:\n\
  Name: Thomas Müller\n\
  Rufnummer: +49 30 12345678\n\
  Postleitzahl: 10115\n\n\
Identitätsprüfung:\n\
  Steuer-ID: 65929970489\n\
  Personalausweis: L01X00T471\n\n\
Österreichischer Partner:\n\
  SVNR: 1238150185\n\
  PLZ: 1010\n\n\
Schweizer Kontakt:\n\
  AHV-Nummer: 756.1234.5678.97\n\
  PLZ: 8001\n\n\
Internationale Daten:\n\
  Reisepass: 123456789\n\
  BIC-Code: DEUTDEFF\n\
  Geburtsdatum: 15 März 1990\n\
  Standort: 48.1351,11.5820\n\
  Gerätekennung: 490154203237518\n\n\
Ende der Notizen.\n";

const DE_COMMON_PII_TEXT: &str = "\
KUNDENSERVICE — GESPRÄCHSNOTIZ\n\
Vorgang: #KD-2025-0317\n\
Datum: 2025-03-15\n\n\
Kundeninformationen:\n\
  Name: Anna Schmidt\n\
  E-Mail: a.schmidt@example.de\n\
  Rufnummer: +49 30 12345678\n\
  Alternativ: Handynummer: +49 151 98765432\n\n\
Identitätsprüfung:\n\
  Steuer-ID: 65929970489\n\n\
Adresse:\n\
  Friedrichstraße 43\n\
  Postleitzahl: 10117\n\
  Berlin, Deutschland\n\n\
Bankverbindung:\n\
  BIC-Code: DEUTDEFF\n\n\
Notizen:\n\
Die Kundin hat sich wegen einer fehlerhaften Rechnung gemeldet.\n\
Eine Bestätigung wurde an buchhaltung@firma-beispiel.de gesendet.\n\
Rückruf geplant an Rufnummer: +49 89 98765432.\n\n\
Status: In Bearbeitung — warte auf Kundenrückruf.";

const DE_AT_CH_ADDRESS_TEXT: &str = "\
Einwohnermeldeamt — Adressverifikation\n\n\
Die folgenden Adressen müssen überprüft werden:\n\
- Mieter A: Anschrift: Musterstraße 42, 10115 Berlin\n\
- Mieter B: Wohnadresse: Hauptstraße 10-12, 80331 München\n\
- Mieter C: Meldeadresse: Bahnhofstr. 1, 60311 Frankfurt\n\
- Mieter D: Anschrift: Schillerstraße 10, 1010 Wien\n\
- Mieter E: Wohnadresse: Josefstädterstraße 21/5, 1080 Wien\n\
- Mieter F: Anschrift: Bahnhofstrasse 1, 8001 Zürich\n\
- Mieter G: Wohnadresse: Bundesplatz 3, 3003 Bern\n\
Alle Adressen müssen im Melderegister verifiziert werden.\n\
Kontaktieren Sie das Einwohnermeldeamt bei Fragen.";

const DE_AT_CH_POSTFACH_TEXT: &str = "\
Deutsche Post — Postfachzustellung\n\n\
Postfächer zur Überprüfung:\n\
- Kunde A: Postfach: 1234, 10557 Berlin\n\
- Kunde B: PF: 56, 80331 München\n\
- Kunde C: Postfach: 789, 5020 Salzburg\n\
- Kunde D: Postfach: 567, 6000 Luzern\n\
Alle Postfächer müssen im System registriert sein.\n\
Kontaktieren Sie die Deutsche Post bei Fragen.";

const DE_PACKSTATION_TEXT: &str = "\
DHL — Packstation-Verwaltung\n\n\
Packstationen zur Überprüfung:\n\
- Kunde A: Packstation: 109, 01099 Dresden\n\
- Kunde B: Postfiliale: 502, 10115 Berlin\n\
Alle Packstationen müssen registriert sein.\n\
Kontaktieren Sie DHL bei Fragen.";

const FR_CH_ADDRESS_TEXT: &str = "\
La Poste — Vérification des adresses\n\n\
Les adresses suivantes doivent être vérifiées :\n\
- Client A: adresse: 15 rue de la Paix, 75002 Paris\n\
- Client B: domicile: 42 boulevard Haussmann, 75009 Paris\n\
- Client C: résidence: 3 place Bellecour, 69002 Lyon\n\
- Client D: habitation: 7 allée des Pins, 13008 Marseille\n\
- Client E: adresse de livraison: 25 cours de l'Intendance, 33000 Bordeaux\n\
- Client F: domicile: rue du Général-Dufour 24, 1211 Genève\n\
- Client G: résidence: avenue Nestlé 55, 1800 Vevey\n\
Toutes les adresses doivent être vérifiées dans le système.\n\
Contactez La Poste en cas de questions.";

const FR_CH_BOITE_POSTALE_TEXT: &str = "\
La Poste — Gestion des boîtes postales et cases postales\n\n\
Boîtes et cases postales à vérifier :\n\
- Client A: BP: 1234, 75008 Paris\n\
- Client B: boîte postale: 56, 69001 Lyon\n\
- Client C: BP: 789, 97100 Basse-Terre\n\
- Client D: case postale: 2272, 1950 Sion\n\
- Client E: CP: 440, 1211 Genève\n\
Toutes les boîtes postales doivent être enregistrées.\n\
Contactez La Poste en cas de questions.";

// Text with 5 PIIs handled by HyperscanDetector (structurally unique, no keywords needed):
// Email, CreditCard, UsSsn, Iban, IpAddress
const HYPERSCAN_5_TEXT: &str = "\
FRAUD INVESTIGATION — CASE #FI-2025-0442\n\
Date: 2025-02-20\n\n\
Subject contacted us via j.doe@example.com regarding unauthorized access.\n\
The compromised card number is 4111 1111 1111 1111, used in two transactions.\n\
A second card 5500 0000 0000 0004 was also flagged.\n\n\
Identity verification on file: SSN 078-05-1120.\n\
Wire transfer traced to IBAN DE89 3704 0044 0532 0130 00.\n\
A second IBAN GB29 NWBK 6016 1331 9268 19 was linked to the account.\n\n\
Login originated from IP 203.0.113.55. Secondary access from 2001:0db8:85a3:0000:0000:8a2e:0370:7334.\n\
Notifications sent to alert-team@bank.example.com.\n\n\
Case Status: Under Review.";

// Text with 5 PIIs handled by KeywordContextDetector (keyword + value):
// UsPhoneNumber, PassportNumber, SwiftBic, UsEin, PreciseGeolocation
const KEYWORD_5_TEXT: &str = "\
COMPLIANCE AUDIT — RECORD #CA-2025-0891\n\
Date: 2025-03-10\n\n\
Primary contact phone: (555) 867-5309. Alternate telephone: 555-234-7890.\n\n\
Travel document verification:\n\
  Passport number: 123456789\n\
  Second passport: 987654321\n\n\
Banking details:\n\
  SWIFT code: DEUTDEFF\n\
  Backup BIC: BNPAFRPP\n\n\
Corporate registration:\n\
  EIN: 12-3456789\n\
  Secondary EIN: 20-1234567\n\n\
Site inspection coordinates:\n\
  GPS location: 40.7128,-74.0060\n\
  Secondary coordinates: 51.5074,-0.1278\n\n\
Audit Status: Pending Review.";

fn make_long_clean_text() -> String {
    CLEAN_TEXT.repeat(20)
}

// Measures bytes/second throughput of mark_piis across different input sizes
// and content types: PII-free text (~500B), mixed PII (~2KB), and long clean text (~10KB).
fn throughput_mark_piis(c: &mut Criterion) {
    let scanner = Scanner::new().unwrap();
    let long_clean = make_long_clean_text();

    let mut group = c.benchmark_group("throughput_mark_piis");

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

// Measures bytes/second throughput of mark_piis and has_piis on a realistic
// French support-ticket containing only the 5 most common France PII types
// (email, phone, NIR, postal code, SIRET). More representative of
// everyday French-language proxy traffic than the exhaustive FR_MIXED_TEXT fixture.
fn throughput_fr_common_pii(c: &mut Criterion) {
    let scanner = Scanner::new().unwrap();

    let mut group = c.benchmark_group("throughput_fr_common_pii");
    group.throughput(Throughput::Bytes(FR_COMMON_PII_TEXT.len() as u64));

    group.bench_function("mark_piis", |b| {
        b.iter(|| scanner.mark_piis(FR_COMMON_PII_TEXT));
    });

    group.bench_function("has_piis", |b| {
        b.iter(|| scanner.has_piis(FR_COMMON_PII_TEXT));
    });

    group.finish();
}

// Measures bytes/second throughput of mark_piis and has_piis on a realistic
// German support-ticket containing common DACH PII types (email, phone,
// Steuer-ID, postal code, BIC). Representative of everyday German-language
// proxy traffic.
fn throughput_de_common_pii(c: &mut Criterion) {
    let scanner = Scanner::new().unwrap();

    let mut group = c.benchmark_group("throughput_de_common_pii");
    group.throughput(Throughput::Bytes(DE_COMMON_PII_TEXT.len() as u64));

    group.bench_function("mark_piis", |b| {
        b.iter(|| scanner.mark_piis(DE_COMMON_PII_TEXT));
    });

    group.bench_function("has_piis", |b| {
        b.iter(|| scanner.has_piis(DE_COMMON_PII_TEXT));
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

    // International phones
    group.bench_function("gb_phone", |b| {
        b.iter(|| scanner.mark_piis(GB_PHONE_TEXT));
    });

    group.bench_function("au_phone", |b| {
        b.iter(|| scanner.mark_piis(AU_PHONE_TEXT));
    });

    group.bench_function("nz_phone", |b| {
        b.iter(|| scanner.mark_piis(NZ_PHONE_TEXT));
    });

    group.bench_function("ie_phone", |b| {
        b.iter(|| scanner.mark_piis(IE_PHONE_TEXT));
    });

    group.bench_function("za_phone", |b| {
        b.iter(|| scanner.mark_piis(ZA_PHONE_TEXT));
    });

    group.bench_function("za_passport", |b| {
        b.iter(|| scanner.mark_piis(ZA_PASSPORT_TEXT));
    });

    group.bench_function("za_drivers_license", |b| {
        b.iter(|| scanner.mark_piis(ZA_DL_TEXT));
    });

    group.bench_function("us_za_postal_code", |b| {
        b.iter(|| scanner.mark_piis(US_ZA_POSTAL_TEXT));
    });

    group.bench_function("ie_eircode", |b| {
        b.iter(|| scanner.mark_piis(IE_EIRCODE_TEXT));
    });

    group.bench_function("au_drivers_license", |b| {
        b.iter(|| scanner.mark_piis(AU_DL_TEXT));
    });

    group.bench_function("au_abn", |b| {
        b.iter(|| scanner.mark_piis(AU_ABN_TEXT));
    });

    // API secrets
    group.bench_function("aws_access_key", |b| {
        b.iter(|| scanner.mark_piis(AWS_ACCESS_KEY_TEXT));
    });

    group.bench_function("github_token", |b| {
        b.iter(|| scanner.mark_piis(GITHUB_TOKEN_TEXT));
    });

    group.bench_function("aws_secret_key", |b| {
        b.iter(|| scanner.mark_piis(AWS_SECRET_KEY_TEXT));
    });

    // Country-specific passports
    group.bench_function("gb_passport", |b| {
        b.iter(|| scanner.mark_piis(GB_PASSPORT_TEXT));
    });

    group.bench_function("au_passport", |b| {
        b.iter(|| scanner.mark_piis(AU_PASSPORT_TEXT));
    });

    group.bench_function("ca_passport", |b| {
        b.iter(|| scanner.mark_piis(CA_PASSPORT_TEXT));
    });

    group.bench_function("nz_passport", |b| {
        b.iter(|| scanner.mark_piis(NZ_PASSPORT_TEXT));
    });

    group.bench_function("ie_passport", |b| {
        b.iter(|| scanner.mark_piis(IE_PASSPORT_TEXT));
    });

    // Date of birth
    group.bench_function("date_of_birth", |b| {
        b.iter(|| scanner.mark_piis(DOB_TEXT));
    });

    // Postal codes
    group.bench_function("gb_postcode", |b| {
        b.iter(|| scanner.mark_piis(GB_POSTCODE_TEXT));
    });

    group.bench_function("ca_postal_code", |b| {
        b.iter(|| scanner.mark_piis(CA_POSTAL_CODE_TEXT));
    });

    // Crypto addresses
    group.bench_function("bitcoin_address", |b| {
        b.iter(|| scanner.mark_piis(BITCOIN_ADDRESS_TEXT));
    });

    group.bench_function("ethereum_address", |b| {
        b.iter(|| scanner.mark_piis(ETHEREUM_ADDRESS_TEXT));
    });

    // Bank accounts
    group.bench_function("au_bank_account", |b| {
        b.iter(|| scanner.mark_piis(AU_BANK_ACCOUNT_TEXT));
    });

    group.bench_function("ca_bank_account", |b| {
        b.iter(|| scanner.mark_piis(CA_BANK_ACCOUNT_TEXT));
    });

    // France
    group.bench_function("fr_nir", |b| {
        b.iter(|| scanner.mark_piis(FR_NIR_TEXT));
    });

    group.bench_function("fr_siret", |b| {
        b.iter(|| scanner.mark_piis(FR_SIRET_TEXT));
    });

    group.bench_function("fr_phone", |b| {
        b.iter(|| scanner.mark_piis(FR_PHONE_TEXT));
    });

    group.bench_function("fr_mixed", |b| {
        b.iter(|| scanner.mark_piis(FR_MIXED_TEXT));
    });

    group.bench_function("fr_ch_address", |b| {
        b.iter(|| scanner.mark_piis(FR_CH_ADDRESS_TEXT));
    });

    group.bench_function("fr_ch_boite_postale", |b| {
        b.iter(|| scanner.mark_piis(FR_CH_BOITE_POSTALE_TEXT));
    });

    // Germany/Austria/Switzerland
    group.bench_function("de_steuer_id", |b| {
        b.iter(|| scanner.mark_piis(DE_STEUER_ID_TEXT));
    });

    group.bench_function("de_phone", |b| {
        b.iter(|| scanner.mark_piis(DE_PHONE_TEXT));
    });

    group.bench_function("at_svnr", |b| {
        b.iter(|| scanner.mark_piis(AT_SVNR_TEXT));
    });

    group.bench_function("ch_ahv", |b| {
        b.iter(|| scanner.mark_piis(CH_AHV_TEXT));
    });

    group.bench_function("de_mixed", |b| {
        b.iter(|| scanner.mark_piis(DE_MIXED_TEXT));
    });

    group.bench_function("de_at_ch_address", |b| {
        b.iter(|| scanner.mark_piis(DE_AT_CH_ADDRESS_TEXT));
    });

    group.bench_function("de_at_ch_postfach", |b| {
        b.iter(|| scanner.mark_piis(DE_AT_CH_POSTFACH_TEXT));
    });

    group.bench_function("de_packstation", |b| {
        b.iter(|| scanner.mark_piis(DE_PACKSTATION_TEXT));
    });

    // Person names
    group.bench_function("person_name", |b| {
        b.iter(|| scanner.mark_piis(PERSON_NAME_TEXT));
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

// Measures bytes/second throughput of HyperscanDetector in isolation on 5 common
// structurally-unique PIIs (Email, CreditCard, UsSsn, Iban, IpAddress).
// Shows detector cost without KeywordContextDetector overhead.
fn throughput_hyperscan_detector(c: &mut Criterion) {
    let kinds: HashSet<PiiKind> = [
        PiiKind::Email,
        PiiKind::CreditCard,
        PiiKind::UsSsn,
        PiiKind::Iban,
        PiiKind::IpAddress,
    ]
    .into_iter()
    .collect();
    let detector = HyperscanDetector::new(&kinds).unwrap();
    let long_clean = make_long_clean_text();

    let inputs: &[(&str, &str)] = &[
        ("clean_500b", CLEAN_TEXT),
        ("pii_5types", HYPERSCAN_5_TEXT),
        ("clean_10kb", &long_clean),
    ];

    let mut group = c.benchmark_group("throughput_hyperscan_detector");
    for (name, text) in inputs {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(BenchmarkId::new("has_piis", name), text, |b, input| {
            b.iter(|| detector.has_piis(input));
        });
        group.bench_with_input(BenchmarkId::new("mark_piis", name), text, |b, input| {
            b.iter(|| detector.mark_piis(input));
        });
    }
    group.finish();
}

// Measures bytes/second throughput of KeywordContextDetector in isolation on 5 common
// keyword-based PIIs (UsPhoneNumber, PassportNumber, SwiftBic, UsEin, PreciseGeolocation).
// Shows keyword-detection + regex-extraction cost without HyperscanDetector overhead.
fn throughput_keyword_detector(c: &mut Criterion) {
    let kinds: HashSet<PiiKind> = [
        PiiKind::UsPhoneNumber,
        PiiKind::PassportNumber,
        PiiKind::SwiftBic,
        PiiKind::UsEin,
        PiiKind::PreciseGeolocation,
    ]
    .into_iter()
    .collect();
    let languages: HashSet<Language> = Language::all().iter().copied().collect();
    let detector = KeywordContextDetector::new(&kinds, &languages).unwrap();
    let long_clean = make_long_clean_text();

    let inputs: &[(&str, &str)] = &[
        ("clean_500b", CLEAN_TEXT),
        ("pii_5types", KEYWORD_5_TEXT),
        ("clean_10kb", &long_clean),
    ];

    let mut group = c.benchmark_group("throughput_keyword_detector");
    for (name, text) in inputs {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(BenchmarkId::new("has_piis", name), text, |b, input| {
            b.iter(|| detector.has_piis(input));
        });
        group.bench_with_input(BenchmarkId::new("mark_piis", name), text, |b, input| {
            b.iter(|| detector.mark_piis(input));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    throughput_mark_piis,
    throughput_has_piis,
    throughput_us_common_pii,
    throughput_fr_common_pii,
    throughput_de_common_pii,
    has_piis_vs_mark_piis,
    per_pii_kind,
    clean_text_overhead,
    throughput_hyperscan_detector,
    throughput_keyword_detector
);
criterion_main!(benches);
