- [x] There is support for punnycode in emails
  - there should be also in other PIIs
  - also HTML entities and URL-encoding should be supported
  - it applies to:
    - [x] hyperscan scanner
    - [x] keyword context scanner
- [x] There's lots of #[cfg(feature = "parallel")] or #[cfg(feature = "hyperscan")] and related
  - consider gettint rid of features completely (at least hyperscan) and make them constant
  - it also eats additional tokens as cargo tests have to be run with combination of feature flags
- [dismissed - can be done by lib user] mark_piis and redact seem to not have has_piis call in order to avoid costly catching groups in case of lack of PII presence
- [dismissed - data extraction from files will be proxy's responsibility] the library supports text scanning, which means no support for scanning attachments and files like PDFs, docx, etc.
- [x] tests are slow for hyperscan, optimize them
- [x] Unit tests: global detector initialization is inconsistent (new_all() vs. new())
- Decoding support (from URL-encoded or HTML entities) probably should be moved to HTTP proxy
- [x] react() has some flaws:
  - [dismissed - it's user's job] performance: it doesn't run has_piis() before redacting
  - [x] writes output to `impt Write` instead of returning string.
- [x] has_piis in HyperscanDetector should have identical flow as in KeywordContextDetector (extraction validation)
  - after all, just extraction validation has been inctroduced
- [x] nested JSON support in detection (according to ChatGPT, Many leaks occur inside deep JSON fields, logs, or structured payloads.)
  - also thorough tests for PIIs in query string are a must
- [ ] PII candidates (noticed in Kong AI PII anonymizer service): person’s nationality, religious, or political group, zip code (!) (https://developer.konghq.com/plugins/ai-sanitizer/#ai-pii-anonymizer-service)
- [x] No support for CSV/TSV and deeply nested JSON
- [x] not all data is redacted, but probably should:

x curl -s -X POST http://127.0.0.1:8082/api/customers \
    -H 'Content-Type: application/json' \
    -d '{
      "customer":{
        "full_name":"Margaret Elizabeth Thompson",
        "date_of_birth":"1978-11-04",
        "email":"m.thompson@acme.co.uk",
        "phone_uk":"+44 20 7946 0958",
        "phone_us":"+1-415-555-0132",
        "address":{"line1":"10 Downing Street","postcode":"SW1A 2AA","lat":51.5034,"lon":-0.1276},
        "gov_ids":{"nino":"QQ123456C","nhs":"943 4765919","us_ssn":"123-45-6789","us_itin":"900-70-1234","passport_gb":"GB123456789"}
      },
      "payment":{
        "card_pan":"4111 1111 1111 1111","cvv":"123","expiry":"12/29",
        "iban":"GB82 WEST 1234 5698 7654 32","swift":"BARCGB22",
        "aba_routing":"026009593","crypto_btc":"1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
        "crypto_eth":"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEB0"
      },
      "device":{"ip":"203.0.113.42","mac":"00:1A:2B:3C:4D:5E","imei":"490154203237518","vin":"1HGCM82633A004352"},
      "secrets":{"aws_key":"AKIAIOSFODNN7EXAMPLE","aws_secret":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","gh_token":"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"}
    }'

x curl -s -X POST 'http://127.0.0.1:8082/mp/collect?measurement_id=G-XXXX&api_secret=demo' \
    -H 'Content-Type: application/json' \
    -d '{
      "client_id":"555.1713456789",
      "user_id":"jane.smith@testmail.org",
      "user_properties":{
        "crm_email":{"value":"jane.smith@testmail.org"},
        "billing_card_last4":{"value":"5500 0000 0000 0004"},
        "loyalty_nino":{"value":"AB 12 34 56 C"},
        "phone":{"value":"+33 1 42 68 53 00"}
      },
      "events":[{
        "name":"purchase",
        "params":{
          "transaction_id":"T-9021",
          "currency":"GBP","value":249.99,
          "customer_name":"Jane Smith",
          "dob":"1990-03-15",
          "shipping_address":"221B Baker Street, London NW1 6XE",
          "ip_override":"198.51.100.7",
          "items":[{"item_name":"Premium plan for dr. John H. Watson","item_id":"SKU-42"}]
        }
      }]
    }' | jq

x curl -s -X POST http://127.0.0.1:8082/matomo.php \
    -H 'Content-Type: application/json' \
    -d '{
      "requests":[
"?idsite=1&rec=1&url=https://shop.example/checkout?email=alice.martinez@example.de&card=5500000000000004&action_name=Checkout+for+Alice+Martinez+(DOB+1982-07-09)&uid=alice.martinez@example.de&_id=9f2c&_cvar={\"1\":[\"iban\",\"DE893704 0044 0532 0130 00\"],\"2\":[\"passport\",\"C01X00T47\"]}",
"?idsite=1&rec=1&url=https://shop.example/confirm&ec_id=ORD-778&ec_items=[[\"SKU-1\",\"Gift+for+Herr+Hans+Mueller\",\"Gifts\",49.00,1]]&country=DE&cip=203.0.113.77&ua=Mozilla/5.0"
      ]
    }' | jq


- [ ] Inconsistencies between countries: sometimes passport number is not present, sometimes is, sometimes address is not present, sometimes is - verify for all countries and pii kinds
- [x] Many systems internally use naming in English, even though they handle data in different language, e.g. JSON fields are in English, data is in German. Hence, probably all non-English PII kinds should have support in English language
- [x] There are tests for detection. There should be also extensive tests for avoiding false positives
- [x] GB Address and postal code overlap; it also causes wrong count of redacted PIIs in /v1/redact
- [x] Systemic approach to PIIs overlap and counting
- [ ] Should labels from redaction be url-encoded when URLs are handled? E.g. should following labels url-encoded? v=1&tid=UA-12345-1&cid=35009a79-1a05-49d7-b876-2b884d0f825b&t=event&ec=account&ea=signup&el=newsletter&uid=[EMAIL]&uip=[IP_ADDRESS]&dp=%2Fcheckout&dt=Checkout&cd1=Jane%20Doe&cd2=[PHONE_NUMBER]