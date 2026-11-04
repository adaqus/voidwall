# Benchmarks: add-secret-kinds

Measured 2026-11-04 on one machine, `cargo bench -p voidwall-pii --bench pii_benchmark`.
Values are criterion medians.

- Base: `fe00bf1` (before the patterns of section 3), built from a clean export.
- After: this change.

Base and after ran back to back, twice (rounds 1 and 2), because a first single run
showed a ~25% drift in groups this change does not touch (`throughput_hyperscan_detector`
and `throughput_keyword_detector` with no secret kind enabled).

`MIXED_PII_TEXT` differs between base and after only in the two AWS sample values: each
is replaced by a real-shaped value of the same length (task 5.2).

## Task 5.1: baseline (single run)

| Bench | Base |
|---|---|
| `throughput_mark_piis/mark_piis/clean_500b` | 8.09 µs |
| `throughput_mark_piis/mark_piis/mixed_2kb` | 367.53 µs |
| `throughput_mark_piis/mark_piis/clean_10kb` | 146.41 µs |
| `throughput_has_piis/has_piis/clean_500b` | 7.94 µs |
| `throughput_has_piis/has_piis/mixed_2kb` | 13.96 µs |
| `throughput_has_piis/has_piis/clean_10kb` | 142.10 µs |

## Task 5.2: base and after, interleaved

| Bench | Base 1 | After 1 | Base 2 | After 2 |
|---|---|---|---|---|
| `mark_piis/clean_500b` | 8.13 µs | 10.27 µs | 8.17 µs | 10.28 µs |
| `mark_piis/mixed_2kb` | 358.53 µs | 391.71 µs | 364.20 µs | 380.90 µs |
| `mark_piis/clean_10kb` | 143.22 µs | 174.69 µs | 143.89 µs | 326.17 µs (outlier) |
| `has_piis/clean_500b` | 7.98 µs | 10.14 µs | 8.08 µs | 10.78 µs |
| `has_piis/mixed_2kb` | 14.03 µs | 12.92 µs | 14.01 µs | 13.86 µs |
| `has_piis/clean_10kb` | 145.53 µs | 232.00 µs | 152.43 µs | 178.59 µs |
| `mark_piis/secrets_mixed` (new) | – | 22.95 µs | – | 23.23 µs |
| `has_piis/secrets_mixed` (new) | – | 3.40 µs | – | 3.65 µs |

Result: on clean text the full scanner costs about 22–27% more (about +2 µs per 500 B,
+31 µs per 10 KB). On the mixed corpus `mark_piis` costs 5–9% more, and `has_piis` does not
change, because it stops at the first finding.

## One pattern alone (design, Risks)

`secret_pattern_cost`: a `HyperscanDetector` with one kind enabled, `mark_piis` over
`clean_10kb`.

| Kind | Time |
|---|---|
| `AZURE_AD_CLIENT_SECRET` (no leading literal) | 18.76 µs |
| `URL_CREDENTIALS` (no leading literal, inner `://`) | 5.33 µs |
| `JWT` | 5.52 µs |
| `OPENAI_API_KEY` | 5.34 µs |
| `REPLICATE_API_TOKEN` | 5.38 µs |

`AZURE_AD_CLIENT_SECRET` costs about 13 µs per 10 KB more than a literal-prefixed pattern,
about 40% of the whole clean-text increase.
