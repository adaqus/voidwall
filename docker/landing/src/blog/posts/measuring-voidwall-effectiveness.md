---
title: Measuring Voidwall’s PII Detection Effectiveness
tag: Data Protection
date: 2026-07-13
read: 8 min read
excerpt: How well does Voidwall actually detect PII? We measure precision and recall on a curated English AI4Privacy dataset, broken down by category and data structure.
---

In the previous post, we explained the basics of measuring PII detection effectiveness. The knowledge from that post provides a good foundation for understanding how well Voidwall performs.

Measuring precision and recall is not a trivial task. It requires a high-quality input dataset. But wait, does that mean we need real PII belonging to real people? Not necessarily. The strongest evidence usually comes from representative production data with reliable annotations. Before such data is available, a carefully validated synthetic dataset can provide a useful initial evaluation.

Our choice was one of the AI4Privacy datasets: [ai4privacy/pii-masking-300k](https://huggingface.co/datasets/ai4privacy/pii-masking-300k). It is a synthetic dataset supporting most of the languages covered by Voidwall. During the initial dataset review, it became clear that it had to be additionally curated to improve its quality. The steps taken to achieve this are described at the end of this post.

As the dataset review turned out to require a significant amount of work, we decided to limit the first evaluation to English only. The curated dataset contains 5,766 rows with 31,371 text spans containing PII. The dataset is large enough to characterize Voidwall’s behaviour on this English subset, although it does not replace evaluation on production traffic.

## Results

To characterize Voidwall’s effectiveness, we measured precision and recall for supported PII in the following ways:

* general, aggregated across all supported PII types and data structures
* per category
* per data structure, separately for structured, semi-structured, and prose text

### General precision and recall

| Precision | Recall |
| --------: | -----: |
|     0.965 |  0.713 |

Precision turned out to be very high. This means that when Voidwall signals that it has found PII in a given piece of data, there is little chance that the detection is wrong. The corresponding recall is lower, reflecting Voidwall’s conservative approach. It prefers not to guess and signals the presence of PII only when there is a high probability of being correct.

On the curated dataset, Voidwall showed that it is especially well suited to use cases where false positives are costly and maintaining confidence in detection results is crucial.

### Category breakdown

The categories and their names were taken from the AI4Privacy dataset and mapped to PII types supported by Voidwall.

| Category           | Ground-truth spans | Recall | Precision |
| ------------------ | -----------------: | -----: | --------: |
| BOD (day of birth) |              2,308 |  0.795 |     0.995 |
| DRIVERLICENSE      |              2,180 |  0.398 |     0.992 |
| EMAIL              |              2,172 |  0.999 |     0.973 |
| GEOCOORD           |                371 |  0.790 |     0.983 |
| GIVENNAME1         |              1,664 |  0.714 |     0.896 |
| GIVENNAME2         |                416 |  0.644 |     0.896 |
| IP                 |              1,812 |  1.000 |     0.984 |
| LASTNAME1          |              1,789 |  0.706 |     0.896 |
| LASTNAME2          |                447 |  0.653 |     0.896 |
| LASTNAME3          |                142 |  0.627 |     0.896 |
| PASSPORT           |              3,595 |  0.822 |     0.999 |
| POSTCODE           |              4,008 |  0.573 |     0.981 |
| SECADDRESS         |              1,798 |  0.653 |     0.987 |
| SOCIALNUMBER       |              3,242 |  0.494 |     0.997 |
| STREET             |              3,793 |  0.807 |     0.988 |
| TEL                |              1,634 |  0.736 |     0.982 |

Precision remained high for most structured identifiers. Name detection was a notable exception, with precision of 89.6%, reflecting the ambiguity of identifying names without stronger contextual signals. First names and last names may also be ordinary words.

The situation is different for recall. It varies among categories, ranging from 39.8% to 100%. We will take a closer look at the weaker categories and work on improving their results.

### Data structure breakdown

We divided the data into the following structure types:

* structured, with a rigid and well-defined structure, such as JSON, XML, or YAML
* semi-structured, such as lists or Markdown containing explicit labels and values, for example `- name: Tom - surname: Smith`
* plain prose, such as emails, letters, and chats, where PII values may appear on their own or alongside contextual keywords

| Data type                            | Precision | Recall |
| ------------------------------------ | --------: | -----: |
| Structured (JSON, XML, YAML)         |     0.960 |  0.729 |
| Semi-structured (Markdown, lists)    |     0.969 |  0.708 |
| Plain prose (emails, letters, chats) |     0.963 |  0.640 |


Voidwall achieved similar precision across all data types. It performed best on structured and semi-structured data. Recall was lower for prose, by approximately eight percentage points compared with structured data.

## Dataset

We used [ai4privacy/pii-masking-300k](https://huggingface.co/datasets/ai4privacy/pii-masking-300k) as available on 23 June 2026. Instead of treating every synthetic label as ground truth, we created a curated evaluation set by removing rows containing examples that appeared invalid, mislabeled, or unrealistic for the claimed locale or data type.

Some records were labelled as national identity-card numbers even though the generated values could not be associated with a recognized issuing authority or country-specific format. We therefore excluded that category from the evaluation.

To review as many rows as possible within a reasonable amount of time, we created an evaluation skill in Claude Code and ran it using the Opus 4.8 model. The evaluation followed these steps, using mainly the `source_text` and `privacy_mask` fields from each row:

1. Retrieve the first or next 100 rows.
2. Delete a row if:

   * all span annotations in the row are broken, meaning that they point to values different from those present in `privacy_mask`
   * all values in `privacy_mask` fail validation using a Voidwall validator*
3. Keep a row if:

   * it is unclear whether a value is valid, for example because Voidwall has no validator for it or no real-world specification exists or describes its validation
   * at least one value in the row is valid
4. Repeat from step 1.

<p class="vw-footnote"><span class="vw-footnote-mark">*</span> Voidwall validators are well tested and implemented on the basis of issuing-authority specifications.</p>

The curated dataset contains the following numbers of rows and ground-truth spans for each data structure:

| Data type                                         |  Rows | Ground-truth spans |
| ------------------------------------------------- | ----: | -----------------: |
| Structured (JSON, XML, YAML)                      | 2,332 |             10,645 |
| Semi-structured (Markdown, lists, key-value data) | 3,228 |             19,572 |
| Plain prose (emails, letters, chats)              |   206 |              1,154 |

Plain prose is substantially underrepresented in this evaluation, so its result should be treated as preliminary. The dataset provides stronger evidence for structured and semi-structured payloads, which are also Voidwall’s primary target.

## Conclusion

On this curated English subset, Voidwall achieved 96.5% precision and 71.3% recall across the evaluated categories. These results characterize it as a conservative, low-noise detector, with the strongest evidence covering structured and semi-structured data.

Deployed at the HTTP boundary, Voidwall can serve as an early preventive layer, blocking or redacting high-confidence PII detections before requests reach logs, databases, analytics platforms, LLM applications, AI agents, or external APIs.
