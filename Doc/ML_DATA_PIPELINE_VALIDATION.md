# ML Data Pipeline Validation

Last verified: 2026-09-01 (local run; derived data is intentionally ignored by Git).

## Safety and processing behavior

- Email and URL processing are offline-only: no candidate URL is fetched, opened, resolved, or rendered.
- MIME charset declarations are untrusted metadata. The shared decoder validates the declared codec, then falls back through UTF-8, Latin-1, and CP1252. Decode/parser defects are preserved as structured warnings instead of aborting a run.
- Empty, unreadable, oversized, non-RFC822-like, malformed, duplicate, and insufficient-text mail is logged in `datasets/metadata/email_processing_issues_*.jsonl`. The source corpus is retained; `--copy-quarantine` explicitly requests a copied quarantine artifact.
- URL input accepts only static HTTP(S) values, strips fragments for identity, rejects control characters, credentials, invalid ports, and unsupported schemes, and logs reasons without retaining unnecessary raw values.
- Exact email text duplicates are removed before output. SimHash near-duplicate groups are assigned as one split group, so related templates cannot appear in more than one split.

## Verified run

Commands executed from the repository root:

```powershell
python process_email_dataset.py
python process_url_dataset.py
python data_quality.py
python create_splits.py --stratified
python train.py
python evaluation.py --model email_classifier
python evaluation.py --model url_classifier
```

Email processing scanned 14,497 candidate files and produced 4,502 valid JSONL records: 2,721 benign and 1,781 spam. It removed 2,641 exact duplicates, skipped 7,351 unlabelled Enron reference messages, logged three insufficient-visible-text samples, and found 116 near-duplicate groups covering 305 records. Every output JSONL line validated successfully.

URL processing inspected three local feeds. It produced 300 valid phishing records, with no duplicate normalized URLs. It logged an unrecognised benign CSV layout and one over-length URL. It did not visit either value.

Quality checks found no malformed JSONL lines, invalid schemas, empty processed email text, invalid URL normalization, or residual exact duplicates. The email class ratio is 0.655 (spam to benign), so it is not materially imbalanced. The URL corpus has only one class and is therefore explicitly marked not training-ready.

The deterministic group-aware split produced:

| Dataset | Train | Validation | Test | Leakage check |
| --- | ---: | ---: | ---: | --- |
| Email | 3,152 | 675 | 675 | Pass: zero exact and group overlaps |
| URL | 210 | 45 | 45 | Pass: zero normalized-URL overlaps |

## Model result and limitations

The email baseline is TF-IDF word 1–2 grams plus balanced Logistic Regression, trained only on the legitimate benign and spam labels present locally. Its 675-message held-out result was 0.9763 accuracy, 0.9751 macro F1, and 0.0147 benign false-positive rate. Class metrics were: benign precision/recall/F1 0.9757/0.9853/0.9805; spam 0.9772/0.9625/0.9698. Confusion matrix: `[[402, 6], [10, 257]]` (rows true benign/spam, columns predicted benign/spam).

No URL classifier was trained or evaluated because the staged URL data contains only phishing records. Email phishing, BEC, and malware classes are likewise unavailable and are reported as unsupported; no synthetic labels or samples were created. These results describe a narrow, same-source benign-versus-spam baseline, not real-world phishing, malware, BEC, threat attribution, or verdict accuracy.

The runtime model remains disabled by default. When enabled, it exposes the supported and missing labels, and contributes only a low-weight supporting signal; it cannot override deterministic forensic findings or confirmed threat intelligence.

## Repairs made during this validation

1. Replaced direct `payload.decode(declared_charset)` handling with the shared fail-soft decoder.
2. Made root-level processing, quality, split, training, and evaluation commands valid wrappers.
3. Replaced quadratic near-duplicate screening with bounded-feature, banded SimHash candidate checks.
4. Fixed current scikit-learn compatibility by using its automatic multiclass behavior instead of the removed `multi_class` argument.
5. Aligned training, evaluation, and inference normalization, including visible HTML content.
6. Corrected binary ROC generation and generated confusion-matrix, per-class, and ROC artifacts for the email model.

Generated reports and model artifacts live under ignored `datasets/` and `AI_model/models/` paths and can be reproduced with the commands above.
