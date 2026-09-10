# ML and Dataset Pipeline — Email Threat Forensics

This document describes the complete machine learning and dataset infrastructure for the Email Threat Forensics platform.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DATASET PIPELINE                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐          │
│  │  DOWNLOAD│───▶│ PROCESS  │───▶│ QUALITY  │───▶│  SPLITS  │          │
│  │          │    │          │    │          │    │          │          │
│  │ download │    │ process_ │    │ data_    │    │ create_  │          │
│  │ _datasets│    │ _email/  │    │ _quality │    │ _splits  │          │
│  │ .py      │    │ _url_ds  │    │ .py      │    │ .py      │          │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘          │
│       │              │              │              │                     │
│       ▼              ▼              ▼              ▼                     │
│  datasets/     datasets/      datasets/      datasets/                   │
│  raw/          processed/    metadata/      splits/                      │
│  downloads/    emails.jsonl  quality_       email_train.jsonl            │
│                urls.jsonl    report.json   email_val.jsonl               │
│                                 data_       email_test.jsonl             │
│                                 quality_     url_train.jsonl             │
│                                 report.json  url_val.jsonl               │
│                                              url_test.jsonl              │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         TRAINING PIPELINE                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                          │
│  │  TRAIN   │───▶│ EVALUATE │───▶│  MODEL   │                          │
│  │          │    │          │    │ ARTIFACTS│                          │
│  │ train.py │    │evaluation│    │          │                          │
│  └──────────┘    └──────────┘    └──────────┘                          │
│       │              │              │                                    │
│       ▼              ▼              ▼                                    │
│  AI_model/    AI_model/       AI_model/                                 │
│  models/      models/         models/                                   │
│  email_       email_          email_                                    │
│  classifier.  classifier.     classifier.                               │
│  joblib       metrics.json    evaluation/                               │
│  url_         url_            confusion_                                │
│  classifier.  classifier.     matrix.png                                │
│  joblib       metrics.json    roc_curves.png                            │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         INFERENCE INTEGRATION                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  AI_model/inference.py  ──▶  Backend/services/analysis_service.py      │
│       │                        │                                        │
│       │                        ▼                                        │
│       │               ML as ONE forensic signal                         │
│       │               (never overrides confirmed threats)               │
│       ▼                        ▼                                        │
│  classify_email()        _model_analysis()                              │
│  classify_url()          _collect_findings()                            │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Dataset Directory Structure

```
datasets/
├── email/
│   ├── benign/      # Legitimate/ham emails
│   ├── spam/        # Spam emails
│   ├── phishing/    # Phishing emails
│   ├── bec/         # Business Email Compromise emails
│   └── malware/     # Malware delivery emails
├── urls/
│   ├── benign/      # Trusted/benign URLs
│   ├── malicious/   # Malicious URLs
│   ├── phishing/    # Phishing URLs
│   └── suspicious/  # Suspicious URLs
├── raw/             # Raw downloaded archives (gitignored)
├── processed/       # Normalized, deduplicated datasets (gitignored)
├── manifests/       # Dataset manifests and inventories
├── metadata/        # Source registry, quality reports, checksums
├── splits/          # Train/validation/test splits (gitignored)
├── quarantine/      # Corrupted/duplicate/flagged samples (gitignored)
├── downloads/       # Existing public corpora (SpamAssassin, Enron)
├── build_manifest.py
├── manifest.json
└── README.md
```

---

## Source Registry

**File:** `datasets/metadata/sources.json`

Catalog of approved public dataset sources with provenance, licenses, and checksums.

Each source entry contains:
```json
{
  "name": "Apache SpamAssassin Public Corpus: easy_ham",
  "source_url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
  "category": "email",
  "subcategory": "benign",
  "labels": ["benign"],
  "license": "Message copyright remains with original senders...",
  "download_method": "direct_archive",
  "archive_format": "tar.bz2",
  "expected_files": 2500,
  "approx_size_mb": 30,
  "checksum_sha256": "...",
  "checksum_verified": false,
  "download_date": "",
  "raw_size_bytes": 0,
  "file_count": 0,
  "notes": "Non-spam emails, relatively easy to classify."
}
```

### Available Sources (Auto-downloadable)

| Source | Category | Labels | Size | Method |
|--------|----------|--------|------|--------|
| SpamAssassin easy_ham | email/benign | benign | ~30 MB | tar.bz2 |
| SpamAssassin hard_ham | email/benign | benign | ~5 MB | tar.bz2 |
| SpamAssassin spam | email/spam | spam | ~25 MB | tar.bz2 |
| SpamAssassin spam_2 | email/spam | spam | ~20 MB | tar.bz2 |
| CMU Enron Corpus | email/benign | unlabelled | ~423 MB | tar.gz |
| PhishTank | url/phishing | phishing | ~50 MB | API JSON |
| OpenPhish | url/phishing | phishing | ~2 MB | Text feed |
| URLhaus | url/malicious | malicious | ~10 MB | CSV.gz |
| Majestic Million | url/benign | benign | ~50 MB | CSV |
| Cisco Umbrella Top 1M | url/benign | benign | ~20 MB | ZIP |

### Manual Download Required

| Source | Category | Labels | Reason |
|--------|----------|--------|--------|
| APWG eCrime Exchange | url/phishing | phishing | Membership required |
| TREC Spam Track | email/mixed | spam, benign | License review needed |
| Nazario Phishing Corpus | email/phishing | phishing | Manual download |
| Kaggle Phishing Emails | email/phishing | phishing, benign | Kaggle terms |
| BEC Dataset | email/bec | bec | Manual download |
| Malware Email Samples | email/malware | malware | Safe handling required |

---

## Data Processing

### Email Normalization Schema

**Output:** `datasets/processed/emails.jsonl` (JSONL)

```json
{
  "id": "sha256_prefix",
  "label": "benign|spam|phishing|bec|malware",
  "subject": "Email subject line",
  "body_text": "Plain text body (truncated to 10KB)",
  "body_html": "HTML body (truncated to 10KB)",
  "sender_domain": "example.com",
  "has_url": true,
  "url_count": 3,
  "attachment_count": 0,
  "source_dataset": "easy_ham",
  "source_file": "datasets/downloads/easy_ham/001",
  "sha256": "full_sha256_of_raw_email",
  "text_hash": "sha256_of_normalized_text_for_dedup"
}
```

### URL Normalization Schema

**Output:** `datasets/processed/urls.jsonl` (JSONL)

```json
{
  "id": "sha256_prefix",
  "url": "http://example.com/path?query=1",
  "normalized_url": "http://example.com/path?query=1",
  "label": "benign|malicious|phishing|suspicious",
  "source_dataset": "urlhaus",
  "domain": "example.com",
  "tld": "com",
  "scheme": "http",
  "port": "80",
  "path": "/path",
  "query": "query=1",
  "fragment": ""
}
```

### Processing Steps

1. **Extract** — Parse RFC822 emails or URL feeds
2. **Normalize** — Standardize text, redact volatile tokens (URLs, emails, tokens)
3. **Deduplicate** — Exact deduplication via SHA-256 of normalized text
4. **Detect near-duplicates** — Group by sender_domain + subject prefix
5. **Validate** — Remove corrupted, empty, or too-short records
6. **Quarantine** — Move duplicates/corrupted to `datasets/quarantine/`

---

## Data Quality

**File:** `datasets/metadata/data_quality_report.json`

### Checks Performed

| Check | Email | URL |
|-------|-------|-----|
| Exact duplicates | ✓ (text_hash) | ✓ (normalized_url) |
| Near duplicates | ✓ (cosine similarity) | — |
| Empty records | ✓ | ✓ |
| Corrupted records | ✓ | ✓ |
| Label validation | ✓ (expected: benign,spam,phishing,bec,malware) | ✓ (expected: benign,malicious,phishing,suspicious) |
| Class distribution | ✓ | ✓ |
| Source distribution | ✓ | ✓ |
| Text length stats | ✓ | — |
| URL/attachment stats | ✓ | — |
| Domain/TLD stats | — | ✓ |

### Key Metrics Reported

- **Benign False Positive Rate** — Critical for forensic use
- **Phishing Recall** — Must be high for threat detection
- **Per-class Precision/Recall/F1** — For all labels
- **Macro/Weighted F1** — Overall performance

---

## Train/Validation/Test Splits

**Directory:** `datasets/splits/`

### Leakage Prevention Strategy

| Data Type | Group Key | Reason |
|-----------|-----------|--------|
| Emails | `text_hash` (normalized text SHA-256) | Same campaign/template → same split |
| URLs | `normalized_url` | Same URL → same split |

### Split Ratios (Default)

- **Train:** 70%
- **Validation:** 15%
- **Test:** 15%

### Stratified Option

Use `--stratified` flag to maintain label proportions within each group.

### Verification

Each split run produces a leakage check:
```json
{
  "train_groups": 1500,
  "val_groups": 320,
  "test_groups": 315,
  "train_val_overlap": 0,
  "train_test_overlap": 0,
  "val_test_overlap": 0,
  "leakage_free": true
}
```

---

## Model Training

### Email Classifier

**Model:** `email_classifier.joblib`

- **Algorithm:** TF-IDF (word 1-2 grams) + Logistic Regression (multinomial)
- **Features:** Subject + body text (normalized)
- **Labels:** `benign`, `spam`, `phishing`, `bec`, `malware` (only if training data exists)
- **Max features:** 75,000
- **Class weighting:** Balanced

### URL Classifier

**Model:** `url_classifier.joblib`

- **Algorithm:** TF-IDF (char 3-5 grams) + Logistic Regression (multinomial)
- **Features:** URL + domain + path (normalized)
- **Labels:** `benign`, `malicious`, `phishing`, `suspicious` (only if training data exists)
- **Max features:** 75,000
- **Class weighting:** Balanced

### Training Command

```bash
# Train both models
python "AI_model/train.py"

# Train only email classifier
python "AI_model/train.py" --email-only

# Train only URL classifier
python "AI_model/train.py" --url-only

# Custom parameters
python "AI_model/train.py" --max-features 100000 --max-iter 2000
```

### Output Artifacts

```
AI_model/models/
├── email_classifier.joblib          # Trained pipeline + metadata
├── email_classifier.metrics.json    # Training metadata + metrics
├── url_classifier.joblib
├── url_classifier.metrics.json
└── evaluation/
    ├── email_classifier_confusion_matrix.png
    ├── email_classifier_confusion_matrix_normalized.png
    ├── email_classifier_roc_curves.png
    ├── email_classifier_per_class_metrics.png
    ├── email_classifier_evaluation_report.json
    └── (same for url_classifier)
```

---

## Model Evaluation

### Metrics Generated

| Metric | Description |
|--------|-------------|
| Accuracy | Overall correct predictions |
| Macro F1 | Unweighted mean of per-class F1 |
| Weighted F1 | Support-weighted mean of per-class F1 |
| Per-class Precision | TP / (TP + FP) per class |
| Per-class Recall | TP / (TP + FN) per class |
| Per-class F1 | Harmonic mean of P/R per class |
| **Benign False Positive Rate** | **Critical: benign incorrectly flagged as threat** |
| **Phishing Recall** | **Critical: phishing emails detected** |
| Confusion Matrix | N×N matrix (raw + normalized) |
| ROC Curves | One-vs-rest AUC per class |

### Visualizations

- Confusion matrix (raw counts)
- Normalized confusion matrix (percentages)
- ROC curves (one-vs-rest)
- Per-class precision/recall/F1 bar charts

---

## Inference Integration

**Module:** `AI_model/inference.py`

### Functions

```python
# Email classification
classify_email(text: str) -> dict
classify_email_from_parts(subject, body_text, body_html) -> dict

# URL classification
classify_url(text: str) -> dict
classify_url_from_parts(url, domain, path) -> dict

# Model info
get_model_info() -> dict
```

### Output Format

```json
{
  "status": "available|disabled|not_trained|insufficient_text|inference_error",
  "predicted_class": "benign|spam|phishing|bec|malware|malicious|suspicious",
  "confidence": 0.87,
  "confidence_level": "high|medium|low",
  "all_probabilities": {
    "benign": 0.05,
    "spam": 0.10,
    "phishing": 0.87
  },
  "model_version": "2026-01-15T10:30:00+00:00",
  "model_name": "email_classifier",
  "supported_labels": ["benign", "spam", "phishing"],
  "missing_labels": ["bec", "malware"],
  "model_available": true,
  "note": "Model confidence describes classification confidence, not attacker confidence. This is one forensic signal among many."
}
```

### Unavailable Model Response

```json
{
  "status": "not_trained",
  "predicted_class": "unknown",
  "confidence": 0.0,
  "model_available": false
}
```

---

## ML Integration in Analysis Service

**File:** `Backend/services/analysis_service.py`

### Integration Principles

1. **ML is ONE forensic signal** — Never the sole determinant
2. **ML must NOT override:**
   - Confirmed malicious threat intelligence (VirusTotal, URLhaus, etc.)
   - Strong authentication evidence (SPF/DKIM/DMARC FAIL)
   - Attachment malware evidence (executable extensions, MIME mismatch)
   - Deterministic dangerous URI detection (unsafe schemes, embedded credentials)
3. **Evidence fusion is explainable** — Each signal contributes with explicit weight

### How ML Contributes

| ML Prediction | Confidence | Weight | Evidence Tier |
|---------------|------------|--------|---------------|
| phishing/malware/bec | ≥0.85 (high) | +5 | model_support |
| phishing/malware/bec | 0.65-0.85 (med) | +3 | model_support |
| spam | ≥0.85 | +3 | model_support |
| benign | ≥0.85 | -3 | model_support |
| other/low confidence | <0.65 | 0 | — |

### In Report Output

```json
"nlp_analysis": {
  "classification": "phishing_like",
  "model_analysis": {
    "email_classifier": {
      "status": "available",
      "predicted_class": "phishing",
      "confidence": 0.87,
      "confidence_level": "high",
      "all_probabilities": {...},
      "model_version": "...",
      "model_available": true
    },
    "url_classifier_summary": [...]
  }
}
```

---

## Complete CLI Workflow

```bash
# 1. Download approved public datasets
python "AI_model/download_datasets.py"

# 2. Process email datasets
python "AI_model/process_email_dataset.py"

# 3. Process URL datasets
python "AI_model/process_url_dataset.py"

# 4. Run quality checks
python "AI_model/data_quality.py"

# 5. Create leakage-preventing splits
python "AI_model/create_splits.py" --stratified

# 6. Train models
python "AI_model/train.py"

# 7. Evaluate models
python "AI_model/evaluation.py" --model email_classifier
python "AI_model/evaluation.py" --model url_classifier

# 8. Verify integration
python main.py  # Start API server
# Visit http://127.0.0.1:8000 and analyze an email
```

---

## Git Policy

### Tracked (Committed)
- All pipeline scripts (`AI_model/*.py`, `datasets/build_manifest.py`)
- Source registry (`datasets/metadata/sources.json`)
- Documentation (`README.md`, `ML_AND_DATASET_PIPELINE.md`, `Doc/Dataset_Collection_Report.md`)
- Manifest (`datasets/manifest.json`)
- Empty directory placeholders (`.gitkeep`)

### Gitignored (Not Committed)
- `datasets/raw/` — Raw downloaded archives
- `datasets/processed/` — Normalized JSONL files
- `datasets/splits/` — Train/val/test splits
- `datasets/quarantine/` — Flagged samples
- `datasets/downloads/` — Public corpora (except manifests)
- `AI_model/models/*.joblib` — Trained model artifacts
- `AI_model/models/*.metrics.json` — Model metrics
- `AI_model/models/evaluation/` — Evaluation outputs

---

## Limitations

### Current Data Limitations

| Label | Status | Notes |
|-------|--------|-------|
| benign | ✓ Available | SpamAssassin easy_ham, hard_ham, Enron |
| spam | ✓ Available | SpamAssassin spam, spam_2 |
| phishing | ⚠ Limited | PhishTank/OpenPhish are URLs, not emails. Nazario corpus needs manual download. |
| bec | ✗ Insufficient | No public BEC email corpus available |
| malware | ✗ Insufficient | Malware delivery emails require safe handling environment |

**Missing labels are marked `INSUFFICIENT DATA` in model metadata and excluded from training.**

### Model Limitations

1. **TF-IDF + Logistic Regression** — Not a deep learning model; limited context understanding
2. **Training data bias** — SpamAssassin corpus is from 2003-2005; may not reflect modern threats
3. **No behavioral analysis** — Only static text features; no dynamic/execution analysis
4. **Confidence ≠ Threat certainty** — High confidence means "model is sure of this class" not "this is definitely a threat"
4. **Forensic signal only** — Must be combined with threat intel, authentication, attachment analysis

### Operational Limitations

- Dataset downloads require internet access
- PhishTank requires API key in `.env` (`PHISHTANK_API_KEY`)
- Large corpora (Enron 423 MB) take time to download/extract
- Model training requires ~2-4 GB RAM for 75K features
- Evaluation visualizations require matplotlib

---

## Configuration

### Environment Variables (`.env`)

```bash
# Enable ML inference in analysis pipeline
ML_MODEL_ENABLED=true

# Enable threat intelligence (required for some URL sources)
THREAT_INTELLIGENCE_ENABLED=true

# PhishTank API key (free registration at phishtank.com)
PHISHTANK_API_KEY=your_key_here

# OpenPhish feed path (optional local file)
OPENPHISH_FEED_PATH=datasets/raw/openphish_feed.txt

# Network enrichment for domain intelligence
NETWORK_ENRICHMENT_ENABLED=false
```

---

## Extending the Pipeline

### Adding a New Email Dataset

1. Add source to `datasets/metadata/sources.json`
2. Run `python "AI_model/download_datasets.py" --source "Source Name"`
3. Run `python "AI_model/process_email_dataset.py"`
4. Run quality checks and create splits
5. Retrain: `python "AI_model/train.py" --email-only`

### Adding a New URL Dataset

1. Add source to `datasets/metadata/sources.json`
2. Implement parser in `process_url_dataset.py` (if new format)
3. Run download and process
4. Retrain URL classifier: `python "AI_model/train.py" --url-only`

### Adding a New ML Model Type

1. Create new training function in `train.py`
2. Add inference function in `inference.py`
3. Integrate in `analysis_service.py` `_model_analysis` and `_collect_findings`
4. Follow evidence fusion principles (supporting signal only)

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "No training data for label X" | Label marked as missing; collect more data or accept limitation |
| Download fails | Check network, source URL validity; some sources require manual download |
| Memory error during training | Reduce `--max-features` or use smaller sample with `--limit-per-label` |
| Leakage check fails | Verify group keys (`text_hash`, `normalized_url`) are populated |
| Model not loading in API | Ensure `ML_MODEL_ENABLED=true` and model files exist in `AI_model/models/` |

---

## Future Work

- [ ] Add deep learning model option (transformer-based)
- [ ] Implement active learning loop for analyst feedback
- [ ] Add ensemble methods combining multiple models
- [ ] Create model versioning and A/B testing framework
- [ ] Add drift detection for production monitoring
- [ ] Integrate with MLOps tools (MLflow, DVC)

---

## References

- [SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/)
- [CMU Enron Email Dataset](https://www.cs.cmu.edu/~enron/)
- [PhishTank](https://www.phishtank.com/)
- [OpenPhish](https://openphish.com/)
- [URLhaus](https://urlhaus.abuse.ch/)
- [Majestic Million](https://majestic.com/reports/majestic-million)
- [Cisco Umbrella Popularity List](https://umbrella.cisco.com/blog/2020/06/16/top-1-million-domains)
- [scikit-learn Documentation](https://scikit-learn.org/)