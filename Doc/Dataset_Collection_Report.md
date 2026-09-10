# Dataset Collection Report

Status: PARTIALLY COMPLETE — the project has locally staged public email corpora, but not the requested 10 GB target and no labelled phishing/BEC/malware or URL corpus.

## Local inventory

`python datasets/build_manifest.py` creates `datasets/manifest.json` from the current files. The inventory records path, size, file count, source URL, intended labels, and a stable inventory hash. It does not download data, upload samples, or overwrite corpus contents.

| Source | Intended use | Supervised label | Provenance / usage note |
| --- | --- | --- | --- |
| Apache SpamAssassin Public Corpus (`easy_ham`, `hard_ham`) | baseline benign examples | `benign` | The public-corpus readme labels easy/hard ham as non-spam; it also says message copyright remains with original senders and warns never to send corpus messages through live mail systems. |
| Apache SpamAssassin Public Corpus (`spam`, `spam_2`) | baseline spam examples | `spam` | The public-corpus readme identifies these directories as spam; they are not labelled phishing, BEC, or malware. |
| CMU CALO Enron corpus subset (`maildir`) | real-world parser/correlation validation | no supervised label | CMU distributes it for research, warns about privacy, and documents redactions/integrity limitations. It is excluded from the spam baseline. |

Source URLs: [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/), [SpamAssassin corpus readme](https://svn.apache.org/repos/asf/spamassassin/site/publiccorpus/readme.html?p=1507079), and [CMU Enron dataset](https://www.cs.cmu.edu/~enron/).

## Data quality controls

- The ML loader accepts only the explicit SpamAssassin directory labels.
- Normalized-text SHA-256 removes exact duplicates before the stratified split.
- Archives and raw corpora remain separate from generated models and reports.
- Enron files are never presumed benign or used as spam labels.
- URL data and trusted URL references have dedicated directories, but no universal trusted-domain rule exists.

## Limitations and next collection step

The local corpus is substantially smaller than the 10 GB target. Do not pad it with duplicates. Add independently labelled, licence-reviewed phishing, BEC, malware-delivery, and malicious/suspicious URL sources before training those classes. Record their exact download date, licence, source URL, hashes, and label scheme in the generated manifest before use.
