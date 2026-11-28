# MailSentra Cybersecurity Dataset Portfolio & Governance

This directory contains metadata, provenance registries, and sanitized offline sample fixtures for the 15 cybersecurity intelligence datasets evaluated for MailSentra Module 5 (URL Security Analysis).

## Security & Governance Rules

1. **Strict Offline Execution**: MailSentra scanners, analyzers, and test fixtures MUST NEVER perform live network requests, DNS queries, or TCP handshakes against dataset URLs.
2. **Defanging & Neutralization**: All active URLs stored in documentation or sample fixtures are sanitized/defanged (`hxxp://`, `[.]`) to eliminate accidental click-through hazards.
3. **No Secret or PII Storage**: Datasets must not contain user credentials, API keys, or private tenant information.
4. **License & Attribution**: Source provenance, academic licenses, and attribution guidelines are strictly documented in `dataset_registry.csv` and `dataset_manifest.json`.
5. **No Large Binaries in Git**: Heavy raw corpora (>10MB) remain externalized; only deterministic schema manifests, checksums, and bounded test fixtures are tracked in the repository.

## Dataset Portfolio Overview

| ID | Dataset Name | Provider | Access Status | Integration Status | License |
|---|---|---|---|---|---|
| DS-01 | ISCX-URL-2016 | Univ. of New Brunswick (CIC) | Open / Request | ASSESSED | Academic / Research |
| DS-02 | PhiUSIIL Phishing (UCI) | UCI Machine Learning Repository | Open | VALIDATED | CC BY 4.0 |
| DS-03 | PhiUSIIL Phishing (Mendeley v2) | Mendeley Data / Univ. of Leòn | Open | VALIDATED | CC BY 4.0 |
| DS-04 | URL-Phish | Mendeley Data | Open | ASSESSED | CC BY 4.0 |
| DS-05 | PhishStorm | Aalto University | Restricted | BLOCKED | Unspecified / Academic |
| DS-06 | EBBU2017 | GitHub (ebubekirbbr/pdd) | Open | ASSESSED | Public / Open |
| DS-07 | PWD2021 | Mendeley Data | Open | ASSESSED | CC BY 4.0 |
| DS-08 | PILU-60K | Univ. of Leòn (GVIS) | Open | ASSESSED | Research Only |
| DS-09 | Malicious URLs (Kaggle) | Kaggle (sid321axn) | Registration Required | ASSESSED | Community Data (ODbL) |
| DS-10 | PhreshPhish | Hugging Face | Open | ASSESSED | Apache 2.0 |
| DS-11 | PhishTank | Cisco Talos / PhishTank | API / Developer Registration | USED_IN_TESTS | Non-Commercial / Attribution |
| DS-12 | OpenPhish | OpenPhish Global Intelligence | Free Feed / Tiered | ASSESSED | Terms of Use / Non-Commercial |
| DS-13 | URLhaus | abuse.ch / Bern Univ. of App. Sci. | Open API / CSV | USED_IN_TESTS | CC0 1.0 Universal |
| DS-14 | Tranco | Tranco Research Team | Open Download | USED_IN_TESTS | MIT License |
| DS-15 | Common Crawl | Common Crawl Foundation | Open S3 / Index API | ASSESSED | Terms of Use |
