# MailSentra Engineering Roadmap

## Overview

The development of MailSentra is structured into four disciplined, sequential phases. This phased approach guarantees architectural integrity, thorough unit testing, and production-grade stability at every stage.

---

## Phase Breakdown

```mermaid
gantt
    title MailSentra Engineering Timeline
    dateFormat  YYYY-MM-DD
    section Phase 1: Foundation
    Architecture & Module Contracts       :done,    p1a, 2026-11-20, 2026-11-24
    FastAPI Core & DB Schemas             :active,  p1b, 2026-11-24, 2026-11-27
    React Admin Shell & Dev Setup         :active,  p1c, 2026-11-24, 2026-11-28
    section Phase 2: Ingestion & Protocols
    MIME Parser & Body Normalizer         :         p2a, 2026-11-29, 2026-12-05
    SPF, DKIM, DMARC DNS Engine           :         p2b, 2026-12-06, 2026-12-12
    Identity & Typosquatting Module       :         p2c, 2026-12-13, 2026-12-19
    section Phase 3: Threat Analytics
    URL Security & Un-shortener Engine    :         p3a, 2026-12-20, 2026-12-27
    Attachment Forensic Analyzer          :         p3b, 2026-12-28, 2027-01-05
    BEC & NLP Semantic Analyzer           :         p3c, 2027-01-06, 2027-01-14
    section Phase 4: Intelligence & Release
    Threat Intel Connectors (OTX/VT)      :         p4a, 2027-01-15, 2027-01-22
    Explainable Risk Scoring Engine       :         p4b, 2027-01-23, 2027-01-30
    Alert Dispatchers & SOC Console UI    :         p4c, 2027-01-31, 2027-02-10
```

---

### Phase 1: Technical Foundation (Current Scope)
- [x] High-level architectural specification and component boundaries.
- [x] Technology selection and evaluation matrix.
- [x] Modular project directory structure separating security modules from API/DB layers.
- [x] Foundational documentation: `README.md`, `ARCHITECTURE.md`, `TECH_STACK.md`, `SECURITY_DESIGN.md`, `DEVELOPMENT_ROADMAP.md`.
- [x] Initial backend setup: FastAPI application, Pydantic v2 schemas, configuration management, SQLite/PostgreSQL async engine.
- [x] Strongly typed module data contracts (`contracts.py`) defining interfaces for all 13 modules.
- [x] Initial frontend setup: React 18 + TypeScript + Vite project shell with Tailwind CSS.
- [x] Health check endpoints, API routing structure, and Pytest verification suite.

### Phase 2: Core Parsing, Identity & Protocol Verification (Next Scope)
- [ ] **Email Ingestion Module**: RFC 5322 EML file upload, raw MIME byte stream handling, and payload size bounds.
- [ ] **Email Parsing & Normalization Module**: Multi-part MIME decoding, RFC 2047 header normalization, body text extraction, HTML stripping, defanged link extraction.
- [ ] **Authentication Protocols Module**: Asynchronous DNS query engine for SPF validation, DKIM signature verification, and DMARC alignment/policy calculation.
- [ ] **Sender Identity Verification Module**: Display name spoofing detection, executive impersonation rules, Levenshtein distance typosquatting engine, and Punycode/IDN analysis.
- [ ] Test harness for RFC-compliant test emails and real-world spoofing test cases.

### Phase 3: Payload & Behavioral Threat Analytics
- [ ] **URL Security Module**: URL canonicalization, redirect following, IP-host detection, suspicious TLD categorization, and zero-width character detection.
- [ ] **Attachment Security Module**: File magic byte identification (countering double extensions), SHA-256 hash calculation, Office document macro detection, and archive structure inspection.
- [ ] **Social Engineering & BEC Module**: Linguistic intent modeling, financial wire transfer heuristics, payroll modification prompts, and urgent call-to-action indicators.

### Phase 4: Intelligence Enrichment, Risk Scoring & SOC Experience
- [ ] **Threat Intelligence Module**: Integration connectors for AbuseIPDB, VirusTotal, and AlienVault OTX with multi-level LRU/database caching.
- [ ] **Risk Scoring Engine**: Multi-vector Bayesian/weighted scoring algorithm producing normalized threat scores (0–100) with explainable rationale trees.
- [ ] **Alert & Notification Module**: Syslog (RFC 5424), Webhook, Slack, and Microsoft Teams dispatchers.
- [ ] **Admin Dashboard**: Full SOC triage interface with email deep-dive inspector, header hop visualizer, and audit log reviewer.
- [ ] End-to-end integration test suite and containerized Docker deployment.
