# MailSentra: Enterprise Email Security & Threat Detection Platform

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blue)](#)
[![Python](https://img.shields.io/badge/Python-3.11%2B%20%7C%203.13-blue?logo=python)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi)](#)
[![React](https://img.shields.io/badge/React-18%20%7C%2019-61DAFB?logo=react)](#)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-3178C6?logo=typescript)](#)
[![Tests](https://img.shields.io/badge/Tests-878%20Passing-brightgreen)](#)
[![License](https://img.shields.io/badge/License-Proprietary-red)](#)

MailSentra is an enterprise email threat detection and forensics platform designed to identify advanced email threats, executive and brand impersonation, structural header anomalies, deceptive links, and disguised attachments using deterministic, explainable risk scoring.

---

## Capabilities & Architecture Status

MailSentra distinguishes strictly between implemented analytical capabilities, offline/heuristic components, and planned future integrations:

### 1. Implemented & Verified Capabilities
* **RFC 5322 Ingestion & Parsing**: Native EML/MIME upload pipeline supporting multi-part decoding, RFC 2047 header normalization, body text extraction, script neutralization, and defanged link extraction (`ScanService`).
* **Sender Identity & Header Integrity**:
  - **Structural Header Verification (Priority 1)**: Actionable detection of `MALFORMED_SENDER_ADDRESS`, `DUPLICATE_FROM_HEADER`, `MISSING_FROM_HEADER`, and related RFC 5322 anomalies with non-punitive handling of empty `Return-Path`.
  - **Display-Name Brand Impersonation (Priority 3)**: Protected brand matching against 17 enterprise profiles with explicit domain authorization (Risk B remediation) and graded scoring (Risk A remediation: standalone mismatch evaluates to `SUSPICIOUS`, requiring corroborating threat evidence to reach `MALICIOUS`).
  - **Cousin-Domain & Homoglyph Spoofing**: Levenshtein distance typosquatting scans and visual IDN/Punycode homoglyph normalization.
* **Static URL Security Analysis**:
  - **Subdomain Brand Impersonation (Priority 2)**: Offline Public Suffix List (PSL)-aware detection of legitimate brands embedded in attacker-controlled subdomains (e.g. `signin.paypal.com.evil.org`) with canonical brand-domain exclusions.
  - **Static Link Defanging & TLD Scoring**: Pattern heuristics for IP-literal hosts and high-risk top-level domains (e.g. `.xyz`, `.top`).
* **Static Attachment Forensics**: Pure-Python in-memory file magic-byte identification (DOS/MZ, PE, ELF, Mach-O, PDF, ZIP/OpenXML), double-extension detection (e.g. `.xlsx.exe`), SHA-256 calculation, macro presence heuristics, and archive traversal bounds checking.
* **Explainable Unified Risk Engine**: Deterministic multi-vector scoring aggregating Identity, Authentication, URL, and Attachment signals into clear classifications (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`) with cross-analyzer brand deduplication and failure isolation.
* **SOC Analyst Console**: React 18 + Vite dashboard providing incident inspection views, header hop tracking, attachment forensics cards, and append-only audit logging.

### 2. Partially Implemented & Offline-Only Capabilities
* **Authentication Protocols Evaluation**: Local parsing for `Authentication-Results` and `Received-SPF` headers, policy evaluation trees, and DMARC enforcement modeling. In direct EML upload mode without live MTA relay telemetry, SPF evaluates as `NOT_EVALUATED` and DMARC evaluates under a fail-safe incomplete state rather than speculating.
* **Offline Heuristics**: URL and attachment inspection operates strictly offline using deterministic heuristics without contacting external cloud services.

### 3. Planned Integrations & Future Work
* **Live Enterprise Connectors**: SMTP milter relay integration and Microsoft 365 / Google Workspace Graph API listeners.
* **Live Threat Intelligence Feeds**: Production API connectors for VirusTotal, AbuseIPDB, and AlienVault OTX.
* **Dynamic Sandbox Detonation**: Automated virtualized guest execution for suspicious attachments.
* **Live Alert Dispatchers**: Webhook, RFC 5424 Syslog, Slack, and Microsoft Teams live notification dispatchers.
* **Deep NLP Intent Modeling**: Computational linguistics intent scoring and LLM embedding analysis for financial coercion.

---

## Project Structure

```
MailSentra/
├── backend/                  # FastAPI Core Backend & Detection Engine
│   ├── app/
│   │   ├── api/              # REST API Versioning & Endpoints (v1)
│   │   ├── core/             # Configuration, JWT Security, Audit Engine, Logging
│   │   ├── db/               # SQLAlchemy Async Engine, Base Models, Sessions
│   │   ├── models/           # Relational Models (User, ScanIncident, Alert, AuditLog)
│   │   ├── schemas/          # Pydantic v2 Request/Response Data Contracts
│   │   ├── modules/          # Dedicated Security & Ingestion Subsystems
│   │   │   ├── contracts.py  # Strongly typed interfaces between all detection modules
│   │   │   ├── ingestion/    # EML, MIME, and stream ingestion
│   │   │   ├── parser/       # RFC 5322 parsing & body normalization
│   │   │   ├── identity/     # Sender verification, brand impersonation & header integrity
│   │   │   ├── auth_protocols/# SPF, DKIM, DMARC parsing & policy evaluation
│   │   │   ├── url_analysis/ # URL deconstruction, PSL subdomain inspection & defanging
│   │   │   ├── attachment_analysis/ # In-memory file magic, macro, hash analysis
│   │   │   ├── risk_engine/  # Deterministic multi-vector risk scoring
│   │   │   └── audit/        # Append-only security audit trail
│   │   └── services/         # Orchestration & workflow services (ScanService)
│   ├── tests/                # Pytest unit, integration, and regression test suite
│   ├── .env.example          # Sanitized backend environment template
│   ├── requirements.txt      # Python dependencies
│   └── main.py               # ASGI application entrypoint
├── frontend/                 # React 18 + TypeScript + Vite Dashboard
│   ├── src/
│   │   ├── components/       # Reusable UI components & layouts
│   │   ├── pages/            # Dashboard, Scan, Alert, and Audit views
│   │   ├── services/         # Axios API clients with auto-interceptors
│   │   ├── types/            # TypeScript interfaces matching backend schemas
│   │   ├── App.tsx           # Application route definitions
│   │   └── main.tsx          # React application root
│   ├── package.json          # Node dependencies and build scripts
│   ├── vite.config.ts        # Vite configuration and proxy rules
│   └── tailwind.config.js    # Tailwind CSS styling framework
├── ARCHITECTURE.md           # Full system architecture and component designs
├── TECH_STACK.md             # Technology evaluation and justifications
├── DEVELOPMENT_ROADMAP.md    # Multi-phase engineering roadmap and substantiated statuses
├── SECURITY_DESIGN.md        # Threat model, RBAC matrix, and defensive controls
├── CONTROLLED_DETECTION_TESTS.md # Five verified controlled detection test runs
└── README.md                 # Primary project documentation
```

---

## Architectural Documentation

For deep technical details, please refer to:
- [ARCHITECTURE.md](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/ARCHITECTURE.md): Complete module-by-module technical specification, data contracts, and Mermaid architecture diagrams.
- [TECH_STACK.md](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/TECH_STACK.md): Comprehensive justification for each language, framework, database, and library.
- [SECURITY_DESIGN.md](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/SECURITY_DESIGN.md): Threat modeling (STRIDE), authentication security, RBAC enforcement, and defensive coding standards.
- [DEVELOPMENT_ROADMAP.md](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/DEVELOPMENT_ROADMAP.md): Detailed multi-phase delivery timeline and substantiated capability statuses.
- [CONTROLLED_DETECTION_TESTS.md](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/CONTROLLED_DETECTION_TESTS.md): Verified execution reports for the five controlled detection tests.

---

## Quickstart (Local Development)

### Prerequisites
- **Python**: 3.11+ (Python 3.13 tested)
- **Node.js**: v18+ (Node v24 tested)
- **PowerShell** or Unix Shell

### 1. Backend Setup

```powershell
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Start backend server
python main.py
```
The FastAPI backend server will be live at `http://127.0.0.1:8000`.
- Interactive API Docs (Swagger): `http://127.0.0.1:8000/docs`
- Redoc API Docs: `http://127.0.0.1:8000/redoc`
- System Health Check: `http://127.0.0.1:8000/api/v1/health`

### 2. Frontend Setup

```powershell
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```
The MailSentra Admin Console will be live at `http://localhost:5173`.

---

## Operational Status & Release Readiness

- **Current State:** **READY FOR CONTROLLED DEMONSTRATION**
- **Test Suite:** **878 / 878 Passing** (100% pass rate in ~41s)
- **Frontend Console:** Production build verified via Vite & TypeScript 5.5 (0 errors)
- **Controlled Tests:** 5 / 5 verified controlled fixture runs documented in [CONTROLLED_DETECTION_TESTS.md](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/CONTROLLED_DETECTION_TESTS.md)
- **Live API Verification:** Full end-to-end integration verified (`verify_live_api.py`)

### Running Verification Tests

```powershell
# Run full backend test suite
$env:PYTHONPATH=".;backend"; & backend\.venv\Scripts\pytest.exe backend/tests/ -q

# Run live API verification
$env:PYTHONPATH=".;backend"; & backend\.venv\Scripts\python.exe backend/tests/verify_live_api.py

# Build frontend
cd frontend
npm run build
```
