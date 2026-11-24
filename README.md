# MailSentra: Enterprise Email Security & Threat Detection Platform

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blue)](#)
[![Python](https://img.shields.io/badge/Python-3.11%2B%20%7C%203.13-blue?logo=python)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi)](#)
[![React](https://img.shields.io/badge/React-18%20%7C%2019-61DAFB?logo=react)](#)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-3178C6?logo=typescript)](#)
[![License](https://img.shields.io/badge/License-Proprietary-red)](#)

MailSentra is a next-generation email threat defense system designed to protect enterprise communications against advanced phishing, executive impersonation (display name and cousin domain spoofing), Business Email Compromise (BEC), malicious redirects, and weaponized attachments.

---

## Key Capabilities (Planned System Architecture)

- **Comprehensive Ingestion**: Dual-mode ingestion pipeline supporting direct RFC 5322 EML/MIME upload, SMTP relay milters, and M365/Google Workspace Graph API connectors.
- **Deep Email Parsing**: Multi-layer MIME traversal, header decoding (RFC 2047), hidden payload extraction, and body normalization.
- **Cryptographic Authentication**: Real-time DNS-based evaluation of SPF (RFC 7208), DKIM (RFC 6376), and DMARC (RFC 7489) alignment and policy enforcement.
- **Identity & Impersonation Defense**: VIP/Executive target matching, domain similarity algorithms (Levenshtein, Jaro-Winkler, visual homoglyph punycode detection), and Envelope-From vs. Header-From mismatch detection.
- **URL & Attachment Inspection**: Defanged URL normalization, redirect following, entropy checking, file magic-byte validation, polyglot detection, and cryptographic hashing (SHA-256).
- **Explainable Threat Scoring**: Deterministic multi-dimensional risk engine calculating contextual risk ratings (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`) with auditable decision logs.
- **SOC Analyst Operations**: Operational console featuring incident queues, deep inspection views, audit logs, and SIEM/SOAR alert dispatchers.

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
│   │   ├── modules/          # 13 Dedicated Security & Ingestion Subsystems
│   │   │   ├── contracts.py  # Strongly typed interfaces between all detection modules
│   │   │   ├── ingestion/    # EML, MIME, and stream ingestion
│   │   │   ├── parser/       # RFC 5322 parsing & body normalization
│   │   │   ├── identity/     # Sender verification & lookalike detection
│   │   │   ├── auth_protocols/# SPF, DKIM, DMARC validation
│   │   │   ├── url_analysis/ # URL deconstruction, redirection, reputation
│   │   │   ├── attachment/   # File magic, macro, hash analysis
│   │   │   ├── social_engineering/ # BEC, urgency, payroll diversion
│   │   │   ├── threat_intel/ # OTX, VirusTotal, AbuseIPDB integration
│   │   │   ├── risk_engine/  # Deterministic Bayesian/Weighted risk scoring
│   │   │   ├── alerts/       # Notification dispatchers (Webhook, Syslog)
│   │   │   └── audit/        # Append-only security audit trail
│   │   └── services/         # Orchestration & workflow services
│   ├── tests/                # Pytest unit and integration test suite
│   ├── .env.example          # Backend environment variables
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
├── docs/                     # Technical specifications and manuals
├── ARCHITECTURE.md           # Full system architecture and component designs
├── TECH_STACK.md             # Technology evaluation and justifications
├── DEVELOPMENT_ROADMAP.md    # Multi-phase engineering roadmap
├── SECURITY_DESIGN.md        # Threat model, RBAC matrix, and defensive controls
└── README.md                 # Primary project documentation
```

---

## Architectural Documentation

For deep technical details, please refer to:
- [ARCHITECTURE.md](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/ARCHITECTURE.md): Complete module-by-module technical specification, data contracts, and Mermaid architecture diagrams.
- [TECH_STACK.md](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/TECH_STACK.md): Comprehensive justification for each language, framework, database, and library.
- [SECURITY_DESIGN.md](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/SECURITY_DESIGN.md): Threat modeling (STRIDE), authentication security, RBAC enforcement, and defensive coding standards.
- [DEVELOPMENT_ROADMAP.md](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/DEVELOPMENT_ROADMAP.md): Detailed multi-phase delivery timeline.

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

# Copy environment variables
cp .env.example .env

# Run database migrations / initialization & start API server
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

## Execution Constraints & Governance

> [!IMPORTANT]
> **Part 1 Scope**: This phase establishes the system architecture, foundational runtime, strongly typed module data contracts, security schemas, documentation, and development environment. Phishing detection logic, heuristics, and external threat intelligence APIs will be introduced in subsequent modular phases according to [DEVELOPMENT_ROADMAP.md](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/DEVELOPMENT_ROADMAP.md).
