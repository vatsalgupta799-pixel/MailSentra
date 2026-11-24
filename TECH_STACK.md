# MailSentra Technology Stack & Evaluation Matrix

## 1. Architectural Philosophy

MailSentra adheres to three core engineering guidelines:
1. **Practicality over Novelty**: Favor battle-tested, security-hardened tools with active ecosystems.
2. **Deterministic Security**: The core inspection pipeline must run reliably in offline, air-gapped, or local development environments without requiring complex third-party SaaS dependencies.
3. **Decoupled Monolith**: Keep the architecture in a unified repository with clear domain boundaries, avoiding premature microservice orchestration overhead while maintaining strict internal abstraction layers.

---

## 2. Technology Selection Matrix

| Tier | Chosen Technology | Evaluated Alternatives | Decisive Architectural Rationale |
| :--- | :--- | :--- | :--- |
| **Backend Framework** | **FastAPI (Python 3.11+)** | Django, Flask, Express.js, Go (Gin) | Native async ASGI, automatic OpenAPI v3 documentation, strict Pydantic v2 validation, seamless integration with Python's deep cybersecurity analysis toolchains. Flask lacks modern async; Django introduces unnecessary ORM/template coupling. |
| **Backend Language** | **Python 3.13** | Go, Rust, TypeScript (Node) | Python is the uncontested standard in cybersecurity and computational linguistics. Native access to parsing engines (`email`, `dnspython`, `authres`), forensic libraries (`pefile`, `oletools`), and machine learning toolsets without inter-process IPC overhead. |
| **Frontend Framework** | **React 18 / 19 + TypeScript + Vite** | Next.js, Vue 3, SvelteKit, Streamlit | SPA architecture separates frontend presentation from backend security logic. Vite offers lightning-fast builds and sub-second HMR. Streamlit is suitable for research prototypes but fails enterprise SOC dashboard requirements (multi-panel triage, granular state control, custom canvas routing). Next.js introduces redundant server-side compute. |
| **Styling & Icons** | **Tailwind CSS + Lucide Icons** | Material UI, Ant Design, Chakra UI | Utility-first CSS provides maximum design control, zero runtime overhead, and clean dark-mode implementation for SOC analysts. Lucide provides consistent, modern iconography. |
| **Primary Database** | **PostgreSQL 16+ (Prod) / SQLite (Dev)** | MongoDB, MySQL, Cassandra | Relational schema ensures strict transactional guarantees for RBAC, audit trails, and scan incidents. Native `JSONB` support allows flexible storage of dynamic module evaluations and raw header graphs while preserving SQL indexing. SQLite with WAL mode allows friction-free local execution. |
| **ORM & Migrations** | **SQLAlchemy 2.0 (Async) + Alembic** | Tortoise-ORM, Prisma, Peewee | Industry-standard enterprise ORM with full async/await support, connection pooling, and strict schema migration governance via Alembic. |
| **Email Parsing** | **Python `email` + `dnspython` + `tldextract`** | `mail-parser`, `flanker` | Python standard library `email` handles RFC 5322 MIME structures without third-party abandonment risk. `dnspython` enables direct asynchronous DNS queries for SPF/DKIM/DMARC. `tldextract` accurately separates subdomains, domains, and Public Suffixes. |
| **Authentication** | **JWT (OAuth2 Password Bearer) + Passlib (Argon2id/Bcrypt)** | Auth0, Firebase, Keycloak | Fully self-hosted, air-gappable authentication. Protects user credentials using modern memory-hard hashing algorithms (Argon2id) and stateless, signed tokens with role-based claim enforcement. |
| **Background Processing** | **FastAPI `BackgroundTasks` (Dev) / Celery + Redis (Prod)** | Celery only, Temporal, RQ | Pluggable task abstraction: development and light workloads run in-process with zero infrastructure overhead; production scales horizontally by swapping in Celery worker queues against Redis. |
| **API Communication** | **RESTful HTTP/JSON + Axios (Frontend)** | gRPC, GraphQL | Standardized REST with Pydantic contract validation. Fully documented via OpenAPI/Swagger. Front-end Axios clients utilize centralized response and auth token interceptors. |
| **Testing Suite** | **Pytest + Pytest-Asyncio + Vitest (Frontend)** | Unittest, Jest | Pytest provides concise test fixtures, parameterization, and native async support for FastAPI `httpx.AsyncClient` test harnesses. |
| **Containerization** | **Docker + Docker Compose** | Kubernetes, Nomad | Multi-stage Dockerfiles provide lean, production-ready container images with minimal attack surfaces for both frontend and backend. |

---

## 3. Deep-Dive Justifications

### 3.1 Why FastAPI over Flask or Django?
Security engineering requires strict contract validation. When an email contains malformed unicode, unusual header encodings, or oversized payloads, standard frameworks often produce unhandled exceptions or vulnerable deserialization flaws. FastAPI, powered by **Pydantic v2**, enforces strict schema parsing at the HTTP boundary before payloads reach business logic. Furthermore, FastAPI's asynchronous architecture handles multiple concurrent DNS lookups (crucial for SPF, DKIM, and DMARC verification) without blocking the thread pool.

### 3.2 Why React with Vite over Next.js?
MailSentra is a security tool deployed in enterprise environments. Next.js relies on Node.js server runtime logic for Server-Side Rendering (SSR) and API routes. In security architectures, having two backend layers (Next.js Node server + Python API server) doubles the operational attack surface and introduces redundant proxy routing. By adopting a pure client-side **React SPA compiled via Vite**, the entire frontend compiles down to static HTML, CSS, and JavaScript that can be hosted securely behind Nginx or embedded directly, leaving all security enforcement to the hardened FastAPI backend.

### 3.3 Why Hybrid SQLite/PostgreSQL?
Developers and security researchers testing MailSentra locally should not be forced to install Docker or manage PostgreSQL background services merely to run a scan. By architecting the data access layer on **SQLAlchemy 2.0 with asynchronous drivers**, MailSentra runs natively on SQLite (`sqlite+aiosqlite:///./mailsentra.db`) during development, and switches to PostgreSQL (`postgresql+asyncpg://...`) in production environments simply by updating the `DATABASE_URL` environment variable.
