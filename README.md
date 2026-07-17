# 🛡 Phish Analyzer Desktop

> A local, privacy-first desktop tool for analysing suspicious `.eml` files for phishing indicators.  
> No cloud. No telemetry. Everything runs on your machine.

[![Build](https://github.com/your-org/phish-analyzer/actions/workflows/build-windows.yml/badge.svg)](../../actions/workflows/build-windows.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Security Audited](https://img.shields.io/badge/security-audited-brightgreen)](#security)

---

## What it does

Phish Analyzer Desktop takes a raw `.eml` email file, runs it through a multi-layer detection
pipeline, and produces a structured verdict with every signal explained — locally, with no data
leaving your machine unless you choose to call external APIs.

| Layer | What is checked |
|---|---|
| **Email headers** | SPF / DKIM / DMARC authentication, Reply-To vs From domain mismatch, Return-Path mismatch |
| **Sender domain** | Lookalike / typosquat detection (leetspeak-normalised similarity), punycode / IDN homograph encoding, suspicious TLDs |
| **URLs** | Suspicious keywords, raw-IP hosts, URL shorteners, punycode domains, suspicious TLDs, redirect chains, page title extraction |
| **Attachments** | Dangerous extensions, double-extension disguises, macro-enabled Office docs, embedded executables, archive inspection, MIME magic-byte mismatch, document metadata |
| **Body** | Urgency/pressure language, lure-category detection (invoice, password-reset, IT helpdesk, account-takeover, exec-impersonation, shipping), anchor-text vs href mismatches |
| **Threat intel** | VirusTotal URL + file-hash reputation, AbuseIPDB sender-IP reputation, Shodan IP intelligence |

Every signal has a configurable weight. The final suspicion **score** maps to a **verdict**:

- 🔴 **Phishing** — score ≥ 9
- 🟡 **Suspicious** — score 5–8
- 🟢 **Benign** — score < 5

---

## Screenshots

> Upload page — drag and drop a `.eml` file, browse the analysis history

```
┌──────────────────────────────────────────────────────────────┐
│ 🛡 Phish Analyzer              ⚙ Settings    🌙 Dark         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│         ↑  Drop a .eml file here  or  click to browse       │
│              RFC 822 .eml  •  Max 25 MB                      │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ Analysis History   [12]                                      │
│ 🔍 Search...          All verdicts ▾  ↻ Refresh  ✕ Delete   │
│──────────────────────────────────────────────────────────────│
│ Filename      Subject         From           Verdict  Score  │
│ invoice.eml   Urgent payment  ceo@evil.com   PHISHING   14   │
│ update.eml    Verify account  no-reply@...   SUSPICIOUS  6   │
└──────────────────────────────────────────────────────────────┘
```

> Report page — tabbed detail view with score ring and verdict badge

```
┌──────────────────────────────────────────────────────────────┐
│ ← Back   invoice.eml — Urgent payment    ⚠ Phishing  [14]  │
│──────────────────────────────────────────────────────────────│
│ 📋 Overview  🔍 Headers  🔗 URLs  📎 Attachments  🛡 Intel  │
│──────────────────────────────────────────────────────────────│
│ ┌─ SUMMARY ──────────────────────────────────────────────┐  │
│ │ An email arrived from ceo@evil.com with the subject     │  │
│ │ 'Urgent payment required'. Authentication failed for    │  │
│ │ SPF, DKIM. The sender domain resembles 'paypal.com'.   │  │
│ │ 3 URLs found — 2 triggered suspicious indicators.       │  │
│ │ PHISHING — Multiple high-confidence indicators found.   │  │
│ └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Phish Analyzer Desktop (single process)         │
│                                                                     │
│  ┌───────────────────────────────┐   ┌───────────────────────────┐  │
│  │        PySide6 Frontend       │   │     FastAPI Backend        │  │
│  │                               │   │     (daemon thread)        │  │
│  │  MainWindow                   │   │                           │  │
│  │  ├── UploadPage               │   │  Routes                   │  │
│  │  │   ├── DropZone             │   │  ├── POST /analyses        │  │
│  │  │   └── AnalysesTable        │   │  ├── GET  /analyses/{id}  │  │
│  │  └── ReportPage               │   │  ├── GET  /analyses       │  │
│  │      ├── ScoreRing            │   │  ├── PUT  /settings       │  │
│  │      ├── VerdictBadge         │   │  └── GET  /health         │  │
│  │      └── Tabbed cards         │   │                           │  │
│  │                               │   │  Services                 │  │
│  │  Controllers (MVC)            │   │  ├── analysis_service     │  │
│  │  ├── UploadController         │◄──┤  ├── eml_parser_service   │  │
│  │  ├── AnalysesController  HTTP │   │  ├── scoring_service      │  │
│  │  ├── ReportController    over │   │  ├── threat_signals       │  │
│  │  └── SettingsController  lo-  │   │  ├── url_intel_service    │  │
│  │                          cal  │   │  ├── attachment_intel     │  │
│  │  ApiClient               host │   │  └── report_service       │  │
│  │  (requests.Session)      only │   │                           │  │
│  │                               │   │  Enrichment               │  │
│  │  QThreadPool workers          │   │  ├── virustotal_provider  │  │
│  │  (non-blocking HTTP calls)    │   │  ├── abuseipdb_provider   │  │
│  └───────────────────────────────┘   │  └── shodan_provider      │  │
│                                      │                           │  │
│                                      │  Repositories + Models    │  │
│                                      │  └── SQLite (aiosqlite)   │  │
│                                      └───────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  shared/   Pydantic schemas — single contract for both sides │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Data at rest:  %LOCALAPPDATA%\PhishAnalyzer\PhishAnalyzerDesktop\  │
│                 ├── phish_analyzer.db   (SQLite)                    │
│                 ├── uploads/{id}/       (.eml originals)            │
│                 └── phish_analyzer.log                              │
└─────────────────────────────────────────────────────────────────────┘

  External API calls (optional — only when keys are configured)
  ┌──────────────┐   ┌─────────────┐   ┌────────────────────────┐
  │  VirusTotal  │   │  AbuseIPDB  │   │  Shodan / InternetDB   │
  │  URL + hash  │   │  Sender IP  │   │  IP intel (free tier)  │
  └──────────────┘   └─────────────┘   └────────────────────────┘
```

### Analysis pipeline (per upload)

```
.eml upload
    │
    ▼
validate_eml_upload()         ← extension, size, RFC 822 headers
    │
    ▼
_sanitize_filename()          ← strip path traversal, cap length
    │
    ▼
Create PENDING row in DB      ← returns 202 immediately
    │
    ▼ (asyncio background task)
eml_parser_service            ← parse headers, body, attachments
    │
    ├── threat_signals         ← lookalike domains, lure categories,
    │                             anchor mismatches, urgency keywords
    │
    ├── url_intelligence       ← follow redirects, extract page titles,
    │                             SSRF-guarded DNS resolution
    │
    ├── attachment_intel       ← magic bytes, macro detection,
    │                             ZIP inspection, metadata extraction
    │
    ├── Enrichment (parallel)
    │   ├── virustotal_provider  (URLs + file hashes)
    │   ├── abuseipdb_provider   (sender IP)
    │   └── shodan_provider      (sender IP, free InternetDB + key API)
    │
    ├── scoring_service        ← weighted signal scoring → verdict
    │
    └── Save DONE row          ← frontend poll returns full detail
```

---

## Project layout

```
phish-analyzer/
├── backend/
│   ├── app_factory.py          FastAPI app + localhost-only middleware
│   ├── server.py               uvicorn daemon-thread host
│   ├── core/                   config, exceptions, logging, defaults
│   ├── database/               engine, session, init/migrations
│   ├── models/                 SQLAlchemy ORM models
│   ├── repositories/           DB access layer (no business logic)
│   ├── routes/                 FastAPI route handlers
│   └── services/
│       ├── analysis_service.py         pipeline orchestrator
│       ├── eml_parser_service.py       RFC 822 parsing
│       ├── scoring_service.py          signal scoring engine
│       ├── threat_signals.py           detection heuristics
│       ├── url_intelligence_service.py redirect chain + page title
│       ├── attachment_intelligence_service.py static file analysis
│       ├── report_service.py           DOCX report builder
│       └── enrichment/
│           ├── virustotal_provider.py
│           ├── abuseipdb_provider.py
│           └── shodan_provider.py
├── frontend/
│   ├── controllers/            MVC controllers (own views + ApiClient)
│   ├── dialogs/                settings, confirm-delete dialogs
│   ├── models/                 QAbstractTableModel, proxy model
│   ├── services/               ApiClient, ThemeManager, SettingsStore
│   ├── views/                  UploadPage, ReportPage, MainWindow
│   └── widgets/                DropZone, VerdictBadge, Toast, KVTable
├── shared/
│   ├── schemas.py              Pydantic models (shared backend + frontend)
│   └── paths.py                OS-aware data directory resolution
├── migrations/                 Alembic migrations
├── assets/
│   ├── themes/                 light.qss, dark.qss
│   └── icons/                  app.ico
├── launcher.py                 app entrypoint
├── requirements.txt            pinned dependencies
├── phish_analyzer.spec         PyInstaller spec
├── installer.iss               Inno Setup installer script
└── .github/workflows/          CI build + release pipeline
```

---

## Setup (development)

### Prerequisites

- Python **3.11** or **3.12** (required for PySide6 wheel availability)
- Windows, macOS, or Linux desktop (packaging to `.exe` requires Windows or CI)
- Git

### Install

```bash
git clone https://github.com/your-org/phish-analyzer.git
cd phish-analyzer

python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### Optional: seed API keys on first run

```bash
cp .env.example .env
# Edit .env and add your keys — these are imported into the DB on first launch.
# After the first run, use the Settings dialog instead.
```

### Run

```bash
python launcher.py
```

The backend starts on `http://127.0.0.1:8756` in a background thread, waits for `/health`, then
opens the Qt window. The backend stops automatically when the window closes.

**Backend only** (for API testing):

```bash
uvicorn backend.app_factory:create_app --factory --host 127.0.0.1 --port 8756
```

---

## API keys (optional)

The app works fully offline with no API keys. The following services add richer threat intelligence:

| Service | Purpose | Free tier |
|---|---|---|
| [VirusTotal](https://www.virustotal.com/gui/join-us) | URL scan (70+ AV engines) + file hash reputation | 500 req/day |
| [AbuseIPDB](https://www.abuseipdb.com/register) | Sender IP abuse reputation | 1 000 req/day |
| [Shodan](https://account.shodan.io/register) | IP open ports, CVEs, tags | Paid (InternetDB free fallback built-in) |

Enter keys in **⚙ Settings → API Keys**. Keys are stored in the local SQLite database — never
transmitted anywhere except to the respective API service.

---

## Database migrations

Migrations run automatically at every startup. To create a new migration after changing a model:

```bash
alembic revision --autogenerate -m "describe the change"
```

---

## Packaging (Windows `.exe`)

**Option A — CI (recommended):**

Push a version tag to trigger a full release build:

```bash
git tag v1.2.0
git push origin v1.2.0
```

The GitHub Actions workflow builds on `windows-latest`, runs Inno Setup, and publishes the installer
as a GitHub Release asset automatically.

**Option B — locally on Windows:**

```bash
# Must be in a Python 3.11 or 3.12 venv
pyinstaller phish_analyzer.spec
```

Produces `dist/PhishAnalyzerDesktop/` (onedir, not onefile — avoids Defender false-positive on
extraction). Wrap with Inno Setup (`installer.iss`) for a single-file installer.

---

## Security

A full security audit was completed on 2026-07-18. All identified issues are fixed.

| ID | Severity | Issue | Status |
|---|---|---|---|
| HIGH-01 | High | Localhost-only middleware | ✅ Fixed |
| HIGH-02 | High | Upload queue-depth guard not enforced | ✅ Fixed |
| HIGH-03 | High | Path traversal via uploaded filename | ✅ Fixed |
| HIGH-04 | High | `Content-Disposition` header injection | ✅ Fixed |
| HIGH-05 | High | `DELETE /analyses` had no confirmation guard | ✅ Fixed |
| MED-01 | Medium | SQL injection (ORM parameterised queries) | ✅ Fixed |
| MED-02 | Medium | API keys exposed via `GET /settings` | ✅ Fixed |
| MED-03 | Medium | Oversized body / resource exhaustion | ✅ Fixed |
| MED-04 | Medium | Malformed requests return 422, not 500 | ✅ Fixed |
| MED-05 | Medium | Raw error strings stored without sanitization | ✅ Fixed |

Key protections:

- **Localhost-only** — the backend rejects all non-loopback requests at middleware level
- **No API key exposure** — `GET /settings` returns only `configured: true/false`, never the key value
- **Filename sanitization** — path traversal stripped before any filesystem write
- **Input size limits** — 25 MB file upload cap, 200 KB body text cap, 500-item list cap on settings
- **XXE-safe XML parsing** — `defusedxml` used for OOXML metadata extraction
- **Error string sanitization** — `_safe_error()` strips API keys / paths from exception messages before DB storage

Run the included test suite against a live backend:

```bash
python security_test.py
```

---

## Contributing

1. Fork the repo and create a branch: `git checkout -b feature/my-feature`
2. Make changes — follow the existing layered architecture (routes → services → repositories → models)
3. Test with the sample `.eml` files: `phishing_office_1.eml`, `phishing_office_2.eml`
4. Open a pull request with a clear description of what changed and why

---

## License

MIT — see [LICENSE](LICENSE).

---

*Phish Analyzer Desktop — built for security analysts, SOC teams, and anyone who wants to understand what's inside a suspicious email.*
