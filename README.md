# 🛡 Phish Analyzer Desktop

> A local, privacy-first desktop tool for analysing suspicious `.eml` files for phishing indicators.  
> No cloud. No telemetry. Everything runs on your machine.

[![Build](https://github.com/hussein-design/Phish-analyzer/actions/workflows/build-windows.yml/badge.svg)](https://github.com/hussein-design/Phish-analyzer/actions/workflows/build-windows.yml)
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
| [urlscan.io](https://urlscan.io/user/signup) | URL detonation — screenshot, redirect chain, page title, malicious verdict | 100 public scans/day |

Enter keys in **⚙ Settings → API Keys**. Keys are stored in the local SQLite database — never
transmitted anywhere except to the respective API service.

All external API responses are cached in a persistent SQLite table (same DB file as the analysis
store) so repeated analyses of the same indicators — including after an app restart — do not consume
extra API quota. TTLs: 1 h for VT/AbuseIPDB/Shodan, 4 h for urlscan.io.

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

## Phase 0 — bug fixes (2026-10-01)

A full code audit was performed after the initial security review. **15 bugs were identified**
(BUG-01 through BUG-13, BUG-17, BUG-18 — IDs 14–16 were not assigned during this audit).
**13 were fixed**; 2 were deliberately deferred as low-severity (BUG-09, BUG-11, documented
below). The commit message for this work reads "15 bugs fixed" — that is imprecise; the correct
statement is 15 found, 13 fixed, 2 deferred. A regression test for each *fixed* bug lives in
`tests/test_phase0_regression.py` (37 tests, all passing).

| ID | Severity | File | Issue | Fix |
|---|---|---|---|---|
| BUG-01 | Medium | `eml_parser_service.py` | `extract_sender_ip()` only matched IPv4 — IPv6 sender IPs silently returned `None`, skipping AbuseIPDB/Shodan lookups | Added IPv6 regex to all three extraction strategies |
| BUG-02 | Medium | `eml_parser_service.py` | `parse_eml_bytes()` had no exception handling — a corrupt `.eml` propagated a raw `eml_parser` exception | Wrapped in `try/except`, re-raised as `InvalidEmlError` |
| BUG-03 | Medium | `eml_parser_service.py` | `extract_text_from_body()` coerced `bytes` content to `str()` repr (`"b'hello'"`) instead of decoding | Added `bytes.decode("utf-8", errors="replace")` guard |
| BUG-04 | **High** | `analysis_service.py` | Base64-encoded attachment payloads were replaced with `b""` — static analysis and hash computation silently skipped for those attachments | Attempt `base64.b64decode()` before falling back to `b""` |
| BUG-05 | High | `analysis_service.py` | `hash_attachment_content()` and the payload-for-intel extraction could disagree when payload was a string | Resolved by BUG-04 fix (same code path) |
| BUG-06 | **High** | `scoring_service.py` | VT URL scoring loop fired once *per matching URL*, inflating the score by N× instead of scoring once per analysis | Changed to hit-once pattern matching all other rules |
| BUG-07 | **High** | `threat_signals.py` | `find_lookalike_domain()` ran the brand-token combosquat check *before* the legitimate-domain exemption — `mail.microsoft.com` would be flagged | Moved the exemption check to run before any brand matching |
| BUG-08 | Medium | `url_intelligence_service.py` | Relative redirects (`redirect?foo=bar`) were not resolved against the base URL — only `/absolute-path` redirects were handled | Replaced manual split with `urllib.parse.urljoin` |
| BUG-09 | Low | `url_intelligence_service.py` | Invalid IP strings like `999.999.999.999` unnecessarily hit the DNS resolver in `_is_private_host_async()` | Minor — DNS resolver handles this gracefully; documented |
| BUG-10 | Medium | `attachment_intelligence_service.py` | OLE2 VBA heuristic matched the plain ASCII string `b"VBA"`, causing false positives on any document mentioning "VBA" in text | Removed broad match; kept only `b"_VBA_PROJECT"` and `b"V\x00B\x00A"` (directory entry signatures) |
| BUG-11 | Low | `validation_service.py` | An email with only a `Subject:` header passes validation but then fails `eml_parser` in the pipeline | Low severity — pipeline exception handler catches it; documented |
| BUG-12 | Medium | `virustotal_provider.py` | `scan_url_async(wait_for_completion=True)` had no timeout — a slow VT analysis could hold the rate-limit semaphore indefinitely | Wrapped with `asyncio.wait_for(timeout=120)` |
| BUG-13 | Medium | `analysis_service.py` | `sha256_list` was built before payload decoding, so base64-string attachments had no hash for VT enrichment | Moved `sha256_list` construction to after Phase 3 decode; fall back to `hashlib.sha256(decoded)` |
| BUG-17 | Low | `eml_parser_service.py` | `extract_auth_from_raw()` used the legacy `email` policy — RFC2047-encoded auth headers not decoded | Changed to `policy.default` |
| BUG-18 | Medium | `analysis_service.py` | `mkdir()`/`write_bytes()` in `submit_upload()` could raise `PermissionError` (uncaught), returning a raw 500 | Wrapped in `try/except OSError`, re-raised as `InvalidEmlError` |

Run the regression tests:

```bash
pytest tests/test_phase0_regression.py -v
```

---

## Phase 1 — Dynamic analysis (2026-10-01)

URL and attachment detonation via two optional providers. All new fields are optional — the tool
works with no new keys configured.

### urlscan.io URL detonation

Configure `URLSCAN_API_KEY` in `.env` (first-run seed) or enter the key in **⚙ Settings → API Keys**.

| Field in `.env` | Settings key | Purpose |
|---|---|---|
| `URLSCAN_API_KEY` | urlscan_key | urlscan.io API key for URL detonation |

When configured, the most suspicious URL from each email is submitted to urlscan.io for detonation.
The analysis waits up to **120 seconds** for the scan to complete (outer pipeline cap: 135 s), then
stores:

- Screenshot URL (`urlscan_screenshot_url`)
- Redirect chain observed during detonation (`urlscan_redirect_chain`)
- Final landing-page URL and title
- Verdict (`malicious` / `suspicious` / `benign`)
- Score contribution: +4 pts (malicious), +2 pts (suspicious)

### Hybrid Analysis (Falcon Sandbox) attachment detonation

Configure via **⚙ Settings → Sandbox** — set provider to `hybrid_analysis` and enter the API key.

The existing Any.run / Hybrid Analysis sandbox integration (Phase 5) was extended to use Hybrid
Analysis's full `/submit/file` endpoint (Windows 10 64-bit environment) instead of quick-scan,
with polling of `/report/{job_id}/summary` for behavioral data:

- Spawned process names
- Network contacts (hosts/domains)
- Extracted IOCs (dropped files, indicators)
- Score contribution: +5 pts (malicious), +3 pts (suspicious)

### Static vs dynamic score split

The final verdict now shows two separate sub-scores:

- `static_score` — headers, auth, URL heuristics, VT, AbuseIPDB, static attachment analysis
- `dynamic_score` — urlscan detonation + sandbox detonation results only

Both are stored in the DB and returned in `GET /analyses/{id}`.

### New migration

Run after upgrading:

```bash
alembic upgrade head
```

Migration `d1e2f3a4b5c6` adds 13 new columns to `email_analyses` and `urlscan_key` to `app_settings`.

### Response caching

All external API calls are cached in a persistent SQLite table (`enrichment_cache`) in the same
database file as the analysis store. Cache entries survive app restarts — re-scanning a previously
seen URL, IP, or file hash within the TTL window makes zero API calls.

| Provider | Namespace | TTL |
|---|---|---|
| VirusTotal URLs | `virustotal_url` | 3 600 s (1 h) |
| VirusTotal hashes | `virustotal_hash` | 3 600 s (1 h) |
| AbuseIPDB | `abuseipdb` | 3 600 s (1 h) |
| Shodan | `shodan` | 3 600 s (1 h) |
| urlscan.io | `urlscan` | 14 400 s (4 h) |
| Hybrid Analysis | `hybrid_analysis` | 14 400 s (4 h) |

The cache uses a two-layer design: an in-memory L1 (monotonic TTL, no I/O) in front of the
SQLite L2 (wall-clock TTL, survives restarts). A miss in L1 falls through to L2 and repopulates
L1. Failed DB writes are non-fatal — the in-memory entry remains valid for the current session.
TTL defaults are defined in `backend/services/enrichment/cache.py` and can be overridden per call.

Run the Phase 1 tests:

```bash
pytest tests/test_phase1_dynamic_analysis.py -v
```

Expected: **47 passed**

---

## Phase 2 — Rule-based behavioral analysis (2026-10-01)

A third, independent signal category — `behavioral_score` — built from sender/recipient history
tracked over time, not from inspecting a single email in isolation.  This is the foundation BEC
(Business Email Compromise) detection will build on.

### What it detects

| Signal | Fires when | Requires history? | Score weight |
|---|---|---|---|
| `first_time_sender` | This sender has never emailed this recipient before | Yes (cold-start safe) | +1 |
| `domain_age_anomaly` | Sender's domain was registered within 30 days of the email | No (async RDAP/WHOIS) | +3 |
| `display_name_mismatch` | From display implies a trusted brand but sending domain is not legitimate for it | No | +2 |
| `reply_chain_break` | Subject looks like Re:/Fwd: but sender is not in the known thread history | Yes (cold-start safe) | +3 |
| `send_time_anomaly` | Email sent at an unusual hour for this sender (needs ≥5 observations) | Yes (threshold-gated) | +1 |

All five scores add up to `behavioral_score`, which is stored and returned **independently** — it
is never merged into the combined `score` field.  The UI and API surface all three separately:
`static_score | dynamic_score | behavioral_score`.

### Cold-start policy

The first `N` emails analyzed for a new recipient mailbox have no history to compare against.
Rather than produce false positives, the three history-dependent signals default to **False**
(neutral) until data exists:

- `first_time_sender` — returns False when the recipient has no history at all (fresh install)
- `reply_chain_break` — returns False when the thread has no prior messages
- `send_time_anomaly` — returns False until `BEHAVIORAL_MIN_SEND_HISTORY` (default 5) prior
  observations exist for this (recipient, sender) pair

`display_name_mismatch` and `domain_age_anomaly` fire immediately because they are derived
from the email content, not from accumulated history.

The rationale: it is better to miss the first suspicious email to a new mailbox than to raise a
behavioral alert on every email during the warm-up period.  Both signals are still visible via
the content-based static score.

### Domain age lookup

Domain registration dates are looked up via RDAP (tried first) then a free WHOIS-over-HTTP
fallback, and cached via the existing `EnrichmentCache` with:

- **Namespace**: `domain_age`
- **TTL**: 2 592 000 seconds (30 days)
- **Rationale**: Registration dates are immutable facts — once a domain is registered, its
  creation date never changes.  30 days is generous; a 365-day TTL would also be correct.

No API key is required.  The lookup uses public RDAP endpoints and `whoisjsonapi.com` (free, no
registration).  If both fail, `domain_age_anomaly` returns `None` (signal undetermined — no
score contribution and no false positive).

### New persistent tables

Two new tables are created by migration `e2f3a4b5c6d7`:

| Table | Purpose |
|---|---|
| `sender_history` | Per (recipient, sender) pair: first_seen, last_seen, message_count, send_hours (JSON list of UTC hours) |
| `thread_history` | Per (recipient, thread_key): all message-IDs and senders seen in that thread |

Unlike the `enrichment_cache` table (disposable, TTL-based), these tables are **application data**
that the user will want preserved across upgrades.  They use a proper Alembic migration.

### Configuration

All settings have safe defaults — no configuration required to activate behavioral analysis.
Override in `.env` (first-run only) or by environment variable:

| Variable | Default | Meaning |
|---|---|---|
| `BEHAVIORAL_DOMAIN_AGE_THRESHOLD_DAYS` | `30` | Flag domains registered within N days before the email |
| `BEHAVIORAL_MIN_SEND_HISTORY` | `5` | Minimum prior observations before `send_time_anomaly` activates |
| `BEHAVIORAL_SEND_TIME_TOLERANCE_HOURS` | `2` | Hours of tolerance around each historical send hour |
| `BEHAVIORAL_MAX_SEND_HOURS` | `200` | Cap on stored send-hour samples per (recipient, sender) pair |

### History recording

History is written **after** scoring so the current email never influences its own behavioral
scores.  The pipeline order is:

1. `compute_behavioral_signals()` — read history, compute scores
2. `compute_score()` — incorporate behavioral result
3. Save analysis row to DB
4. `record_observation()` — write history for future analyses

### New migration

Run after upgrading:

```bash
alembic upgrade head
```

Migration `e2f3a4b5c6d7` creates `sender_history` and `thread_history` tables and adds 7 new
columns to `email_analyses` (`behavioral_score`, `behavioral_reasons`, and 5 `sig_*` boolean flags).

### Run the Phase 2 tests

```bash
pytest tests/test_phase2_behavioral_analysis.py -v
```

Expected: **~52 passed**

---

## Phase 3 — BEC (Business Email Compromise) detection (2026-10-02)

A fourth independent signal category — `bec_score` — built specifically for attacks that have
**zero static or dynamic signal**: no malicious URL, no attachment, SPF/DKIM pass on the
attacker's own domain.  These emails bypass every content scanner.  BEC detection fires on
social-engineering and impersonation patterns instead.

### What it detects

| Signal | Fires when | Default pts |
|---|---|---|
| `vip_impersonation` | From display name or address matches a VIP in the protected-identity table, but the sending domain is not that VIP's legitimate domain | 4 |
| `financial_request_language` | Body contains keywords from one or more of the five financial pattern categories (see below) | 2 per category, max 6 |
| `vendor_fraud_pattern` | Bank-detail-change language from a sender unknown to the recipient's history | 3 |
| `authority_pressure_combo` | `financial_request_language` fires AND at least one identity signal co-occurs (`vip_impersonation` or `first_time_sender` from Phase 2) | 3 |

### Verdict-merge formula

BEC score contributes at **2× weight** to the combined verdict.  The full formula is:

```
combined_score = static_score + dynamic_score + (bec_score × 2) + behavioral_score

≥ 9  → phishing
≥ 5  → suspicious
< 5  → benign   (subject to BEC_SUSPICIOUS_FLOOR — see below)
```

**Why 2× for BEC, 1× for behavioral:**
`authority_pressure_combo` only fires when two independent signals already co-occur, so a
`bec_score ≥ 4` represents converging evidence.  Doubling it places a VIP-impersonation hit
(4 pts → 8 combined) on par with a known-malicious VirusTotal URL hit (4 pts direct).
Behavioral signals keep 1× because `first_time_sender` alone is weak; even all five behavioral
signals firing together (score = 5) can push a borderline email but cannot manufacture a
phishing verdict from zero content signal.

**Worked example — classic CEO wire-transfer fraud:**

```
From:    "Jane Smith" <attacker@evil-acctg.com>
To:      accounts@corp.com
Subject: Urgent wire needed
Body:    "Please wire transfer the funds to our new account.
          This is time sensitive. Strictly confidential."
Links:   none   Attachments: none   SPF/DKIM: pass
```

| Source | Signal | Points |
|---|---|---|
| static | No bad URLs, no attachments, SPF/DKIM pass | 0 |
| dynamic | No urlscan, no sandbox | 0 |
| behavioral | `first_time_sender` fires (1 pt) | 1 |
| BEC | `vip_impersonation`: "Jane Smith" matches CFO entry, domain is `evil-acctg.com` ≠ `corp.com` | 4 |
| BEC | `financial_request_language`: `wire_transfer` category + `urgency_authority` category = 2 × 2 pts | 4 |
| BEC | `authority_pressure_combo`: financial + vip_impersonation co-occur | 3 |
| **bec_score total** | | **11** |

```
combined_score = 0 + (11 × 2) + 1 = 23  →  verdict: PHISHING
```

Stored independently: `static_score=0`, `dynamic_score=0`, `behavioral_score=1`, `bec_score=11`.
The analyst sees exactly which of the four buckets drove the result.

### BEC_SUSPICIOUS_FLOOR

**Decision: keep it.**

The floor forces the verdict to at least "suspicious" when `bec_score ≥ BEC_SUSPICIOUS_FLOOR`
(default 4) even if the formula would otherwise produce "benign".

It is currently redundant at the default settings: a `bec_score` of 4 with 2× weight already
contributes 8 combined points, which the formula independently calls "suspicious".  It becomes
relevant if signal weights are tuned down in the future — for example, lowering
`bec_financial_per_category` from 2 to 1 would mean two firing categories contribute only 4
combined points (benign by the formula).  The floor catches that case without requiring every
weight-tuning change to also revisit the threshold arithmetic.

Set `BEC_SUSPICIOUS_FLOOR=0` in `.env` to disable it entirely.

### Financial pattern categories

All keyword matching is case-insensitive substring search.  Each category that fires adds 2 pts
to `bec_score`, capped at `BEC_FINANCIAL_MAX_PTS` (default 6).

**Category 1 — `wire_transfer`** (explicit fund-movement vocabulary)

> wire transfer · wire the funds · wire payment · wire $ · initiate a transfer ·
> initiate the transfer · transfer the funds · international transfer · ach transfer ·
> swift transfer · telegraphic transfer · funds transfer · transfer funds · send the money ·
> remit payment · remit the amount · same-day transfer · urgent transfer · immediate transfer

**Category 2 — `bank_detail_change`** (account/routing number change requests)

> new bank account · new account details · new banking details · updated bank · updated account ·
> changed bank · change our bank · new routing number · new account number ·
> account number has changed · banking information has changed · new payment details ·
> please update your records · update your payment · use the following account ·
> use these bank details · our bank details have · payment should be made to

**Category 3 — `urgency_authority`** (executive-pressure and secrecy framing)

> strictly confidential · do not discuss · do not share · between us only ·
> keep this between · personal request · direct request · acting on behalf of the ceo ·
> on behalf of the president · on behalf of our ceo · approved by the board ·
> board has approved · this is time sensitive · needs to be done today ·
> needs to happen today · before end of business · by close of business · eod today ·
> no later than today · do not reply to this email · call me directly

**Category 4 — `gift_card`** (common low-level BEC)

> gift card · gift cards · itunes card · google play card · amazon gift card ·
> steam gift card · buy gift cards · purchase gift cards · send me the codes ·
> scratch the back · redemption code · card number and pin

**Category 5 — `invoice_redirect`** (invoice or payment redirect to new account)

> new invoice · revised invoice · updated invoice · please process this invoice ·
> process the attached invoice · payment for invoice · settle this invoice ·
> redirect this payment · send payment to · please use new account for future payments ·
> future invoices should be · upcoming payments should go to ·
> we have changed our bank · effective immediately

To add or remove keywords, edit `_FINANCIAL_PATTERN_CATEGORIES` in
`backend/services/bec_signals_service.py`.  No code changes to detection logic are required —
the patterns are data.

### !! False-positive risk: `financial_request_language` !!

This is the signal most likely to fire on legitimate emails.  Known cases:

- CFO asking a supplier to confirm wire-transfer details
- Finance team circulating a payment approval for an invoice
- IT team asking a vendor to update banking details after a legitimate account change
- Executive asking team to purchase gift cards for a legitimate incentive programme

**The formula provides one layer of protection:** a single `financial_request_language` hit
(bec_score = 2) contributes only 4 combined points — benign by the formula, and below
`BEC_SUSPICIOUS_FLOOR` (default 4, exclusive).  It needs a second BEC signal to reach
"suspicious".

**The VIP list provides the main mitigation:**
Add real executive and finance-team email addresses to the `vip_identities` table (see below).
Their legitimate emails will still trigger `financial_request_language`, but will **not** trigger
`vip_impersonation` (their sending domain matches `protected_domain`), so
`authority_pressure_combo` will not fire.  This keeps the `bec_score` contribution from a
known-legitimate sender below the "suspicious" threshold.

Analysts should treat `bec_score` and `behavioral_score` as context for investigation, not as
automated block/quarantine decisions.

### VIP / protected-identity table

The `vip_identities` table is **admin-configurable and starts empty**.  There are no hardcoded
entries.  When the table is empty, `vip_impersonation` is silently disabled (returns False).

**Schema** (created by migration `g4b5c6d7e8f9`):

| Column | Type | Purpose |
|---|---|---|
| `name` | VARCHAR(255) | Human-readable label, e.g. "Jane Smith (CFO)" |
| `protected_email` | VARCHAR(512) nullable | Real email address, e.g. "jane.smith@corp.com" |
| `protected_domain` | VARCHAR(255) | Legitimate sending domain, e.g. "corp.com" |
| `title` | VARCHAR(128) nullable | Role label for UI display, e.g. "Chief Financial Officer" |
| `is_active` | BOOLEAN | Soft-delete — set False instead of deleting to preserve history |

A sender whose display name contains all words of a VIP's `name` (case-insensitive) but whose
sending domain does **not** match `protected_domain` (or a subdomain of it) triggers the signal.
Exact bare-address spoofing (address matches `protected_email` but wrong domain) also fires.

Populate via direct DB edit or a future Settings UI row.  Typical entries:

- CEO, CFO, COO, board members
- Finance team members with wire-transfer authority
- IT administrators (to catch fake IT password-reset / gift-card requests)
- Key external partners (auditors, legal counsel, major vendors)

### `vendor_fraud_pattern`

Fires when `financial_request_language` is present **and** the sender has never previously
contacted this recipient (using the `sender_history` table from Phase 2).  An In-Reply-To
tiebreaker suppresses the signal when the email correctly references a known thread message-ID,
allowing legitimate new-thread financial emails from partners who haven't emailed before.

Cold-start: returns False (neutral) when the recipient mailbox has no history at all.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `BEC_SUSPICIOUS_FLOOR` | `4` | Minimum `bec_score` to force verdict to "suspicious" when formula says "benign". Set to 0 to disable. |
| `BEC_FINANCIAL_MAX_PTS` | `6` | Cap on points `financial_request_language` can contribute per analysis (prevents runaway scoring on verbose emails). |

Override in `.env` or by environment variable.  The scoring weights for individual signals
(`bec_vip_impersonation`, `bec_financial_per_category`, `bec_vendor_fraud`,
`bec_authority_pressure`) can be overridden via the `scoring_weights` dict in the Settings DB
row (same mechanism as all other signal weights).

### New DB table

Migration `g4b5c6d7e8f9` creates:

- `vip_identities` table (see schema above)
- Six new columns on `email_analyses`: `bec_score`, `bec_reasons`, `sig_vip_impersonation`,
  `sig_financial_request`, `sig_vendor_fraud`, `sig_authority_pressure`

Run after upgrading:

```bash
alembic upgrade head
```

### Run the Phase 3 tests

```bash
pytest tests/test_phase3_bec.py -v
```

Expected: **84 passed**

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
