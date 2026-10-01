# Phish-Analyzer — Development Handoff

**Last commit:** `phase-3: BEC detection — vip_impersonation, financial_request_language, vendor_fraud, authority_pressure_combo`  
**Branch:** `main`  
**Date:** 2026-10-02

---

## What was completed

### Phase 0 — Audit and Bug Patch ✅

A full code audit was performed. **15 bugs were identified, 13 fixed, 2 deliberately deferred.**
37 regression tests added in `tests/test_phase0_regression.py` — all pass.

> Note: the Phase 0 commit message reads "15 bugs fixed" — that is imprecise.
> Correct count: 15 found, 13 fixed, 2 deferred (BUG-09 and BUG-11, low severity, documented in README).

#### Files changed in Phase 0

| File | Bugs fixed |
|---|---|
| `backend/services/eml_parser_service.py` | BUG-01, BUG-02, BUG-03, BUG-17 |
| `backend/services/analysis_service.py` | BUG-04/05, BUG-13, BUG-18 |
| `backend/services/scoring_service.py` | BUG-06 |
| `backend/services/threat_signals.py` | BUG-07 |
| `backend/services/url_intelligence_service.py` | BUG-08 |
| `backend/services/attachment_intelligence_service.py` | BUG-10 |
| `backend/services/enrichment/virustotal_provider.py` | BUG-12 |

#### Bugs fixed (summary)

- **BUG-01** IPv6 sender IPs now extracted
- **BUG-02** `parse_eml_bytes()` wraps corrupt input as `InvalidEmlError`
- **BUG-03** `bytes` body content decoded properly (no more `"b'hello'"` in scored text)
- **BUG-04/05** Base64-encoded attachment payloads decoded before static analysis and hashing
- **BUG-06** VT URL scoring fires once per analysis, not once per matching URL
- **BUG-07** Legitimate subdomains (`mail.microsoft.com`) no longer flagged as lookalikes
- **BUG-08** Relative HTTP redirects resolved correctly via `urllib.parse.urljoin`
- **BUG-10** OLE2 VBA false positives eliminated (plain `b"VBA"` match removed)
- **BUG-12** VT `scan_url_async` now has a 120 s timeout via `asyncio.wait_for`
- **BUG-13** SHA-256 list built after payload decode; base64 attachments now get VT hash enrichment
- **BUG-17** Auth header parsing uses `email.policy.default` (RFC2047 decoding)
- **BUG-18** `mkdir()`/`write_bytes()` `PermissionError` now returns clean 422

#### Not fixed (low severity, documented)
- **BUG-09** Invalid IP strings hit DNS unnecessarily in SSRF guard — harmless
- **BUG-11** Single-header emails pass validation then fail in pipeline — caught by exception handler

---

### Phase 1 — Dynamic Analysis ✅

URL detonation via urlscan.io, attachment behavioral detonation via Hybrid Analysis (Falcon Sandbox),
persistent enrichment cache, static/dynamic score split.
47 new tests in `tests/test_phase1_dynamic_analysis.py` — all pass.

**Total test count at Phase 1 completion: 84 (37 Phase 0 + 47 Phase 1), all passing.**

#### Files changed in Phase 1

| File | What changed |
|---|---|
| `backend/services/enrichment/urlscan_provider.py` | **NEW** — urlscan.io URL detonation provider |
| `backend/services/enrichment/cache.py` | **NEW** — SQLite-backed persistent enrichment cache |
| `backend/services/enrichment/sandbox_provider.py` | Extended Hybrid Analysis to use `/submit/file` + behavioral report polling |
| `backend/services/enrichment/virustotal_provider.py` | Added persistent cache reads/writes |
| `backend/services/enrichment/abuseipdb_provider.py` | Added persistent cache reads/writes |
| `backend/services/enrichment/shodan_provider.py` | Added persistent cache reads/writes |
| `backend/services/scoring_service.py` | Dynamic signal scoring, static/dynamic score split |
| `backend/services/analysis_service.py` | Wired urlscan + dynamic attachment detonation |
| `backend/models/analysis.py` | 13 new columns for dynamic analysis results |
| `backend/models/app_settings.py` | `urlscan_key` column |
| `backend/repositories/settings_repository.py` | `set_urlscan` flag in `save_all()` |
| `backend/routes/analyses.py` | New dynamic fields mapped in `_to_detail()` |
| `backend/routes/settings.py` | `urlscan_key` read/write |
| `backend/app_factory.py` | Cache `init_cache()` and `close()` wired into lifespan |
| `shared/schemas.py` | urlscan/dynamic attachment/score-split fields in `EmailDetail`; new `ScoringWeights` entries |
| `migrations/versions/d1e2f3a4b5c6_phase1_dynamic_analysis.py` | **NEW** — Alembic migration |
| `tests/test_phase1_dynamic_analysis.py` | **NEW** — 47 tests |
| `README.md` | Phase 1 documented; urlscan in API keys table; cache TTL table |
| `.env.example` | Added `URLSCAN_API_KEY=` |
| `HANDOFF.md` | This file |

#### What Phase 1 built

**urlscan.io URL detonation** (`urlscan_provider.py`):
- Submits the first URL from each email to urlscan.io
- Polls every 10 s, up to 120 s internal cap
- Outer pipeline timeout: 135 s (120 s inner cap + 15 s grace) — inner always fires first
- Parses: screenshot URL, redirect chain observed during detonation, final page title, verdict
- Scores: +4 pts malicious, +2 pts suspicious — in `dynamic_score`, not `static_score`
- Runs concurrently in the same `asyncio.gather` as VT/AbuseIPDB/Shodan
- Returns `status="no_key"` immediately when unconfigured — zero pipeline latency

**Hybrid Analysis behavioral report** (`sandbox_provider.py`):
- Upgraded from quick-scan (`/api/v2/quick-scan/file`) to full detonation (`/api/v2/submit/file`, Windows 10 64-bit env)
- Polls `/report/{job_id}/summary` for: process names, network contacts, IOCs, verdict, threat score
- Falls back to quick-scan if full-submit endpoint returns an error
- New public helper: `fetch_hybrid_behavioral_report(job_id, sha256, api_key)`
- All result dicts now include `processes`, `network_calls`, `iocs` fields
- Scores: +5 pts malicious, +3 pts suspicious — in `dynamic_score`

**Static/dynamic score split** (`scoring_service.py`):
- `compute_score()` returns `static_score`, `static_reasons`, `dynamic_score`, `dynamic_reasons` alongside combined `score`/`verdict`/`reasons`
- Dynamic signals only contribute when provider `status == "done"` — timeout/error/no_key = 0
- All existing callers still work (new params are optional, defaults to None)

**Persistent enrichment cache** (`cache.py` + all providers):
- Two-layer: L1 in-memory (monotonic TTL, zero I/O) + L2 SQLite table `enrichment_cache`
- L2 uses wall-clock TTL so entries survive app restarts
- `init_cache(db_path)` called at startup from `app_factory.py` lifespan
- Before init (tests, early startup): in-memory only, no buffering
- DB writes are non-fatal — L1 entry remains valid if SQLite write fails
- TTLs: VT/AbuseIPDB/Shodan 3 600 s; urlscan/Hybrid Analysis 14 400 s
- No Alembic migration needed — table created by `CREATE TABLE IF NOT EXISTS` in `init_cache()`

#### Known gaps / open items from Phase 1 review

1. **Sandbox original failure unknown** — The previous developer said the Phase 5 sandbox was "failing and hidden." The code I received was already wired and not gated. I replaced the quick-scan path with full detonation, which may have incidentally fixed whatever was broken — but without knowing the original error, this cannot be confirmed. **Before approving Phase 1 as complete, run an end-to-end manual test with a real Hybrid Analysis API key against a macro-enabled attachment.**

2. **Hybrid Analysis cache not keyed** — The `hybrid_analysis` namespace is defined in `DEFAULT_TTLS` but no provider currently writes to it. The sandbox is submitted per-analysis (file payload, not a stable key), so caching requires keying on SHA-256. When `submit_for_sandbox` returns `status="done"` for a Hybrid Analysis job, the result should be cached under `("hybrid_analysis", sha256)` and the `_run_pipeline` path should check the cache before submitting. This was left out of Phase 1 to keep scope bounded. **Track as Phase 2 work item.**

3. **urlscan only detonates the first URL** — The pipeline picks `urls[0]` unconditionally. A smarter heuristic would prefer a URL that is already marked suspicious by static analysis (shortener, keyword, IP host). This requires building `url_rows` before calling urlscan, which means restructuring the pipeline order. **Track as Phase 2 polish item.**

4. **`dynamic_attachment_*` columns vs `sandbox_*` columns** — Both sets of columns now exist in `email_analyses`. The `sandbox_*` columns (from Phase 5) capture the legacy Any.run/quick-scan result; `dynamic_attachment_*` captures the Phase 1 full behavioral result. They currently duplicate each other for Hybrid Analysis. The frontend (report_page, report_controller) only reads `sandbox_*` — it does not yet render the new behavioral data. **Track for UI work.**

---

---

### Phase 2 — Behavioral analysis ✅

Sender/recipient relationship history, domain age, display-name mismatch, reply-chain injection,
and send-time anomaly signals.  Phase 2 also wired the behavioral_signals_service into the
analysis pipeline and extended scoring_service with a third independent score column.
59 new tests in `tests/test_phase2_behavioral_analysis.py` — all pass.

**Total test count at Phase 2 completion: 143 (37+47+59), all passing.**

#### Files changed in Phase 2

| File | What changed |
|---|---|
| `backend/services/behavioral_signals_service.py` | **NEW** — 5 behavioral signals, `compute_behavioral_signals()`, `record_observation()` |
| `backend/models/sender_history.py` | **NEW** — per-(recipient, sender) message count + send-hour list |
| `backend/models/thread_history.py` | **NEW** — per-(recipient, thread_key) message history for reply-chain break |
| `backend/services/analysis_service.py` | Wired behavioral signals before `compute_score()`, records observation after |
| `backend/services/scoring_service.py` | Added `behavioral_result` param, 3-way score split |
| `backend/models/analysis.py` | `behavioral_score`, `behavioral_reasons`, `sig_*` columns |
| `backend/routes/analyses.py` | Behavioral fields mapped in `_to_detail()` |
| `shared/schemas.py` | Behavioral fields in `EmailDetail` |
| `backend/services/eml_parser_service.py` | `get_email_date()`, `get_recipient()`, `get_in_reply_to()` helpers |
| `migrations/versions/e2f3a4b5c6d7_phase2_behavioral_analysis.py` | **NEW** — Alembic migration |
| `migrations/versions/f3a4b5c6d7e8_add_in_reply_to_thread_history.py` | **NEW** — In-Reply-To tiebreaker column |
| `tests/test_phase2_behavioral_analysis.py` | **NEW** — 59 tests |

---

### Phase 3 — BEC (Business Email Compromise) detection ✅

Four BEC-specific signals wired into the analysis pipeline as an independent fourth score category.
BEC score contributes at 2× weight to the combined verdict (vs 1× for behavioral) because BEC
signals are combinatorial — they only fire together when converging evidence is present.
84 new tests in `tests/test_phase3_bec.py` — all pass.

**Total test count at Phase 3 completion: 227 (37+47+59+84), all passing.**

#### Files changed in Phase 3

| File | What changed |
|---|---|
| `backend/services/bec_signals_service.py` | **NEW** — 4 BEC signals, `compute_bec_signals()`, `BecResult`, `BEC_SUSPICIOUS_FLOOR` |
| `backend/models/vip_identity.py` | **NEW** — admin-configurable VIP/protected-identity table |
| `backend/services/analysis_service.py` | Wired BEC signals after behavioral block; passes `bec_result` to `compute_score()`; saves 6 BEC columns |
| `backend/services/scoring_service.py` | Added `bec_result` param, 2× BEC weight in combined score, `BEC_SUSPICIOUS_FLOOR` verdict floor |
| `backend/models/analysis.py` | `bec_score`, `bec_reasons`, `sig_vip_impersonation`, `sig_financial_request`, `sig_vendor_fraud`, `sig_authority_pressure` columns |
| `backend/routes/analyses.py` | BEC fields mapped in `_to_detail()` |
| `shared/schemas.py` | BEC fields in `EmailDetail` |
| `migrations/versions/g4b5c6d7e8f9_phase3_bec_detection.py` | **NEW** — Alembic migration; creates `vip_identities` table and adds 6 BEC columns to `email_analyses` |
| `frontend/views/report_page.py` | **NEW** `_card_bec` / `_lbl_bec` widget added to Overview tab |
| `frontend/views/_report_display.py` | **NEW** `_populate_bec()` wired into `populate()` dispatcher |
| `README.md` | Phase 3 BEC section added |
| `.env.example` | `BEC_SUSPICIOUS_FLOOR` and `BEC_FINANCIAL_MAX_PTS` added |
| `tests/test_phase3_bec.py` | **NEW** — 84 tests |

#### What Phase 3 built

**Signal 1 — vip_impersonation** (`_check_vip_impersonation`):
- Loads the `vip_identities` table (admin-populated DB table, not hardcoded).
- Fires when the From display name matches a VIP's name but the sending domain ≠ protected_domain.
- Also fires on exact bare-address spoofing (protected_email match from wrong domain).
- Subdomain of protected_domain is explicitly allowed (no false positive for mail.corp.com).
- Default weight: **4 pts**.

**Signal 2 — financial_request_language** (`_check_financial_request_language`):
- Five keyword-pattern categories: `wire_transfer`, `bank_detail_change`, `urgency_authority`,
  `gift_card`, `invoice_redirect`.
- Each firing category adds `_PTS_FINANCIAL_PER_CATEGORY` (default 2) up to `BEC_FINANCIAL_MAX_PTS` (default 6).
- Case-insensitive, pre-compiled regex — zero regex compilation overhead at runtime.
- ⚠️ **Known false-positive risk** — legitimate finance emails trigger this. See module docstring
  for mitigation guidance (keep the VIP list accurate).

**Signal 3 — vendor_fraud_pattern** (`_check_vendor_fraud_pattern`):
- Bank-detail-change language (financial_fired=True) + sender unknown in `sender_history`.
- In-Reply-To tiebreaker: if In-Reply-To matches a known thread message_id, suppresses the signal.
- Cold-start guard: if the recipient has no prior history at all, returns neutral (False).
- Default weight: **3 pts**.

**Signal 4 — authority_pressure_combo** (`_check_authority_pressure_combo`):
- Fires when `financial_request_language` AND at least one identity signal co-occur:
  `vip_impersonation` or `first_time_sender` (Phase 2 flag, passed in from `behavioral_result_obj`).
- Additive — on top of the individual signals, not instead of them.
- Default weight: **3 pts**.

**Scoring formula (combined_score)**:
```
combined_score = static_score + dynamic_score + (bec_score × 2) + behavioral_score
```
Verdict thresholds: ≥ 9 → phishing, ≥ 5 → suspicious, < 5 → benign.

`BEC_SUSPICIOUS_FLOOR` (default 4, env-overridable): if `bec_score ≥ floor` and the formula
would produce "benign", the verdict is forced to "suspicious".  Handles zero-content BEC emails.

---

## What comes next — Phase 4 (formerly Phase 3)

### Phase 4 — Dynamic enrichment background updates

The current design returns the static verdict immediately and runs all enrichment in the same
pipeline task. Phase 4 decouples them:

- Static verdict returned immediately (already done)
- Enrichment (VT, AbuseIPDB, Shodan, urlscan, sandbox) fires as a **separate** background task
- Frontend polls and shows a per-provider "Enriching…" state
- Results update the analysis row when each provider completes

The `re_enrich` endpoint already exists. The gap is per-provider status tracking in the UI and a
background-task trigger on upload rather than inline enrichment.

**Entry point for the next session:**

```
1. Read: backend/services/analysis_service.py  (pipeline orchestrator — understand current flow)
2. Read: backend/app_factory.py  (lifespan, background task patterns)
3. Read: frontend/views/  (understand how the UI currently polls status)
4. Design: per-provider status fields or a separate enrichment_status table
5. Implement: background-task trigger on upload; static verdict returned first
6. Implement: frontend per-provider "Enriching…" state (spinner per provider)
7. Tests: mock background task execution, verify status transitions
```

---

## How to run tests

```bash
cd Phish-analyzer
pip install pytest pytest-asyncio
pytest tests/ -v
```

Expected: **227 passed** (37 Phase 0 + 47 Phase 1 + 59 Phase 2 + 84 Phase 3)

## How to run the app

```bash
cd Phish-analyzer
python launcher.py
```

Backend starts on `http://127.0.0.1:8756`. Opens Qt window automatically.

## Key architectural constraints (must be respected in all future phases)

1. **Local-first** — no new mandatory cloud dependency, no telemetry
2. **Async external calls** — all new API calls must be `async` (httpx/aiohttp), non-blocking
3. **Response caching** — every external API response cached with configurable TTL (now implemented via SQLite-backed `enrichment_cache`)
4. **Feature-flagged** — all new integrations optional via config; tool works with zero new API keys
5. **Unit tests with mocked HTTP** — no real network calls in tests
6. **README + `.env.example` updated** for every new setting or API key
7. **`routes/analyses.py` `_to_detail()` must be updated** whenever new DB columns are added to `EmailAnalysis` — this was missed in Phase 1 initial delivery and caught in review
