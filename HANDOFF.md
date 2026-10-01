# Phish-Analyzer — Development Handoff

**Last commit:** `a5bd875` — `phase-0: audit and bug patch (15 bugs fixed, 37 regression tests)`  
**Branch:** `main`  
**Date:** 2026-10-01

---

## What was completed

### Phase 0 — Audit and Bug Patch ✅

A full audit of the backend codebase was performed. 15 bugs were found and fixed across 7 files.
37 regression tests were added in `tests/test_phase0_regression.py` — all pass.

#### Files changed

| File | Bugs fixed |
|---|---|
| `backend/services/eml_parser_service.py` | BUG-01, BUG-02, BUG-03, BUG-17 |
| `backend/services/analysis_service.py` | BUG-04/05, BUG-13, BUG-18 |
| `backend/services/scoring_service.py` | BUG-06 |
| `backend/services/threat_signals.py` | BUG-07 |
| `backend/services/url_intelligence_service.py` | BUG-08 |
| `backend/services/attachment_intelligence_service.py` | BUG-10 |
| `backend/services/enrichment/virustotal_provider.py` | BUG-12 |
| `tests/test_phase0_regression.py` | *new* — 37 regression tests |
| `README.md` | Phase 0 bug table added |

#### Bugs fixed (summary)

- **BUG-01** IPv6 sender IPs now extracted (AbuseIPDB/Shodan lookups were silently skipped)
- **BUG-02** `parse_eml_bytes()` now raises `InvalidEmlError` on corrupt input instead of leaking internals
- **BUG-03** `bytes` body content now decoded properly (was producing `"b'hello'"` in scored text)
- **BUG-04/05** Base64-encoded attachment payloads are now decoded; previously dropped silently
- **BUG-06** VT URL scoring fires once per analysis, not once per matching URL (score inflation fixed)
- **BUG-07** Legitimate subdomains (`mail.microsoft.com`) no longer flagged as lookalikes
- **BUG-08** Relative HTTP redirects resolved correctly with `urllib.parse.urljoin`
- **BUG-10** OLE2 VBA false positives eliminated (plain `b"VBA"` match removed)
- **BUG-12** VT `scan_url_async` now has a 120s timeout via `asyncio.wait_for`
- **BUG-13** SHA-256 list built after payload decode; base64 attachments now get VT hash enrichment
- **BUG-17** Auth header parsing uses `email.policy.default` (RFC2047 decoding)
- **BUG-18** `mkdir()`/`write_bytes()` `PermissionError` now returns clean 422 instead of 500

#### Not fixed (low severity, documented)
- **BUG-09** Invalid IP strings hit DNS unnecessarily in SSRF guard — harmless, DNS handles gracefully
- **BUG-11** Single-header emails pass `validate_eml_upload()` then fail in pipeline — caught by exception handler, acceptable

#### Dependency check
All pinned versions in `requirements.txt` were verified against PyPI — no phantom versions, no known CVEs.

---

## What comes next — Phase 1 (Dynamic analysis, rule-based behavioral analysis, BEC detection)

The original prompt describes three remaining phases. Here is what each entails:

### Phase 1 — Rule-based behavioral analysis & BEC detection

**Goal:** Detect Business Email Compromise patterns that static header checks miss.

Key things to build:

1. **BEC detection service** (`backend/services/bec_detection_service.py`)
   - Wire-transfer / direct-payment request detection
   - Executive impersonation via display-name spoofing (CEO/CFO name in From display, but domain doesn't match HR records)
   - First-contact detection (sender never seen before in history)
   - Reply-chain injection (email has In-Reply-To but no prior thread in DB)
   - Lookalike free-email domains (`paypal-support@gmail.com` style)

2. **Rule engine** (`backend/services/rule_engine.py`)
   - YAML-configurable rules: `if signal X and signal Y → add Z points + reason`
   - Load from `config.yaml` or settings DB, hot-reloadable
   - Each rule has: `id`, `name`, `conditions`, `score_delta`, `verdict_override`, `enabled` flag
   - Feature-flagged: engine is optional, tool works without it

3. **Scoring integration**
   - `bec_detection_service` results fed into `scoring_service.compute_score()`
   - New scoring weight keys: `bec_wire_transfer`, `bec_exec_impersonation`, `bec_first_contact`, `bec_reply_injection`
   - New DB columns on `EmailAnalysis`: `bec_signals` (JSON list), `bec_score_contribution` (int)

4. **Schema updates** (`shared/schemas.py`)
   - Add `bec_signals: list[dict]` to `EmailDetail`
   - Add `bec_score_contribution: int` to `EmailDetail`

5. **Migration**
   - New Alembic migration for `bec_signals` + `bec_score_contribution` columns

6. **Tests** — unit tests with mocked inputs for every BEC rule

**Entry point for the next session:**

```
Start at: backend/services/  — create bec_detection_service.py
Then:     backend/services/  — create rule_engine.py  
Then:     backend/services/scoring_service.py — integrate new signals
Then:     shared/schemas.py — add BEC fields
Then:     migrations/versions/ — new Alembic migration
Then:     tests/test_phase1_bec.py — unit tests
```

### Phase 2 — Dynamic analysis (sandbox integration) — *already partially done*

The `sandbox_provider.py` (Any.run + Hybrid Analysis) is already implemented in Phase 5 of the
existing code. What's missing for "dynamic analysis" as described in the prompt:

- **URL detonation fallback** — already implemented but needs more robust tracking
- **Behavioral report parsing** — extract process trees, network IOCs, dropped files from sandbox JSON
- **Dynamic verdict integration** — if sandbox says "malicious", boost score regardless of static verdict
- A new `DynamicAnalysisResult` schema and DB columns for behavioral IOCs

### Phase 3 — Dynamic enrichment background updates

The current design returns the static verdict immediately and does enrichment in the same pipeline
task. The prompt asks for a true background-task / callback pattern where:

- Static verdict is returned immediately (already done)
- Enrichment (VT, AbuseIPDB, Shodan, sandbox) fires as a separate background task
- Frontend polls and shows a "Enriching…" state per-provider
- Results update the analysis row when they arrive

The `re_enrich` endpoint already exists — the gap is the per-provider status tracking in the UI.

---

## How to run tests

```bash
cd Phish-analyzer
pip install pytest pytest-asyncio
pytest tests/test_phase0_regression.py -v
```

Expected: **37 passed**

## How to run the app

```bash
cd Phish-analyzer
python launcher.py
```

Backend starts on `http://127.0.0.1:8756`. Opens Qt window automatically.

## Key architectural constraints (from original prompt — must be respected in all future phases)

1. **Local-first** — no new mandatory cloud dependency, no telemetry
2. **Async external calls** — all new API calls must be `async` (httpx/aiohttp), non-blocking
3. **Response caching** — every external API response cached with configurable TTL
4. **Feature-flagged** — all new integrations must be optional via config; tool must work with zero new API keys
5. **Unit tests with mocked HTTP** — no real network calls in tests
6. **README + `.env.example` updated** for every new setting or API key
