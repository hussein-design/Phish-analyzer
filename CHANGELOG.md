# Changelog

All notable changes to Phish Analyzer Desktop are documented here.

---

## [3.0.0] — 2026-10-02

### Summary

Phish Analyzer v3.0 delivers four full development phases on top of the original CLI prototype:
a security and correctness audit, dynamic URL/attachment detonation, behavioral sender-history
analysis, and Business Email Compromise (BEC) detection. The result is a
production-quality local desktop tool that analyses `.eml` files through four independent signal
layers, all configurable and all explainable.

---

### Phase 0 — Audit and Bug Patch

A full code audit found 15 bugs; 13 were fixed before v3.0.

| Bug | Fix |
|-----|-----|
| BUG-01 | IPv6 sender IPs now extracted from Received headers |
| BUG-02 | `parse_eml_bytes()` wraps corrupt input as `InvalidEmlError` instead of a raw parser exception that leaked internal paths |
| BUG-03 | Body `bytes` content decoded correctly — no more `"b'hello'"` strings in scored text |
| BUG-04/05 | Base64-encoded attachment payloads decoded before static analysis and SHA-256 hashing |
| BUG-06 | VirusTotal URL scoring fires once per analysis, not once per matching URL |
| BUG-07 | Legitimate subdomains (e.g. `mail.microsoft.com`) no longer flagged as lookalikes |
| BUG-08 | Relative HTTP redirect URLs resolved correctly via `urllib.parse.urljoin` |
| BUG-10 | OLE2 VBA detection false positives eliminated (removed plain `b"VBA"` byte-match) |
| BUG-12 | VirusTotal `scan_url_async(wait_for_completion=True)` now capped at 120 s via `asyncio.wait_for` |
| BUG-13 | SHA-256 list built after payload decode so base64 attachments receive VT hash enrichment |
| BUG-17 | Auth-result header parsing uses `email.policy.default` (correct RFC 2047 decoding) |
| BUG-18 | `mkdir()`/`write_bytes()` `PermissionError` on Windows returns a clean HTTP 422 |

37 regression tests added (`tests/test_phase0_regression.py`).

---

### Phase 1 — Dynamic Analysis

**New: urlscan.io URL detonation**
- Submits the first safe, public URL from each email to urlscan.io for live detonation
- Parses screenshot URL, full redirect chain, final page title, and urlscan verdict
- Scores: +4 pts malicious, +2 pts suspicious (in `dynamic_score`, not `static_score`)
- 135 s outer pipeline cap (120 s inner scan cap + 15 s grace)
- Returns `status="no_key"` immediately when unconfigured — zero pipeline latency

**New: Hybrid Analysis full behavioral detonation**
- Upgraded from quick-scan to full Windows 10 64-bit sandbox (`/api/v2/submit/file`)
- Polls `/report/{job_id}/summary` for: process names, network contacts, IOCs, verdict, threat score
- Scores: +5 pts malicious, +3 pts suspicious (in `dynamic_score`)
- Falls back to quick-scan if full-submit endpoint returns an error

**New: Static/dynamic score split**
- `compute_score()` now returns `static_score` and `dynamic_score` separately alongside the combined `score`
- Dynamic signals only contribute when provider `status == "done"` — timeout/error/no_key = 0

**New: Persistent enrichment cache**
- Two-layer cache: L1 in-memory (monotonic TTL) + L2 SQLite (`enrichment_cache` table)
- L2 uses wall-clock TTL so entries survive app restarts
- TTLs: VT/AbuseIPDB/Shodan 3 600 s; urlscan/Hybrid Analysis 14 400 s
- Non-fatal DB write failures fall back to L1 in-memory entry

**Security fix (Phase 1 audit)**
- SSRF guard (`_is_safe_for_external_submission`) now applied before submitting URLs to urlscan.io
  and to the sandbox — attacker-controlled email URLs pointing at internal addresses
  (RFC-1918, loopback, metadata services) are now blocked from reaching cloud APIs

47 new tests added (`tests/test_phase1_dynamic_analysis.py`).

---

### Phase 2 — Behavioral Analysis

**New: 5 independent behavioral signals** (`behavioral_signals_service.py`)

| Signal | Description | Default weight |
|--------|-------------|----------------|
| `first_time_sender` | Sender has never contacted this recipient before | 1 pt |
| `domain_age_anomaly` | Sender domain registered within 30 days of send date (RDAP/WHOIS) | 3 pts |
| `display_name_mismatch` | From display name implies a brand the sending domain doesn't belong to | 2 pts |
| `reply_chain_break` | Subject is Re:/Fwd: but sender is not in the known thread history | 3 pts |
| `send_time_anomaly` | Email sent at an hour outside this sender's historical pattern | 1 pt |

**New: Persistent sender/thread history**
- `sender_history` table: per-(recipient, sender) message count and per-hour send distribution
- `thread_history` table: per-(recipient, thread_key) message participation for reply-chain detection
- In-Reply-To tiebreaker on `reply_chain_break`: legitimate continuations suppressed
- History written *after* scoring — current email never inflates its own scores

**New: Domain age lookup**
- RDAP primary (rdap.org → iana.org fallback), WHOIS-over-HTTP secondary
- Cached 30 days (registration dates are immutable facts)
- Fails gracefully on lookup failure — signal returns None (neutral), never inflates score

**New: Behavioral score column**
- `behavioral_score` is a third independent column alongside `static_score` and `dynamic_score`
- Combined formula: `combined = static + dynamic + (bec × 2) + behavioral`
- Individual signal flags surfaced as DB columns for UI and API consumers

59 new tests added (`tests/test_phase2_behavioral_analysis.py`).

---

### Phase 3 — BEC Detection

**New: 4 independent BEC signals** (`bec_signals_service.py`)

| Signal | Description | Default weight |
|--------|-------------|----------------|
| `vip_impersonation` | From display or address matches a VIP identity but sending domain ≠ protected_domain | 4 pts |
| `financial_request_language` | Body matches BEC wire-transfer / bank-detail-change patterns (5 categories) | 2 pts/category, max 6 |
| `vendor_fraud_pattern` | Financial language from a sender unknown to sender_history | 3 pts |
| `authority_pressure_combo` | Financial language + VIP impersonation or first-time sender co-occur | 3 pts (additive) |

**New: VIP identity table**
- `vip_identities` DB table — admin-populated, not hardcoded
- Supports name-based and exact-address-based impersonation detection
- Subdomain of protected_domain is explicitly allowed (no false positive for `mail.corp.com`)

**New: BEC suspicious floor**
- `BEC_SUSPICIOUS_FLOOR` (default 4, env-overridable): if `bec_score ≥ floor` and the
  formula would produce "benign", the verdict is forced to "suspicious"
- Handles zero-content BEC emails where static/dynamic analysis returns near-zero signal

**Scoring formula**
```
combined_score = static_score + dynamic_score + (bec_score × 2) + behavioral_score
```
- Verdict thresholds: ≥ 9 → phishing, ≥ 5 → suspicious, < 5 → benign

84 new tests added (`tests/test_phase3_bec.py`).

---

### Pre-release audit (v3.0 gate)

The following issues were identified and resolved before the v3.0 tag:

**Fixed — SSRF guard not applied (HIGH)**
`_is_safe_for_external_submission()` was defined but not called before submitting URLs to
urlscan.io or the sandbox. Fixed: guard is now applied on both submission paths. Internal
addresses are silently skipped (no error surfaced to the user — they simply receive no
detonation result for that URL).

**Fixed — BEC vendor_fraud tiebreaker comment clarified (LOW)**
`in_reply_to in rows` — `rows` is `result.scalars().all()` which correctly returns
`list[str | None]`. Code logic was correct; added a clarifying comment to prevent future
refactoring confusion.

**Fixed — Version string updated (LOW)**
`FastAPI(version="1.0.0")` updated to `"3.0.0"`.

**Fixed — README build badge placeholder (LOW)**
`your-org` placeholder replaced with `hussein-design/Phish-analyzer`.

**Not fixed — API keys in git history (CRITICAL — action required)**
`virustotal_key` (`d99172f1…`) and `abuseipdb_key` (`8a879574…`) were committed in
`config.yaml` in commit `fac9bed` and remain in git history even though they were cleared
in `fcea474`. **These keys MUST be rotated immediately.** The keys are not in the current
codebase (config.yaml is gitignored and has empty values at HEAD), but anyone with access
to this repository's history can retrieve them.

To rotate:
1. Log in to VirusTotal → API Key settings → regenerate
2. Log in to AbuseIPDB → Account → API → revoke and reissue

Git history rewrite (BFG / `git filter-repo`) is possible but risky for a shared repo —
that decision is left to the repository owner.

**Not fixed — No pyproject.toml (INFORMATIONAL)**
No `pyproject.toml`, `setup.py`, or `__version__.py` exists. Version lives only in
`app_factory.py`. Acceptable for a desktop app distributed as a PyInstaller `.exe`, but
consider adding a `pyproject.toml` with `[project] version = "3.0.0"` if you want
`pip install -e .` to work cleanly.

---

### Test suite

| Phase | Tests | Total |
|-------|-------|-------|
| Phase 0 — regression | 37 | 37 |
| Phase 1 — dynamic analysis | 47 | 84 |
| Phase 2 — behavioral analysis | 59 | 143 |
| Phase 3 — BEC detection | 84 | 227 |

**All 227 tests pass.**

---

## [2.1.0] — (prior release)

UI redesign, re-enrich endpoint, DOCX report polish, ABI/enrichment stability fixes.

## [2.0.0] — (prior release)

Security hardening, structured enrichment status, clear UI feedback.

## [1.0.0] — (initial upload)

Original CLI prototype ported to FastAPI + PySide6 desktop app.
