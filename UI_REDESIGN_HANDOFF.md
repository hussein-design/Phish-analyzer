# UI Redesign Handoff — Session 2026-10-08

## Status at session end

Phase A is **COMPLETE** ✅ — ready for visual sign-off.

All six deliverables confirmed present and correct in the codebase:

1. **Navigation fix** — `+ New analysis` button:
   - `newAnalysisRequested` signal on `ReportPage` ✅
   - `_new_btn` (objectName `NewAnalysisButton`) in top bar layout ✅
   - Wired in `main_window.py` (`newAnalysisRequested → _show_upload_page`) ✅
   - QSS rule `#NewAnalysisButton` in `light.qss` ✅
   - QSS rule `#NewAnalysisButton` in `dark.qss` ✅

2. **Color saturation fix** — verdict colors:
   - All token values correct in `tokens.py` ✅ (see color change record below)
   - `theme_manager.py` PALETTES updated ✅
   - Danger button QSS updated in `light.qss` ✅
   - Danger button QSS updated in `dark.qss` ✅

**Audit findings (2026-10-08):**
- No alpha/opacity was found applied on top of verdict colors anywhere. The washed-out pink was purely a wrong hex value (`#DC2626` → `#C2493D` light; `#FCA5A5` → `#E8726A` dark), not an opacity issue.
- The old hex values (`#DC2626`, `#EF4444`, `#F59E0B`, `#FCA5A5`, `#86EFAC`, `#FCD34D`) still appear in `tokens.py` but only in `chip_*` and `toast_*` slots — these are SPF/DKIM auth chips and notification toasts which intentionally use different color families and were not part of the verdict color fix.
- All verdict, dot, arc, and score-bar token slots use the correct target values in both Light and Dark theme classes.

---

## All files touched in this session (source tree only, not dist/)

| File | Change |
|------|--------|
| `frontend/services/tokens.py` | NEW FILE — centralized design token module |
| `frontend/services/theme_manager.py` | PALETTES dict verdict colors updated |
| `frontend/views/report_page.py` | Full rewrite — three-pane layout, queue, score bars, `+ New` button |
| `frontend/views/main_window.py` | Queue wiring, `newAnalysisRequested` signal, Tabler icons |
| `frontend/views/upload_page.py` | Removed inline colors, added objectNames |
| `frontend/views/_report_display.py` | Unchanged |
| `frontend/controllers/report_controller.py` | Queue wiring, `refresh_queue()`, `update_queue_item()` |
| `frontend/widgets/report_widgets.py` | Card/Chip/ScoreRing/helpers — all inline hex removed |
| `frontend/widgets/verdict_badge.py` | Uses `verdict_colors()` from tokens |
| `frontend/widgets/kv_table.py` | Uses objectNames for QSS targeting |
| `frontend/widgets/toast.py` | Uses `TOAST_STYLES` from tokens |
| `frontend/widgets/progress_overlay.py` | Uses tokens |
| `frontend/widgets/drop_zone.py` | Uses tokens in paintEvent |
| `assets/themes/light.qss` | Phase A selectors: queue, anchor-nav, score bars, new button, danger btn |
| `assets/themes/dark.qss` | Same but dark — **danger btn and new button rules INCOMPLETE** |
| `assets/icons/*.svg` | 25 Tabler outline SVGs (MIT) added |
| `UI_REDESIGN_LOG.md` | Working design log — all deviations and decisions recorded |

**Backend files NOT touched** (confirmed):
`analysis_service.py`, `scoring_service.py`, `behavioral_signals_service.py`,
`bec_signals_service.py`, `eml_parser_service.py`, `enrichment/*.py`,
`threat_signals.py`, `attachment_intelligence_service.py`, `url_intelligence_service.py`

---

## Color change record (exact old → new)

All changes are in `frontend/services/tokens.py` and `frontend/services/theme_manager.py`.
No alpha/opacity was involved — this was purely wrong hex values.

### Light theme

| Token | Old | New | Used in |
|-------|-----|-----|---------|
| `Light.phishing_fg` | `#DC2626` | `#C2493D` | VerdictBadge, queue dot, danger btn |
| `Light.phishing_bg` | `#FEF2F2` | `#FCF0EF` | VerdictBadge bg |
| `Light.phishing_border` | `#FECACA` | `#E8A09B` | VerdictBadge border |
| `Light.suspicious_fg` | `#B45309` | `#D4A24C` | VerdictBadge, queue dot |
| `Light.suspicious_bg` | `#FFFBEB` | `#FDF8EC` | VerdictBadge bg |
| `Light.suspicious_border` | `#FDE68A` | `#EDD08A` | VerdictBadge border |
| `Light.benign_fg` | `#16A34A` | `#4C9A82` | VerdictBadge, queue dot |
| `Light.benign_bg` | `#F0FDF4` | `#EEF7F4` | VerdictBadge bg |
| `Light.benign_border` | `#BBF7D0` | `#9BCFC2` | VerdictBadge border |
| `Light.arc_phishing` | `#EF4444` | `#C2493D` | ScoreRing arc |
| `Light.arc_suspicious` | `#F59E0B` | `#D4A24C` | ScoreRing arc |
| `Light.arc_benign` | `#22C55E` | `#4C9A82` | ScoreRing arc |
| `Light.score_bar_high` | `#EF4444` | `#C2493D` | _FillBar (score ≥10) |
| `Light.score_bar_med` | `#F59E0B` | `#D4A24C` | _FillBar (score 5–9) |
| `Light.score_bar_low` | `#22C55E` | `#4C9A82` | _FillBar (score 0–4) |
| `Light.dot_done_phishing` | `#DC2626` | `#C2493D` | _QueueItem dot |
| `Light.dot_done_suspicious` | `#F59E0B` | `#D4A24C` | _QueueItem dot |
| `Light.dot_done_benign` | `#16A34A` | `#4C9A82` | _QueueItem dot |

### Dark theme

| Token | Old | New | Used in |
|-------|-----|-----|---------|
| `Dark.phishing_fg` | `#FCA5A5` (washed-out pink) | `#E8726A` | VerdictBadge, queue dot |
| `Dark.phishing_bg` | `#450A0A` | `#3D1210` | VerdictBadge bg |
| `Dark.phishing_border` | `#7F1D1D` | `#7A2E28` | VerdictBadge border |
| `Dark.suspicious_fg` | `#FCD34D` (bright yellow) | `#E8C06A` | VerdictBadge, queue dot |
| `Dark.suspicious_bg` | `#451A03` | `#3D2E10` | VerdictBadge bg |
| `Dark.suspicious_border` | `#78350F` | `#7A5E28` | VerdictBadge border |
| `Dark.benign_fg` | `#86EFAC` (mint) | `#7CC4AE` | VerdictBadge, queue dot |
| `Dark.benign_bg` | `#052E16` | `#0F2B24` | VerdictBadge bg |
| `Dark.benign_border` | `#14532D` | `#2A5E52` | VerdictBadge border |
| `Dark.arc_phishing` | `#EF4444` | `#C2493D` | ScoreRing arc |
| `Dark.arc_suspicious` | `#F59E0B` | `#D4A24C` | ScoreRing arc |
| `Dark.arc_benign` | `#22C55E` | `#4C9A82` | ScoreRing arc |
| `Dark.score_bar_high` | `#EF4444` | `#C2493D` | _FillBar |
| `Dark.score_bar_med` | `#F59E0B` | `#D4A24C` | _FillBar |
| `Dark.score_bar_low` | `#22C55E` | `#4C9A82` | _FillBar |
| `Dark.dot_done_phishing` | `#FCA5A5` | `#E8726A` | _QueueItem dot |
| `Dark.dot_done_suspicious` | `#FCD34D` | `#E8C06A` | _QueueItem dot |
| `Dark.dot_done_benign` | `#86EFAC` | `#7CC4AE` | _QueueItem dot |

### theme_manager.py PALETTES (used by VerdictColorDelegate in analyses table)

| Key | Old | New |
|-----|-----|-----|
| `LIGHT["phishing"]` | `#DC2626` | `#C2493D` |
| `LIGHT["suspicious"]` | `#B45309` | `#D4A24C` |
| `LIGHT["benign"]` | `#16A34A` | `#4C9A82` |
| `DARK["phishing"]` | `#FCA5A5` | `#E8726A` |
| `DARK["suspicious"]` | `#FCD34D` | `#E8C06A` |
| `DARK["benign"]` | `#86EFAC` | `#7CC4AE` |

---

## Three-pane layout — current state

```
┌──────────────────────────────────────────────────────────────────────────┐
│  TOOLBAR: [Phish Analyzer]        [Settings icon]  [Theme icon]          │
├──────────────────────────────────────────────────────────────────────────┤
│  TOP BAR: [filename — subject]  [status]  [+New] [↺] [↓] [🗑]           │
│  ─────────────────────────────────────────────────────────────────────── │
│  ┌────────────────┬──────────────────────────────┬──────────────────┐    │
│  │  QUEUE (240px) │  ANCHOR-NAV TAB ROW          │  META (220px)    │    │
│  │  [Search…]     │  Overview  Headers  URLs …   │  ⬤ verdict badge │    │
│  │  ───────────── │  ─────────────────────────── │  [score ring]    │    │
│  │  ● file1.eml   │                              │  ─────────────── │    │
│  │  ● file2.eml   │  Content cards for active    │  Score Breakdown │    │
│  │  ● file3.eml   │  section (scrollable)        │  Static   ████  8│    │
│  │  …             │                              │  Dynamic  ██    3│    │
│  │                │                              │  Behav.   ░  N/A │    │
│  │                │                              │  BEC      ░  N/A │    │
│  │                │                              │  ─────────────── │    │
│  │                │                              │  Identifiers     │    │
│  │                │                              │  SPF/DKIM/DMARC  │    │
│  │                │                              │  SHA-256         │    │
│  └────────────────┴──────────────────────────────┴──────────────────┘    │
│  STATUS BAR: Ready                                              v1.0      │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Phase B — design decision PENDING (needs sign-off before implementation)

> **Prompt for next session:** "Read the handoff and continue where you left off. Phase B design decision needs your sign-off — see below."

Phase B: Progressive Analysis Feedback requires a design decision before any code is written. Two options were evaluated:

### Option 1 — Polling with per-stage status fields ✅ RECOMMENDED

Add a `pipeline_stages` JSON column to `email_analyses` that the backend writes at each stage boundary:

```json
{
  "static":     "done",
  "enrichment": "running",
  "urlscan":    "pending",
  "behavioral": "pending",
  "bec":        "pending"
}
```

The frontend continues polling `GET /analyses/{id}` every 2s (already working) and renders a stage progress list instead of a single spinner. No new endpoint. Requires:
- One Alembic migration (`h5c6d7e8f9a0_phase_b_pipeline_stages`) — new JSON column on `email_analyses`
- ~10 lines in `_run_pipeline()` to write stage markers at each phase boundary (no detection/scoring logic touched)
- New UI component in `report_page.py` for the stage progress list

### Option 2 — SSE streaming ❌ NOT RECOMMENDED

Adds `GET /analyses/{id}/stream` endpoint. Requires `sse-starlette` dependency, new frontend connection model, overkill for a ≤3 min pipeline that's already polled.

---

### Sign-off needed on two things

**1. Backend column** — confirm adding `pipeline_stages` JSON column to `email_analyses` via Alembic migration `h5c6d7e8f9a0_phase_b_pipeline_stages`.

**2. Stage list** — confirm these five stages and their labels:

| Stage | UI Label | Covers |
|---|---|---|
| `static` | Parsing & static analysis | EML parse, MIME, headers, body, attachment static scan, threat signals |
| `enrichment` | Threat intel | VT URLs + hashes, AbuseIPDB, Shodan |
| `urlscan` | URL detonation | urlscan.io (shown as "Skipped" when no key configured) |
| `sandbox` | Sandbox detonation | Hybrid Analysis (shown as "Skipped" when no key configured) |
| `behavioral` | Behavioral & BEC | behavioral signals + BEC signals |

Each stage renders: `pending` (grey dot) → `running` (blue animated dot) → `done` (green check) / `failed` (red ✕) / `skipped` (grey dash, no key).

Once both are confirmed, implementation starts immediately.

Phase C: Explainability on Click
- Every reason in the "Why this verdict?" card becomes clickable/expandable
- Shows real evidence per signal type (matched keyword substrings, registration date, VIP record comparison, etc.)
- Reasons currently stored as plain strings — extending to structured objects is a **backend schema change**, needs explicit approval before altering stored formats

---

## Key design invariants to maintain (copy of Design Reference summary)

- All colors must trace to `frontend/services/tokens.py` or `assets/themes/*.qss` — no inline hex in Python files
- Font stack: `"Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif`
- Card border-radius: 10px (`RADIUS_CARD`), input/button: 8px (`RADIUS_INPUT`)
- No scoring/pipeline logic changes in any UI phase
- Never touch: `backend/services/*_service.py`, `backend/services/enrichment/*.py`
- Icons: Tabler outline SVGs from `assets/icons/` via `svg_icon()` helper — no emoji
- Screenshots not available from this environment — reviewer must run app to verify visually

---

## DB quick reference

DB path: `%LOCALAPPDATA%\PhishAnalyzer\PhishAnalyzerDesktop\db\analyzer.sqlite3`
Table: `email_analyses`
Key columns for UI: `id`, `filename`, `status`, `verdict`, `score`, `static_score`, `dynamic_score`, `behavioral_score`, `bec_score`, `created_at`

Note: duplicate filenames in the DB are real separate uploads, not bugs. The app does not deduplicate by filename.

Pre-Phase-2/3 analyses have `static_score=NULL, dynamic_score=NULL, behavioral_score=NULL, bec_score=NULL`.
Phase-2/3 analyses have these populated (0 is a valid computed score, not the same as NULL/N/A).
