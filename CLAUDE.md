# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Two things coexist in this repo:

1. **`main.py`** — the original single-file CLI that analyzes a `.eml` file for phishing indicators
   and writes a console report + `.docx`. Kept for reference; not used by the desktop app.
2. **The desktop app** (`backend/`, `frontend/`, `shared/`, `migrations/`, `launcher.py`) — a full
   port of `main.py`'s logic into a local PySide6 UI talking to an in-process FastAPI/SQLite backend.
   This is the actively developed artifact. See `README.md` for setup/run/packaging commands.

## Running things

- Desktop app: `python launcher.py` (starts the backend on a background thread, then the Qt UI).
- Backend alone: `uvicorn backend.app_factory:create_app --factory --host 127.0.0.1 --port 8756`.
- Legacy CLI: `python main.py path/to/email.eml`.
- No formal test suite. Verify backend changes with `curl`/`httpx` against the sample `.eml` files
  (`phishing_office_1.eml`, `phishing_office_2.eml`); verify frontend changes by running
  `launcher.py` and exercising the upload → report flow, or headlessly with
  `QT_QPA_PLATFORM=offscreen` for scripted Qt smoke tests.
- New migration after changing a model in `backend/models/`: `alembic revision --autogenerate -m "..."`.

## Desktop app architecture

**Two routed pages only** — `UploadPage` (drop zone/browse + the embedded, searchable/sortable
analyses history table) and `ReportPage` (full analysis detail). Settings is a toolbar-triggered
modal dialog, not a third route. Don't add more top-level pages without checking this is still the
intended scope — it was a deliberate simplification from a larger original spec.

**Backend** (`backend/`), layered `routes/ -> services/ -> repositories/ -> models/`:
- `services/eml_parser_service.py` and `report_service.py` are near-verbatim ports of `main.py`'s
  parsing/DOCX functions. `scoring_service.py` started as a port but now goes well beyond the CLI:
  `services/threat_signals.py` adds lookalike/typosquat/combosquat sender-domain detection (leetspeak-
  normalized `difflib` similarity + brand-name substring, not just exact brand-domain mismatch),
  punycode/IDN homograph domains, suspicious TLDs, URL shorteners, and dangerous/double file
  extensions; urgency/pressure language in the body is scanned separately. All of these are
  configurable (weights + lists) via the `app_settings` row / Settings dialog, same as the original
  signals — adding a new signal means: a pure detector function in `threat_signals.py`, a weight in
  `ScoringWeights` (`shared/schemas.py`) + `DEFAULT_SCORING_WEIGHTS` (`backend/core/defaults.py`), the
  scoring block in `compute_score()`, persistence fields on the relevant model + an Alembic migration,
  and the mapper in `routes/analyses.py`.
- `services/analysis_service.py` is the orchestrator: upload returns immediately with a `PENDING` row,
  then an `asyncio.create_task` pipeline updates status to `RUNNING` → `DONE`/`FAILED`. The frontend
  polls `GET /analyses/{id}`. A module-level `_in_flight_tasks` dict keeps task references alive
  (asyncio can GC fire-and-forget tasks otherwise).
- `server.py` runs uvicorn **in a background thread of the same process** (`asyncio.run` inside a
  daemon `Thread`), not a subprocess — a frozen PyInstaller onefile/onedir exe has no reliable
  separate `python.exe` to spawn. The async SQLAlchemy engine is created inside FastAPI's `lifespan`
  startup, not at import time, because `aiosqlite` binds to whichever event loop creates it.
- Secrets/config: `.env` (`backend/core/config.py`, `pydantic-settings`) provides **first-run seed
  values only**. The live, GUI-editable source of truth is the single-row `app_settings` DB table —
  Settings-dialog edits must take effect immediately, which only a DB write gives a desktop app.
- `shared/schemas.py` is the one Pydantic contract used both as FastAPI `response_model`s and for
  frontend response parsing — don't create a parallel duplicate schema layer on either side.

**Frontend** (`frontend/`), MVC in Qt terms:
- Views (`views/`, `widgets/`, `dialogs/`) are pure presentation — they never import `ApiClient`.
- Models (`models/`) are `QAbstractTableModel`/`QSortFilterProxyModel` — no networking; `fetchMore()`
  just emits a signal for the controller to fulfill.
- Controllers (`controllers/`) own a View + `ApiClient`, and are the only place that calls
  `run_async()` (`services/async_worker.py`, `QThreadPool`+`QRunnable`). Never touch a widget from
  inside a worker's `run()` — only from the `succeeded`/`failed` slots Qt marshals back to the GUI
  thread.
- `services/eml_sniff.py` does a cheap client-side `.eml` sniff (first ~8KB) before upload, so a bad
  file fails fast with a toast instead of a backend round trip.
- Theming is QSS files (`assets/themes/{light,dark}.qss`) + `ThemeManager`, not manual `QPalette`
  code, because of custom-painted widgets (verdict badge, drop zone, toast).

**Packaging**: `phish_analyzer.spec`, PyInstaller `--onedir` (not `--onefile` — see README). Must be
built from a Python 3.11/3.12 venv; this repo's default interpreter may be newer than what
PySide6/PyInstaller currently ship wheels for. `.github/workflows/build-windows.yml` builds it on a
hosted `windows-latest` runner (push to `main` or trigger manually) — use this instead of a local
Windows box when one isn't available.

## Known issue

`config.yaml` (legacy CLI only) is committed to git with what look like real VirusTotal/AbuseIPDB API
keys. Rotate them regardless of any refactor — they're in git history. The desktop app never reads
this file.
