# Phish Analyzer Desktop

A local, single-user desktop app for analyzing `.eml` files for phishing indicators (SPF/DKIM/DMARC,
header mismatches, suspicious URLs/attachments, VirusTotal + AbuseIPDB enrichment) and viewing a
generated report. PySide6 UI talking to an in-process FastAPI/SQLite backend over `127.0.0.1` only.

The original single-file CLI (`main.py`, `config.yaml`) is still present for reference — the desktop
app is a full port of its logic, not a wrapper around it.

## Project layout

```
backend/     FastAPI app: routes -> services -> repositories -> models (SQLAlchemy async + SQLite)
frontend/    PySide6 app: controllers -> views/widgets/dialogs, Qt models for the analyses table
shared/      Pydantic schemas + app-data path resolution used by both sides
migrations/  Alembic migrations
assets/      QSS themes, icons (bundled into the packaged app)
launcher.py  Entrypoint: starts the backend in-process, then the Qt UI
```

## Setup (development)

Requires Python 3.11 or 3.12 for the frontend (see "Packaging" below for why). Backend-only work is
fine on newer interpreters.

```bash
python -m venv .venv
source .venv/bin/activate        # .venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env             # optional: seed VT/AbuseIPDB keys for first run
```

## Running

```bash
python launcher.py
```

This starts the FastAPI backend on a background thread (default `http://127.0.0.1:8756`, falls back
to an OS-assigned free port if that one is busy), waits for `/health`, then opens the PySide6 window.
The backend shuts down automatically when the window closes.

Two pages: **Upload** (drag-and-drop or browse for a `.eml` file, plus the searchable/sortable
history of past analyses) and **Report** (full analysis detail, DOCX export, delete). Settings
(API keys, scoring weights) are a toolbar-triggered dialog, not a separate page.

The SQLite database, uploaded `.eml` originals, and logs live in the OS per-user app-data directory
(e.g. `%LOCALAPPDATA%\PhishAnalyzer\PhishAnalyzerDesktop` on Windows), never next to the app itself.

## Running the backend alone

Useful for API testing without the desktop UI:

```bash
uvicorn backend.app_factory:create_app --factory --host 127.0.0.1 --port 8756
```

Docs at `http://127.0.0.1:8756/docs`.

## Database migrations

Migrations run automatically at every startup (`alembic upgrade head`, invoked from code — never a
manual step). To generate a new migration after changing a model in `backend/models/`:

```bash
alembic revision --autogenerate -m "describe the change"
```

## Packaging (Windows `.exe`)

**Option A — CI (no Windows machine needed):** push to `main` (or run it manually from the Actions
tab) and `.github/workflows/build-windows.yml` builds on a hosted `windows-latest` runner, then
uploads `PhishAnalyzerDesktop-windows` as a downloadable artifact from the workflow run.

**Option B — locally on Windows:**

```bash
pyinstaller phish_analyzer.spec
```

Produces a `dist/PhishAnalyzerDesktop/` onedir build (not `--onefile` — onefile re-extracts on every
launch and is a common Defender/SmartScreen false-positive trigger; wrap the onedir output with an
Inno Setup installer if a single double-clickable file is required).

**Build this on Windows, from a Python 3.11 or 3.12 virtualenv.** PySide6/PyInstaller wheel
availability varies a lot by interpreter version; 3.11/3.12 is the safest bet at time of writing.
Verify on a clean Windows VM that the app starts with no console flash and that data persists in
`%LOCALAPPDATA%` across restarts — PyInstaller-frozen Qt apps occasionally fail to locate the
`qwindows.dll` platform plugin, which only shows up on a machine without a separate Qt install.

## Security note

`config.yaml` (used only by the legacy `main.py` CLI) is committed to git with what look like real
VirusTotal/AbuseIPDB API keys. Rotate those keys — they're in git history regardless of this
refactor. The desktop app never uses `config.yaml`; its secrets live in `.env` (first-run seed only,
gitignored) and are edited live through the Settings dialog thereafter.
