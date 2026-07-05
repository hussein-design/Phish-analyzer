# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec for Phish Analyzer Desktop.

Strategy: --onedir (not --onefile).
  onefile re-extracts the whole bundle to a temp dir on every launch — that's
  a slow cold start for a PySide6+FastAPI app and a common Windows Defender /
  SmartScreen false-positive trigger.  Wrap the onedir output with the
  accompanying Inno Setup script (installer.iss) to produce a single
  installable .exe that users download from GitHub Releases.

Build (from a Python 3.11 or 3.12 venv — see README):
    python generate_icon.py   # once, to produce assets/icons/app.ico
    pyinstaller phish_analyzer.spec --noconfirm
Output: dist/PhishAnalyzerDesktop/
"""

from pathlib import Path
import os, sys

project_root = Path(SPECPATH)

_icon_path = project_root / "assets" / "icons" / "app.ico"
icon_file = str(_icon_path) if _icon_path.exists() else None

# Locate the publicsuffixlist package data file at spec-evaluation time so we
# can bundle it.  publicsuffixlist loads it via __file__-relative path, which
# breaks inside a frozen bundle unless we place the .dat next to the module.
import importlib.util as _ilu
_psl_spec = _ilu.find_spec("publicsuffixlist")
_psl_pkg_dir = str(Path(_psl_spec.origin).parent) if _psl_spec else None

a = Analysis(
    ["launcher.py"],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        # Theme QSS files, icons — loaded at runtime from shared.paths.assets_dir()
        (str(project_root / "assets"), "assets"),
        # Alembic migration scripts — run at startup to init/upgrade the DB
        (str(project_root / "migrations"), "migrations"),
        (str(project_root / "alembic.ini"), "."),
        # publicsuffixlist data file — eml_parser loads this via __file__-relative
        # open(); without it the parser crashes with FileNotFoundError on first use.
        *([(_psl_pkg_dir, "publicsuffixlist")] if _psl_pkg_dir else []),
    ],
    hiddenimports=[
        # ── uvicorn ──────────────────────────────────────────────────────────
        # These modules are selected at runtime via string config; PyInstaller's
        # static import scanner never sees them.
        "uvicorn.lifespan.on",
        "uvicorn.lifespan.off",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.http.httptools_impl",
        "uvicorn.protocols.websockets.wsproto_impl",
        "uvicorn.protocols.websockets.websockets_impl",
        "uvicorn.loops.asyncio",
        "uvicorn.logging",

        # ── anyio (async I/O backend used by Starlette/FastAPI) ──────────────
        "anyio",
        "anyio._backends._asyncio",
        "anyio._backends._trio",
        "anyio.abc",
        "anyio.streams.memory",
        "anyio.streams.stapled",
        "anyio.streams.tls",

        # ── FastAPI / Starlette internals ────────────────────────────────────
        "starlette.routing",
        "starlette.middleware",
        "starlette.middleware.base",
        "starlette.middleware.cors",
        "starlette.requests",
        "starlette.responses",
        "starlette.background",
        "starlette.datastructures",
        "starlette.exceptions",
        "starlette.types",
        "starlette.concurrency",

        # ── python-multipart (FastAPI file upload) ───────────────────────────
        "multipart",
        "multipart.multipart",

        # ── pydantic v2 ──────────────────────────────────────────────────────
        "pydantic",
        "pydantic.deprecated.class_validators",
        "pydantic.deprecated.config",
        "pydantic.deprecated.tools",
        "pydantic_core",
        "pydantic_settings",

        # ── SQLAlchemy async / aiosqlite ──────────────────────────────────────
        "sqlalchemy.dialects.sqlite",
        "sqlalchemy.ext.asyncio",
        "aiosqlite",

        # ── httpx (used by vt-py async client) ───────────────────────────────
        "httpx",
        "httpx._transports.default",
        "httpx._transports.asgi",

        # ── h11 (HTTP/1.1 implementation used by uvicorn) ────────────────────
        "h11",
        "h11._readers",
        "h11._writers",
        "h11._connection",
        "h11._events",

        # ── email parsing ─────────────────────────────────────────────────────
        "email",
        "email.mime",
        "email.mime.multipart",
        "email.mime.text",
        "eml_parser",
        "eml_parser.decode",
        "eml_parser.parser",
        "eml_parser.regexes",
        "eml_parser.routing",
        "bs4",
        # publicsuffixlist — eml_parser imports this at runtime; the .dat data
        # file is bundled via the datas entry above.
        "publicsuffixlist",

        # ── python-docx (DOCX report generation) ─────────────────────────────
        "docx",
        "docx.oxml",
        "docx.oxml.ns",

        # ── platformdirs (app-data path resolution) ───────────────────────────
        "platformdirs",

        # ── requests (health-check polling in launcher.py) ────────────────────
        "requests",
        "requests.adapters",
        "requests.auth",
        "requests.packages",

        # ── vt-py (VirusTotal async client) ───────────────────────────────────
        "vt",
        "vt.client",
        "vt.feed",
        "vt.iterator",
        "vt.object",
        "vt.utils",

        # ── misc standard-library modules frequently missed by the scanner ─────
        "logging.handlers",
        "difflib",
        "hashlib",
        "socket",
        "json",
        "re",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Large packages we definitely don't use — keeps the bundle leaner
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "IPython",
        "notebook",
        "PIL",         # Pillow is only used at build time (generate_icon.py)
        "cv2",
        "torch",
        "tensorflow",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PhishAnalyzerDesktop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,     # no console-window flash on double-click
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_file,
    version_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="PhishAnalyzerDesktop",
)
