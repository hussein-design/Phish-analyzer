# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec.

--onedir, not --onefile: onefile self-extracts the whole bundle to a fresh
temp dir on every launch (slow cold start for a PySide6+FastAPI app) and is
a common Windows Defender/SmartScreen false-positive trigger. If a single
double-clickable deliverable is required, wrap this onedir output with an
Inno Setup installer instead of switching to --onefile.

Build (from a Python 3.11/3.12 venv -- see README for why):
    pyinstaller phish_analyzer.spec
"""

from pathlib import Path

project_root = Path(SPECPATH)

_icon_path = project_root / "assets" / "icons" / "app.ico"
icon_file = str(_icon_path) if _icon_path.exists() else None

a = Analysis(
    ["launcher.py"],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        (str(project_root / "assets"), "assets"),
        (str(project_root / "migrations"), "migrations"),
        (str(project_root / "alembic.ini"), "."),
    ],
    hiddenimports=[
        # uvicorn/FastAPI protocol implementations PyInstaller's static
        # import scan can miss since they're selected dynamically at runtime.
        "uvicorn.lifespan.on",
        "uvicorn.lifespan.off",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.http.httptools_impl",
        "uvicorn.protocols.websockets.wsproto_impl",
        "uvicorn.protocols.websockets.websockets_impl",
        "uvicorn.loops.asyncio",
        "aiosqlite",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    console=False,  # no console window flash on Windows
    icon=icon_file,
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
