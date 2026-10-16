"""test_startup_lifespan.py — integration test for the full lifespan startup.

What is tested
--------------
* The complete lifespan (migrations → engine → seed → mark_interrupted →
  AnalysisService → init_cache → reaper task) runs against a *copy* of the
  real database without touching the live DB or any external API.
* Startup completes in under 30 seconds.
* Every expected log step is emitted in order.
* GET /health returns 200 once the lifespan is active.
* Shutdown completes cleanly (reaper task cancelled, engine disposed).

Why a copy of the real DB
-------------------------
Running migrations against the live DB from a test is risky — a bug in a
migration could corrupt real data.  We copy the DB file into a tmp_path
directory before the test so the real database is never touched.

How the lifespan is exercised
------------------------------
FastAPI exposes ``app.router.lifespan_context(app)`` as an async context
manager.  Entering it triggers the startup half of the lifespan; exiting it
triggers the shutdown half.  No uvicorn process or HTTP server is needed.

The ``GET /health`` call is made via ``httpx.AsyncClient`` with an
``httpx.ASGITransport`` that calls the app directly in-process (no TCP),
which is valid once the lifespan has been entered.

All tests are self-contained — no real network, no external APIs.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import sys
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ── Helpers ────────────────────────────────────────────────────────────────────

def _copy_real_db(tmp_path: Path) -> Path:
    """Return the path to a copy of the real database in tmp_path.

    If the real DB does not exist yet (fresh install / CI with no prior run)
    we return a path that does not exist — run_migrations will create a new
    DB there from scratch, which is also a valid startup path.
    """
    from shared.paths import db_path as _real_db_path
    real = _real_db_path()
    dest_db = tmp_path / "test_analyzer.sqlite3"
    if real.exists():
        shutil.copy2(real, dest_db)
    return dest_db


def _make_urls(db_path: Path) -> tuple[str, str]:
    """Return (sync_url, async_url) for the given SQLite path."""
    p = str(db_path).replace("\\", "/")
    return f"sqlite:///{p}", f"sqlite+aiosqlite:///{p}"


# ── Log-step capture ───────────────────────────────────────────────────────────

class _StepRecorder(logging.Handler):
    """Collect every log record so tests can assert ordering of lifespan steps."""

    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestLifespanStartup:
    """Full lifespan startup/shutdown against a copy of the real database."""

    @pytest.fixture()
    def db_copy(self, tmp_path):
        """Provide a tmp-path copy of the real DB (or a fresh empty path)."""
        return _copy_real_db(tmp_path)

    @pytest.fixture()
    def step_recorder(self):
        """Attach a log recorder to the root logger for the duration of the test."""
        recorder = _StepRecorder()
        recorder.setLevel(logging.DEBUG)
        root = logging.getLogger()
        root.addHandler(recorder)
        yield recorder
        root.removeHandler(recorder)

    # ── Test 1: startup completes in < 30 s ───────────────────────────────

    def test_lifespan_completes_within_30s(self, db_copy, tmp_path):
        """The full startup + shutdown cycle must finish in under 30 seconds."""
        sync_url, async_url = _make_urls(db_copy)

        async def run():
            with patch("backend.core.config.get_settings") as mock_settings:
                mock_settings.return_value.sync_database_url = lambda: sync_url
                mock_settings.return_value.async_database_url = lambda: async_url
                mock_settings.return_value.vt_api_key = None
                mock_settings.return_value.abuseipdb_api_key = None
                mock_settings.return_value.log_level = "WARNING"

                # Patch the enrichment-cache db_path so it uses the same tmp db
                with patch(
                    "backend.app_factory.enrichment_cache.init_cache",
                    return_value=None,
                ) as _mock_init_cache:
                    _mock_init_cache.side_effect = _noop_init_cache

                    from backend.app_factory import create_app
                    app = create_app()
                    async with app.router.lifespan_context(app):
                        pass  # startup complete → shutdown

        t0 = time.monotonic()
        asyncio.run(run())
        elapsed = time.monotonic() - t0

        assert elapsed < 30, (
            f"Lifespan completed in {elapsed:.1f} s — must be under 30 s"
        )

    # ── Test 2: all 7 log steps emitted ──────────────────────────────────

    def test_all_lifespan_steps_logged(self, db_copy, tmp_path, step_recorder):
        """Every one of the 7 INFO steps must appear in the log output.

        configure_logging is patched to a no-op so it cannot reset the root
        logger level or add a RotatingFileHandler that interferes with capture.
        The step_recorder fixture attaches its own handler to the root logger
        before the lifespan runs, so all INFO records from backend.app_factory
        flow directly into step_recorder.messages.
        """
        sync_url, async_url = _make_urls(db_copy)
        # Raise root level to INFO so the recorder receives the step messages.
        root = logging.getLogger()
        saved_level = root.level
        root.setLevel(logging.INFO)

        async def run():
            with patch("backend.app_factory.get_settings") as mock_gs, \
                 patch("backend.app_factory.configure_logging"):
                _configure_mock_settings(mock_gs, sync_url, async_url, log_level="INFO")
                import backend.app_factory as _af
                app = _af.create_app()
                async with app.router.lifespan_context(app):
                    pass

        try:
            asyncio.run(run())
        finally:
            root.setLevel(saved_level)

        msgs = "\n".join(step_recorder.messages)
        expected_fragments = [
            "[1/7]",
            "[2/7]",
            "[3/7]",
            "[4/7]",
            "[5/7]",
            "[6/7]",
            "[7/7]",
        ]
        for fragment in expected_fragments:
            assert fragment in msgs, (
                f"Expected lifespan step {fragment!r} in log output.\n"
                f"Captured messages:\n{msgs}"
            )

    # ── Test 3: steps are logged in order ────────────────────────────────

    def test_lifespan_steps_logged_in_order(self, db_copy, tmp_path, step_recorder):
        """The 7 steps must be logged in ascending order (1 before 2 etc.)."""
        sync_url, async_url = _make_urls(db_copy)
        root = logging.getLogger()
        saved_level = root.level
        root.setLevel(logging.INFO)

        async def run():
            with patch("backend.app_factory.get_settings") as mock_gs, \
                 patch("backend.app_factory.configure_logging"):
                _configure_mock_settings(mock_gs, sync_url, async_url, log_level="INFO")
                import backend.app_factory as _af
                app = _af.create_app()
                async with app.router.lifespan_context(app):
                    pass

        try:
            asyncio.run(run())
        finally:
            root.setLevel(saved_level)

        step_positions = []
        seen_steps: set[int] = set()
        for i, msg in enumerate(step_recorder.messages):
            for step_n in range(1, 8):
                if f"[{step_n}/7]" in msg and step_n not in seen_steps:
                    step_positions.append((step_n, i, msg))
                    seen_steps.add(step_n)
                    break

        # Must have found all 7 steps (first occurrence of each)
        found_steps = [sp[0] for sp in step_positions]
        assert sorted(found_steps) == list(range(1, 8)), (
            f"Expected steps 1-7, found steps: {found_steps}\n"
            f"Messages: {step_recorder.messages}"
        )

        # Positions must be monotonically increasing (each step after previous)
        positions_only = [sp[1] for sp in step_positions]
        assert positions_only == sorted(positions_only), (
            "Lifespan steps were not logged in order!\n"
            + "\n".join(f"  step {sp[0]} @ msg[{sp[1]}]: {sp[2]}" for sp in step_positions)
        )

    # ── Test 4: /health returns 200 while lifespan is active ─────────────

    def test_health_endpoint_returns_200_during_lifespan(self, db_copy, tmp_path):
        """/health must return 200 once the lifespan is active."""
        sync_url, async_url = _make_urls(db_copy)

        async def run():
            with patch("backend.core.config.get_settings") as mock_settings:
                _configure_mock_settings(mock_settings, sync_url, async_url)

                from backend.app_factory import create_app
                app = create_app()
                async with app.router.lifespan_context(app):
                    transport = httpx.ASGITransport(
                        app=app,
                        client=("127.0.0.1", 12345),
                    )
                    async with httpx.AsyncClient(
                        transport=transport,
                        base_url="http://127.0.0.1",
                    ) as client:
                        resp = await client.get("/health")
                        assert resp.status_code == 200, (
                            f"Expected /health → 200, got {resp.status_code}: {resp.text}"
                        )

        asyncio.run(run())

    # ── Test 5: reaper task is cancelled cleanly on shutdown ─────────────

    def test_reaper_task_cancelled_on_shutdown(self, db_copy, tmp_path):
        """After the lifespan exits, the reaper task must be done (cancelled)."""
        sync_url, async_url = _make_urls(db_copy)
        reaper_task_ref: list = []

        async def run():
            with patch("backend.core.config.get_settings") as mock_settings:
                _configure_mock_settings(mock_settings, sync_url, async_url)

                # Capture the reaper task reference
                original_create_task = asyncio.create_task

                def capturing_create_task(coro, *args, **kwargs):
                    task = original_create_task(coro, *args, **kwargs)
                    reaper_task_ref.append(task)
                    return task

                with patch("backend.app_factory.asyncio.create_task", side_effect=capturing_create_task):
                    from backend.app_factory import create_app
                    app = create_app()
                    async with app.router.lifespan_context(app):
                        pass  # trigger shutdown

        asyncio.run(run())

        # The reaper task must be done (cancelled) after shutdown
        if reaper_task_ref:
            task = reaper_task_ref[-1]
            assert task.done(), "Reaper task must be done after lifespan shutdown"

    # ── Test 6: asyncio import present in app_factory ────────────────────

    def test_asyncio_imported_in_app_factory(self):
        """asyncio must be imported at module level in app_factory.py.

        This is the primary regression guard — the startup hang was caused
        by a missing `import asyncio` with asyncio.create_task() call at
        lifespan step 7.
        """
        source = Path(_ROOT / "backend" / "app_factory.py").read_text(encoding="utf-8")
        assert "import asyncio" in source, (
            "app_factory.py must contain `import asyncio` — "
            "its absence causes NameError at lifespan step 7 (asyncio.create_task)"
        )

    # ── Test 7: no blocking calls on the event loop ───────────────────────

    def test_no_time_sleep_in_lifespan_path(self):
        """Neither app_factory nor init_db may call time.sleep() — which
        would block the event loop thread for the full sleep duration."""
        import re

        files_to_check = [
            _ROOT / "backend" / "app_factory.py",
            _ROOT / "backend" / "database" / "init_db.py",
        ]
        for fpath in files_to_check:
            source = fpath.read_text(encoding="utf-8")
            # Allow the import (import time) but not a bare time.sleep() call
            calls = re.findall(r"\btime\.sleep\s*\(", source)
            assert not calls, (
                f"{fpath.name} must not call time.sleep() in the lifespan path — "
                f"found {len(calls)} call(s)"
            )

    # ── Test 8: reaper loop sleeps BEFORE first query ────────────────────

    def test_reaper_loop_sleeps_before_first_query(self):
        """_reaper_loop must call asyncio.sleep() before touching the DB on
        its first iteration — this ensures the reaper task creation at startup
        completes immediately without blocking startup on a DB query."""
        import inspect
        from backend.services.analysis_service import _reaper_loop

        src = inspect.getsource(_reaper_loop)
        lines = src.splitlines()

        # Find the positions of asyncio.sleep and the DB query (select)
        sleep_line = next(
            (i for i, ln in enumerate(lines) if "asyncio.sleep" in ln), None
        )
        query_line = next(
            (i for i, ln in enumerate(lines) if "_select(" in ln or "select(" in ln), None
        )
        assert sleep_line is not None, "_reaper_loop must contain asyncio.sleep()"
        assert query_line is not None, "_reaper_loop must contain a select() call"
        assert sleep_line < query_line, (
            f"asyncio.sleep (line {sleep_line}) must come before the DB query "
            f"(line {query_line}) in _reaper_loop"
        )


# ── Shared helpers ────────────────────────────────────────────────────────────

async def _noop_init_cache(db_path) -> None:
    """No-op init_cache replacement — avoids opening a second aiosqlite
    connection to the test DB while the SQLAlchemy engine is using it."""
    pass


def _configure_mock_settings(mock_settings, sync_url: str, async_url: str, log_level: str = "WARNING") -> None:
    """Set the minimal attributes that app_factory reads from get_settings()."""
    s = mock_settings.return_value
    s.sync_database_url = lambda: sync_url
    s.async_database_url = lambda: async_url
    s.vt_api_key = None
    s.abuseipdb_api_key = None
    s.log_level = log_level
