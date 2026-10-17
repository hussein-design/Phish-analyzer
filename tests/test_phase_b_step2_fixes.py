"""test_phase_b_step2_fixes.py — regression tests for three targeted fixes.

Fix 1 — Poll cap final fetch
  - At _POLL_MAX_ATTEMPTS+1, a final GET is issued via _on_final_poll_result.
  - If the analysis is DONE in the final fetch, it is displayed normally.
  - If the analysis is still PENDING in the final fetch, show_poll_error
    is called with the "Still running" message and no display() call.
  - Polling is stopped regardless of the final fetch result.
  - Re-opening a PENDING/RUNNING analysis (show_analysis) restarts polling.

Fix 2 — Overlay hardening
  - ProgressOverlay.stop() cancels the auto-hide timer.
  - ProgressOverlay.start() arms the auto-hide timer.
  - AUTO_HIDE_S is defined and positive.
  - The outer overlay widget has WA_TransparentForMouseEvents set.
  - The inner card does NOT have WA_TransparentForMouseEvents.
  - UploadPage.showEvent hides the overlay when _uploading is False.
  - UploadPage.showEvent does not hide the overlay when _uploading is True.
  - UploadController._on_upload_finished calls set_uploading(False).
  - set_uploading tracks _uploading state correctly.

Fix 3 — httpx/httpcore logger levels (source check only — no Qt needed)
  - configure_logging sets httpx to WARNING.
  - configure_logging sets httpcore to WARNING.
"""

from __future__ import annotations

import sys
import logging
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_detail(status: str = "DONE", pipeline_stages: dict | None = None):
    from shared.schemas import EmailDetail
    return EmailDetail(
        id=42,
        filename="x.eml",
        status=status,
        created_at=datetime(2026, 10, 16, 10, 0, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 10, 16, 10, 1, 0, tzinfo=timezone.utc),
        pipeline_stages=pipeline_stages,
    )


def _make_detail_dict(**kw) -> dict:
    return _make_detail(**kw).model_dump(mode="json")


def _make_ctrl():
    """ReportController with all Qt deps mocked; no Qt event loop needed.

    _poll_timer is NOT mocked — it is the real QTimer created by __init__,
    which is what we want to exercise.  Tests that previously checked
    ``ctrl._poll_timer.stop.assert_called()`` have been updated to check
    ``ctrl._poll_analysis_id`` instead, which is the canonical "poll active"
    marker.
    """
    from PySide6.QtCore import QTimer
    from frontend.controllers.report_controller import ReportController
    ctrl = ReportController.__new__(ReportController)
    ctrl.api_client = MagicMock()
    ctrl.notification_center = MagicMock()
    ctrl.report_page = MagicMock()
    ctrl.report_page._current_status = None
    # Real QTimer — never mocked, never deleted, reused for every poll session
    ctrl._poll_timer = QTimer()
    ctrl._poll_timer.timeout.connect(lambda: None)  # dummy slot so connect() works
    ctrl._poll_analysis_id = 42
    ctrl._poll_attempts = 0
    ctrl._poll_fail_count = 0
    ctrl._poll_start_time = datetime(2026, 10, 16, 10, 0, 0, tzinfo=timezone.utc)
    return ctrl


# ─────────────────────────────────────────────────────────────────────────────
# Fix 1 — Poll cap final fetch
# ─────────────────────────────────────────────────────────────────────────────

class TestPollCapFinalFetch:
    """At the cap, a final GET fires then polling stops regardless."""

    def test_final_fetch_issued_at_cap(self):
        from frontend.controllers.report_controller import _POLL_MAX_ATTEMPTS
        ctrl = _make_ctrl()
        ctrl._poll_attempts = _POLL_MAX_ATTEMPTS  # next tick is the cap-crossing tick

        calls = []

        def fake_run_async(fn, *args, on_success=None, **kw):
            calls.append(on_success)

        ctrl.run_async = fake_run_async
        ctrl._stop_polling = MagicMock()

        ctrl._poll_tick()

        # _stop_polling must be called
        ctrl._stop_polling.assert_called_once()
        # run_async was called with _on_final_poll_result as on_success
        assert len(calls) == 1
        assert calls[0] == ctrl._on_final_poll_result

    def test_final_fetch_done_displays_result(self):
        ctrl = _make_ctrl()
        data = _make_detail_dict(status="DONE")
        ctrl._on_final_poll_result(data)
        ctrl.report_page.display.assert_called_once()
        ctrl.notification_center.show_toast.assert_called()

    def test_final_fetch_failed_displays_result(self):
        ctrl = _make_ctrl()
        data = _make_detail_dict(status="FAILED")
        ctrl._on_final_poll_result(data)
        ctrl.report_page.display.assert_called_once()

    def test_final_fetch_still_pending_shows_still_running_message(self):
        ctrl = _make_ctrl()
        data = _make_detail_dict(status="PENDING")
        ctrl._on_final_poll_result(data)
        # display must NOT be called — analysis is not done
        ctrl.report_page.display.assert_not_called()
        # show_poll_error must be called with the "Still running" message
        ctrl.report_page.show_poll_error.assert_called_once()
        msg = ctrl.report_page.show_poll_error.call_args[0][0]
        assert "Still running" in msg

    def test_final_fetch_still_running_shows_still_running_message(self):
        ctrl = _make_ctrl()
        data = _make_detail_dict(status="RUNNING")
        ctrl._on_final_poll_result(data)
        ctrl.report_page.display.assert_not_called()
        ctrl.report_page.show_poll_error.assert_called_once()

    def test_final_fetch_still_pending_shows_warning_toast(self):
        ctrl = _make_ctrl()
        data = _make_detail_dict(status="PENDING")
        ctrl._on_final_poll_result(data)
        ctrl.notification_center.show_toast.assert_called_once()
        kw = ctrl.notification_center.show_toast.call_args[1]
        assert kw.get("level") == "warning"

    def test_final_fetch_exception_does_not_propagate(self):
        """A corrupt payload must not raise out of the final handler."""
        ctrl = _make_ctrl()
        ctrl._on_final_poll_result({"bad": "data"})  # schema validation will raise

    def test_normal_tick_below_cap_uses_on_poll_result(self):
        """Below the cap, on_success must be _on_poll_result, not final."""
        ctrl = _make_ctrl()
        ctrl._poll_attempts = 1

        calls = []

        def fake_run_async(fn, *args, on_success=None, **kw):
            calls.append(on_success)

        ctrl.run_async = fake_run_async
        ctrl._poll_tick()

        assert len(calls) == 1
        assert calls[0] == ctrl._on_poll_result

    def test_show_analysis_restarts_polling_after_cap(self):
        """Re-selecting a PENDING analysis re-opens polling via _on_loaded."""
        ctrl = _make_ctrl()
        ctrl._poll_analysis_id = None  # poll was stopped at cap

        start_calls = []
        ctrl._start_polling = lambda aid: start_calls.append(aid)
        ctrl._stop_polling = MagicMock()

        # Simulate _on_loaded receiving PENDING detail
        data = _make_detail_dict(status="PENDING")
        ctrl._on_loaded(data)

        assert start_calls == [42]

    def test_show_analysis_does_not_restart_polling_for_done(self):
        ctrl = _make_ctrl()
        start_calls = []
        ctrl._start_polling = lambda aid: start_calls.append(aid)
        ctrl._stop_polling = MagicMock()

        data = _make_detail_dict(status="DONE")
        ctrl._on_loaded(data)

        assert start_calls == []


# ─────────────────────────────────────────────────────────────────────────────
# Fix 1b — Real QTimer: no crash after repeated start/stop/show cycles
# ─────────────────────────────────────────────────────────────────────────────

class TestRealQTimerNoCrash:
    """Builds a ReportController with a real QTimer and exercises the full
    _start_polling / _stop_polling / show_analysis cycle ten times without
    raising RuntimeError or any other exception.

    This is the regression guard for:
        "RuntimeError: Internal C++ object (QTimer) already deleted"
    which occurred when _stop_polling called deleteLater() and the next
    _start_polling tried to re-use the dangling pointer.
    """

    def _make_real_ctrl(self):
        """ReportController with a real QTimer but mocked everything else."""
        from PySide6.QtCore import QTimer
        from frontend.controllers.report_controller import ReportController

        ctrl = ReportController.__new__(ReportController)
        ctrl.api_client = MagicMock()
        ctrl.notification_center = MagicMock()
        ctrl.report_page = MagicMock()
        ctrl.report_page._current_status = None
        # Real QTimer — same as what __init__ creates
        ctrl._poll_timer = QTimer()
        ctrl._poll_timer.timeout.connect(lambda: None)
        ctrl._poll_analysis_id = None
        ctrl._poll_attempts = 0
        ctrl._poll_fail_count = 0
        ctrl._poll_start_time = None
        return ctrl

    def test_start_stop_ten_times_no_exception(self):
        """_start_polling then _stop_polling ten times must never raise."""
        ctrl = self._make_real_ctrl()
        for i in range(10):
            ctrl._start_polling(i + 1)
            ctrl._stop_polling()
        # If we get here, no RuntimeError was raised.
        assert ctrl._poll_analysis_id is None
        assert not ctrl._poll_timer.isActive()

    def test_show_analysis_then_stop_ten_times_no_exception(self):
        """show_analysis (which calls _stop_polling then run_async) and
        _stop_polling ten times must never raise.

        run_async is intercepted so no real HTTP call is made.
        """
        ctrl = self._make_real_ctrl()

        def fake_run_async(fn, *args, on_success=None, on_error=None, on_finished=None, **kw):
            # Simulate an immediate DONE response so show_analysis resolves cleanly.
            if on_success is not None:
                on_success(_make_detail_dict(status="PENDING"))

        ctrl.run_async = fake_run_async

        for i in range(10):
            ctrl.show_analysis(i + 1)
            ctrl._stop_polling()

        assert ctrl._poll_analysis_id is None

    def test_show_detail_pending_then_show_detail_done_no_exception(self):
        """show_detail with PENDING (starts poll) followed immediately by
        show_detail with DONE (stops poll) ten times — no exception."""
        ctrl = self._make_real_ctrl()

        pending_detail = _make_detail(status="PENDING")
        done_detail = _make_detail(status="DONE")

        for _ in range(10):
            ctrl.show_detail(pending_detail)  # starts poll
            ctrl.show_detail(done_detail)      # stops poll

        assert ctrl._poll_analysis_id is None
        assert not ctrl._poll_timer.isActive()


# ─────────────────────────────────────────────────────────────────────────────
# Fix 2 — Overlay hardening
# ─────────────────────────────────────────────────────────────────────────────

class TestOverlayHardening:
    """ProgressOverlay safety timer and mouse pass-through."""

    def _make_overlay(self):
        """Build a ProgressOverlay with a mocked parent (no Qt event loop)."""
        from frontend.widgets.progress_overlay import ProgressOverlay

        parent = MagicMock()
        parent.rect.return_value = MagicMock(width=MagicMock(return_value=800),
                                              height=MagicMock(return_value=600))

        # Bypass actual Qt widget construction
        ov = ProgressOverlay.__new__(ProgressOverlay)
        ov._auto_hide_timer = MagicMock()
        ov._label = MagicMock()
        ov._card = MagicMock()
        ov._bar = MagicMock()
        return ov

    def test_auto_hide_s_defined_and_positive(self):
        from frontend.widgets.progress_overlay import ProgressOverlay
        assert hasattr(ProgressOverlay, "AUTO_HIDE_S")
        assert ProgressOverlay.AUTO_HIDE_S > 0

    def test_start_arms_auto_hide_timer(self):
        ov = self._make_overlay()
        ov._refresh_styles = MagicMock()
        ov._reposition = MagicMock()
        ov.show = MagicMock()
        ov.raise_ = MagicMock()

        ov.start("Uploading…")

        ov._auto_hide_timer.start.assert_called_once()
        fired_ms = ov._auto_hide_timer.start.call_args[0][0]
        from frontend.widgets.progress_overlay import ProgressOverlay
        assert fired_ms == ProgressOverlay.AUTO_HIDE_S * 1000

    def test_stop_cancels_auto_hide_timer(self):
        ov = self._make_overlay()
        ov.hide = MagicMock()

        ov.stop()

        ov._auto_hide_timer.stop.assert_called_once()
        ov.hide.assert_called_once()

    def test_stop_is_idempotent(self):
        """Calling stop() twice must not raise."""
        ov = self._make_overlay()
        ov.hide = MagicMock()
        ov.stop()
        ov.stop()

    def test_outer_widget_has_mouse_pass_through_in_source(self):
        """WA_TransparentForMouseEvents must be set on the outer widget."""
        src = Path(_ROOT / "frontend" / "widgets" / "progress_overlay.py").read_text(encoding="utf-8")
        assert "WA_TransparentForMouseEvents" in src

    def test_inner_card_does_not_set_mouse_pass_through(self):
        """The _card widget must NOT get WA_TransparentForMouseEvents."""
        src = Path(_ROOT / "frontend" / "widgets" / "progress_overlay.py").read_text(encoding="utf-8")
        # The attribute must appear exactly once (on self, not on self._card)
        lines_with_attr = [l for l in src.splitlines() if "WA_TransparentForMouseEvents" in l]
        # None of those lines may reference _card
        for line in lines_with_attr:
            assert "_card" not in line, (
                f"WA_TransparentForMouseEvents should only be set on self, "
                f"not on _card. Found: {line!r}"
            )


class TestUploadPageOverlayGuard:
    """UploadPage.showEvent hides the overlay when no upload is in flight."""

    def _make_page(self):
        from frontend.views.upload_page import UploadPage
        page = UploadPage.__new__(UploadPage)
        page._overlay = MagicMock()
        page._uploading = False
        return page

    def test_show_event_hides_overlay_when_not_uploading(self):
        page = self._make_page()
        page.showEvent(MagicMock())
        page._overlay.stop.assert_called()

    def test_show_event_does_not_hide_overlay_when_uploading(self):
        page = self._make_page()
        page._uploading = True
        page.showEvent(MagicMock())
        page._overlay.stop.assert_not_called()

    def test_set_uploading_true_sets_flag_and_starts_overlay(self):
        page = self._make_page()
        page._overlay.start = MagicMock()
        page.set_uploading(True, "Uploading…")
        assert page._uploading is True
        page._overlay.start.assert_called_once_with("Uploading…")

    def test_set_uploading_false_clears_flag_and_stops_overlay(self):
        page = self._make_page()
        page._uploading = True
        page.set_uploading(False)
        assert page._uploading is False
        page._overlay.stop.assert_called_once()


class TestUploadControllerFinally:
    """UploadController hides the overlay via on_finished in all paths."""

    def test_on_upload_finished_calls_set_uploading_false(self):
        from frontend.controllers.upload_controller import UploadController
        ctrl = UploadController.__new__(UploadController)
        ctrl.upload_page = MagicMock()
        ctrl._on_upload_finished()
        ctrl.upload_page.set_uploading.assert_called_once_with(False)

    def test_on_finished_wired_to_on_upload_finished(self):
        """_start_upload must pass on_finished=self._on_upload_finished."""
        src = Path(_ROOT / "frontend" / "controllers" / "upload_controller.py").read_text(encoding="utf-8")
        assert "on_finished=self._on_upload_finished" in src


# ─────────────────────────────────────────────────────────────────────────────
# Fix 3 — httpx / httpcore log suppression (source-level check)
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpLoggerSuppression:
    def test_httpx_set_to_warning_in_source(self):
        src = Path(_ROOT / "backend" / "core" / "logging.py").read_text(encoding="utf-8")
        assert '"httpx"' in src or "'httpx'" in src
        assert "WARNING" in src

    def test_httpcore_set_to_warning_in_source(self):
        src = Path(_ROOT / "backend" / "core" / "logging.py").read_text(encoding="utf-8")
        assert '"httpcore"' in src or "'httpcore'" in src

    def test_configure_logging_sets_httpx_to_warning(self):
        """configure_logging() must leave httpx at WARNING or higher."""
        # Reset state so we can call configure_logging cleanly
        httpx_logger = logging.getLogger("httpx")
        original_level = httpx_logger.level
        try:
            with patch("backend.core.logging.log_file_path") as mock_path:
                import tempfile, os
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".log")
                tmp.close()
                mock_path.return_value = Path(tmp.name)
                from backend.core.logging import configure_logging
                configure_logging("INFO")
            assert httpx_logger.level == logging.WARNING
        finally:
            httpx_logger.setLevel(original_level)
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    def test_configure_logging_sets_httpcore_to_warning(self):
        httpcore_logger = logging.getLogger("httpcore")
        original_level = httpcore_logger.level
        try:
            with patch("backend.core.logging.log_file_path") as mock_path:
                import tempfile, os
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".log")
                tmp.close()
                mock_path.return_value = Path(tmp.name)
                from backend.core.logging import configure_logging
                configure_logging("INFO")
            assert httpcore_logger.level == logging.WARNING
        finally:
            httpcore_logger.setLevel(original_level)
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
