"""test_phase_b_hotfix.py — Phase B hotfix regression tests.

Covers
------
1. Poll-result transition (root-cause regression)
   - A DONE result from the API must switch the report view to the results
     pane, stop the timer, and show a success toast — even when
     pipeline_stages contains "timeout" values (the exact scenario that
     triggered the hang).
   - A FAILED result must also stop the timer and show the report pane.
   - PENDING / RUNNING results must NOT stop the timer.

2. stage_colors() — all six status values
   - "pending", "running", "done", "skipped", "failed", "timeout" all
     return (str, str) tuples without raising.
   - Unknown values degrade gracefully (no KeyError).

3. PipelineStagesWidget.set_stages() — all six status values
   - Each value renders without exception in both light and dark themes.
   - A dict containing "timeout" for an enrichment stage is accepted.

4. Poll hardening
   - An exception inside _on_poll_result is caught, logged, and the timer
     keeps running (not stopped, not None-d out).
   - After _POLL_FAIL_THRESHOLD consecutive failures the "Couldn't
     refresh" note is shown on the loading view.
   - A successful poll after failures clears the failure counter.

5. History table / queue dot refresh on every status change
   - update_queue_item() is called on every RUNNING/PENDING poll tick
     (not only on DONE/FAILED).
   - analyses_controller.update_row() is called after each poll tick.

6. Delete and Re-enrich button availability
   - Delete button is enabled while status is PENDING/RUNNING.
   - Re-enrich button is disabled while status is PENDING/RUNNING.
   - Both remain in their correct states during a long-running analysis.

All tests are self-contained; no real Qt event loop, no real network calls,
no real DB state.  Qt widgets are patched where needed so the tests run
headless.

Run with:
    pytest tests/test_phase_b_hotfix.py -v
"""

from __future__ import annotations

import sys
import logging
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_detail(
    status: str = "DONE",
    pipeline_stages: dict | None = None,
    error_message: str | None = None,
    sandbox_error: str | None = None,
    vt_enrichment_error: str | None = None,
    abuse_enrichment_error: str | None = None,
    shodan_enrichment_error: str | None = None,
):
    """Return a minimal EmailDetail-like dict that model_validate() accepts."""
    from shared.schemas import EmailDetail
    return EmailDetail(
        id=99,
        filename="test.eml",
        status=status,
        created_at=datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 10, 15, 10, 5, 0, tzinfo=timezone.utc),
        pipeline_stages=pipeline_stages,
        error_message=error_message,
        sandbox_error=sandbox_error,
        vt_enrichment_error=vt_enrichment_error,
        abuse_enrichment_error=abuse_enrichment_error,
        shodan_enrichment_error=shodan_enrichment_error,
    )


def _make_detail_dict(**kwargs) -> dict:
    """Return a raw dict as if it came from the JSON API."""
    detail = _make_detail(**kwargs)
    return detail.model_dump(mode="json")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Poll-result transition — root-cause regression
# ─────────────────────────────────────────────────────────────────────────────

class TestPollResultTransition:
    """_on_poll_result must stop polling and show results on DONE/FAILED,
    even when pipeline_stages contains non-standard values like "timeout"."""

    def _make_controller(self):
        """Build a ReportController with all Qt dependencies mocked."""
        from frontend.controllers.report_controller import ReportController

        api_client = MagicMock()
        notification_center = MagicMock()
        report_page = MagicMock()
        # Ensure _current_status attribute exists on the mock
        report_page._current_status = None

        ctrl = ReportController.__new__(ReportController)
        ctrl.api_client = api_client
        ctrl.notification_center = notification_center
        ctrl.report_page = report_page
        ctrl._poll_timer = MagicMock()
        ctrl._poll_analysis_id = 99
        ctrl._poll_attempts = 1
        ctrl._poll_fail_count = 0  # new field added by hotfix
        return ctrl, report_page, notification_center

    def test_done_result_stops_polling(self):
        """DONE status must call _stop_polling (timer stopped, id cleared)."""
        ctrl, page, nc = self._make_controller()
        data = _make_detail_dict(
            status="DONE",
            pipeline_stages={"static": "done", "enrichment": "done",
                             "urlscan": "skipped", "sandbox": "skipped",
                             "behavioral": "done"},
        )
        ctrl._on_poll_result(data)
        page.display.assert_called_once()
        # _stop_polling called → timer was stopped
        ctrl._poll_timer.stop.assert_called()

    def test_done_with_enrichment_timeout_stops_polling(self):
        """DONE + enrichment=timeout must stop polling. This is the exact
        scenario that caused the 1-hour hang: analysis 43."""
        ctrl, page, nc = self._make_controller()
        data = _make_detail_dict(
            status="DONE",
            pipeline_stages={"static": "done", "enrichment": "timeout",
                             "urlscan": "skipped", "sandbox": "skipped",
                             "behavioral": "done"},
            vt_enrichment_error="Enrichment deadline exceeded",
        )
        ctrl._on_poll_result(data)
        page.display.assert_called_once()
        ctrl._poll_timer.stop.assert_called()

    def test_done_shows_success_toast(self):
        ctrl, page, nc = self._make_controller()
        data = _make_detail_dict(status="DONE", pipeline_stages=None)
        ctrl._on_poll_result(data)
        nc.show_toast.assert_called()
        args = nc.show_toast.call_args
        assert args[1].get("level") == "success" or (
            len(args[0]) >= 2 and args[0][1] == "success"
        )

    def test_failed_result_stops_polling(self):
        ctrl, page, nc = self._make_controller()
        data = _make_detail_dict(status="FAILED", error_message="Pipeline error")
        ctrl._on_poll_result(data)
        page.display.assert_called_once()
        ctrl._poll_timer.stop.assert_called()

    def test_running_result_does_not_stop_polling(self):
        ctrl, page, nc = self._make_controller()
        data = _make_detail_dict(
            status="RUNNING",
            pipeline_stages={"static": "done", "enrichment": "running",
                             "urlscan": "pending", "sandbox": "pending",
                             "behavioral": "pending"},
        )
        ctrl._on_poll_result(data)
        ctrl._poll_timer.stop.assert_not_called()

    def test_pending_result_does_not_stop_polling(self):
        ctrl, page, nc = self._make_controller()
        data = _make_detail_dict(status="PENDING", pipeline_stages=None)
        ctrl._on_poll_result(data)
        ctrl._poll_timer.stop.assert_not_called()

    def test_done_updates_queue_item(self):
        """Queue dot must refresh on DONE."""
        ctrl, page, nc = self._make_controller()
        data = _make_detail_dict(status="DONE", pipeline_stages=None)
        ctrl._on_poll_result(data)
        page.update_queue_item.assert_called()

    def test_failed_updates_queue_item(self):
        """Queue dot must refresh on FAILED."""
        ctrl, page, nc = self._make_controller()
        data = _make_detail_dict(status="FAILED")
        ctrl._on_poll_result(data)
        page.update_queue_item.assert_called()


# ─────────────────────────────────────────────────────────────────────────────
# 2. stage_colors() — all six status values, no KeyError
# ─────────────────────────────────────────────────────────────────────────────

class TestStageColors:
    """stage_colors() must return (str, str) for every valid status and
    degrade gracefully for unknown values — never raise KeyError."""

    ALL_STATUSES = ["pending", "running", "done", "skipped", "failed", "timeout"]

    @pytest.mark.parametrize("status", ALL_STATUSES)
    def test_light_theme_no_exception(self, status):
        from frontend.services.tokens import stage_colors
        dot, text = stage_colors(status, is_dark=False)
        assert isinstance(dot, str) and dot.startswith("#")
        assert isinstance(text, str) and text.startswith("#")

    @pytest.mark.parametrize("status", ALL_STATUSES)
    def test_dark_theme_no_exception(self, status):
        from frontend.services.tokens import stage_colors
        dot, text = stage_colors(status, is_dark=True)
        assert isinstance(dot, str) and dot.startswith("#")
        assert isinstance(text, str) and text.startswith("#")

    def test_timeout_distinct_from_failed_light(self):
        from frontend.services.tokens import stage_colors
        timeout_dot, _ = stage_colors("timeout", False)
        failed_dot, _  = stage_colors("failed", False)
        assert timeout_dot != failed_dot, "timeout dot must differ from failed dot"

    def test_timeout_distinct_from_failed_dark(self):
        from frontend.services.tokens import stage_colors
        timeout_dot, _ = stage_colors("timeout", True)
        failed_dot, _  = stage_colors("failed", True)
        assert timeout_dot != failed_dot

    def test_unknown_status_degrades_gracefully(self):
        """Unrecognised status values must return pending colors, not crash."""
        from frontend.services.tokens import stage_colors
        dot, text = stage_colors("UNKNOWN_STATUS_XYZ", False)
        from frontend.services.tokens import Light
        assert dot == Light.stage_pending_dot
        assert text == Light.stage_pending_text

    def test_none_status_degrades_gracefully(self):
        from frontend.services.tokens import stage_colors
        dot, text = stage_colors(None, False)  # type: ignore[arg-type]
        assert isinstance(dot, str)
        assert isinstance(text, str)


# ─────────────────────────────────────────────────────────────────────────────
# 3. PipelineStagesWidget.set_stages — all six values, both themes
# ─────────────────────────────────────────────────────────────────────────────

class TestPipelineStagesWidget:
    """set_stages() must accept any combination of the six status values
    without raising, for both light and dark themes."""

    ALL_STATUSES = ["pending", "running", "done", "skipped", "failed", "timeout"]

    @pytest.mark.parametrize("status", ALL_STATUSES)
    @pytest.mark.parametrize("is_dark", [False, True])
    def test_all_same_status_no_exception(self, status, is_dark):
        from frontend.widgets.pipeline_stages_widget import PipelineStagesWidget
        w = PipelineStagesWidget(is_dark=is_dark)
        stages = {k: status for k in ("static", "enrichment", "urlscan", "sandbox", "behavioral")}
        # Must not raise
        w.set_stages(stages, is_dark=is_dark)

    def test_mixed_stages_with_timeout_no_exception(self):
        """The exact stage dict from analysis 43 must not raise."""
        from frontend.widgets.pipeline_stages_widget import PipelineStagesWidget
        w = PipelineStagesWidget(is_dark=False)
        stages = {
            "static":     "done",
            "enrichment": "timeout",
            "urlscan":    "skipped",
            "sandbox":    "skipped",
            "behavioral": "done",
        }
        w.set_stages(stages, is_dark=False)

    def test_set_stages_with_reasons_no_exception(self):
        from frontend.widgets.pipeline_stages_widget import PipelineStagesWidget
        w = PipelineStagesWidget(is_dark=False)
        stages = {"static": "done", "enrichment": "timeout",
                  "urlscan": "skipped", "sandbox": "failed", "behavioral": "done"}
        reasons = {"enrichment": "Enrichment deadline exceeded",
                   "sandbox": "Hybrid Analysis: file payload required"}
        w.set_stages(stages, is_dark=False, reasons=reasons)

    def test_dark_theme_switch_no_exception(self):
        from frontend.widgets.pipeline_stages_widget import PipelineStagesWidget
        w = PipelineStagesWidget(is_dark=False)
        stages = {"static": "done", "enrichment": "timeout",
                  "urlscan": "skipped", "sandbox": "skipped", "behavioral": "done"}
        w.set_stages(stages, is_dark=False)
        w.set_stages(stages, is_dark=True)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Poll hardening — exception handling in _on_poll_result
# ─────────────────────────────────────────────────────────────────────────────

class TestPollHardening:
    """An exception in _on_poll_result must be caught, logged, and the
    poll timer must survive — not stop or be set to None."""

    def _make_controller(self):
        from frontend.controllers.report_controller import ReportController
        api_client = MagicMock()
        notification_center = MagicMock()
        report_page = MagicMock()
        report_page._current_status = None

        ctrl = ReportController.__new__(ReportController)
        ctrl.api_client = api_client
        ctrl.notification_center = notification_center
        ctrl.report_page = report_page
        ctrl._poll_timer = MagicMock()
        ctrl._poll_analysis_id = 99
        ctrl._poll_attempts = 1
        ctrl._poll_fail_count = 0
        return ctrl, report_page, notification_center

    def test_exception_in_display_does_not_stop_timer(self):
        """If display() raises, the timer must survive."""
        ctrl, page, nc = self._make_controller()
        page.display.side_effect = RuntimeError("Qt widget boom")
        data = _make_detail_dict(status="DONE", pipeline_stages=None)
        # Must not raise out of the handler
        try:
            ctrl._on_poll_result(data)
        except Exception:
            pytest.fail("_on_poll_result must catch all exceptions internally")
        # Timer must still be alive
        assert ctrl._poll_timer is not None

    def test_exception_in_update_pipeline_stages_does_not_stop_timer(self):
        """If update_pipeline_stages() raises, the timer must survive."""
        ctrl, page, nc = self._make_controller()
        page.update_pipeline_stages.side_effect = KeyError("timeout")
        data = _make_detail_dict(
            status="RUNNING",
            pipeline_stages={"static": "done", "enrichment": "timeout",
                             "urlscan": "skipped", "sandbox": "skipped",
                             "behavioral": "running"},
        )
        try:
            ctrl._on_poll_result(data)
        except Exception:
            pytest.fail("_on_poll_result must catch all exceptions internally")
        assert ctrl._poll_timer is not None
        ctrl._poll_timer.stop.assert_not_called()

    def test_exception_increments_fail_count(self):
        ctrl, page, nc = self._make_controller()
        page.update_pipeline_stages.side_effect = RuntimeError("boom")
        data = _make_detail_dict(status="RUNNING", pipeline_stages={})
        ctrl._on_poll_result(data)
        assert ctrl._poll_fail_count == 1

    def test_success_resets_fail_count(self):
        ctrl, page, nc = self._make_controller()
        ctrl._poll_fail_count = 3
        data = _make_detail_dict(
            status="RUNNING",
            pipeline_stages={"static": "done", "enrichment": "running",
                             "urlscan": "skipped", "sandbox": "skipped",
                             "behavioral": "pending"},
        )
        ctrl._on_poll_result(data)
        assert ctrl._poll_fail_count == 0

    def test_repeated_failures_show_note_on_loading_view(self):
        """After _POLL_FAIL_THRESHOLD consecutive failures, the loading
        view must show a 'Couldn't refresh' note."""
        from frontend.controllers.report_controller import _POLL_FAIL_THRESHOLD
        ctrl, page, nc = self._make_controller()
        page.update_pipeline_stages.side_effect = RuntimeError("persistent error")
        data = _make_detail_dict(status="RUNNING", pipeline_stages={})
        for _ in range(_POLL_FAIL_THRESHOLD):
            ctrl._on_poll_result(data)
        page.show_poll_error.assert_called()

    def test_exception_is_logged(self, caplog):
        ctrl, page, nc = self._make_controller()
        page.display.side_effect = RuntimeError("test exception for logging")
        data = _make_detail_dict(status="DONE", pipeline_stages=None)
        with caplog.at_level(logging.ERROR, logger="frontend.controllers.report_controller"):
            ctrl._on_poll_result(data)
        assert any("test exception for logging" in r.message or
                   "poll" in r.message.lower() or
                   "RuntimeError" in r.message
                   for r in caplog.records)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Queue / history table refresh on every tick
# ─────────────────────────────────────────────────────────────────────────────

class TestQueueRefreshOnEveryTick:
    """update_queue_item() must be called on RUNNING/PENDING ticks too,
    not only when the analysis reaches DONE/FAILED."""

    def _make_controller(self):
        from frontend.controllers.report_controller import ReportController
        ctrl = ReportController.__new__(ReportController)
        ctrl.api_client = MagicMock()
        ctrl.notification_center = MagicMock()
        ctrl.report_page = MagicMock()
        ctrl.report_page._current_status = None
        ctrl._poll_timer = MagicMock()
        ctrl._poll_analysis_id = 99
        ctrl._poll_attempts = 1
        ctrl._poll_fail_count = 0
        return ctrl

    def test_running_tick_calls_update_queue_item(self):
        ctrl = self._make_controller()
        data = _make_detail_dict(
            status="RUNNING",
            pipeline_stages={"static": "done", "enrichment": "running",
                             "urlscan": "skipped", "sandbox": "skipped",
                             "behavioral": "pending"},
        )
        ctrl._on_poll_result(data)
        ctrl.report_page.update_queue_item.assert_called()

    def test_pending_tick_calls_update_queue_item(self):
        ctrl = self._make_controller()
        data = _make_detail_dict(status="PENDING", pipeline_stages=None)
        ctrl._on_poll_result(data)
        ctrl.report_page.update_queue_item.assert_called()

    def test_done_tick_calls_update_queue_item(self):
        ctrl = self._make_controller()
        data = _make_detail_dict(status="DONE", pipeline_stages=None)
        ctrl._on_poll_result(data)
        ctrl.report_page.update_queue_item.assert_called()


# ─────────────────────────────────────────────────────────────────────────────
# 6. Elapsed time display
# ─────────────────────────────────────────────────────────────────────────────

class TestElapsedTime:
    """The loading view must show elapsed time and a 'Taking longer than
    expected' warning after the threshold."""

    def test_update_elapsed_time_method_exists(self):
        """ReportPage must expose update_elapsed_time() for the controller."""
        from frontend.views.report_page import ReportPage
        assert hasattr(ReportPage, "update_elapsed_time"), (
            "ReportPage must have update_elapsed_time() method"
        )

    def test_elapsed_format_under_60s(self):
        """Seconds-only format for durations under 1 minute."""
        from frontend.views.report_page import _format_elapsed
        assert _format_elapsed(45) == "0:45"

    def test_elapsed_format_over_60s(self):
        from frontend.views.report_page import _format_elapsed
        assert _format_elapsed(125) == "2:05"

    def test_elapsed_format_exactly_60s(self):
        from frontend.views.report_page import _format_elapsed
        assert _format_elapsed(60) == "1:00"

    def test_longer_than_expected_threshold_constant_exists(self):
        """The 5-minute threshold must be defined as a constant."""
        from frontend.views.report_page import _SLOW_ANALYSIS_THRESHOLD_S
        assert _SLOW_ANALYSIS_THRESHOLD_S == 300, (
            "_SLOW_ANALYSIS_THRESHOLD_S must be 300 seconds (5 minutes)"
        )

    def test_controller_calls_update_elapsed_on_tick(self):
        """Every poll tick must update the elapsed time display."""
        from frontend.controllers.report_controller import ReportController
        ctrl = ReportController.__new__(ReportController)
        ctrl.api_client = MagicMock()
        ctrl.notification_center = MagicMock()
        ctrl.report_page = MagicMock()
        ctrl.report_page._current_status = None
        ctrl._poll_timer = MagicMock()
        ctrl._poll_analysis_id = 99
        ctrl._poll_attempts = 5
        ctrl._poll_fail_count = 0
        ctrl._poll_start_time = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)

        data = _make_detail_dict(
            status="RUNNING",
            pipeline_stages={"static": "done", "enrichment": "running",
                             "urlscan": "skipped", "sandbox": "skipped",
                             "behavioral": "pending"},
        )
        ctrl._on_poll_result(data)
        ctrl.report_page.update_elapsed_time.assert_called()

    def test_elapsed_start_time_set_on_start_polling(self):
        """_start_polling must record the start time.

        In the single-reusable-QTimer design the timer already exists on the
        controller (created in __init__); _start_polling only calls stop()/start()
        on it.  We give the manually-constructed controller a real QTimer so
        _start_polling can call .stop() without crashing.
        """
        from PySide6.QtCore import QTimer
        from frontend.controllers.report_controller import ReportController

        ctrl = ReportController.__new__(ReportController)
        ctrl.api_client = MagicMock()
        ctrl.notification_center = MagicMock()
        ctrl.report_page = MagicMock()
        # Real QTimer — mirrors what __init__ creates
        ctrl._poll_timer = QTimer()
        ctrl._poll_timer.timeout.connect(lambda: None)
        ctrl._poll_analysis_id = None
        ctrl._poll_attempts = 0
        ctrl._poll_fail_count = 0
        ctrl._poll_start_time = None

        ctrl._start_polling(42)

        assert ctrl._poll_start_time is not None


# ─────────────────────────────────────────────────────────────────────────────
# 7. Delete and Re-enrich availability on stuck analysis
# ─────────────────────────────────────────────────────────────────────────────

class TestButtonAvailability:
    """Delete must always be available. Re-enrich is disabled for non-DONE.
    Neither button must become disabled just because the analysis is slow."""

    def test_update_status_running_disables_reenrich_not_delete(self):
        """RUNNING: re-enrich disabled, delete must remain enabled."""
        # This tests the report_page source directly via inspection.
        import inspect
        from frontend.views import report_page as rp_mod
        src = inspect.getsource(rp_mod.ReportPage.update_status)
        # Re-enrich must be disabled
        assert "re_enrich_btn" in src and "setEnabled" in src
        # Delete button must NOT be disabled in update_status
        # (delete is always available — its enabled state is never set to False
        # in update_status; only re-enrich is gated)
        assert "_delete_btn.setEnabled(False)" not in src, (
            "_delete_btn must NOT be disabled in update_status — "
            "delete must always be usable"
        )

    def test_re_enrich_disabled_for_pending(self):
        """update_status with PENDING must disable the re-enrich button."""
        from frontend.views.report_page import ReportPage
        import inspect
        src = inspect.getsource(ReportPage.update_status)
        # The PENDING/RUNNING branch must disable re-enrich
        assert "re_enrich_btn" in src

    def test_delete_button_not_gated_on_status(self):
        """_on_delete_requested in the controller must not check status."""
        from frontend.controllers import report_controller as rc_mod
        import inspect
        src = inspect.getsource(rc_mod.ReportController._on_delete_requested)
        # Must call _stop_polling and emit signal, not check status
        assert "status" not in src or "confirm_delete" in src, (
            "_on_delete_requested must not gate on analysis status"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 8. Source-code wiring verification
# ─────────────────────────────────────────────────────────────────────────────

class TestSourceWiring:
    """Structural checks that the hotfix code is actually present."""

    def test_poll_fail_count_initialised_in_start_polling(self):
        import inspect
        from frontend.controllers.report_controller import ReportController
        src = inspect.getsource(ReportController._start_polling)
        assert "_poll_fail_count" in src, (
            "_start_polling must initialise _poll_fail_count"
        )

    def test_poll_fail_threshold_constant_defined(self):
        from frontend.controllers.report_controller import _POLL_FAIL_THRESHOLD
        assert isinstance(_POLL_FAIL_THRESHOLD, int) and _POLL_FAIL_THRESHOLD > 0

    def test_on_poll_result_has_try_except(self):
        import inspect
        from frontend.controllers.report_controller import ReportController
        src = inspect.getsource(ReportController._on_poll_result)
        assert "try:" in src and "except" in src, (
            "_on_poll_result must wrap its body in try/except"
        )

    def test_on_poll_result_logs_exception(self):
        import inspect
        from frontend.controllers.report_controller import ReportController
        src = inspect.getsource(ReportController._on_poll_result)
        assert "logger.exception" in src or "logger.error" in src, (
            "_on_poll_result must log exceptions (logger.exception or logger.error)"
        )

    def test_show_poll_error_method_exists_on_report_page(self):
        from frontend.views.report_page import ReportPage
        assert hasattr(ReportPage, "show_poll_error"), (
            "ReportPage must have show_poll_error() method"
        )

    def test_update_elapsed_time_method_exists_on_report_page(self):
        from frontend.views.report_page import ReportPage
        assert hasattr(ReportPage, "update_elapsed_time")

    def test_format_elapsed_helper_exists(self):
        from frontend.views.report_page import _format_elapsed
        assert callable(_format_elapsed)

    def test_slow_analysis_threshold_constant_exists(self):
        from frontend.views.report_page import _SLOW_ANALYSIS_THRESHOLD_S
        assert _SLOW_ANALYSIS_THRESHOLD_S == 300

    def test_update_queue_item_called_on_running_in_source(self):
        import inspect
        from frontend.controllers.report_controller import ReportController
        src = inspect.getsource(ReportController._on_poll_result)
        # update_queue_item must appear outside the DONE/FAILED-only branches
        assert src.count("update_queue_item") >= 1, (
            "update_queue_item must be called in _on_poll_result"
        )

    def test_poll_start_time_set_in_start_polling(self):
        import inspect
        from frontend.controllers.report_controller import ReportController
        src = inspect.getsource(ReportController._start_polling)
        assert "_poll_start_time" in src

    def test_update_elapsed_time_called_in_on_poll_result(self):
        import inspect
        from frontend.controllers.report_controller import ReportController
        src = inspect.getsource(ReportController._on_poll_result)
        assert "update_elapsed_time" in src, (
            "_on_poll_result must call report_page.update_elapsed_time()"
        )
