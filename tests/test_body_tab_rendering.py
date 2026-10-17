"""Tests for body-tab rendering fixes.

Covers:
  1. A 3-line body retains its line breaks (white-space:pre-wrap).
  2. '<script>' in the body appears as literal text, never executed/hidden.

These tests exercise the _populate_body logic directly via the module function
rather than through the full ReportPage widget, avoiding the need for a running
Qt event loop beyond the QApplication already provided by conftest.py.
"""

from __future__ import annotations

import html
import sys
from pathlib import Path
from unittest.mock import MagicMock

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ─────────────────────────────────────────────────────────────────────────────
# Helper: build a minimal fake page + detail objects
# ─────────────────────────────────────────────────────────────────────────────

def _make_page_and_detail(body_text: str):
    """Return (fake_page, fake_detail) sufficient for _populate_body."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QLabel

    lbl = QLabel()
    lbl.setWordWrap(True)
    # Start in PlainText mode (same as body_label() factory)
    lbl.setTextFormat(Qt.TextFormat.PlainText)

    page = MagicMock()
    page._lbl_body = lbl

    detail = MagicMock()
    detail.body_preview = body_text

    return page, detail


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBodyTabRendering:

    def test_three_line_body_preserves_newlines(self):
        """A 3-line body must retain its line breaks in the rendered HTML.

        _populate_body wraps the escaped text in
        <div style="white-space:pre-wrap">…</div> so the QLabel (in RichText
        mode) renders newlines visually.  We verify this by checking that the
        HTML set on the label contains the escaped newlines (&#10; or the
        literal newline) inside a pre-wrap wrapper.
        """
        from PySide6.QtCore import Qt
        from frontend.views._report_display import _populate_body

        body = "Line 1\nLine 2\nLine 3"
        page, detail = _make_page_and_detail(body)
        _populate_body(page, detail)

        lbl = page._lbl_body
        # After _populate_body the label must be in RichText mode
        assert lbl.textFormat() == Qt.TextFormat.RichText, (
            "Label must switch to RichText after _populate_body so pre-wrap works"
        )

        rendered = lbl.text()
        # The div wrapper with pre-wrap must be present
        assert "white-space:pre-wrap" in rendered, (
            f"Expected white-space:pre-wrap in rendered HTML; got: {rendered!r}"
        )
        # The plain-text content must be present (html.escape does not touch \n)
        assert "Line 1" in rendered, "Line 1 must appear in rendered HTML"
        assert "Line 2" in rendered, "Line 2 must appear in rendered HTML"
        assert "Line 3" in rendered, "Line 3 must appear in rendered HTML"
        # Newlines must be present as literal \n (html.escape does not escape them)
        assert "\n" in rendered, (
            "Newlines must be preserved inside the pre-wrap wrapper"
        )

        # Also verify the plain-text cache is set correctly
        assert page._body_plain_cache == body, (
            "_body_plain_cache must hold the original plain text for highlight re-use"
        )

    def test_script_tag_in_body_is_literal_text(self):
        """'<script>' in the body must appear as the literal string, not be executed.

        html.escape converts '<' → '&lt;' and '>' → '&gt;', so the script tag
        can never be interpreted by Qt's HTML renderer as markup.
        """
        from PySide6.QtCore import Qt
        from frontend.views._report_display import _populate_body

        evil_body = "Hello <script>alert('xss')</script> World"
        page, detail = _make_page_and_detail(evil_body)
        _populate_body(page, detail)

        lbl = page._lbl_body
        rendered = lbl.text()

        # The raw <script> tag must NOT appear in the rendered HTML
        assert "<script>" not in rendered, (
            "Raw <script> tag must be escaped, not present literally in HTML"
        )
        # The escaped form must be present so the analyst can read the original content
        escaped_tag = html.escape("<script>")  # "&lt;script&gt;"
        assert escaped_tag in rendered, (
            f"Escaped script tag '{escaped_tag}' must appear in rendered HTML "
            f"so the analyst sees it as literal text; got: {rendered!r}"
        )
        # The label is in RichText mode (pre-wrap enabled)
        assert lbl.textFormat() == Qt.TextFormat.RichText
