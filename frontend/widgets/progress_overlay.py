"""Upload progress overlay — shown only during the POST /analyses request.

Design: a solid, token-colored card centered in the drop-zone area rather
than a full-screen semi-transparent dim that draws over table content.

The card is a child widget of the UploadPage.  It is sized to a fixed width
and auto-height, then re-centered on every parent Resize event so it always
appears in the middle of the visible area above the table, never on top of it.

All colors sourced from frontend.services.tokens — no inline hex values.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, QPoint, Qt
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from frontend.services.tokens import Dark, Light


class ProgressOverlay(QWidget):
    """Solid-card upload progress indicator.

    Parented to the upload page.  Shown only while the POST /analyses HTTP
    request is in flight — hidden immediately on success or error (before the
    UI switches to the report view).  Never shown during the analysis itself.
    """

    _CARD_WIDTH = 320   # fixed card width in px

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        # Transparent outer widget — only the inner card has a background.
        # This means the overlay does NOT dim or draw over table content.
        self.setStyleSheet("background: transparent;")
        parent.installEventFilter(self)

        # ── Inner card ────────────────────────────────────────────────────
        self._card = QFrame(self)
        self._card.setObjectName("ProgressCard")
        self._card.setFixedWidth(self._CARD_WIDTH)

        card_lyt = QVBoxLayout(self._card)
        card_lyt.setContentsMargins(24, 20, 24, 20)
        card_lyt.setSpacing(12)
        card_lyt.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._label = QLabel("")
        self._label.setObjectName("ProgressCardLabel")
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._label.setWordWrap(True)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)   # indeterminate
        self._bar.setFixedWidth(self._CARD_WIDTH - 48)
        self._bar.setFixedHeight(6)
        self._bar.setTextVisible(False)

        card_lyt.addWidget(self._label)
        card_lyt.addWidget(self._bar)

        self._refresh_styles()
        self.hide()

    # ── Theming ───────────────────────────────────────────────────────────

    def _refresh_styles(self) -> None:
        bg = self.palette().window().color()
        is_dark = bg.lightness() < 128
        t = Dark if is_dark else Light

        # Solid card: token surface color + border + shadow simulation via border
        self._card.setStyleSheet(
            f"QFrame#ProgressCard {{"
            f"  background-color: {t.surface};"
            f"  border: 1px solid {t.border};"
            f"  border-radius: 12px;"
            f"}}"
        )
        self._label.setStyleSheet(
            f"color: {t.text}; font-size: 14px; font-weight: 600; "
            "background: transparent; border: none; padding-bottom: 4px;"
        )
        self._bar.setStyleSheet(
            f"QProgressBar {{ background-color: {t.overlay_bar_bg}; border: none; border-radius: 3px; }}"
            f"QProgressBar::chunk {{ background-color: {t.overlay_bar_chunk}; border-radius: 3px; }}"
        )

    # ── Geometry ──────────────────────────────────────────────────────────

    def _reposition(self) -> None:
        """Center the overlay widget over the parent's drop zone area.

        The overlay widget fills the parent so it intercepts clicks during
        upload.  The inner card is centered horizontally and positioned in
        the upper-center area (above the table) so it sits on top of the
        drop zone visually without covering the history table.
        """
        parent = self.parent()
        if parent is None:
            return
        pr = parent.rect()
        # Fill the entire parent so the outer widget can intercept mouse events
        self.setGeometry(pr)

        # Center the card in the upper quarter of the parent (drop-zone area)
        # so it appears above the table.  drop zone is typically the top 180-220 px.
        card_h = self._card.sizeHint().height()
        if card_h <= 0:
            card_h = 80  # fallback before first layout pass
        # Place the card vertically centered in the top 200 px
        zone_center_y = min(100, pr.height() // 4)
        x = (pr.width() - self._CARD_WIDTH) // 2
        y = max(8, zone_center_y - card_h // 2)
        self._card.move(x, y)
        self._card.adjustSize()

    def eventFilter(self, watched, event) -> bool:
        if watched is self.parent() and event.type() == QEvent.Type.Resize:
            self._reposition()
        return super().eventFilter(watched, event)

    # ── Public API ────────────────────────────────────────────────────────

    def start(self, message: str = "Uploading…") -> None:
        self._refresh_styles()
        self._label.setText(message)
        self._reposition()
        self.show()
        self.raise_()

    def stop(self) -> None:
        self.hide()
