"""Upload progress overlay — shown only during the POST /analyses request.

Design: a solid, token-colored card centered in the drop-zone area rather
than a full-screen semi-transparent dim that draws over table content.

The card is a child widget of the UploadPage.  It is sized to a fixed width
and auto-height, then re-centered on every parent Resize event so it always
appears in the middle of the visible area above the table, never on top of it.

All colors sourced from frontend.services.tokens — no inline hex values.

Safety measures
───────────────
- Mouse events pass through the transparent outer widget to the page beneath
  it; only the inner card absorbs events so the table remains interactive.
- An internal QTimer auto-hides the overlay after AUTO_HIDE_S seconds as a
  hard backstop against the overlay getting stuck (e.g. if the on_finished
  callback is never called due to a worker crash).
- ``stop()`` is idempotent and safe to call multiple times.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, QTimer
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

    _CARD_WIDTH  = 320   # fixed card width in px
    AUTO_HIDE_S  = 30    # hard backstop: auto-hide after this many seconds

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        # Transparent outer widget — mouse events pass through to the page.
        # Only the inner card (a child widget) blocks mouse events so the
        # analyses table beneath the overlay stays fully interactive.
        self.setStyleSheet("background: transparent;")
        # WA_TransparentForMouseEvents on the outer widget; the card does NOT
        # have this attribute so it still receives events normally.
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        parent.installEventFilter(self)

        # ── Auto-hide safety timer ─────────────────────────────────────────
        self._auto_hide_timer = QTimer(self)
        self._auto_hide_timer.setSingleShot(True)
        self._auto_hide_timer.timeout.connect(self.stop)

        # ── Inner card ────────────────────────────────────────────────────
        self._card = QFrame(self)
        self._card.setObjectName("ProgressCard")
        self._card.setFixedWidth(self._CARD_WIDTH)
        # Card absorbs mouse events (does NOT have WA_TransparentForMouseEvents)

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
        """Center the card just below the drop-zone widget's real bottom edge.

        The overlay is parented to the UploadPage which exposes its DropZone
        as ``self.drop_zone``.  We map the drop zone's bottom-right corner to
        the parent's coordinate space to get the real pixel position regardless
        of layout margins, window size, or DPI — no hardcoded height constants.

        Falls back to a 220 px estimate if the parent has no ``drop_zone``
        attribute (e.g. during unit tests that construct the overlay standalone).
        """
        parent = self.parent()
        if parent is None:
            return
        pr = parent.rect()
        # Fill the entire parent so the outer widget can intercept mouse events
        self.setGeometry(pr)

        card_h = self._card.sizeHint().height()
        if card_h <= 0:
            card_h = 80  # fallback before first layout pass

        # Use the drop zone's real bottom edge when available.
        drop_zone = getattr(parent, "drop_zone", None)
        if drop_zone is not None:
            # mapTo converts drop_zone-local (0, bottom) to parent coordinates.
            dz_bottom = drop_zone.mapTo(parent, drop_zone.rect().bottomLeft()).y()
        else:
            dz_bottom = 220  # fallback constant (DropZone.maximumHeight)

        x = (pr.width() - self._CARD_WIDTH) // 2
        y = min(dz_bottom + 8, max(8, pr.height() // 2 - card_h // 2))
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
        # Arm the auto-hide backstop — cancelled by stop() on normal completion
        self._auto_hide_timer.start(self.AUTO_HIDE_S * 1000)

    def stop(self) -> None:
        self._auto_hide_timer.stop()
        self.hide()
