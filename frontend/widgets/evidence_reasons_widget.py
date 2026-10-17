"""EvidenceReasonsWidget — expandable reason list with per-signal evidence panels.

Each reason string is matched against a reason_evidence list by exact string.
A matched reason gets a chevron and toggles a key/value evidence panel beneath.
Unmatched reasons are plain text rows.

BEC financial-language evidence additionally shows a "Show in body" button that
emits show_in_body(phrases: list[str]) for the caller to highlight and switch to
the Body tab.

NULL reason_evidence (pre-Phase-C analysis) shows a muted note instead of
chevrons.

Design rules
────────────
  • All colors from tokens.py — zero inline hex values.
  • No animation.
  • Long text wraps (WordWrap on all labels).
  • showEvent re-applies programmatic colors (Qt re-polish gotcha).
  • set_reasons() diffs and updates in-place — does NOT rebuild the widget.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from frontend.services.tokens import Dark, Light, svg_icon


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

_TRUNCATE_LEN = 300


def _truncate(text: str) -> tuple[str, str | None]:
    """Return (display_text, tooltip_text_or_None).

    If *text* exceeds _TRUNCATE_LEN characters, display_text is cut at that
    boundary and suffixed with "…", and tooltip_text carries the full value.
    This prevents attacker-controlled evidence values from running off-pane
    and limits the visual footprint of very long strings.
    """
    if len(text) <= _TRUNCATE_LEN:
        return text, None
    return text[:_TRUNCATE_LEN] + "…", text


def _body_label(text: str = "") -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    # SECURITY: force plain text so attacker-controlled evidence values are
    # never interpreted as HTML/RichText by Qt's AutoText detection.
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    return lbl


def _mono_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    # SECURITY: same as _body_label — attacker text must never render as HTML.
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    lbl.setStyleSheet(
        "font-family:'Consolas','Courier New',monospace; font-size:12px;"
    )
    return lbl


# ─────────────────────────────────────────────────────────────────────────────
# _EvidencePanel — the expandable KV grid shown under a matched reason
# ─────────────────────────────────────────────────────────────────────────────

class _EvidencePanel(QFrame):
    """Key/value grid showing signal evidence.  Hidden by default; toggled open."""

    show_in_body = Signal(list)   # emitted for financial evidence "Show in body"

    def __init__(self, evidence: dict, signal_id: str, is_dark: bool, parent=None):
        super().__init__(parent)
        self._evidence = evidence
        self._signal_id = signal_id
        self._is_dark = is_dark

        self.setFrameShape(QFrame.Shape.NoFrame)
        lyt = QVBoxLayout(self)
        lyt.setContentsMargins(24, 6, 12, 8)
        lyt.setSpacing(4)

        # Render evidence key/value pairs
        self._rows: list[tuple[QLabel, QLabel]] = []
        self._build_rows(lyt)

        # "Show in body" button for financial language evidence
        self._show_btn: QPushButton | None = None
        if signal_id == "financial_request_language":
            phrases = self._collect_phrases(evidence)
            if phrases:
                btn = QPushButton("Show in body")
                btn.setFixedHeight(26)
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                btn.setObjectName("EvidenceShowBodyBtn")
                btn.clicked.connect(lambda: self.show_in_body.emit(phrases))
                btn_row = QHBoxLayout()
                btn_row.setContentsMargins(0, 4, 0, 0)
                btn_row.addWidget(btn)
                btn_row.addStretch()
                lyt.addLayout(btn_row)
                self._show_btn = btn

        self.hide()
        self._apply_colors()

    def _collect_phrases(self, evidence: dict) -> list[str]:
        """Flatten all matched phrases from financial evidence categories."""
        cats = evidence.get("categories") or {}
        phrases: list[str] = []
        for phrase_list in cats.values():
            if isinstance(phrase_list, list):
                phrases.extend(str(p) for p in phrase_list)
        return phrases

    @staticmethod
    def _set_truncated(lbl: QLabel, text: str) -> None:
        """Set *text* on *lbl*, truncating to _TRUNCATE_LEN chars.

        If the value is longer than _TRUNCATE_LEN the label shows the
        truncated form with "…" and the full value is placed in the tooltip
        so the analyst can still read it without it running off-pane.
        Both the label text and the tooltip are set as plain text (the label's
        format is already PlainText from _body_label / _mono_label).
        """
        display, tooltip = _truncate(text)
        lbl.setText(display)
        if tooltip is not None:
            lbl.setToolTip(tooltip)

    def _build_rows(self, lyt: QVBoxLayout) -> None:
        """Render evidence dict as key: value rows.

        Special-cases:
          • 'categories' dict (financial evidence) — expands per-category.
          • 'urls' list — renders as a bullet list.
          • Other lists — comma-joined.

        All displayed values are truncated to _TRUNCATE_LEN characters with
        the full value available in the tooltip (security: prevents very long
        attacker-controlled strings from rendering off-pane).
        """
        ev = self._evidence or {}
        for key, val in ev.items():
            k_lbl = _body_label(f"{key}:")
            k_lbl.setObjectName("EvidenceKey")

            if key == "categories" and isinstance(val, dict):
                # Financial categories: one sub-row per category
                k_lbl.setText("matched categories:")
                lyt.addWidget(k_lbl)
                for cat, phrases in val.items():
                    phrase_str = ",  ".join(str(p) for p in (phrases or []))
                    full_text = f"  {cat.replace('_', ' ')}:  {phrase_str}"
                    sub = _mono_label("")
                    self._set_truncated(sub, full_text)
                    sub.setObjectName("EvidenceVal")
                    lyt.addWidget(sub)
                    self._rows.append((k_lbl, sub))
                continue

            if key == "urls" and isinstance(val, list):
                lyt.addWidget(k_lbl)
                for item in val:
                    if isinstance(item, dict):
                        raw_url = str(item.get("url", ""))
                        url_display, url_tip = _truncate(raw_url)
                        text = f"  {url_display}  (engines: {item.get('engines', 0)})"
                    else:
                        raw = str(item)
                        raw_display, _ = _truncate(raw)
                        text = f"  {raw_display}"
                        url_tip = _ if _ else None
                    v_lbl = _mono_label("")
                    v_lbl.setText(text)
                    if url_tip:
                        v_lbl.setToolTip(url_tip)
                    v_lbl.setObjectName("EvidenceVal")
                    lyt.addWidget(v_lbl)
                    self._rows.append((k_lbl, v_lbl))
                continue

            if isinstance(val, list):
                display = ",  ".join(str(x) for x in val)
            else:
                display = str(val) if val is not None else "—"

            v_lbl = _mono_label("")
            self._set_truncated(v_lbl, display)
            v_lbl.setObjectName("EvidenceVal")

            row_lyt = QHBoxLayout()
            row_lyt.setContentsMargins(0, 0, 0, 0)
            row_lyt.setSpacing(8)
            row_lyt.addWidget(k_lbl)
            row_lyt.addWidget(v_lbl, 1)
            lyt.addLayout(row_lyt)
            self._rows.append((k_lbl, v_lbl))

    def _apply_colors(self) -> None:
        t = Dark if self._is_dark else Light
        self.setStyleSheet(
            f"background:{t.evidence_panel_bg};"
            f"border-left: 3px solid {t.evidence_panel_border};"
            f"border-radius:4px;"
        )
        for k_lbl, v_lbl in self._rows:
            k_lbl.setStyleSheet(
                f"color:{t.evidence_key_color}; font-size:12px; font-weight:600;"
            )
            v_lbl.setStyleSheet(
                f"color:{t.evidence_val_color}; font-size:12px;"
            )
        if self._show_btn is not None:
            self._show_btn.setStyleSheet(
                f"QPushButton#EvidenceShowBodyBtn {{"
                f"  background:{t.primary}; color:#FFFFFF;"
                f"  border:none; border-radius:4px; padding:2px 10px; font-size:12px;"
                f"}}"
                f"QPushButton#EvidenceShowBodyBtn:hover {{"
                f"  background:{t.primary_hover};"
                f"}}"
            )

    def set_dark(self, is_dark: bool) -> None:
        self._is_dark = is_dark
        self._apply_colors()

    def showEvent(self, event) -> None:   # noqa: N802
        super().showEvent(event)
        self._apply_colors()


# ─────────────────────────────────────────────────────────────────────────────
# _ReasonRow — one reason entry (plain text or clickable with evidence panel)
# ─────────────────────────────────────────────────────────────────────────────

class _ReasonRow(QWidget):
    """One numbered reason row.

    If evidence is provided: shows a chevron button that toggles the
    _EvidencePanel below the reason text.
    If no evidence: plain text only, no chevron.
    """

    show_in_body = Signal(list)

    def __init__(
        self,
        number: int,
        reason: str,
        evidence: dict | None,
        signal_id: str | None,
        is_dark: bool,
        parent=None,
    ):
        super().__init__(parent)
        self._is_dark = is_dark
        self._open = False
        self._evidence = evidence
        self._has_evidence = evidence is not None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 2, 0, 2)
        outer.setSpacing(0)

        # ── Header row: [chevron] [number. text] ──────────────────────────
        header = QWidget()
        h_lyt = QHBoxLayout(header)
        h_lyt.setContentsMargins(0, 0, 0, 0)
        h_lyt.setSpacing(6)

        self._chevron_btn: QPushButton | None = None
        if self._has_evidence:
            btn = QPushButton()
            btn.setFixedSize(20, 20)
            btn.setFlat(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setObjectName("EvidenceChevron")
            btn.setToolTip("Show / hide evidence")
            btn.clicked.connect(self._toggle)
            self._chevron_btn = btn
            h_lyt.addWidget(btn)
        else:
            spacer = QWidget()
            spacer.setFixedWidth(20)
            h_lyt.addWidget(spacer)

        self._reason_lbl = _body_label(f"{number}.  {reason}")
        self._reason_lbl.setObjectName("ReasonText")
        if self._has_evidence:
            self._reason_lbl.setCursor(Qt.CursorShape.PointingHandCursor)
            self._reason_lbl.mousePressEvent = lambda _e: self._toggle()
        h_lyt.addWidget(self._reason_lbl, 1)
        outer.addWidget(header)

        # ── Evidence panel (hidden until toggled) ─────────────────────────
        self._panel: _EvidencePanel | None = None
        if self._has_evidence and signal_id is not None:
            panel = _EvidencePanel(evidence, signal_id, is_dark)
            panel.show_in_body.connect(self.show_in_body)
            self._panel = panel
            outer.addWidget(panel)

        self._apply_colors()

    def _toggle(self) -> None:
        if self._panel is None:
            return
        self._open = not self._open
        self._panel.setVisible(self._open)
        self._update_chevron()

    def _update_chevron(self) -> None:
        if self._chevron_btn is None:
            return
        t = Dark if self._is_dark else Light
        icon_name = "chevron-down" if self._open else "chevron-right"
        icon = svg_icon(icon_name, color=t.evidence_chevron_color, size=14)
        if icon:
            self._chevron_btn.setIcon(icon)
            self._chevron_btn.setText("")
        else:
            self._chevron_btn.setText("▼" if self._open else "▶")

    def _apply_colors(self) -> None:
        t = Dark if self._is_dark else Light
        self._reason_lbl.setStyleSheet(f"color:{t.text}; font-size:13px;")
        self._update_chevron()
        if self._panel is not None:
            self._panel.set_dark(self._is_dark)

    def set_dark(self, is_dark: bool) -> None:
        self._is_dark = is_dark
        self._apply_colors()

    def showEvent(self, event) -> None:   # noqa: N802
        super().showEvent(event)
        self._apply_colors()


# ─────────────────────────────────────────────────────────────────────────────
# EvidenceReasonsWidget — public API
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceReasonsWidget(QWidget):
    """Drop-in replacement for the plain-text QLabel reasons list.

    Public API
    ──────────
    set_reasons(reasons, evidence_list, is_dark)
        Update in-place.  Diffs against current state — does not rebuild
        if reasons and evidence_list are unchanged.

    show_in_body  Signal(list[str])
        Emitted when the user clicks "Show in body" on a BEC financial row.
        Payload: list of matched phrase strings.

    Design notes
    ────────────
    • NULL evidence_list → shows a muted "predates this feature" note and
      no chevrons, regardless of how many reasons exist.
    • Empty evidence_list (non-NULL) → reasons render plain (no matches).
    • Rows are updated in-place on set_reasons() — scroll position is
      preserved across poll ticks.
    """

    show_in_body = Signal(list)

    def __init__(self, is_dark: bool = False, parent=None):
        super().__init__(parent)
        self._is_dark = is_dark
        self._reasons: list[str] = []
        self._evidence_list: list[dict] | None = None
        self._rows: list[_ReasonRow] = []

        self._lyt = QVBoxLayout(self)
        self._lyt.setContentsMargins(0, 0, 0, 0)
        self._lyt.setSpacing(2)

        # Placeholder shown when no reasons are set yet
        self._placeholder = _body_label("No specific red flags triggered.")
        self._placeholder.setObjectName("EvidencePlaceholder")
        self._lyt.addWidget(self._placeholder)

        # Muted note for NULL evidence_list (pre-Phase-C analyses)
        self._null_note = _body_label(
            "Evidence not recorded (analysis predates this feature)."
        )
        self._null_note.setObjectName("EvidenceNullNote")
        self._null_note.hide()
        self._lyt.addWidget(self._null_note)

        self._apply_colors()

    # ── Public interface ──────────────────────────────────────────────────

    def set_reasons(
        self,
        reasons: list[str],
        evidence_list: list[dict] | None,
        is_dark: bool,
    ) -> None:
        """Update widget in-place.

        If reasons and evidence_list are identical to the current state this
        is a no-op (preserves open/closed toggle state across poll ticks).
        """
        # Fast-path: nothing changed
        if (reasons == self._reasons
                and evidence_list == self._evidence_list
                and is_dark == self._is_dark):
            return

        self._is_dark = is_dark
        changed_evidence = evidence_list != self._evidence_list
        changed_reasons = reasons != self._reasons

        self._reasons = list(reasons)
        self._evidence_list = evidence_list

        if changed_reasons or changed_evidence:
            self._rebuild()
        else:
            # Only theme changed — re-apply colors
            self._apply_colors()

    # ── Internal ──────────────────────────────────────────────────────────

    def _rebuild(self) -> None:
        """Tear down existing rows and rebuild from current state."""
        # Remove existing reason rows
        for row in self._rows:
            self._lyt.removeWidget(row)
            row.deleteLater()
        self._rows.clear()

        reasons = self._reasons
        ev_list = self._evidence_list  # None = pre-Phase-C

        # Build a lookup: reason_string → (evidence dict, signal_id)
        ev_map: dict[str, tuple[dict, str]] = {}
        if ev_list is not None:
            for item in ev_list:
                r = item.get("reason", "")
                ev = item.get("evidence")
                sig = item.get("signal", "")
                if r and ev is not None:
                    ev_map[r] = (ev, sig)

        if not reasons:
            self._placeholder.setText(
                "No specific red flags triggered by the current rules."
            )
            self._placeholder.show()
            self._null_note.hide()
            self._apply_colors()
            return

        self._placeholder.hide()

        # Show NULL note below reasons when evidence_list is None
        self._null_note.setVisible(ev_list is None)

        for i, reason in enumerate(reasons):
            matched = ev_map.get(reason)
            evidence = matched[0] if matched else None
            signal_id = matched[1] if matched else None
            row = _ReasonRow(
                number=i + 1,
                reason=reason,
                evidence=evidence,
                signal_id=signal_id,
                is_dark=self._is_dark,
            )
            row.show_in_body.connect(self.show_in_body)
            # Insert before the null_note widget
            insert_idx = self._lyt.indexOf(self._null_note)
            self._lyt.insertWidget(insert_idx, row)
            self._rows.append(row)

        self._apply_colors()

    def _apply_colors(self) -> None:
        t = Dark if self._is_dark else Light
        self._placeholder.setStyleSheet(f"color:{t.text_muted}; font-size:13px;")
        self._null_note.setStyleSheet(
            f"color:{t.evidence_note_color}; font-size:12px; font-style:italic;"
        )
        for row in self._rows:
            row.set_dark(self._is_dark)

    def showEvent(self, event) -> None:   # noqa: N802
        """Re-apply programmatic colors after Qt re-polish."""
        super().showEvent(event)
        self._apply_colors()
