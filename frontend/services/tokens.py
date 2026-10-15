"""Centralized design tokens for the Phish Analyzer UI.

This module is the single source of truth for all colors, fonts, and spacing
used in programmatic styling (paintEvent, setStyleSheet calls, etc.).

Rules:
  - Every color used anywhere in the frontend must trace back to a token here
    OR to the QSS theme files (assets/themes/*.qss) for QSS-only rules.
  - Do NOT add new hex values in individual widget files. Add a token here first.
  - Dark/light variants are stored as (light_value, dark_value) tuples where
    needed, or as separate LIGHT / DARK sub-dicts.
  - The PALETTES dict in theme_manager.py stays as the authoritative source for
    verdict/status semantic colors (consumed by non-UI backend-facing code too).
    Tokens here import and re-export those values so there is one point of change.
"""

from __future__ import annotations

# ── Font stack ────────────────────────────────────────────────────────────────

FONT_UI      = '"Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif'
FONT_MONO    = '"Consolas", "Courier New", monospace'
FONT_SIZE_BASE    = 13   # px
FONT_SIZE_SMALL   = 12   # px
FONT_SIZE_XSMALL  = 11   # px
FONT_SIZE_HEADING = 14   # px

# ── Border radius ─────────────────────────────────────────────────────────────

RADIUS_CARD   = 10   # px — cards
RADIUS_INPUT  = 8    # px — inputs, buttons, chips
RADIUS_CHIP   = 8    # px

# ── Spacing ───────────────────────────────────────────────────────────────────

SPACING_PAGE_H    = 20   # px — horizontal page margin
SPACING_PAGE_V    = 16   # px — vertical page margin
SPACING_CARD_BODY = 12   # px — card body spacing
SPACING_SECTION   = 12   # px — between cards in a column

# ── Light theme tokens ────────────────────────────────────────────────────────

class Light:
    # Surfaces
    surface        = "#FFFFFF"
    surface_alt    = "#F8FAFC"
    surface_alt2   = "#F1F5F9"
    surface_overlay = "rgba(15, 23, 42, 0.60)"   # modal overlays

    # Toolbar / status bar
    toolbar_bg     = "#1E3A5F"
    toolbar_text   = "#E2E8F0"
    toolbar_muted  = "#94A3B8"

    # Text
    text           = "#0F172A"
    text_heading   = "#1E3A5F"
    text_muted     = "#64748B"
    text_disabled  = "#94A3B8"

    # Borders / dividers
    border         = "#E2E8F0"
    border_input   = "#CBD5E1"
    border_focus   = "#2563EB"

    # Interactive
    primary        = "#2563EB"
    primary_hover  = "#1D4ED8"
    primary_pressed= "#1E40AF"
    primary_disabled= "#BFDBFE"

    # Selections / highlights
    selection_bg   = "#EFF6FF"
    selection_border= "#BFDBFE"

    # Verdict
    phishing_bg    = "#FCF0EF"
    phishing_fg    = "#C2493D"
    phishing_border= "#E8A09B"
    suspicious_bg  = "#FDF8EC"
    suspicious_fg  = "#D4A24C"
    suspicious_border= "#EDD08A"
    benign_bg      = "#EEF7F4"
    benign_fg      = "#4C9A82"
    benign_border  = "#9BCFC2"
    pending_bg     = "#F8FAFC"
    pending_fg     = "#64748B"
    pending_border = "#CBD5E1"

    # Score arcs (painted, not QSS)
    arc_phishing   = "#C2493D"
    arc_suspicious = "#D4A24C"
    arc_benign     = "#4C9A82"
    arc_track      = "#E2E8F0"

    # Chip presets — (bg, fg, border)
    chip_pass      = ("#F0FDF4", "#16A34A", "#BBF7D0")
    chip_fail      = ("#FEF2F2", "#DC2626", "#FECACA")
    chip_softfail  = ("#FFF7ED", "#C2410C", "#FED7AA")
    chip_neutral   = ("#F1F5F9", "#475569", "#334155")
    chip_unknown   = ("#F1F5F9", "#64748B", "#334155")
    chip_warn      = ("#FFFBEB", "#B45309", "#78350F")
    chip_info      = ("#EFF6FF", "#2563EB", "#1E40AF")
    chip_ok        = ("#F0FDF4", "#16A34A", "#BBF7D0")
    chip_none      = ("#F1F5F9", "#64748B", "#334155")

    # Toast
    toast_info_bg     = "#EFF6FF"
    toast_info_fg     = "#1E40AF"
    toast_info_accent = "#2563EB"
    toast_success_bg  = "#F0FDF4"
    toast_success_fg  = "#14532D"
    toast_success_accent = "#16A34A"
    toast_error_bg    = "#FEF2F2"
    toast_error_fg    = "#7F1D1D"
    toast_error_accent= "#DC2626"
    toast_warn_bg     = "#FFFBEB"
    toast_warn_fg     = "#78350F"
    toast_warn_accent = "#D97706"

    # Drop zone
    dropzone_bg        = "#FFFFFF"
    dropzone_bg_hover  = "#EFF6FF"
    dropzone_border    = "#CBD5E1"
    dropzone_border_hover = "#2563EB"
    dropzone_title     = "#1E3A5F"
    dropzone_subtitle  = "#64748B"
    dropzone_icon      = "#2563EB"

    # Progress overlay
    overlay_bg         = "rgba(15, 23, 42, 0.70)"
    overlay_text       = "#F1F5F9"
    overlay_bar_bg     = "#334155"
    overlay_bar_chunk  = "#3B82F6"

    # Three-pane layout — left nav panel
    nav_bg             = "#F1F5F9"
    nav_border         = "#E2E8F0"
    nav_item_text      = "#475569"
    nav_item_bg_active = "#EFF6FF"
    nav_item_text_active = "#1D4ED8"
    nav_item_border_active = "#2563EB"

    # Three-pane layout — right metadata panel
    meta_bg            = "#F8FAFC"
    meta_border        = "#E2E8F0"

    # Score ring background (behind the ring widget)
    ring_bg            = "transparent"

    # KV table separator
    kv_sep             = "#F1F5F9"
    kv_key_color       = "#64748B"

    # Score bars (right panel)
    # Bar track (empty fill)
    score_bar_track    = "#E2E8F0"
    # Severity fill colors
    score_bar_low      = "#4C9A82"   # 0–4: teal-green (benign hue family)
    score_bar_med      = "#D4A24C"   # 5–9: amber (suspicious hue family)
    score_bar_high     = "#C2493D"   # 10+: red (phishing hue family)
    # Not-analyzed state
    score_bar_na       = "#CBD5E1"   # greyed-out fill for None scores
    score_bar_na_text  = "#94A3B8"

    # Queue panel (left pane)
    queue_bg           = "#F1F5F9"
    queue_border       = "#E2E8F0"
    queue_item_bg      = "transparent"
    queue_item_bg_hover= "#E2E8F0"
    queue_item_bg_active = "#EFF6FF"
    queue_item_border_active = "#2563EB"
    queue_item_text    = "#0F172A"
    queue_item_sub     = "#64748B"
    queue_search_bg    = "#FFFFFF"

    # Status dot colors (in queue)
    dot_pending        = "#94A3B8"
    dot_running        = "#3B82F6"
    dot_done_phishing  = "#C2493D"
    dot_done_suspicious= "#D4A24C"
    dot_done_benign    = "#4C9A82"
    dot_failed         = "#64748B"

    # Anchor-nav tab row (center pane top)
    anchor_tab_bg      = "#F8FAFC"
    anchor_tab_border  = "#E2E8F0"
    anchor_tab_text    = "#64748B"
    anchor_tab_text_active = "#1D4ED8"
    anchor_tab_indicator = "#2563EB"

    # ── Pipeline stage status colors ───────────────────────────────────────
    # Used by PipelineStagesWidget rows (loading view) and the compact
    # pipeline card on the Overview tab.  Each status has a distinct visual
    # treatment so failed ≠ timeout ≠ pending ≠ skipped.
    #
    # pending  — neutral grey dot, muted text (not started yet)
    # running  — blue dot, normal text (in progress — static, no animation)
    # done     — green dot, normal text
    # skipped  — grey dot, italic muted text (feature disabled / no key)
    # failed   — red dot, red text (hard error)
    # timeout  — amber dot, amber text (ran but polling did not complete)

    stage_pending_dot  = "#94A3B8"   # slate-400
    stage_pending_text = "#64748B"   # slate-500

    stage_running_dot  = "#3B82F6"   # blue-500
    stage_running_text = "#1E40AF"   # blue-800  (readable on light bg)

    stage_done_dot     = "#16A34A"   # green-600
    stage_done_text    = "#15803D"   # green-700

    stage_skipped_dot  = "#CBD5E1"   # slate-300
    stage_skipped_text = "#94A3B8"   # slate-400 (visually de-emphasised)

    stage_failed_dot   = "#DC2626"   # red-600
    stage_failed_text  = "#B91C1C"   # red-700

    stage_timeout_dot  = "#D97706"   # amber-600
    stage_timeout_text = "#B45309"   # amber-700


# ── Dark theme tokens ─────────────────────────────────────────────────────────

class Dark:
    # Surfaces
    surface        = "#1E293B"
    surface_alt    = "#0F172A"
    surface_alt2   = "#162032"
    surface_overlay = "rgba(0, 0, 0, 0.75)"

    # Toolbar / status bar
    toolbar_bg     = "#0A0F1E"
    toolbar_text   = "#94A3B8"
    toolbar_muted  = "#475569"

    # Text
    text           = "#F1F5F9"
    text_heading   = "#CBD5E1"
    text_muted     = "#64748B"
    text_disabled  = "#475569"

    # Borders / dividers
    border         = "#334155"
    border_input   = "#334155"
    border_focus   = "#3B82F6"

    # Interactive
    primary        = "#3B82F6"
    primary_hover  = "#2563EB"
    primary_pressed= "#1D4ED8"
    primary_disabled= "#1E3A5F"

    # Selections / highlights
    selection_bg   = "#1A2F52"
    selection_border= "#1E3A5F"

    # Verdict
    phishing_bg    = "#3D1210"
    phishing_fg    = "#E8726A"
    phishing_border= "#7A2E28"
    suspicious_bg  = "#3D2E10"
    suspicious_fg  = "#E8C06A"
    suspicious_border= "#7A5E28"
    benign_bg      = "#0F2B24"
    benign_fg      = "#7CC4AE"
    benign_border  = "#2A5E52"
    pending_bg     = "#0F172A"
    pending_fg     = "#64748B"
    pending_border = "#1E293B"

    # Score arcs
    arc_phishing   = "#C2493D"
    arc_suspicious = "#D4A24C"
    arc_benign     = "#4C9A82"
    arc_track      = "#334155"

    # Chip presets — (bg, fg, border)
    chip_pass      = ("#052E16", "#86EFAC", "#BBF7D0")
    chip_fail      = ("#450A0A", "#FCA5A5", "#FECACA")
    chip_softfail  = ("#431407", "#FDBA74", "#FED7AA")
    chip_neutral   = ("#1E293B", "#94A3B8", "#334155")
    chip_unknown   = ("#1E293B", "#64748B", "#334155")
    chip_warn      = ("#451A03", "#FCD34D", "#78350F")
    chip_info      = ("#172554", "#93C5FD", "#1E40AF")
    chip_ok        = ("#052E16", "#86EFAC", "#BBF7D0")
    chip_none      = ("#1E293B", "#64748B", "#334155")

    # Toast
    toast_info_bg     = "#1E293B"
    toast_info_fg     = "#93C5FD"
    toast_info_accent = "#3B82F6"
    toast_success_bg  = "#052E16"
    toast_success_fg  = "#86EFAC"
    toast_success_accent = "#22C55E"
    toast_error_bg    = "#450A0A"
    toast_error_fg    = "#FCA5A5"
    toast_error_accent= "#EF4444"
    toast_warn_bg     = "#451A03"
    toast_warn_fg     = "#FCD34D"
    toast_warn_accent = "#F59E0B"

    # Drop zone
    dropzone_bg        = "#1E293B"
    dropzone_bg_hover  = "#1A2F52"
    dropzone_border    = "#334155"
    dropzone_border_hover = "#3B82F6"
    dropzone_title     = "#CBD5E1"
    dropzone_subtitle  = "#64748B"
    dropzone_icon      = "#3B82F6"

    # Progress overlay
    overlay_bg         = "rgba(0, 0, 0, 0.75)"
    overlay_text       = "#F1F5F9"
    overlay_bar_bg     = "#334155"
    overlay_bar_chunk  = "#3B82F6"

    # Three-pane layout — left nav panel
    nav_bg             = "#162032"
    nav_border         = "#334155"
    nav_item_text      = "#64748B"
    nav_item_bg_active = "#1A2F52"
    nav_item_text_active = "#60A5FA"
    nav_item_border_active = "#3B82F6"

    # Three-pane layout — right metadata panel
    meta_bg            = "#162032"
    meta_border        = "#334155"

    ring_bg            = "transparent"

    # KV table separator
    kv_sep             = "#1E293B"
    kv_key_color       = "#64748B"

    # Score bars (right panel)
    score_bar_track    = "#334155"
    score_bar_low      = "#4C9A82"
    score_bar_med      = "#D4A24C"
    score_bar_high     = "#C2493D"
    score_bar_na       = "#334155"
    score_bar_na_text  = "#475569"

    # Queue panel (left pane)
    queue_bg           = "#162032"
    queue_border       = "#334155"
    queue_item_bg      = "transparent"
    queue_item_bg_hover= "#1E293B"
    queue_item_bg_active = "#1A2F52"
    queue_item_border_active = "#3B82F6"
    queue_item_text    = "#F1F5F9"
    queue_item_sub     = "#64748B"
    queue_search_bg    = "#1E293B"

    # Status dot colors (in queue)
    dot_pending        = "#475569"
    dot_running        = "#3B82F6"
    dot_done_phishing  = "#E8726A"
    dot_done_suspicious= "#E8C06A"
    dot_done_benign    = "#7CC4AE"
    dot_failed         = "#475569"

    # Anchor-nav tab row (center pane top)
    anchor_tab_bg      = "#162032"
    anchor_tab_border  = "#334155"
    anchor_tab_text    = "#64748B"
    anchor_tab_text_active = "#60A5FA"
    anchor_tab_indicator = "#3B82F6"

    # ── Pipeline stage status colors ───────────────────────────────────────
    # Dark-theme counterparts — same semantic meaning, adjusted for dark bg.

    stage_pending_dot  = "#475569"   # slate-600
    stage_pending_text = "#64748B"   # slate-500

    stage_running_dot  = "#60A5FA"   # blue-400
    stage_running_text = "#93C5FD"   # blue-300

    stage_done_dot     = "#4ADE80"   # green-400
    stage_done_text    = "#86EFAC"   # green-300

    stage_skipped_dot  = "#334155"   # slate-700
    stage_skipped_text = "#475569"   # slate-600

    stage_failed_dot   = "#F87171"   # red-400
    stage_failed_text  = "#FCA5A5"   # red-300

    stage_timeout_dot  = "#FCD34D"   # amber-300
    stage_timeout_text = "#FDE68A"   # amber-200


# ── Helpers ───────────────────────────────────────────────────────────────────

def theme(is_dark: bool) -> type[Light] | type[Dark]:
    """Return the correct token class for the current theme."""
    return Dark if is_dark else Light


def chip_colors(preset: str, is_dark: bool) -> tuple[str, str, str]:
    """Return (bg, fg, border) for the given chip preset and theme."""
    t = Dark if is_dark else Light
    attr = f"chip_{preset}"
    return getattr(t, attr, t.chip_neutral)


def verdict_colors(verdict: str | None, is_dark: bool) -> tuple[str, str, str]:
    """Return (bg, fg, border) for the given verdict string and theme."""
    t = Dark if is_dark else Light
    key = (verdict or "pending").lower()
    bg     = getattr(t, f"{key}_bg",     t.pending_bg)
    fg     = getattr(t, f"{key}_fg",     t.pending_fg)
    border = getattr(t, f"{key}_border", t.pending_border)
    return bg, fg, border


def arc_color(verdict: str | None, is_dark: bool) -> str:
    """Return the score ring arc color for the given verdict."""
    t = Dark if is_dark else Light
    if verdict == "phishing":   return t.arc_phishing
    if verdict == "suspicious": return t.arc_suspicious
    return t.arc_benign


TOAST_STYLES = {
    "light": {
        "info":    (Light.toast_info_bg,     Light.toast_info_fg,     Light.toast_info_accent,    "ℹ"),
        "success": (Light.toast_success_bg,  Light.toast_success_fg,  Light.toast_success_accent, "✓"),
        "error":   (Light.toast_error_bg,    Light.toast_error_fg,    Light.toast_error_accent,   "✕"),
        "warning": (Light.toast_warn_bg,     Light.toast_warn_fg,     Light.toast_warn_accent,    "⚠"),
    },
    "dark": {
        "info":    (Dark.toast_info_bg,      Dark.toast_info_fg,      Dark.toast_info_accent,     "ℹ"),
        "success": (Dark.toast_success_bg,   Dark.toast_success_fg,   Dark.toast_success_accent,  "✓"),
        "error":   (Dark.toast_error_bg,     Dark.toast_error_fg,     Dark.toast_error_accent,    "✕"),
        "warning": (Dark.toast_warn_bg,      Dark.toast_warn_fg,      Dark.toast_warn_accent,     "⚠"),
    },
}


def stage_colors(status: str, is_dark: bool) -> tuple[str, str]:
    """Return (dot_color, text_color) for a pipeline stage status string.

    Covers all six valid status values:
        pending / running / done / skipped / failed / timeout

    Returns the 'pending' tokens for any unrecognised value so unknown
    statuses degrade gracefully rather than blowing up at render time.
    """
    t = Dark if is_dark else Light
    s = (status or "pending").lower()
    if s == "running":
        return t.stage_running_dot, t.stage_running_text
    if s == "done":
        return t.stage_done_dot, t.stage_done_text
    if s == "skipped":
        return t.stage_skipped_dot, t.stage_skipped_text
    if s == "failed":
        return t.stage_failed_dot, t.stage_failed_text
    if s == "timeout":
        return t.stage_timeout_dot, t.stage_timeout_text
    # pending (and any unknown value)
    return t.stage_pending_dot, t.stage_pending_text


def score_bar_color(score: int | None, is_dark: bool) -> str:
    """Return the fill color for a score bar.

    Returns the 'not-analyzed' color when score is None.
    Thresholds: 0-4 green, 5-9 amber, 10+ red.
    """
    t = Dark if is_dark else Light
    if score is None:
        return t.score_bar_na
    if score >= 10:
        return t.score_bar_high
    if score >= 5:
        return t.score_bar_med
    return t.score_bar_low


def status_dot_color(status: str, verdict: str | None, is_dark: bool) -> str:
    """Return the colored dot color for an email queue item."""
    t = Dark if is_dark else Light
    s = (status or "").upper()
    if s == "PENDING":
        return t.dot_pending
    if s == "RUNNING":
        return t.dot_running
    if s == "FAILED":
        return t.dot_failed
    # DONE — color by verdict
    v = (verdict or "").lower()
    if v == "phishing":
        return t.dot_done_phishing
    if v == "suspicious":
        return t.dot_done_suspicious
    if v == "benign":
        return t.dot_done_benign
    return t.dot_pending


# ── SVG icon loader ───────────────────────────────────────────────────────────

from pathlib import Path as _Path


def _icons_dir() -> _Path:
    """Resolve assets/icons/ relative to this file's location."""
    return _Path(__file__).parent.parent.parent / "assets" / "icons"


def svg_icon(name: str, color: str = "#64748B", size: int = 16):
    """Load a Tabler SVG by filename stem, tint it with `color`, return QIcon.

    The SVGs use stroke="currentColor" — we substitute the actual hex value
    so Qt's SVG renderer honours it at the requested pixel size.

    Returns None if the SVG file is not found (graceful degradation).
    """
    try:
        from PySide6.QtCore import QByteArray
        from PySide6.QtGui import QIcon
        from PySide6.QtSvg import QSvgRenderer
        from PySide6.QtGui import QPixmap, QPainter

        svg_path = _icons_dir() / f"{name}.svg"
        if not svg_path.exists():
            return None

        raw = svg_path.read_text(encoding="utf-8")
        # Replace currentColor with the requested tint color
        tinted = raw.replace("currentColor", color)
        data = QByteArray(tinted.encode("utf-8"))

        renderer = QSvgRenderer(data)
        if not renderer.isValid():
            return None

        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)  # must use the enum, not int 0 — on Windows,
        # fill(0x00000000) creates an opaque black pixmap instead of a transparent one.
        painter = QPainter(pixmap)
        renderer.render(painter)
        painter.end()

        return QIcon(pixmap)
    except Exception:
        return None
