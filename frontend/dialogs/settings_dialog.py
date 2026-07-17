"""API keys (masked) + scoring weights form -- a modal dialog, NOT a routed
page, so it doesn't add a third route beyond Upload/Report.

Includes:
  - VirusTotal API key
  - AbuseIPDB API key
  - Shodan API key (Phase 2)
  - Sandbox provider + API key (Phase 5)
  - Full scoring weights including new Phase 1-4 signals
  - Suspicious URL keywords / TLDs / shorteners / urgency phrases
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QScrollArea,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

_WEIGHT_LABELS = {
    # ── Original signals ──────────────────────────────────────────────────
    "brand_mismatch":                  "Brand mismatch (display name)",
    "brand_domain_lookalike":          "Lookalike/typosquat sender domain",
    "brand_domain_lookalike_threshold":"Lookalike similarity threshold (%)",
    "spf_fail":                        "SPF failure",
    "dkim_fail":                       "DKIM failure",
    "dmarc_fail":                      "DMARC failure",
    "header_issue":                    "Header issue (each)",
    "url_bad_keyword":                 "Suspicious URL keyword",
    "url_ip_host":                     "URL uses raw IP host",
    "url_shortener":                   "URL uses a link shortener",
    "suspicious_tld":                  "Suspicious top-level domain",
    "punycode_domain":                 "Punycode / IDN homograph domain",
    "attachment_executable":           "Dangerous attachment extension",
    "attachment_double_extension":     "Attachment double extension",
    "body_urgency_keyword":            "Urgency/pressure language in body",
    "vt_malicious_threshold":          "VirusTotal malicious engine threshold",
    "vt_malicious_points":             "VirusTotal malicious points",
    "abuseipdb_high_score":            "AbuseIPDB high-score threshold",
    "abuseipdb_points":                "AbuseIPDB high-score points",
    # ── Phase 1: social engineering signals ──────────────────────────────
    "lure_category":                   "Lure category detected (per category)",
    "anchor_mismatch":                 "Anchor text / href mismatch",
    # ── Phase 2–4 new signals ─────────────────────────────────────────────
    "redirect_suspicious":             "Suspicious redirect chain in URL",
    "macro_enabled":                   "Macro-enabled Office attachment",
    "embedded_executable":             "Embedded executable in attachment",
    "mime_magic_mismatch":             "MIME magic-byte mismatch in attachment",
    "vt_hash_malicious_points":        "VirusTotal attachment hash — malicious",
}

_SANDBOX_PROVIDERS = ["", "anyrun", "hybrid_analysis"]


class SettingsDialog(QDialog):
    def __init__(self, settings: dict, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(560)
        self.setMinimumHeight(680)

        outer_layout = QVBoxLayout(self)

        content = QWidget()
        layout = QVBoxLayout(content)

        # ── API Keys group ────────────────────────────────────────────────
        keys_group = QGroupBox("API Keys")
        keys_form = QFormLayout(keys_group)

        # VirusTotal
        vt_configured = settings.get("virustotal_key_configured", False)
        vt_status_label = QLabel(
            "✓ Configured  (leave blank to keep, or type a new key to replace)"
            if vt_configured else "✗ Not configured"
        )
        vt_status_label.setStyleSheet(
            "color: #37864a; font-size: 11px;" if vt_configured
            else "color: #c05000; font-size: 11px;"
        )
        self.vt_key_edit = QLineEdit()
        self.vt_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.vt_key_edit.setPlaceholderText(
            "Leave blank to keep existing key" if vt_configured
            else "Paste your VirusTotal API key here"
        )
        vt_widget = _key_widget(vt_status_label, self.vt_key_edit)

        # AbuseIPDB
        abuse_configured = settings.get("abuseipdb_key_configured", False)
        abuse_status_label = QLabel(
            "✓ Configured  (leave blank to keep, or type a new key to replace)"
            if abuse_configured else "✗ Not configured"
        )
        abuse_status_label.setStyleSheet(
            "color: #37864a; font-size: 11px;" if abuse_configured
            else "color: #c05000; font-size: 11px;"
        )
        self.abuse_key_edit = QLineEdit()
        self.abuse_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.abuse_key_edit.setPlaceholderText(
            "Leave blank to keep existing key" if abuse_configured
            else "Paste your AbuseIPDB API key here"
        )
        abuse_widget = _key_widget(abuse_status_label, self.abuse_key_edit)

        # Shodan (Phase 2)
        shodan_configured = settings.get("shodan_key_configured", False)
        shodan_status_label = QLabel(
            "✓ Configured  (leave blank to keep, or type a new key to replace)"
            if shodan_configured else "✗ Not configured  (InternetDB free tier is always used)"
        )
        shodan_status_label.setStyleSheet(
            "color: #37864a; font-size: 11px;" if shodan_configured
            else "color: #888; font-size: 11px;"
        )
        self.shodan_key_edit = QLineEdit()
        self.shodan_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.shodan_key_edit.setPlaceholderText(
            "Leave blank to keep existing key" if shodan_configured
            else "Optional — enables deep Shodan host lookups"
        )
        shodan_widget = _key_widget(shodan_status_label, self.shodan_key_edit)

        keys_form.addRow("VirusTotal API key", vt_widget)
        keys_form.addRow("AbuseIPDB API key", abuse_widget)
        keys_form.addRow("Shodan API key", shodan_widget)

        # ── Sandbox group (Phase 5) ───────────────────────────────────────
        sandbox_group = QGroupBox("Sandbox Detonation (Phase 5)")
        sandbox_form = QFormLayout(sandbox_group)

        sandbox_configured = settings.get("sandbox_key_configured", False)
        current_provider = settings.get("sandbox_provider") or ""

        self.sandbox_provider_combo = QComboBox()
        for p in _SANDBOX_PROVIDERS:
            label = {"": "— disabled —", "anyrun": "Any.run", "hybrid_analysis": "Hybrid Analysis"}.get(p, p)
            self.sandbox_provider_combo.addItem(label, p)
        # Select current provider
        idx = self.sandbox_provider_combo.findData(current_provider)
        if idx >= 0:
            self.sandbox_provider_combo.setCurrentIndex(idx)

        sandbox_key_status_label = QLabel(
            "✓ Key configured  (leave blank to keep, or type a new key to replace)"
            if sandbox_configured else "✗ No API key — required for detonation"
        )
        sandbox_key_status_label.setStyleSheet(
            "color: #37864a; font-size: 11px;" if sandbox_configured
            else "color: #c05000; font-size: 11px;"
        )
        self.sandbox_key_edit = QLineEdit()
        self.sandbox_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.sandbox_key_edit.setPlaceholderText(
            "Leave blank to keep existing key" if sandbox_configured
            else "Paste sandbox API key here"
        )
        sandbox_key_widget = _key_widget(sandbox_key_status_label, self.sandbox_key_edit)

        sandbox_form.addRow("Provider", self.sandbox_provider_combo)
        sandbox_form.addRow("API key", sandbox_key_widget)

        # ── Scoring weights group ─────────────────────────────────────────
        scoring_group = QGroupBox("Scoring weights")
        scoring_form = QFormLayout(scoring_group)
        self._weight_spins: dict[str, QSpinBox] = {}
        scoring = settings.get("scoring", {})
        for key, label in _WEIGHT_LABELS.items():
            spin = QSpinBox()
            spin.setRange(0, 100)
            spin.setValue(int(scoring.get(key, 0)))
            self._weight_spins[key] = spin
            scoring_form.addRow(label, spin)

        # ── List groups ───────────────────────────────────────────────────
        keywords_group = QGroupBox("Suspicious URL keywords (comma-separated)")
        keywords_layout = QVBoxLayout(keywords_group)
        self.keywords_edit = QLineEdit(", ".join(settings.get("url_suspicious_keywords", [])))
        keywords_layout.addWidget(self.keywords_edit)

        tlds_group = QGroupBox("Suspicious TLDs (comma-separated, include the dot)")
        tlds_layout = QVBoxLayout(tlds_group)
        self.tlds_edit = QLineEdit(", ".join(settings.get("suspicious_tlds", [])))
        tlds_layout.addWidget(self.tlds_edit)

        shorteners_group = QGroupBox("URL shortener domains (comma-separated)")
        shorteners_layout = QVBoxLayout(shorteners_group)
        self.shorteners_edit = QLineEdit(", ".join(settings.get("url_shorteners", [])))
        shorteners_layout.addWidget(self.shorteners_edit)

        urgency_group = QGroupBox("Urgency/pressure phrases (comma-separated)")
        urgency_layout = QVBoxLayout(urgency_group)
        self.urgency_edit = QLineEdit(", ".join(settings.get("urgency_keywords", [])))
        urgency_layout.addWidget(self.urgency_edit)

        brands_group = QGroupBox("Brand domains (read-only)")
        brands_layout = QVBoxLayout(brands_group)
        brands_text = QTextEdit()
        brands_text.setReadOnly(True)
        lines = [
            f"{brand}: {', '.join(domains)}"
            for brand, domains in settings.get("brand_domains", {}).items()
        ]
        brands_text.setPlainText("\n".join(lines))
        brands_text.setMaximumHeight(100)
        brands_layout.addWidget(brands_text)

        layout.addWidget(keys_group)
        layout.addWidget(sandbox_group)
        layout.addWidget(scoring_group)
        layout.addWidget(keywords_group)
        layout.addWidget(tlds_group)
        layout.addWidget(shorteners_group)
        layout.addWidget(urgency_group)
        layout.addWidget(brands_group)
        layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        outer_layout.addWidget(scroll)
        outer_layout.addWidget(buttons)

    # ── Payload helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_csv(text: str) -> list[str]:
        return [item.strip() for item in text.split(",") if item.strip()]

    def scoring_payload(self) -> dict:
        return {key: spin.value() for key, spin in self._weight_spins.items()}

    def keywords_payload(self) -> list[str]:
        return self._parse_csv(self.keywords_edit.text())

    def tlds_payload(self) -> list[str]:
        return self._parse_csv(self.tlds_edit.text())

    def shorteners_payload(self) -> list[str]:
        return self._parse_csv(self.shorteners_edit.text())

    def urgency_payload(self) -> list[str]:
        return self._parse_csv(self.urgency_edit.text())

    def keys_payload(self) -> dict:
        """Returns only the fields the user actually filled in.

        Leaving a field blank means 'leave unchanged'.
        Omitting the field from the returned dict = 'no change'.
        """
        payload: dict[str, str] = {}
        if self.vt_key_edit.text():
            payload["virustotal_key"] = self.vt_key_edit.text()
        if self.abuse_key_edit.text():
            payload["abuseipdb_key"] = self.abuse_key_edit.text()
        if self.shodan_key_edit.text():
            payload["shodan_key"] = self.shodan_key_edit.text()
        return payload

    def sandbox_payload(self) -> dict:
        """Returns sandbox provider and key if they have been touched.

        The provider combo always has a value so we always include it.
        The key is only included when the user typed something.
        """
        payload: dict = {}
        provider = self.sandbox_provider_combo.currentData() or ""
        payload["sandbox_provider"] = provider or None
        if self.sandbox_key_edit.text():
            payload["sandbox_api_key"] = self.sandbox_key_edit.text()
        return payload


# ── Private helper ─────────────────────────────────────────────────────────────

def _key_widget(status_label: QLabel, line_edit: QLineEdit) -> QWidget:
    """Stack a status label above the key input in a compact widget."""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(2)
    layout.addWidget(status_label)
    layout.addWidget(line_edit)
    return widget
