"""API keys (masked) + scoring weights form -- a modal dialog, NOT a routed
page, so it doesn't add a third route beyond Upload/Report.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QLineEdit,
    QScrollArea,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

_WEIGHT_LABELS = {
    "brand_mismatch": "Brand mismatch (display name)",
    "brand_domain_lookalike": "Lookalike/typosquat sender domain",
    "brand_domain_lookalike_threshold": "Lookalike similarity threshold (%)",
    "spf_fail": "SPF failure",
    "dkim_fail": "DKIM failure",
    "dmarc_fail": "DMARC failure",
    "header_issue": "Header issue (each)",
    "url_bad_keyword": "Suspicious URL keyword",
    "url_ip_host": "URL uses raw IP host",
    "url_shortener": "URL uses a link shortener",
    "suspicious_tld": "Suspicious top-level domain",
    "punycode_domain": "Punycode / IDN homograph domain",
    "attachment_executable": "Dangerous attachment extension",
    "attachment_double_extension": "Attachment double extension",
    "body_urgency_keyword": "Urgency/pressure language in body",
    "vt_malicious_threshold": "VirusTotal malicious engine threshold",
    "vt_malicious_points": "VirusTotal malicious points",
    "abuseipdb_high_score": "AbuseIPDB high-score threshold",
    "abuseipdb_points": "AbuseIPDB high-score points",
}


class SettingsDialog(QDialog):
    def __init__(self, settings: dict, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(520)
        self.setMinimumHeight(600)

        outer_layout = QVBoxLayout(self)

        content = QWidget()
        layout = QVBoxLayout(content)

        keys_group = QGroupBox("API Keys")
        keys_form = QFormLayout(keys_group)

        self.vt_key_edit = QLineEdit()
        self.vt_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.vt_key_edit.setPlaceholderText(
            "•••• (configured, leave blank to keep)"
            if settings.get("virustotal_key_configured")
            else "Not configured"
        )

        self.abuse_key_edit = QLineEdit()
        self.abuse_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.abuse_key_edit.setPlaceholderText(
            "•••• (configured, leave blank to keep)"
            if settings.get("abuseipdb_key_configured")
            else "Not configured"
        )

        keys_form.addRow("VirusTotal API key", self.vt_key_edit)
        keys_form.addRow("AbuseIPDB API key", self.abuse_key_edit)

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
        """Only includes a key when the user actually typed something --
        leaving a field blank means 'leave unchanged', not 'clear it'."""
        payload: dict[str, str] = {}
        if self.vt_key_edit.text():
            payload["virustotal_key"] = self.vt_key_edit.text()
        if self.abuse_key_edit.text():
            payload["abuseipdb_key"] = self.abuse_key_edit.text()
        return payload
