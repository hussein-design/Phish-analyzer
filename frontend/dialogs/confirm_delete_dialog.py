from __future__ import annotations

from PySide6.QtWidgets import QMessageBox, QWidget


def confirm_delete(parent: QWidget, filename: str) -> bool:
    result = QMessageBox.question(
        parent,
        "Delete analysis",
        f'Delete the analysis for "{filename}"? This cannot be undone.',
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    return result == QMessageBox.StandardButton.Yes
