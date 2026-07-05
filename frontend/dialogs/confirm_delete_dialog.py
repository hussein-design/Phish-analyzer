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


def confirm_clear_history(parent: QWidget) -> bool:
    """Ask the user to confirm wiping their entire analysis history."""
    box = QMessageBox(parent)
    box.setWindowTitle("Clear all history")
    box.setText("This will permanently delete all analyses and their uploaded files.")
    box.setInformativeText("This cannot be undone. Are you sure?")
    box.setIcon(QMessageBox.Icon.Warning)
    box.setStandardButtons(
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
    )
    box.setDefaultButton(QMessageBox.StandardButton.Cancel)
    return box.exec() == QMessageBox.StandardButton.Yes
