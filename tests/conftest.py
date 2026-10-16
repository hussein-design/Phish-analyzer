"""conftest.py — shared pytest fixtures for the Phish Analyzer test suite.

QApplication fixture
────────────────────
PySide6 widgets require a running QApplication before they can be
instantiated.  Without one the process aborts immediately (no Python
exception — a hard C++ abort) which kills the entire test session.

The ``qapp`` session-scoped, autouse fixture creates exactly one
QApplication for the whole test run.  Because it is ``autouse=True`` it
applies to every test without needing to be requested explicitly.

The QApplication is only actually created on the first use; subsequent
``QApplication.instance()`` calls return the existing one, so there is no
overhead for tests that do not use widgets.
"""

from __future__ import annotations

import sys
import pytest


@pytest.fixture(scope="session", autouse=True)
def qapp():
    """Session-scoped QApplication — created once, reused by all tests.

    ``autouse=True`` ensures it is available before any test tries to
    instantiate a Qt widget.  Tests that do not use Qt widgets incur only
    the cost of a ``QApplication.instance()`` call (effectively free).
    """
    try:
        from PySide6.QtWidgets import QApplication

        app = QApplication.instance()
        if app is None:
            # sys.argv must be provided; Qt expects at least argv[0].
            app = QApplication(sys.argv)
        yield app
        # Do NOT call app.exec_() or app.quit() — tests do not enter the
        # event loop, and pytest manages process exit.
    except ImportError:
        # PySide6 not installed — yield None and let individual widget tests
        # fail on import rather than crashing the whole session.
        yield None
