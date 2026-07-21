"""Shared isolation for the sourcing tests.

``cybersec_slm.core.LOGS`` is a module constant resolved from the data root at
*import* time, and ``sourcing.run`` binds it at import too. So a test that sets
``CYBERSEC_SLM_DATA_ROOT`` in a fixture does **not** re-point it, and
``run.discover()`` writes its review CSV and ``summary-*.json`` into the real
repo's ``logs/discovered/``. That is not just untidy: the dashboard reads the
newest summary back, so a test run leaves the UI reporting a sourcing run that
never happened.

This redirects it for every test in this package.
"""

from __future__ import annotations

import pytest

from cybersec_slm.core import DEFAULT_PROFILE as PROFILE


@pytest.fixture(autouse=True)
def _isolate_sourcing_logs(tmp_path, monkeypatch):
    from cybersec_slm.sourcing import orchestrator, run

    logs = str(tmp_path / "logs" / PROFILE)
    # The engine writes its review CSV + summary-*.json to ``orchestrator.LOGS`` (a
    # constant bound from the data root at import); ``run`` re-exports it. Redirect
    # both so a test run never writes into the real repo's logs (which the dashboard
    # reads back).
    monkeypatch.setattr(orchestrator, "LOGS", logs, raising=False)
    monkeypatch.setattr(run, "LOGS", logs, raising=False)
    yield
