"""Shared isolation for the dashboard tests.

``cybersec_slm.core.LOGS`` is a module constant resolved from the data root at
*import* time, so a test that sets ``CYBERSEC_SLM_DATA_ROOT`` in a fixture does
**not** re-point it. ``run_all.main()`` therefore wrote its ``active_run_log.txt``
pointer into the REAL repo's ``logs/``.

That is not merely untidy. The dashboard reads that pointer to decide which log
belongs to the live run, so running this suite while a pipeline is going made the
UI follow a *test's* log — reporting "stage 5/5: schema" over a run that was
actually mid-clean, and hiding the real run's progress.

This redirects it for every test in this package.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_dashboard_logs(tmp_path, monkeypatch):
    from cybersec_slm import core

    monkeypatch.setattr(core, "LOGS", str(tmp_path / "logs"), raising=False)
    yield
