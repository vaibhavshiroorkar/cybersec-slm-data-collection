"""run_v2_pipeline calls ingest+clean -> final_global_dedup -> eda -> normalize."""
from cybersec_slm.ingestion import parallel


def test_pipeline_order(monkeypatch):
    order = []
    monkeypatch.setattr(parallel, "run_ingest_clean",
                        lambda *a, **k: order.append("ingest") or {"ok": 1})
    monkeypatch.setattr(parallel.cleaning_pipeline, "final_global_dedup",
                        lambda d, resume=False: order.append("dedup") or {"kept": 1})
    monkeypatch.setattr(parallel, "run_deep_eda",
                        lambda enforce=True: order.append("eda") or {"passed": True})
    monkeypatch.setattr(parallel, "run_normalize",
                        lambda resume=False: order.append("normalize") or {"n": 1})

    result = parallel.run_v2_pipeline(normalize=True)
    assert order == ["ingest", "dedup", "eda", "normalize"]
    assert result["phase"] == "complete"
