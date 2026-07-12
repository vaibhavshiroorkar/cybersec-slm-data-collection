"""run_v2_pipeline runs the five stages in order: ingest -> clean -> eda -> schema."""
from cybersec_slm.ingestion import parallel


def test_pipeline_order(monkeypatch):
    order = []
    monkeypatch.setattr(parallel, "run_ingest",
                        lambda *a, **k: order.append("ingest") or {"ok": 1})
    monkeypatch.setattr(parallel, "run_clean",
                        lambda **k: order.append("clean") or {"out": 1, "dedup": {}})
    monkeypatch.setattr(parallel, "run_deep_eda",
                        lambda enforce=True: order.append("eda") or {"passed": True})
    monkeypatch.setattr(parallel, "run_normalize",
                        lambda resume=False: order.append("normalize") or {"n": 1})

    result = parallel.run_v2_pipeline(normalize=True)
    assert order == ["ingest", "clean", "eda", "normalize"]
    assert result["phase"] == "complete"
