"""Tests for the orchestration helpers (Prefect-optional; no Prefect required)."""

from __future__ import annotations

from cybersec_slm.orchestration import flows


def test_module_imports_without_prefect():
    # the decorators degrade to no-ops, so tasks are plain callables
    assert callable(flows.extract_clean_source)
    assert callable(flows.build_corpus)


def test_load_descriptors_returns_manifest():
    ds = flows._load_descriptors()
    assert isinstance(ds, list) and len(ds) > 0
    assert all("kind" in d for d in ds)


def test_dvc_snapshot_noop_without_dvc(monkeypatch):
    monkeypatch.setattr(flows.shutil, "which", lambda _name: None)
    # must not raise even though there is no dvc binary
    flows._dvc_snapshot(push=True)
