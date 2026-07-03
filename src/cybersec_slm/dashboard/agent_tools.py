#!/usr/bin/env python3
"""Read-only tool wrappers for the dashboard's Q&A agent.

Each function wraps :mod:`cybersec_slm.dashboard.data` and trims its output to
something small enough for an LLM's context window. Pure functions -> plain
dict/list; no Streamlit import, no network call, so every function is
unit-tested the same way ``data.py`` is: seed a tmp data root, call, assert.
"""

from __future__ import annotations

from . import data

_MAX_TEXT_EXCERPT = 200
_MAX_SEARCH_LIMIT = 25
_MAX_SIDECAR_LIMIT = 25


def get_pipeline_status() -> dict:
    """Is a run active, how many sources have completed, and the recent log tail."""
    status = data.run_status()
    prog = data.live_progress(tail=10)
    return {
        "state": status["state"],
        "age_seconds": status.get("age"),
        "sources_completed": prog["completed"],
        "sources_total": prog.get("total"),
        "log_tail": prog.get("log_tail", []),
    }


def get_eda_status() -> dict:
    """The most recent EDA sufficiency gate result (pass/fail, blockers, warnings, metrics)."""
    eda = data.latest_eda()
    if not eda:
        return {"available": False}
    violations = eda.get("violations", []) or []
    return {
        "available": True,
        "passed": eda.get("passed"),
        "ts": eda.get("ts"),
        "blockers": [v for v in violations if v.get("severity") == "blocker"],
        "warnings": [v for v in violations if v.get("severity") == "warning"],
        "metrics": eda.get("metrics", {}),
    }


def get_manifest_summary() -> dict:
    """Record/token counts and the domain/subdomain/source/language/license facets."""
    man = data.manifest()
    if not man:
        return {"available": False}
    return {
        "available": True,
        "record_count": man.get("record_count"),
        "token_total": man.get("token_total"),
        "domains": man.get("domains", {}),
        "subdomains": man.get("subdomains", {}),
        "sources": man.get("sources", {}),
        "languages": man.get("languages", {}),
        "licenses": man.get("licenses", {}),
    }


def get_source_table() -> list[dict]:
    """Per-source size/row-count/license summary rows."""
    return data.source_table()


def get_stage_reports() -> dict:
    """Cleaning and normalization stage totals."""
    return {"clean": data.clean_report().get("total"), "normalize": data.normalize_report()}


def search_dataset(query: str = "", domain: str | None = None, subdomain: str | None = None,
                    source: str | None = None, record_type: str | None = None,
                    lang: str | None = None, limit: int = 10) -> dict:
    """Keyword substring + facet search over the corpus; trimmed snippets, not full text."""
    filters = {k: v for k, v in {
        "domain": domain, "subdomain": subdomain, "source": source,
        "record_type": record_type, "lang": lang,
    }.items() if v}
    limit = max(1, min(int(limit), _MAX_SEARCH_LIMIT))
    result = data.dataset_page(filters=filters, search=query or "", offset=0, limit=limit)
    rows = [{
        "id": r.get("id"), "source": r.get("source"), "subdomain": r.get("subdomain_name"),
        "record_type": r.get("record_type"), "lang": r.get("lang"),
        "token_count": r.get("token_count"),
        "text_excerpt": (r.get("text") or "")[:_MAX_TEXT_EXCERPT],
    } for r in result["rows"]]
    return {"rows": rows, "match_count": result["match_count"], "capped": result["capped"]}


def get_rejected_or_dupes(kind: str = "rejected", limit: int = 10) -> list[dict]:
    """Preview records that didn't make it into the corpus (``kind`` selects the sink)."""
    limit = max(1, min(int(limit), _MAX_SIDECAR_LIMIT))
    return data.sidecar(kind, limit=limit)
