#!/usr/bin/env python3
"""Model-judged catalog review - a curation aid (propose-only by default).

Judges every catalog row against a condition stated in plain English ("the data
must concern India") and records approve / decline / review with the model's
reason. No condition is baked in: geography is simply one thing you can ask for.

It runs as two passes on purpose::

    source review --condition "..."   -> logs/reviews/review-<ts>.csv
    source review --apply             -> replays that report

``--apply`` replays the recorded report rather than judging again. A model verdict
is not reproducible, so a second pass would act on judgements you never saw; the
report is both the thing you approved and the audit trail for why a source left
the corpus. Declined rows move to the profile's ``Excluded.csv`` (schema plus an
``Excluded Reason``) and are deleted from the catalog, mirroring
:mod:`sourcing.blacklist` - so ``Blacklist.csv`` keeps meaning strictly
"license is confirmed red", and an excluded row is recoverable with its reason.

Two limits worth knowing. The model sees catalog *metadata* (Name, Sub-Domain,
Description, link, Category), never the records, and Descriptions are search
snippets - a source that is genuinely in scope but never says so will be
declined. And ``review`` verdicts (an unparseable reply, an error, low
confidence) are never applied; they are left for a human, as
:mod:`sourcing.synthetic_scan` does.

Public API:
    classify_row(row, condition, *, cli=None) -> (verdict, confidence, reason)
    scan(condition, spec=None, *, cli=None)   -> list[dict]
    run_scan(condition, spec=None, *, apply=False, cli=None) -> dict
    apply_report(path=None, *, spec=None, condition=None) -> dict
"""

from __future__ import annotations

import csv
import glob
import json
import os
import re
import time

from .. import llm
from ..core import LOGS, logger
from ..ingestion.sources import CATALOG_COLUMNS
from . import profiles, sheet

APPROVE = "approve"
DECLINE = "decline"
REVIEW = "review"
VERDICTS = (APPROVE, DECLINE, REVIEW)

# Below this the verdict is downgraded to `review`: the model saying "decline,
# 0.3" is not a basis for removing a source from the corpus.
MIN_APPLY_CONFIDENCE = 0.7

REPORT_COLS = ("condition", "name", "sub_domain", "link", "category",
               "verdict", "confidence", "reason")

EXCLUDED_REASON_COL = "Excluded Reason"

SYSTEM_PROMPT = (
    "You judge whether a dataset belongs in a training corpus, given a condition. "
    "You see only the catalog metadata for one source, never its data. "
    "Reply with ONLY a JSON object, no prose and no code fence: "
    '{"verdict": "approve"|"decline"|"review", "confidence": 0.0-1.0, '
    '"reason": "<one short sentence>"}. '
    "Use approve when the source plainly meets the condition, decline when it "
    "plainly does not, and review when the metadata is too thin to tell — "
    "prefer review over guessing, because a decline removes the source."
)


def reviews_dir() -> str:
    return os.path.join(LOGS, "reviews")


def excluded_path(profile: str | None = None) -> str:
    """The active profile's ``Excluded.csv`` (sits beside its ``Sources.csv``)."""
    return os.path.join(profiles.profile_dir(profile), "Excluded.csv")


def _row_link(row: dict) -> str:
    for key in ("Dataset Link", "dataset_link", "url", "link"):
        val = str(row.get(key) or "").strip()
        if val:
            return val
    return ""


def _prompt(row: dict, condition: str) -> str:
    return (
        f"Condition: {condition}\n\n"
        "Source metadata:\n"
        f"  Name: {row.get('Name') or '(none)'}\n"
        f"  Sub-Domain: {row.get('Sub-Domain') or '(none)'}\n"
        f"  Category: {row.get('Category') or '(none)'}\n"
        f"  Link: {_row_link(row) or '(none)'}\n"
        f"  Description: {row.get('Description') or '(none)'}\n\n"
        "Does this source meet the condition?"
    )


def _parse(reply: str) -> tuple[str, float, str]:
    """Read the model's JSON reply; anything unreadable becomes a `review`.

    The reply is untrusted input: a model can wrap JSON in a fence, add prose, or
    invent a verdict. Nothing here may raise, because one bad reply must not end a
    scan over a whole catalog.
    """
    if not reply:
        return REVIEW, 0.0, "empty reply from the model"
    text = reply.strip()
    if text.startswith("```"):                       # strip a ``` / ```json fence
        text = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", text).strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)    # tolerate prose around it
    if not match:
        return REVIEW, 0.0, f"unparseable reply: {reply[:80]}"
    try:
        data = json.loads(match.group(0))
    except ValueError:
        return REVIEW, 0.0, f"unparseable reply: {reply[:80]}"
    if not isinstance(data, dict):
        return REVIEW, 0.0, f"unparseable reply: {reply[:80]}"

    verdict = str(data.get("verdict") or "").strip().lower()
    if verdict not in VERDICTS:
        return REVIEW, 0.0, f"unknown verdict {verdict!r}"
    try:
        confidence = max(0.0, min(1.0, float(data.get("confidence"))))
    except (TypeError, ValueError):
        confidence = 0.0
    reason = str(data.get("reason") or "").strip()[:200] or "(no reason given)"
    return verdict, confidence, reason


def classify_row(row: dict, condition: str, *, cli=None) -> tuple[str, float, str]:
    """``(verdict, confidence, reason)`` for one catalog row.

    A per-row failure (timeout, rate limit, refusal) becomes a `review`, so a
    partial scan still yields a usable report. A *systemic* failure — no key, no
    SDK — is raised by :func:`llm.client` before any row is judged.
    """
    try:
        reply = llm.ask(SYSTEM_PROMPT, _prompt(row, condition), cli=cli)
    except llm.LLMUnavailable:
        raise
    except Exception as exc:                    # noqa: BLE001 — one row, not the run
        return REVIEW, 0.0, f"{type(exc).__name__}: {exc}"[:200]
    verdict, confidence, reason = _parse(reply)
    if verdict == DECLINE and confidence < MIN_APPLY_CONFIDENCE:
        return REVIEW, confidence, f"low-confidence decline: {reason}"
    return verdict, confidence, reason


def _catalog_rows(spec: str | None) -> tuple[str, list[dict]]:
    path = spec or profiles.catalog_path()
    if not os.path.exists(path):
        return path, []
    with open(path, encoding="utf-8", newline="") as f:
        return path, list(csv.DictReader(f))


def scan(condition: str, spec: str | None = None, *, cli=None) -> list[dict]:
    """Judge every catalog row; one result dict per row (never writes anything)."""
    _path, rows = _catalog_rows(spec)
    cli = cli or llm.client()               # fail before judging anything
    out: list[dict] = []
    for row in rows:
        verdict, confidence, reason = classify_row(row, condition, cli=cli)
        out.append({
            "condition": condition,
            "name": row.get("Name") or "",
            "sub_domain": row.get("Sub-Domain") or "",
            "link": _row_link(row),
            "category": row.get("Category") or "",
            "verdict": verdict,
            "confidence": f"{confidence:.2f}",
            "reason": reason,
        })
    return out


def _write_report(results: list[dict], path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=REPORT_COLS)
        w.writeheader()
        for r in results:
            w.writerow({c: r.get(c, "") for c in REPORT_COLS})
    return path


def latest_report() -> str | None:
    """Newest ``logs/reviews/review-*.csv``, or None."""
    paths = sorted(glob.glob(os.path.join(reviews_dir(), "review-*.csv")))
    return paths[-1] if paths else None


def read_report(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def run_scan(condition: str, spec: str | None = None, *, apply: bool = False,
             cli=None) -> dict:
    """Judge the catalog and write a report; optionally apply it in the same call.

    Returns ``{"report", "counts", "results"}``. Applying here still goes through
    :func:`apply_report`, so a one-shot run and a two-step run remove exactly the
    same rows.
    """
    condition = (condition or "").strip()
    if not condition:
        raise ValueError("a --condition is required to review the catalog")

    results = scan(condition, spec, cli=cli)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    path = _write_report(results, os.path.join(reviews_dir(), f"review-{stamp}.csv"))

    counts = {v: sum(1 for r in results if r["verdict"] == v) for v in VERDICTS}
    logger.info(f"review: {len(results)} source(s) judged -> " +
                " ".join(f"{v}={counts[v]}" for v in VERDICTS))
    logger.info(f"review: report -> {path}")

    out = {"report": path, "counts": counts, "results": results}
    if apply:
        out["applied"] = apply_report(path, spec=spec, condition=condition)
    else:
        logger.info("review: propose-only — re-run with --apply to move the "
                    f"{counts[DECLINE]} declined source(s)")
    return out


def _append_excluded(path: str, rows: list[dict]) -> None:
    """Append rows to Excluded.csv, creating it with the catalog schema + reason."""
    cols = list(CATALOG_COLUMNS) + [EXCLUDED_REASON_COL]
    exists = os.path.exists(path) and os.path.getsize(path) > 0
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        if not exists:
            w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})


def apply_report(path: str | None = None, *, spec: str | None = None,
                 condition: str | None = None) -> dict:
    """Replay a review report: move its declined rows out of the catalog.

    ``condition``, when given, must match the condition the report was generated
    for — applying a report you built for a different question would silently
    remove sources for a reason you never asked about.

    Only high-confidence ``decline`` rows move; ``review`` and ``approve`` are left
    alone. Idempotent: a replayed report finds its rows already gone and no-ops.
    """
    path = path or latest_report()
    if not path or not os.path.exists(path):
        return {"moved": 0, "rows": [], "report": path}

    report = read_report(path)
    recorded = {r.get("condition", "") for r in report} or {""}
    if condition is not None and recorded != {condition.strip()}:
        raise ValueError(
            f"report {os.path.basename(path)} was generated for "
            f"{sorted(recorded)!r}, not {condition.strip()!r} — re-run the review "
            "or apply it without --condition")

    declined = {r["link"] for r in report
                if r.get("verdict") == DECLINE and r.get("link")}
    if not declined:
        logger.info(f"review: nothing to apply from {os.path.basename(path)}")
        return {"moved": 0, "rows": [], "report": path}

    reasons = {r["link"]: r.get("reason", "") for r in report}
    csv_path, rows = _catalog_rows(spec)
    hit = [r for r in rows if _row_link(r) in declined]
    if not hit:
        logger.info("review: declined sources are already out of the catalog")
        return {"moved": 0, "rows": [], "report": path}

    for r in hit:
        r[EXCLUDED_REASON_COL] = reasons.get(_row_link(r), "")
    _append_excluded(excluded_path(), hit)
    sheet.delete_rows(csv_path, links=[_row_link(r) for r in hit])

    logger.info(f"review: moved {len(hit)} source(s) -> "
                f"{os.path.relpath(excluded_path())}")
    return {"moved": len(hit),
            "rows": [{"name": r.get("Name", ""), "link": _row_link(r),
                      "reason": r.get(EXCLUDED_REASON_COL, "")} for r in hit],
            "report": path}
