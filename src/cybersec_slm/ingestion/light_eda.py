#!/usr/bin/env python3
"""Per-source light EDA — the ingestion-gate quality check.

Runs immediately after a source is fetched and converted to JSONL, *before*
the aggregated cleaning stage.  Its job is to **instantly reject** sources that
are corrupted or structurally unusable, and to **annotate** sources with
metadata flags (synthetic, license risk, security hazards) that downstream
stages can act on.

The check is deliberately fast (samples at most ``SAMPLE_SIZE`` records) and
conservative (it rejects only truly broken sources — a few bad records are
expected and handled by cleaning).

Rejection criteria (any one triggers rejection):
    1. No .jsonl files produced by fetch
    2. 0 valid records (100% parse errors)
    3. >80% of records have no usable text
    4. Median garbage ratio >0.50 across sampled records

Public API:
    assess_source(folder, descriptor) -> (passed, report)
"""

from __future__ import annotations

import json
import os
from statistics import median

from ..cleaning.common import PARSE_ERROR, find_input_files, text_of
from ..core import DROPPED, iter_jsonl, logger
from . import hazard_scan
from .license_gate import classify_license
from .sources import source_identity, synthetic_identities

SAMPLE_SIZE = 200

# Rejection thresholds
MAX_EMPTY_RATE = 0.80          # reject if >80% records have no usable text
MAX_MEDIAN_GARBAGE = 0.50      # reject if median garbage ratio >0.50


def _garbage_ratio(text: str) -> float:
    """Fraction of chars that are not alphanumeric, whitespace, or common punctuation."""
    if not text:
        return 0.0
    bad = sum(1 for c in text
              if not (c.isalnum() or c.isspace() or c in ".,;:!?'\"()[]{}-_/\\@#%&*+=<>|~`$^"))
    return bad / len(text)


def _collect_records(folder: str, *, max_records: int = SAMPLE_SIZE) -> list[dict]:
    """Load up to ``max_records`` valid records from a source folder."""
    records: list[dict] = []
    parse_errors = 0
    total = 0
    for ap, _sub, _source, _rel in find_input_files(folder):
        for rec in iter_jsonl(ap):
            total += 1
            if rec.get(PARSE_ERROR):
                parse_errors += 1
                continue
            records.append(rec)
            if len(records) >= max_records:
                break
        if len(records) >= max_records:
            break
    return records, total, parse_errors


def _count_all_records(folder: str) -> tuple[int, int]:
    """Count total records and parse errors in the folder (full scan)."""
    total = 0
    parse_errors = 0
    for ap, _sub, _source, _rel in find_input_files(folder):
        for rec in iter_jsonl(ap):
            total += 1
            if rec.get(PARSE_ERROR):
                parse_errors += 1
    return total, parse_errors


def _has_jsonl_files(folder: str) -> bool:
    """Check whether any .jsonl files exist under the folder."""
    for _ in find_input_files(folder):
        return True
    return False


# Hazard severities, least to most serious. Mirrors hazard_scan.scan_record's two
# levels; an unknown value sorts lowest rather than raising, so a new severity
# added there degrades to "reported" instead of breaking the ingest gate.
_SEVERITY_ORDER = ("info", "warning")


def _worse(candidate: str | None, current: str | None) -> bool:
    """True when ``candidate`` is a more serious severity than ``current``."""
    def rank(s: str | None) -> int:
        try:
            return _SEVERITY_ORDER.index(s or "info")
        except ValueError:
            return 0
    return current is None or rank(candidate) > rank(current)


def assess_source(folder: str, descriptor: dict, *,
                  synthetic_ids: frozenset[str] | None = None,
                  scan_hazards: bool = True) -> tuple[bool, dict]:
    """Run the light EDA gate on one fetched source.

    Parameters
    ----------
    folder : str
        Path to the source's raw output folder (data/raw/<domain>/<source>/).
    descriptor : dict
        The source descriptor from ``Sources.csv``.
    synthetic_ids : frozenset[str] | None
        Pre-loaded synthetic identities (avoids re-reading the catalog per source).
    scan_hazards : bool
        Whether to run the security-hazard scan (script/iframe injection, base64
        blobs, malware TLDs). Default True; set False for a non-security corpus
        where this check is irrelevant.

    Returns
    -------
    (passed, report) : (bool, dict)
        ``passed`` is False if the source should be rejected.  ``report`` is a
        structured dict with all findings + flags.
    """
    label = descriptor.get("ref") or descriptor.get("slug") or descriptor.get("kind")
    report: dict = {
        "source": label,
        "folder": folder,
        "passed": True,
        "reject_reason": None,
        "record_count": 0,
        "parse_error_count": 0,
        "empty_text_rate": 0.0,
        "median_garbage_ratio": 0.0,
        "flags": {
            "synthetic": False,
            "license_risk": None,
            "security_hazards": [],
        },
    }

    # --- Check 1: any .jsonl files at all? ---
    if not os.path.isdir(folder) or not _has_jsonl_files(folder):
        report["passed"] = False
        report["reject_reason"] = "no JSONL files produced by fetch"
        logger.warning(f"  light-eda REJECT {label}: {report['reject_reason']}")
        return False, report

    # --- Sample records ---
    records, total_sampled, parse_errors = _collect_records(folder)
    report["record_count"] = total_sampled
    report["parse_error_count"] = parse_errors

    # --- Check 2: any valid records? ---
    if not records:
        report["passed"] = False
        report["reject_reason"] = (
            f"0 valid records ({parse_errors} parse errors out of {total_sampled})"
        )
        logger.warning(f"  light-eda REJECT {label}: {report['reject_reason']}")
        return False, report

    # --- Check 3: empty-text rate ---
    empty = sum(1 for rec in records if not text_of(rec).strip())
    empty_rate = empty / len(records)
    report["empty_text_rate"] = round(empty_rate, 3)
    if empty_rate > MAX_EMPTY_RATE:
        report["passed"] = False
        report["reject_reason"] = (
            f"empty-text rate {empty_rate:.0%} exceeds {MAX_EMPTY_RATE:.0%} "
            f"({empty}/{len(records)} sampled records)"
        )
        logger.warning(f"  light-eda REJECT {label}: {report['reject_reason']}")
        return False, report

    # --- Check 4: garbage ratio (sampled) ---
    text_records = [rec for rec in records if text_of(rec).strip()]
    if text_records:
        garbage_ratios = [_garbage_ratio(text_of(rec)) for rec in text_records]
        med_garbage = median(garbage_ratios)
        report["median_garbage_ratio"] = round(med_garbage, 3)
        if med_garbage > MAX_MEDIAN_GARBAGE:
            report["passed"] = False
            report["reject_reason"] = (
                f"median garbage ratio {med_garbage:.2f} exceeds {MAX_MEDIAN_GARBAGE:.2f}"
            )
            logger.warning(f"  light-eda REJECT {label}: {report['reject_reason']}")
            return False, report

    # --- Flags: synthetic source ---
    if synthetic_ids is None:
        synthetic_ids = synthetic_identities()
    src_url = descriptor.get("url") or descriptor.get("start_url")
    ident = source_identity(src_url)
    if ident and ident in synthetic_ids:
        report["flags"]["synthetic"] = True
        logger.info(f"  light-eda FLAG {label}: synthetic source")

    # --- Flags: license risk ---
    lic_ok, lic_reason = classify_license(descriptor.get("license"))
    if not lic_ok:
        report["flags"]["license_risk"] = lic_reason

    # --- Flags: security hazards (sampled) ---
    hazards = hazard_scan.scan_source_sample(records, max_records=SAMPLE_SIZE) \
        if scan_hazards else []
    if hazards:
        # Summarize by type for the report (don't include full snippets at source
        # level). Each finding carries its own severity (scan_record assigns
        # "warning" to script/iframe, javascript: and shell metacharacters, "info"
        # to the rest); this used to hardcode "info" here and throw that away, so
        # every hazard reached the report looking equally unremarkable. Collapsing
        # by type means one row stands for many findings, so the row takes the
        # worst severity among them: an operator scanning the column needs to see
        # the reason to look, not whichever finding happened to sort last.
        type_counts: dict[str, int] = {}
        type_severity: dict[str, str] = {}
        for h in hazards:
            t = h["type"]
            type_counts[t] = type_counts.get(t, 0) + 1
            if _worse(h.get("severity"), type_severity.get(t)):
                type_severity[t] = h.get("severity") or "info"
        report["flags"]["security_hazards"] = [
            {"type": t, "count": c, "severity": type_severity.get(t, "info")}
            for t, c in sorted(type_counts.items())
        ]
        logger.info(f"  light-eda FLAG {label}: {len(hazards)} security hazard(s) "
                    f"across {len(type_counts)} type(s)")

    logger.info(f"  light-eda PASS {label}: {total_sampled} records, "
                f"{parse_errors} parse errors, "
                f"empty_rate={empty_rate:.1%}, "
                f"median_garbage={report['median_garbage_ratio']:.2f}")
    return True, report


def reject_source(folder: str, report: dict) -> None:
    """Move a rejected source's raw folder into ``data/dropped/`` with a sidecar report.

    The sidecar JSON is written alongside the moved folder so it is auditable.
    """
    if not os.path.isdir(folder):
        return
    # Destination: data/dropped/_rejected/<domain>/<source>/
    rel = os.path.relpath(folder, os.path.dirname(os.path.dirname(folder)))
    dest = os.path.join(DROPPED, "_rejected", rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)

    import shutil
    try:
        shutil.move(folder, dest)
    except (OSError, shutil.Error) as ex:
        logger.warning(f"  light-eda: could not move {folder} -> {dest}: {ex}")
        return

    # Write the sidecar report
    sidecar = dest + ".light_eda.json"
    try:
        with open(sidecar, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    except OSError:
        pass
    logger.info(f"  light-eda: rejected source moved to {dest}")
