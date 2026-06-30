#!/usr/bin/env python3
"""Auto-heal pass: re-run every source that failed or produced nothing, fix what
is fixable, and ledger what is not — so a run reaches its *achievable* 100%.

Run this AFTER tools/clean_sources.py. It does NOT touch dropped/ or flagged/
(those are correct removals — duplicates, parse errors, behavioral anomalies);
re-admitting them would corrupt the corpus. Instead it focuses on sources that
yielded no records and decides, per source, whether the cause is recoverable:

  recovered    a retry now produced records (transient WinError 2 folder race,
               network blip, etc.) — these are the wins.
  no_text      in>0 but out==0 with no error: a tabular / feature dataset with no
               natural-language column. 0 text records is correct, not a failure.
  dead_url     fetch returned HTTP 4xx (e.g. a moved NIST PDF). Needs a new URL.
  no_creds     kaggle source with no API token configured.
  error        some other error survived the retries (message kept verbatim).
  unmappable   spreadsheet row that never mapped to a source descriptor.

Retries run SERIALLY by default (--workers 1, in-process): the WinError 2 flood
in the original run was a filesystem race between 6 workers creating/cleaning/
deleting data/raw/ folders concurrently (made worse by Defender scanning the
malware-sample datasets), so healing one-at-a-time removes the race entirely.

    python tools/heal.py                       # heal all sub-domains, serial
    python tools/heal.py --subdomain Quantum
    python tools/heal.py --workers 2 --attempts 3
    python tools/heal.py report                # rebuild the ledger only, no fetching
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

# clean_sources.py pins the project paths / env and exposes the helpers we reuse.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import clean_sources as cs                                     # noqa: E402

from cybersec_slm import core                                  # noqa: E402
from cybersec_slm.cleaning import pipeline                     # noqa: E402
from cybersec_slm.ingestion import worker                     # noqa: E402

LEDGER_JSON = os.path.join(cs.PROJECT, "logs", "heal_ledger.json")
LEDGER_MD = os.path.join(cs.PROJECT, "logs", "heal_ledger.md")

DEFAULT_MAX_SOURCE_MB = 800.0      # skip (ledger) sources whose raw exceeds this


def _remote_size_mb(descriptor: dict) -> float | None:
    """Best-effort total raw size (MB) for a source WITHOUT downloading it.

    Uses metadata APIs (HF/Kaggle file lists, HTTP HEAD) so the oversize guard
    can skip a multi-GB source before paying for the download. Returns None when
    the size can't be determined cheaply (then the guard lets it through).
    """
    kind = descriptor.get("kind")
    try:
        if kind == "hf":
            from cybersec_slm.ingestion.common import (EXT_PRIORITY,
                                                        SKIP_SUBSTRINGS)
            from huggingface_hub import HfApi
            info = HfApi().dataset_info(descriptor["ref"], files_metadata=True)
            sizes = [(s.size or 0) for s in info.siblings
                     if s.rfilename.lower().endswith(EXT_PRIORITY)
                     and not any(x in s.rfilename.lower() for x in SKIP_SUBSTRINGS)]
            return sum(sizes) / (1024 * 1024) if sizes else None
        if kind == "kaggle":
            from kaggle.api.kaggle_api_extended import KaggleApi
            api = KaggleApi(); api.authenticate()
            files = api.dataset_list_files(descriptor["ref"]).files
            total = sum((getattr(f, "totalBytes", None)
                         or getattr(f, "total_bytes", 0) or 0) for f in files)
            return total / (1024 * 1024) if total else None
        if kind in ("url", "github"):
            from cybersec_slm.ingestion.common import remote_size
            url = descriptor.get("url")
            sz = remote_size(url) if url else None
            return sz / (1024 * 1024) if sz else None
    except Exception:
        return None
    return None        # pdf/feed/website: small, never guard

# Error-string fragments that mean "do not bother retrying — the source itself is
# the problem, not the environment".
_DEAD_URL = ("HTTPStatusError", "404", "403", "401", "Client error '4", "NoSuchKey")
_NO_CREDS = ("Could not find kaggle.json", "401 - Unauthorized", "KAGGLE",
             "authenticate", "access_token")
# Fragments that mean "transient — a retry may well succeed".
_TRANSIENT = ("WinError 2", "WinError 3", "WinError 32", "WinError 5",
              "ConnectError", "ConnectTimeout", "ReadTimeout", "ReadError",
              "PoolTimeout", "ProxyError", "RemoteProtocolError",
              "ConnectionError", "TimeoutException", "Temporary failure",
              "Connection reset", "BrokenProcessPool")


def _bucket(err: str | None, in_recs: int, out_recs: int) -> str:
    """Classify a source outcome into a ledger bucket."""
    if out_recs > 0:
        return "recovered"
    if not err:
        return "no_text" if in_recs > 0 else "empty_source"
    low = err.lower()
    if any(s.lower() in low for s in _DEAD_URL):
        return "dead_url"
    if any(s.lower() in low for s in _NO_CREDS):
        return "no_creds"
    if "unsupported file type" in low:
        return "unsupported_format"
    return "error"


def _is_transient(err: str | None) -> bool:
    return bool(err) and any(s in err for s in _TRANSIENT)


def _prior_results() -> dict:
    if os.path.exists(cs.RESULTS_JSON):
        with open(cs.RESULTS_JSON, encoding="utf-8") as f:
            return {int(k): v for k, v in json.load(f).items()}
    return {}


def _run_once(descriptor: dict) -> tuple[str, int, int, str | None]:
    """Fetch+clean one source in-process; return (status, in, out, error)."""
    meta = worker.process_source(descriptor, data_root=cs.PROJECT,
                                 clean_data_dir=core.CLEAN_DATA, keep_raw=False)
    rep = meta.get("clean_report_rows", [])
    in_recs = sum(int(x.get("in", 0)) for x in rep)
    out_recs = sum(int(x.get("out", 0)) for x in rep)
    return meta.get("status"), in_recs, out_recs, meta.get("error")


def _heal_serial(candidates: list[dict], attempts: int,
                 max_source_mb: float = DEFAULT_MAX_SOURCE_MB) -> dict[int, dict]:
    """Retry each candidate up to `attempts` times, serially. Stops early on a
    success (out>0) or a permanent error (dead url / unsupported). Sources whose
    raw exceeds `max_source_mb` are skipped (ledgered) before download."""
    results: dict[int, dict] = {}
    for n, r in enumerate(candidates, 1):
        d = r["descriptor"]
        label = r["name"]

        # oversize guard: probe size cheaply; skip multi-GB sources up front
        if max_source_mb:
            size_mb = _remote_size_mb(d)
            if size_mb and size_mb > max_source_mb:
                print(f"[heal {n}/{len(candidates)}] row{r['row_idx']} "
                      f"{str(d.get('kind')):7} -> oversize_skipped "
                      f"({size_mb:.0f} MB > {max_source_mb:.0f})  {str(label)[:45]}",
                      flush=True)
                results[r["row_idx"]] = {
                    "row_idx": r["row_idx"], "name": label, "url": r["url"],
                    "sub_domain": r["sub_domain"], "kind": d.get("kind"),
                    "status": "skipped", "in": 0, "out": 0,
                    "error": f"raw {size_mb:.0f} MB exceeds {max_source_mb:.0f} MB cap",
                    "bucket": "oversize_skipped"}
                continue

        status = "failed"
        in_recs = out_recs = 0
        err: str | None = "not attempted"
        for attempt in range(1, attempts + 1):
            try:
                status, in_recs, out_recs, err = _run_once(d)
            except Exception as ex:               # never let one source stop healing
                status, err = "failed", f"{type(ex).__name__}: {ex}"
            tag = _bucket(err, in_recs, out_recs)
            print(f"[heal {n}/{len(candidates)}] row{r['row_idx']} "
                  f"{str(d.get('kind')):7} try{attempt} -> {tag} "
                  f"in={in_recs} out={out_recs}  {str(label)[:50]}", flush=True)
            if out_recs > 0 or not _is_transient(err):
                break
            time.sleep(2 * attempt)               # brief backoff before retry
        results[r["row_idx"]] = {
            "row_idx": r["row_idx"], "name": label, "url": r["url"],
            "sub_domain": r["sub_domain"], "kind": d.get("kind"),
            "status": status, "in": in_recs, "out": out_recs, "error": err,
            "bucket": _bucket(err, in_recs, out_recs),
        }
    return results


def _build_ledger(rows: list[dict], heal_results: dict[int, dict],
                  prior: dict) -> dict:
    """Reconcile every spreadsheet row into a final bucket and write the ledger."""
    buckets: dict[str, list[dict]] = {}
    for r in rows:
        er = r["row_idx"]
        if r["descriptor"] is None:
            entry = {"row_idx": er, "name": r["name"], "url": r["url"],
                     "sub_domain": r["sub_domain"], "kind": None,
                     "bucket": "unmappable", "error": "row did not map to a source"}
        else:
            # ground truth: does data/clean/ now hold records for this row?
            _mb, lines = cs.clean_stats(cs.clean_dir_for(r["descriptor"]))
            src = heal_results.get(er) or prior.get(er) or {}
            in_recs = int(src.get("in", 0))
            err = src.get("error")
            heal_bucket = heal_results.get(er, {}).get("bucket")
            if lines > 0:
                bucket = "recovered" if er in heal_results else "ok"
            elif heal_bucket == "oversize_skipped":
                bucket = "oversize_skipped"
            else:
                bucket = _bucket(err, in_recs, 0)
            entry = {"row_idx": er, "name": r["name"], "url": r["url"],
                     "sub_domain": r["sub_domain"],
                     "kind": r["descriptor"].get("kind"),
                     "bucket": bucket, "in": in_recs, "out": lines, "error": err}
        buckets.setdefault(entry["bucket"], []).append(entry)

    summary = {k: len(v) for k, v in sorted(buckets.items())}
    ledger = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
              "summary": summary, "buckets": buckets}
    os.makedirs(os.path.dirname(LEDGER_JSON), exist_ok=True)
    with open(LEDGER_JSON, "w", encoding="utf-8") as f:
        json.dump(ledger, f, indent=2)
    _write_ledger_md(ledger)
    return ledger


def _write_ledger_md(ledger: dict) -> None:
    order = ["ok", "recovered", "no_text", "dead_url", "no_creds",
             "unsupported_format", "oversize_skipped", "empty_source", "error",
             "unmappable"]
    blurb = {
        "ok": "already had records (untouched)",
        "recovered": "produced records after the heal retry",
        "no_text": "tabular/feature data with no natural-language column (0 text is correct)",
        "dead_url": "source URL returned HTTP 4xx — needs a new/updated link",
        "no_creds": "kaggle source skipped (no API token configured)",
        "unsupported_format": "downloaded file could not be parsed as data",
        "oversize_skipped": "raw exceeds the size cap — skipped; run separately if wanted",
        "empty_source": "fetch produced no input rows at all",
        "error": "other error survived retries",
        "unmappable": "spreadsheet row never mapped to a source",
    }
    lines = ["# Heal ledger", "", f"Generated: {ledger['generated']}", "",
             "| bucket | count | meaning |", "|---|---:|---|"]
    for k in order:
        if k in ledger["summary"]:
            lines.append(f"| {k} | {ledger['summary'][k]} | {blurb.get(k,'')} |")
    actionable = [k for k in ("dead_url", "no_creds", "unsupported_format",
                              "oversize_skipped", "error", "unmappable")
                  if k in ledger["buckets"]]
    if actionable:
        lines += ["", "## Needs your attention", ""]
        for k in actionable:
            lines.append(f"### {k} — {blurb.get(k,'')}")
            for e in ledger["buckets"][k]:
                err = f" — {e.get('error')}" if e.get("error") else ""
                lines.append(f"- row {e['row_idx']} · {e['sub_domain']} · "
                             f"{e['name']} · {e.get('url','')}{err}")
            lines.append("")
    with open(LEDGER_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _defender_exclusion(path: str) -> None:
    """Best-effort: exclude data/raw/ from Defender real-time scanning so fetching
    the malware-sample datasets doesn't trigger quarantine mid-run. Needs admin;
    on failure we print the manual command instead of aborting."""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Add-MpPreference -ExclusionPath '{path}'"],
            check=True, capture_output=True, timeout=30)
        print(f"[heal] added Windows Defender exclusion for {path}", flush=True)
    except Exception:
        print("[heal] could not add a Defender exclusion automatically "
              "(run this once, as admin, to avoid malware-dataset quarantines):",
              flush=True)
        print(f'        powershell -Command "Add-MpPreference -ExclusionPath '
              f"'{path}'\"", flush=True)


def heal(subdomain: str | None, workers: int, attempts: int,
         add_exclusion: bool, max_source_mb: float = DEFAULT_MAX_SOURCE_MB) -> None:
    if add_exclusion:
        _defender_exclusion(core.RAW_DATA)

    rows = cs.load_rows(subdomain)
    prior = _prior_results()

    # A row needs healing when data/clean/ holds no records for it AND it isn't a
    # known text-less table (prior run: ok, in>0, out==0) — those aren't failures.
    candidates = []
    for r in rows:
        if r["descriptor"] is None:
            continue
        _mb, lines = cs.clean_stats(cs.clean_dir_for(r["descriptor"]))
        if lines > 0:
            continue
        p = prior.get(r["row_idx"], {})
        if p.get("status") == "ok" and int(p.get("in", 0)) > 0 and int(p.get("out", 0)) == 0:
            continue                                   # text-less table: skip retry
        candidates.append(r)

    scope = subdomain or "all sub-domains"
    print(f"[heal] {scope}: {len(rows)} rows, "
          f"{len(candidates)} need healing (workers={workers}, attempts={attempts})",
          flush=True)

    heal_results: dict[int, dict] = {}
    if candidates:
        if workers and workers > 1:
            heal_results = _heal_parallel(candidates, workers, attempts, max_source_mb)
        else:
            heal_results = _heal_serial(candidates, attempts, max_source_mb)

    # one cross-source dedup pass over everything (re)written, then mark + ledger
    try:
        pipeline.final_global_dedup(core.CLEAN_DATA)
    except Exception as ex:
        print(f"[heal] final dedup skipped: {ex}", flush=True)

    mappable = {r["row_idx"] for r in rows if r["descriptor"]}
    cs.mark_csv(cs.collect_stats(rows), mappable)
    ledger = _build_ledger(rows, heal_results, prior)

    print("\n===== HEAL SUMMARY =====", flush=True)
    for k, v in ledger["summary"].items():
        print(f"  {k:18}: {v}", flush=True)
    print(f"ledger -> {LEDGER_MD}", flush=True)


def _heal_parallel(candidates: list[dict], workers: int, attempts: int,
                   max_source_mb: float = DEFAULT_MAX_SOURCE_MB) -> dict[int, dict]:
    """Pooled retry (faster, but reintroduces some folder contention). Each task
    still retries internally; transient failures are retried in-process."""
    import multiprocessing as mp
    from concurrent.futures import ProcessPoolExecutor, as_completed
    results: dict[int, dict] = {}
    # apply the oversize guard before submitting (skip multi-GB sources)
    runnable = []
    for r in candidates:
        size_mb = _remote_size_mb(r["descriptor"]) if max_source_mb else None
        if size_mb and size_mb > max_source_mb:
            results[r["row_idx"]] = {
                "row_idx": r["row_idx"], "name": r["name"], "url": r["url"],
                "sub_domain": r["sub_domain"], "kind": r["descriptor"].get("kind"),
                "status": "skipped", "in": 0, "out": 0,
                "error": f"raw {size_mb:.0f} MB exceeds {max_source_mb:.0f} MB cap",
                "bucket": "oversize_skipped"}
            print(f"[heal] row{r['row_idx']} oversize_skipped "
                  f"({size_mb:.0f} MB)  {str(r['name'])[:45]}", flush=True)
        else:
            runnable.append(r)
    candidates = runnable
    ctx = mp.get_context("spawn")
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as ex:
        futs = {ex.submit(worker.process_source, r["descriptor"], data_root=cs.PROJECT,
                          clean_data_dir=core.CLEAN_DATA, keep_raw=False): r
                for r in candidates}
        for n, fut in enumerate(as_completed(futs), 1):
            r = futs[fut]
            try:
                meta = fut.result()
                rep = meta.get("clean_report_rows", [])
                in_recs = sum(int(x.get("in", 0)) for x in rep)
                out_recs = sum(int(x.get("out", 0)) for x in rep)
                status, err = meta.get("status"), meta.get("error")
            except Exception as ex2:
                status, in_recs, out_recs, err = "failed", 0, 0, f"{type(ex2).__name__}: {ex2}"
            results[r["row_idx"]] = {
                "row_idx": r["row_idx"], "name": r["name"], "url": r["url"],
                "sub_domain": r["sub_domain"], "kind": r["descriptor"].get("kind"),
                "status": status, "in": in_recs, "out": out_recs, "error": err,
                "bucket": _bucket(err, in_recs, out_recs)}
            print(f"[heal {n}/{len(candidates)}] row{r['row_idx']} "
                  f"{_bucket(err, in_recs, out_recs)} in={in_recs} out={out_recs} "
                  f"{str(r['name'])[:50]}", flush=True)
    return results


def main():
    p = argparse.ArgumentParser(description="Retry failed/empty sources and ledger the rest")
    p.add_argument("action", nargs="?", default="heal", choices=["heal", "report"])
    p.add_argument("--subdomain", default=None)
    p.add_argument("--workers", type=int, default=1,
                   help="serial (1, default) avoids the WinError 2 folder race")
    p.add_argument("--attempts", type=int, default=2,
                   help="retries per source for transient failures")
    p.add_argument("--no-defender-exclusion", action="store_true",
                   help="skip trying to add a data/raw/ Defender exclusion")
    p.add_argument("--max-source-mb", type=float, default=DEFAULT_MAX_SOURCE_MB,
                   help="skip (ledger) sources whose raw exceeds this many MB "
                        "(0 = no cap)")
    args = p.parse_args()

    if args.action == "report":
        rows = cs.load_rows(args.subdomain)
        ledger = _build_ledger(rows, {}, _prior_results())
        for k, v in ledger["summary"].items():
            print(f"  {k:18}: {v}")
        print(f"ledger -> {LEDGER_MD}")
    else:
        heal(args.subdomain, args.workers, args.attempts,
             add_exclusion=not args.no_defender_exclusion,
             max_source_mb=args.max_source_mb)


if __name__ == "__main__":
    main()
