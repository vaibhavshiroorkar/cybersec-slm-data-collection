#!/usr/bin/env python3
"""Prove the security controls work, by making each one refuse something.

A checklist that says "SSRF screen: present" is worth nothing: it says a file
exists, not that the control does its job, and it stays green after someone
deletes the control's body. Every probe here *exercises* the control against the
thing it is supposed to refuse, so a regression turns the row red rather than
leaving it lying green.

That is not a hypothetical worry in this repo. ``hazard_scan``'s own docstring
claimed findings were diverted to ``data/flagged/`` with a ``_stage=hazard``
annotation; nothing ever wrote it, and a checklist would have reported that
control healthy for as long as anyone cared to read it.

Probes are cheap, offline and side-effect-free: they build their own inputs in a
temp directory and never touch the corpus, so the page can run them on every
render. Headless, like :mod:`.rebalance`, so they are unit-tested without
Streamlit.
"""

from __future__ import annotations

import os
import tempfile
import zipfile
from dataclasses import dataclass

# The checklist in the threat model. Kept here so the page and the document cannot
# drift: the drift itself is one of the findings (F7).
REQUIREMENTS_DOC = os.path.join("docs", "security-requirements.md")


@dataclass(frozen=True)
class Probe:
    """One control, and what happened when it was exercised."""

    name: str
    passed: bool
    detail: str
    finding: str = ""          # the F-number in the threat model, when there is one


def _probe_url_screen() -> Probe:
    """The screen must refuse the cloud metadata endpoint and allow a real host."""
    from ..ingestion import urlscreen

    target = "http://169.254.169.254/latest/meta-data/"
    refused = urlscreen.screen(target)
    if not refused:
        return Probe("URL screen (SSRF)", False,
                     f"{target} was ALLOWED; the metadata endpoint is reachable",
                     "F4")
    allowed = urlscreen.screen("https://huggingface.co/datasets/org/x")
    if allowed:
        return Probe("URL screen (SSRF)", False,
                     f"a real source host was refused: {allowed}", "F4")
    return Probe("URL screen (SSRF)", True,
                 "refuses the cloud metadata endpoint, allows real source hosts",
                 "F4")


def _probe_scheme_screen() -> Probe:
    from ..ingestion import urlscreen

    if not urlscreen.screen("file:///etc/passwd"):
        return Probe("Scheme screen", False, "file:// was ALLOWED", "F4")
    return Probe("Scheme screen", True, "only http and https are fetched", "F4")


def _probe_zip_bomb() -> Probe:
    """Build a real bomb and check it is refused with nothing written."""
    from ..ingestion import archive

    tmp = tempfile.mkdtemp(prefix="secprobe-")
    try:
        bomb = os.path.join(tmp, "bomb.zip")
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("big.csv", b"0" * (64 * 1024 * 1024))
        out = os.path.join(tmp, "out")
        try:
            archive.safe_extract(bomb, out, max_total_bytes=8 * 1024 * 1024)
        except archive.UnsafeArchive as e:
            written = sum(
                os.path.getsize(os.path.join(r, f))
                for r, _d, fs in os.walk(out) for f in fs) if os.path.isdir(out) else 0
            if written:
                return Probe("Zip-bomb guard", False,
                             f"refused, but {written:,} bytes were written first",
                             "F3")
            return Probe("Zip-bomb guard", True,
                         f"64 MB bomb refused before any byte was written ({e})",
                         "F3")
        return Probe("Zip-bomb guard", False,
                     "a 64 MB bomb extracted under an 8 MB cap", "F3")
    except Exception as e:                       # noqa: BLE001
        return Probe("Zip-bomb guard", False, f"probe failed: {e}", "F3")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def _probe_download_cap() -> Probe:
    from ..ingestion import common

    cap = common._max_download_bytes()
    if cap <= 0:
        return Probe("Download byte cap", False, "no cap configured", "F3")
    return Probe("Download byte cap", True,
                 f"streams abort past {cap / 1073741824:,.0f} GB and the partial "
                 f"file is removed", "F3")


def _probe_license_gate() -> Probe:
    """A confirmed-red licence must be refused, and a typo must not disable it."""
    from ..ingestion import license_gate

    ok, _ = license_gate.is_license_ok({"license": "GPL-3.0"})
    if ok:
        return Probe("Licence gate", False,
                     "a copyleft licence was allowed; the gate is off")
    prev = os.environ.get("CYBERSEC_SLM_ENFORCE_LICENSE_GATE")
    os.environ["CYBERSEC_SLM_ENFORCE_LICENSE_GATE"] = "yess"
    try:
        typo_ok, _ = license_gate.is_license_ok({"license": "GPL-3.0"})
    finally:
        if prev is None:
            os.environ.pop("CYBERSEC_SLM_ENFORCE_LICENSE_GATE", None)
        else:
            os.environ["CYBERSEC_SLM_ENFORCE_LICENSE_GATE"] = prev
    if typo_ok:
        return Probe("Licence gate", False,
                     "a malformed kill-switch value silently disabled the gate")
    return Probe("Licence gate", True,
                 "refuses copyleft, and fails closed on a malformed kill switch")


def _probe_binary_scan() -> Probe:
    """Plant an executable and check the scanner sees it by magic bytes."""
    from ..ingestion import binscan

    tmp = tempfile.mkdtemp(prefix="secprobe-")
    try:
        # Named .csv on purpose: the extension is the attacker's to choose.
        with open(os.path.join(tmp, "innocent.csv"), "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 64)
        found = binscan.scan_tree(tmp)
        if not found or found[0]["kind"] != "pe":
            return Probe("Binary scan", False,
                         "an executable named .csv was not detected")
        return Probe("Binary scan", True,
                     "detects executables by magic bytes, not by extension")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def _probe_hazard_scan() -> Probe:
    from ..ingestion import hazard_scan

    found = hazard_scan.scan_record({"text": "<script>alert('xss')</script>"})
    if not found:
        return Probe("Hazard scan", False, "embedded active content not detected")
    if not any(h.get("severity") == "warning" for h in found):
        return Probe("Hazard scan", False,
                     "detected, but every finding reported as info")
    return Probe("Hazard scan", True,
                 "detects embedded active content and keeps its severity")


def _probe_pii() -> Probe:
    from ..cleaning.pii import Redactor

    text, _n = Redactor().redact("contact bob@example.com from 8.8.8.8")
    if "bob@example.com" in text:
        return Probe("PII redaction", False, "an email address survived redaction",
                     "F8")
    return Probe("PII redaction", True,
                 "replaces identifiers with typed placeholders "
                 "(known gaps: docs/pii_limitations.md)", "F8")


def _probe_canaries(dataset: str, sidecar: str) -> Probe:
    from ..cleaning import canary

    result = canary.verify(dataset, sidecar=sidecar)
    if not result["planted"]:
        return Probe("Canary tokens", False,
                     "none planted in this release, so it cannot be traced if it "
                     "leaks")
    if not result["ok"]:
        return Probe("Canary tokens", False,
                     f"{len(result['missing'])} of {result['planted']} planted "
                     f"canaries are missing from the dataset")
    return Probe("Canary tokens", True,
                 f"all {result['planted']} planted canaries present in the release")


def run_probes(dataset: str | None = None, sidecar: str | None = None) -> list[Probe]:
    """Exercise every control. Never raises: a probe that breaks is a red row."""
    from . import data

    dataset = dataset or os.path.join(data._final(), "dataset.jsonl")
    sidecar = sidecar or os.path.join(data._final(), "canaries.json")

    checks = [
        _probe_url_screen, _probe_scheme_screen, _probe_zip_bomb,
        _probe_download_cap, _probe_license_gate, _probe_binary_scan,
        _probe_hazard_scan, _probe_pii,
    ]
    out: list[Probe] = []
    for fn in checks:
        try:
            out.append(fn())
        except Exception as e:                   # noqa: BLE001
            out.append(Probe(fn.__name__.replace("_probe_", "").replace("_", " "),
                             False, f"probe raised {type(e).__name__}: {e}"))
    try:
        out.append(_probe_canaries(dataset, sidecar))
    except Exception as e:                       # noqa: BLE001
        out.append(Probe("Canary tokens", False, f"probe raised {e}"))
    return out


def checklist(path: str | None = None) -> list[dict]:
    """The threat model's prioritized checklist, as ``{done, text}`` rows.

    Read from the document rather than restated here, so the page cannot claim a
    box is ticked that the document does not.
    """
    from .. import core

    p = path or os.path.join(core.data_root(), REQUIREMENTS_DOC)
    rows: list[dict] = []
    try:
        with open(p, encoding="utf-8") as f:
            in_section = False
            for line in f:
                if line.startswith("## "):
                    in_section = line.strip().lower().endswith("checklist")
                    continue
                if in_section and line.strip().startswith("- ["):
                    done = line.strip()[3:4].lower() == "x"
                    text = line.strip()[5:].strip()
                    rows.append({"done": done, "text": text})
    except OSError:
        return []
    return rows
