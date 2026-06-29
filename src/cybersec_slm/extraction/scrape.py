#!/usr/bin/env python3
"""Unified scraper -> raw_data/<domain>/<slug>/ (original + jsonl + _SOURCE.json).

PDFs via PyMuPDF (one record per page); JSON feeds via httpx + orjson.
Shares common.py and records everything in the ingest log.

    py -3.13 scrape.py            # all PDFS + FEEDS from manifest
"""

import json
import os

import orjson
import pymupdf

from .common import ONE_MB, RAW_DATA, IngestLog, category_of, http_get, logger, sha256_file
from .manifest import FEEDS, PDFS, XML_FEEDS

BASE = RAW_DATA


def _source_file(folder, title, url, lic):
    json.dump({"source": title, "url": url, "license": lic},
              open(os.path.join(folder, "_SOURCE.json"), "w", encoding="utf-8"), indent=2)


def scrape_pdf(domain, slug, title, lic, url, log):
    folder = os.path.join(BASE, domain, slug); os.makedirs(folder, exist_ok=True)
    logger.info(f"=== PDF: {title} ===")
    r = http_get(url)
    if r.content[:4] != b"%PDF":
        logger.error(f"  not a PDF (HTTP {r.status_code})")
        log.record(kind="pdf", name=slug, category=category_of("pdf"), domain=domain,
                   description=title, source_url=url, origin_format="pdf",
                   license=lic, status="failed: not pdf")
        return
    open(os.path.join(folder, slug + ".pdf"), "wb").write(r.content)
    _source_file(folder, title, url, lic)
    out = os.path.join(folder, slug + ".jsonl")
    doc = pymupdf.open(stream=r.content, filetype="pdf"); n = 0
    with open(out, "w", encoding="utf-8") as f:
        for i, page in enumerate(doc, 1):
            txt = page.get_text().strip()
            if not txt:
                continue
            f.write(json.dumps({"source": title, "url": url, "license": lic,
                                "page": i, "text": txt}, ensure_ascii=False) + "\n")
            n += 1
    doc.close()
    size = os.path.getsize(out)
    logger.info(f"  {n} pages, {size/ONE_MB:.2f} MB")
    log.record(kind="pdf", name=slug, category=category_of("pdf"), domain=domain,
               description=title, source_url=url, origin_format="pdf",
               orig_mb=round(len(r.content) / ONE_MB, 1),
               jsonl_mb=round(size / ONE_MB, 1), rows=n, sha256=sha256_file(out),
               license=lic, status="ok")


def _normalize_feed_record(slug: str, rec: dict, title: str, feed_url: str, lic: str) -> dict:
    """Map a raw feed record to the standard {source, url, license, text} schema.

    MITRE STIX objects use `name` + `description`; CISA KEV uses structured
    vulnerability fields. Both need a proper `text` field so the cleaning
    stage does not drop them as structurally empty.
    """
    if slug.startswith("mitre-attack"):
        ext = rec.get("external_references", [])
        ref = next((r for r in ext if r.get("source_name", "").startswith("mitre")), {})
        name = rec.get("name", "")
        desc = rec.get("description", "")
        phases = [p.get("phase_name", "") for p in rec.get("kill_chain_phases", [])]
        parts = []
        if name:
            parts.append(f"Technique: {name}")
        if ref.get("external_id"):
            parts.append(f"ID: {ref['external_id']}")
        if phases:
            parts.append(f"Tactics: {', '.join(phases)}")
        if desc:
            parts.append(desc)
        return {
            "source": title,
            "url": ref.get("url", feed_url),
            "license": lic,
            "text": "\n\n".join(filter(None, parts)),
            "technique_id": ref.get("external_id", ""),
            "tactic": phases,
        }
    if slug == "cisa-kev":
        cve = rec.get("cveID", "")
        parts = []
        if cve:
            parts.append(f"CVE ID: {cve}")
        if rec.get("vulnerabilityName"):
            parts.append(f"Vulnerability: {rec['vulnerabilityName']}")
        vendor = f"{rec.get('vendorProject', '')} {rec.get('product', '')}".strip()
        if vendor:
            parts.append(f"Affected: {vendor}")
        if rec.get("shortDescription"):
            parts.append(rec["shortDescription"])
        if rec.get("requiredAction"):
            parts.append(f"Required Action: {rec['requiredAction']}")
        return {
            "source": title,
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "license": lic,
            "text": "\n".join(parts),
            "cve_id": cve,
            "date_added": rec.get("dateAdded", ""),
        }
    # Generic fallback: attach provenance; map first recognized field to text.
    out = {"source": title, "url": feed_url, "license": lic}
    out.update(rec)
    if "text" not in out:
        for candidate in ("description", "content", "body", "summary"):
            if out.get(candidate):
                out["text"] = out[candidate]
                break
    return out


def _records_from(data, json_key):
    """Extract a record list from a JSON feed, robust to shape.

    Prefers ``data[json_key]``; falls back to the data itself if it's already a
    list, otherwise the largest list-valued field (covers feeds whose key we
    couldn't guess, e.g. spreadsheet rows with no json_key column)."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get(json_key), list):
            return data[json_key]
        lists = [v for v in data.values() if isinstance(v, list)]
        if lists:
            return max(lists, key=len)
    return []


def scrape_feed(domain, slug, title, lic, url, json_key, log):
    folder = os.path.join(BASE, domain, slug); os.makedirs(folder, exist_ok=True)
    logger.info(f"=== FEED: {title} ===")
    r = http_get(url, timeout=240)
    data = orjson.loads(r.content)
    open(os.path.join(folder, slug + ".json"), "wb").write(r.content)
    _source_file(folder, title, url, lic)
    records = _records_from(data, json_key)
    if slug.startswith("mitre"):
        records = [o for o in records if o.get("type") == "attack-pattern"]
    out = os.path.join(folder, slug + ".jsonl")
    with open(out, "wb") as f:
        for rec in records:
            normalized = _normalize_feed_record(slug, rec, title, url, lic)
            f.write(orjson.dumps(normalized) + b"\n")
    size = os.path.getsize(out)
    logger.info(f"  {len(records):,} rows, {size/ONE_MB:.2f} MB")
    log.record(kind="feed", name=slug, category=category_of("feed"), domain=domain,
               description=title, source_url=url, origin_format="json",
               orig_mb=round(len(r.content) / ONE_MB, 1),
               jsonl_mb=round(size / ONE_MB, 1), rows=len(records),
               sha256=sha256_file(out), license=lic, status="ok")


def scrape_cwe(domain: str, slug: str, title: str, lic: str, url: str,
               log: IngestLog) -> None:
    """Download MITRE CWE XML ZIP and convert each weakness to a JSONL record."""
    import io
    import xml.etree.ElementTree as ET
    import zipfile

    folder = os.path.join(BASE, domain, slug)
    os.makedirs(folder, exist_ok=True)
    logger.info(f"=== CWE XML: {title} ===")

    r = http_get(url, timeout=120)
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        xml_name = next(n for n in z.namelist() if n.endswith(".xml"))
        xml_bytes = z.read(xml_name)

    open(os.path.join(folder, slug + ".xml"), "wb").write(xml_bytes)
    _source_file(folder, title, url, lic)

    root = ET.fromstring(xml_bytes)
    out = os.path.join(folder, slug + ".jsonl")
    n = 0
    with open(out, "w", encoding="utf-8") as f:
        for weakness in root.iter("{http://cwe.mitre.org/cwe-7}Weakness"):
            cwe_id = weakness.get("ID", "")
            name = weakness.get("Name", "")
            desc_el = weakness.find("{http://cwe.mitre.org/cwe-7}Description")
            ext_el = weakness.find("{http://cwe.mitre.org/cwe-7}Extended_Description")
            desc = (desc_el.text or "").strip() if desc_el is not None else ""
            ext = (ext_el.text or "").strip() if ext_el is not None else ""
            text = f"CWE-{cwe_id}: {name}\n\n{desc}"
            if ext:
                text += f"\n\n{ext}"
            rec = {
                "source": title,
                "url": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
                "license": lic,
                "text": text.strip(),
                "cwe_id": f"CWE-{cwe_id}",
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1

    size = os.path.getsize(out)
    logger.info(f"  {n} weaknesses, {size / ONE_MB:.2f} MB")
    log.record(kind="xml_feed", name=slug, category="Feed", domain=domain,
               description=title, source_url=url, origin_format="xml",
               orig_mb=round(len(r.content) / ONE_MB, 1),
               jsonl_mb=round(size / ONE_MB, 1), rows=n,
               sha256=sha256_file(out), license=lic, status="ok")


def run(log=None):
    log = log or IngestLog()
    for e in PDFS:
        try:
            scrape_pdf(*e, log)
        except Exception as ex:
            logger.error(f"  FAILED {e[2]}: {type(ex).__name__}: {ex}")
    for e in FEEDS:
        try:
            scrape_feed(*e, log)
        except Exception as ex:
            logger.error(f"  FAILED {e[2]}: {type(ex).__name__}: {ex}")
    for e in XML_FEEDS:
        try:
            scrape_cwe(*e, log)
        except Exception as ex:
            logger.error(f"  FAILED {e[1]}: {type(ex).__name__}: {ex}")


if __name__ == "__main__":
    run()
    logger.info("=== SCRAPE DONE ===")
