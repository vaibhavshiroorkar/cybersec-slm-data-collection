#!/usr/bin/env python3
"""NVD CVE 2.0 API fetcher — paginated, rate-limited, normalised to schema.

    py -3.13 fetch_nvd.py              # fetch all CVEs
    py -3.13 fetch_nvd.py --key <key>  # with NVD API key (higher rate limit)

Rate limits (NVD 2.0 API):
  Without key: 5 requests / 30 s  ->  sleep 6 s between pages
  With key:    50 requests / 30 s ->  sleep 0.6 s between pages

Each CVE becomes one JSONL record:
    {source, url, license, text, cve_id, severity, published, modified}
"""

from __future__ import annotations

import os
import time

import orjson

from .common import ONE_MB, RAW_DATA, IngestLog, logger, sha256_file

PAGE_SIZE = 2000
_SLEEP_NO_KEY = 6.0
_SLEEP_WITH_KEY = 0.7


def _build_text(cve: dict) -> str:
    """Build a human-readable text block from one CVE object."""
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    metrics = cve.get("metrics", {})
    severity = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            severity = (f"CVSS {data.get('version','')}: "
                        f"{data.get('baseScore','')} "
                        f"({data.get('baseSeverity', '')})")
            break

    refs = [r.get("url", "") for r in cve.get("references", [])[:5] if r.get("url")]
    weaknesses = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en":
                weaknesses.append(d["value"])

    parts = []
    if cve_id:
        parts.append(f"CVE ID: {cve_id}")
    if severity:
        parts.append(f"Severity: {severity}")
    if weaknesses:
        parts.append(f"Weaknesses: {', '.join(weaknesses)}")
    if desc:
        parts.append(desc)
    if refs:
        parts.append("References: " + ", ".join(refs))
    return "\n".join(parts)


def fetch_nvd(domain: str, slug: str, title: str, lic: str, base_url: str,
              log: IngestLog, api_key: str | None = None) -> None:
    folder = os.path.join(RAW_DATA, domain, slug)
    os.makedirs(folder, exist_ok=True)
    logger.info(f"=== NVD API: {title} ===")

    sleep_secs = _SLEEP_WITH_KEY if api_key else _SLEEP_NO_KEY
    headers_extra = {"apiKey": api_key} if api_key else {}
    out_path = os.path.join(folder, slug + ".jsonl")
    total_results = None
    start = 0
    written = 0

    with open(out_path, "wb") as f:
        while True:
            url = f"{base_url}?startIndex={start}&resultsPerPage={PAGE_SIZE}"
            try:
                import httpx
                r = httpx.get(url, headers={**{"User-Agent": "Mozilla/5.0 (corpus-pipeline)"},
                                             **headers_extra},
                              follow_redirects=True, timeout=60)
                r.raise_for_status()
                data = orjson.loads(r.content)
            except Exception as ex:
                logger.error(f"  NVD page {start}: {type(ex).__name__}: {ex}")
                break

            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info(f"  total CVEs: {total_results:,}")

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                rec = {
                    "source": title,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "license": lic,
                    "text": _build_text(cve),
                    "cve_id": cve_id,
                    "severity": next(
                        (e[0].get("cvssData", {}).get("baseSeverity", "")
                         for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
                         if (e := cve.get("metrics", {}).get(key, []))),
                        ""),
                    "published": cve.get("published", ""),
                    "modified": cve.get("lastModified", ""),
                }
                f.write(orjson.dumps(rec) + b"\n")
                written += 1

            logger.info(f"  fetched {start + len(vulns):,} / {total_results:,}")
            start += PAGE_SIZE
            if start >= (total_results or 0):
                break
            time.sleep(sleep_secs)

    size = os.path.getsize(out_path)
    logger.info(f"  {written:,} CVEs, {size / ONE_MB:.1f} MB")
    log.record(kind="api", name=slug, category="API", domain=domain,
               description=title, source_url=base_url, origin_format="json",
               jsonl_mb=round(size / ONE_MB, 1), rows=written,
               sha256=sha256_file(out_path), license=lic, status="ok")


def run(log: IngestLog | None = None, api_key: str | None = None) -> None:
    from .manifest import APIS
    log = log or IngestLog()
    key = api_key or os.environ.get("NVD_API_KEY")
    for entry in APIS:
        try:
            fetch_nvd(*entry, log=log, api_key=key)
        except Exception as ex:
            logger.error(f"  FAILED {entry[1]}: {type(ex).__name__}: {ex}")


if __name__ == "__main__":
    import sys
    key = sys.argv[1] if len(sys.argv) > 1 else None
    run(api_key=key)
    logger.info("=== NVD DONE ===")
