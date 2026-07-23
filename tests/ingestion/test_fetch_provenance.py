"""Provenance written into each record at ingest.

Every record carries a ``source`` so the cleaning and normalize stages can tell
which catalogued source it came from. That field is an identity, so it has to be
the source's name; the description is prose and is logged separately.
"""

import json

import pytest

from cybersec_slm.ingestion import fetch


class _Log:
    def __init__(self):
        self.records = []

    def record(self, **kw):
        self.records.append(kw)


@pytest.fixture
def csv_file(tmp_path):
    p = tmp_path / "rows.csv"
    p.write_text("text,label\nheap overflow in the parser,vuln\n"
                 "sql injection in the login form,vuln\n", encoding="utf-8")
    return str(p)


def _records(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


DESC = ("OSV records of known-malicious npm/PyPI packages, with the "
        "advisory text and affected version ranges.")


def test_converting_a_file_records_the_source_name_not_its_description(tmp_path,
                                                                       csv_file):
    """The bug: record_meta used ``desc``, so a sentence of prose became the
    provenance of every record. 61% of the live corpus was filed that way, under
    188 distinct prose "sources", which is how the funnel's Final row came to
    claim more sources than data/clean has folders.
    """
    out = str(tmp_path / "out.jsonl")

    fetch._convert_and_log(csv_file, out, _Log(), kind="url", name="ossf-malicious-packages",
                           domain="Application Security", desc=DESC,
                           url="https://x/1", lic="MIT")

    recs = _records(out)
    assert recs
    for r in recs:
        assert r["source"] == "ossf-malicious-packages"
        assert DESC not in str(r.get("source"))


def test_combining_an_archives_files_records_the_source_name(tmp_path, csv_file):
    """The repo/zip path builds its own record_meta and had the same bug."""
    out = str(tmp_path / "combined.jsonl")

    fetch._combine_to_jsonl([csv_file], out, _Log(), kind="github", name="zeovan",
                            domain="Application Security", desc=DESC,
                            url="https://x/2", lic="MIT", origin_fmt="csv")

    recs = _records(out)
    assert recs
    for r in recs:
        assert r["source"] == "zeovan"


def test_the_description_is_still_logged_as_the_sources_description(tmp_path,
                                                                    csv_file):
    """Fixing provenance must not lose the description: it belongs on the ingest
    log row, which is where the catalog and the dashboard read it from."""
    log = _Log()

    fetch._convert_and_log(csv_file, str(tmp_path / "out.jsonl"), log, kind="url",
                           name="zeovan", domain="Application Security", desc=DESC,
                           url="https://x/1", lic="MIT")

    [row] = log.records
    assert row["description"] == DESC
    assert row["name"] == "zeovan"


def test_url_and_license_still_ride_on_every_record(tmp_path, csv_file):
    out = str(tmp_path / "out.jsonl")

    fetch._convert_and_log(csv_file, out, _Log(), kind="url", name="zeovan",
                           domain="Application Security", desc=DESC,
                           url="https://x/1", lic="Apache-2.0")

    for r in _records(out):
        assert r["url"] == "https://x/1"
        assert r["license"] == "Apache-2.0"
