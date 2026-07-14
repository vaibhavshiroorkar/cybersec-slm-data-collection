"""Offline tests for sourcing metadata enrichment (no real network)."""

from __future__ import annotations

from datetime import datetime

import pytest

from cybersec_slm.sourcing import enrich
from cybersec_slm.sourcing.enrich import Enricher, enrich_row


# ---------------------------------------------------------------- HF path ------
class _Sib:
    def __init__(self, name, size):
        self.rfilename = name
        self.size = size


class _HfInfo:
    cardData = {"license": "apache-2.0"}
    lastModified = datetime(2024, 3, 1, 10, 0, 0)
    siblings = [_Sib("train.jsonl", 2 * 1048576), _Sib("README.md", 100)]
    author = "CyberCorp"
    downloads = 1234
    tags = ["license:apache-2.0", "task_categories:text-classification",
            "cybersecurity"]


class _FakeHfApi:
    def dataset_info(self, ref, files_metadata=False):
        return _HfInfo()


def test_enrich_hf_fills_all_fields(monkeypatch):
    monkeypatch.setattr("huggingface_hub.HfApi", _FakeHfApi)
    row = {"Dataset Link": "https://huggingface.co/datasets/CyberCorp/threats"}
    out = enrich_row(row)
    assert out["License"] == "apache-2.0"
    assert out["Last Updated"] == "2024-03-01"
    assert out["Original Size (MB)"] == "2.00"        # only the data file counts
    assert out["File Count"] == "1"                   # README.md excluded
    assert out["Author"] == "CyberCorp"
    assert out["Popularity"] == "1234"
    assert "cybersecurity" in out["Tags"]
    assert "license:" not in out["Tags"]              # machine tags dropped


def test_enrich_never_overwrites_existing_value(monkeypatch):
    monkeypatch.setattr("huggingface_hub.HfApi", _FakeHfApi)
    row = {"Dataset Link": "https://huggingface.co/datasets/CyberCorp/threats",
           "License": "GPL-3.0"}
    out = enrich_row(row)
    assert out["License"] == "GPL-3.0"                # kept, not clobbered


def test_enrich_swallows_host_errors(monkeypatch):
    class _Boom:
        def dataset_info(self, *a, **k):
            raise RuntimeError("network down")
    monkeypatch.setattr("huggingface_hub.HfApi", _Boom)
    row = {"Dataset Link": "https://huggingface.co/datasets/x/y"}
    out = enrich_row(row)                             # must not raise
    assert out["Dataset Link"].endswith("x/y")
    assert "License" not in out                       # nothing filled


# ------------------------------------------------------------- GitHub path -----
class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


class _HeadResp:
    def __init__(self, headers):
        self.headers = headers


class _FakeClient:
    def __init__(self, get_resp=None, head_resp=None):
        self._get, self._head = get_resp, head_resp
        self.get_calls, self.head_calls = [], []

    def get(self, url, **kw):
        self.get_calls.append(url)
        return self._get

    def head(self, url, **kw):
        self.head_calls.append(url)
        return self._head


_GH_JSON = {"license": {"spdx_id": "MIT"}, "pushed_at": "2025-06-01T12:00:00Z",
            "size": 2048, "owner": {"login": "octo"}, "stargazers_count": 42,
            "topics": ["security", "nlp"]}


def test_enrich_github_fills_all_fields():
    client = _FakeClient(get_resp=_Resp(200, _GH_JSON))
    row = {"Dataset Link": "https://github.com/octo/repo"}
    out = Enricher(client=client).enrich(row)
    assert out["License"] == "MIT"
    assert out["Last Updated"] == "2025-06-01"
    assert out["Original Size (MB)"] == "2.00"        # 2048 KB / 1024
    assert out["Author"] == "octo"
    assert out["Popularity"] == "42"
    assert out["Tags"] == "security, nlp"


def test_enrich_github_rate_limit_disables_further_github_calls():
    client = _FakeClient(get_resp=_Resp(403, {}))
    e = Enricher(client=client)
    e.enrich({"Dataset Link": "https://github.com/a/b"})
    e.enrich({"Dataset Link": "https://github.com/c/d"})
    assert len(client.get_calls) == 1                 # second call skipped
    assert e._github_ok is False


# --------------------------------------------------------------- URL path ------
def test_enrich_url_head_fills_size_date_author():
    head = _HeadResp({"Content-Length": str(1048576),
                      "Last-Modified": "Wed, 01 Jan 2025 00:00:00 GMT"})
    client = _FakeClient(head_resp=head)
    row = {"Dataset Link": "https://example.com/data/threats.csv"}
    out = Enricher(client=client).enrich(row)
    assert out["Original Size (MB)"] == "1.00"
    assert out["File Count"] == "1"
    assert out["Last Updated"] == "2025-01-01"
    assert out["Author"] == "example.com"


def test_enrich_blank_link_is_noop():
    out = enrich_row({"Dataset Link": ""})
    assert out == {"Dataset Link": ""}


@pytest.mark.parametrize("val,expected", [
    (datetime(2024, 3, 1), "2024-03-01"),
    ("2025-06-01T12:00:00Z", "2025-06-01"),
    ("Wed, 01 Jan 2025 00:00:00 GMT", "2025-01-01"),
    ("garbage", ""),
    (None, ""),
])
def test_fmt_date_variants(val, expected):
    assert enrich._fmt_date(val) == expected
