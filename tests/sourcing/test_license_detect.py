"""Offline tests for deep license detection (no real network)."""

from __future__ import annotations

import pytest

from cybersec_slm.sourcing import license_detect as ld


# ------------------------------------------------------------- normalization ----
@pytest.mark.parametrize("raw,expected", [
    ("https://creativecommons.org/licenses/by/4.0/", "CC BY 4.0"),
    ("https://creativecommons.org/licenses/by-nc-sa/4.0/", "CC BY-NC-SA 4.0"),
    ("https://creativecommons.org/publicdomain/zero/1.0/", "CC0-1.0"),
    ("Creative Commons Attribution-ShareAlike v4.0", "CC BY-SA 4.0"),
    ("cc-by-nc-4.0", "CC BY-NC 4.0"),
    ("Apache 2.0", "Apache-2.0"),
    ("apache-2.0", "Apache-2.0"),
    ("MIT license", "MIT"),
    ("GPL-3.0", "GPL-3.0"),
    ("CC0: Public Domain", "CC0-1.0"),
    ("All Rights Reserved", "All Rights Reserved"),
    ("EPL-2.0", "EPL-2.0"),                    # unknown-but-SPDX-shaped: passthrough
    ("NOASSERTION", ""),
    ("", ""),
    (None, ""),
])
def test_normalize_license(raw, expected):
    assert ld.normalize_license(raw) == expected


# ------------------------------------------------------ pure host extractors ----
class _HfInfo:
    def __init__(self, card=None, tags=None):
        self.cardData = card or {}
        self.tags = tags or []


def test_license_from_hf_info_card():
    assert ld.license_from_hf_info(_HfInfo(card={"license": "apache-2.0"})) == "Apache-2.0"


def test_license_from_hf_info_tag_fallback():
    info = _HfInfo(card={}, tags=["task_categories:x", "license:mit"])
    assert ld.license_from_hf_info(info) == "MIT"


def test_license_from_github_json():
    assert ld.license_from_github_json({"license": {"spdx_id": "MIT"}}) == "MIT"
    assert ld.license_from_github_json({"license": {"spdx_id": "NOASSERTION"}}) == ""
    assert ld.license_from_github_json({"license": None}) == ""


# ------------------------------------------------------------ HTML detectors ----
def _patch_html(monkeypatch, html):
    monkeypatch.setattr(ld, "_get_text", lambda *a, **k: html)


def test_detect_kaggle_json_ld(monkeypatch):
    _patch_html(monkeypatch, '<script>{"license":{"@type":"CreativeWork",'
                             '"name":"Apache 2.0","url":"x"}}</script>')
    assert ld.detect_license("https://www.kaggle.com/datasets/a/b") == "Apache-2.0"


def test_detect_arxiv_cc_href(monkeypatch):
    _patch_html(monkeypatch, '<a href="http://creativecommons.org/licenses/by/4.0/">cc</a>')
    assert ld.detect_license("https://arxiv.org/abs/2504.16310") == "CC BY 4.0"


def test_detect_arxiv_default_nonexclusive(monkeypatch):
    _patch_html(monkeypatch, '<div>License: arXiv.org perpetual nonexclusive-distrib</div>')
    assert ld.detect_license("https://arxiv.org/abs/1234.5678") == "arXiv (non-exclusive)"


def test_detect_generic_rel_license(monkeypatch):
    _patch_html(monkeypatch, '<link rel="license" href="https://creativecommons.org'
                             '/licenses/by-sa/4.0/">')
    assert ld.detect_license("https://owasp.org/x") == "CC BY-SA 4.0"


def test_detect_generic_all_rights_reserved(monkeypatch):
    _patch_html(monkeypatch, '<footer>Copyright 2024 Acme. All Rights Reserved.</footer>')
    assert ld.detect_license("https://vendor.example/blog/post") == "All Rights Reserved"


# --------------------------------------------------- usage-grant / terms prose ---
@pytest.mark.parametrize("html,expected", [
    ('<p>This dataset is free for commercial use.</p>', "Free for commercial use"),
    ('<p>Commercial use is permitted with attribution.</p>', "Commercial use permitted"),
    ('<p>Data are permitted for commercial purposes.</p>', "Commercial use permitted"),
    ('<div>All images here are royalty-free.</div>', "Royalty-free"),
    ('<p>The data is free to use for research and products.</p>', "Free to use"),
    ('<p>Provided free of charge to everyone.</p>', "Free to use"),
    ('<p>Released for public use.</p>', "Public use"),
    ('<p>Licensed for non-commercial use only.</p>', "Non-commercial use only"),
    ('<p>This corpus is free for non-commercial use.</p>', "Non-commercial use only"),
])
def test_detect_generic_usage_grant(monkeypatch, html, expected):
    _patch_html(monkeypatch, html)
    assert ld.detect_license("https://data.example/x") == expected


def test_usage_grant_prefers_machine_tag_over_prose(monkeypatch):
    # An explicit rel=license tag must still win over incidental "public use" prose.
    _patch_html(monkeypatch, '<link rel="license" href="https://opensource.org/licenses/MIT">'
                             '<p>free for public use</p>')
    assert ld.detect_license("https://data.example/x") == "MIT"


def test_usage_grant_from_text_empty_when_no_terms():
    assert ld.usage_grant_from_text("<p>just a description, no terms</p>") == ""
    assert ld.usage_grant_from_text("") == ""


def test_detect_generic_no_signal_returns_empty(monkeypatch):
    _patch_html(monkeypatch, "<html><body>no license here</body></html>")
    assert ld.detect_license("https://example.com/page") == ""


def test_detect_github_html_fallback_no_token(monkeypatch):
    _patch_html(monkeypatch, '<a class="Link--muted" href="/o/r/blob/main/LICENSE">'
                             '<span>MIT license</span></a>')
    assert ld.detect_license("https://github.com/o/r") == "MIT"


class _Resp:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload

    def get(self, url, **kw):
        return _Resp(self._payload)


def test_detect_github_api_with_token(monkeypatch):
    client = _FakeClient({"license": {"spdx_id": "Apache-2.0"}})
    out = ld.detect_license("https://github.com/o/r", client=client,
                            github_token="tok")
    assert out == "Apache-2.0"


def test_detect_license_swallows_errors(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("network down")
    monkeypatch.setattr(ld, "_get_text", _boom)
    assert ld.detect_license("https://example.com/x") == ""       # never raises


def test_detect_license_blank_url():
    assert ld.detect_license("") == ""
