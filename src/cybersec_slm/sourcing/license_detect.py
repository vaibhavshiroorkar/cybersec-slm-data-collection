#!/usr/bin/env python3
"""Deep per-source license detection for the sourcing stage.

The catalog's ``License`` column was blank for most sources because the enricher
only looked at HuggingFace card data and the GitHub API. In reality the license
is almost always *on the source page* - this module goes and finds it, host by
host, and normalizes it to a canonical string:

  - HuggingFace  - ``HfApi().dataset_info`` cardData / ``license:`` tag
  - GitHub       - API ``license.spdx_id`` (with a token), then an HTML fallback
                   (the repo page's license sidebar) so rate-limited runs still resolve
  - Kaggle       - the dataset page's JSON-LD ``"license"`` block
  - arXiv        - the abstract page's ``/licenses/...`` href
  - anything else - the page's ``<link rel="license">`` / JSON-LD ``"license"`` /
                    ``<meta name="license">`` / Creative-Commons text / an explicit
                    "All Rights Reserved" copyright

Best-effort by contract: every network or parse failure returns ``""`` (never
raises), so detection can never abort a discovery or backfill run. ``""`` means
"nothing found" - the row stays blank/Unknown and is never blacklisted for it.

Two layers so callers don't double-fetch:
    license_from_hf_info(info)      - pure, over an already-fetched HF info object
    license_from_github_json(d)     - pure, over an already-fetched GitHub API dict
    detect_license(url, ...)        - fetches + dispatches by host (the public API)
"""

from __future__ import annotations

import re

from ..core import logger

_HF_RE = re.compile(r"huggingface\.co/datasets/([^/?#]+/[^/?#]+)", re.IGNORECASE)
_GH_RE = re.compile(r"github\.com/([^/?#]+)/([^/?#]+)", re.IGNORECASE)
_GH_SKIP = {"orgs", "search", "topics", "about", "features", "marketplace"}
_KAGGLE_RE = re.compile(r"kaggle\.com/datasets/", re.IGNORECASE)
_KAGGLE_SLUG_RE = re.compile(r"kaggle\.com/datasets/([^/?#]+)/([^/?#]+)", re.IGNORECASE)
_ARXIV_RE = re.compile(r"arxiv\.org/(?:abs|pdf|html)/([0-9]+\.[0-9]+)", re.IGNORECASE)

_BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/122.0 Safari/537.36")


# ---------------------------------------------------------------- normalization

# Canonical text forms for the common SPDX ids, keyed by a lowercased needle.
# Order matters: more specific needles first (e.g. "gpl-3" before "gpl").
_TEXT_MAP: list[tuple[str, str]] = [
    ("apache", "Apache-2.0"),
    ("mit", "MIT"),
    ("bsd-3", "BSD-3-Clause"),
    ("bsd-2", "BSD-2-Clause"),
    ("bsd", "BSD"),
    ("agpl", "AGPL-3.0"),
    ("lgpl", "LGPL-3.0"),
    ("gpl-2", "GPL-2.0"),
    ("gplv2", "GPL-2.0"),
    ("gpl-3", "GPL-3.0"),
    ("gplv3", "GPL-3.0"),
    ("gpl", "GPL-3.0"),
    ("mpl", "MPL-2.0"),
    ("cc0", "CC0-1.0"),
    ("odbl", "ODbL-1.0"),
    ("openrail", "OpenRAIL"),
    ("all rights reserved", "All Rights Reserved"),
    ("public domain", "Public Domain"),
]

# Creative Commons element codes -> the SPDX-ish suffix, in canonical order.
_CC_ELEMENTS = [("attribution", "BY"), ("noncommercial", "NC"),
                ("non-commercial", "NC"), ("sharealike", "SA"),
                ("share-alike", "SA"), ("noderiv", "ND")]

# Explicit usage-grant / terms-of-use prose -> a canonical license label. When a
# page carries no machine-readable license but *states* how the data may be used
# ("free for commercial use", "public use", "non-commercial only", ...), that
# statement becomes the license instead of a blank - faithful to what the source
# says, so the gate can then classify it. Order matters: non-commercial phrasing
# is matched first so "free for non-commercial use" is never misread as a
# commercial grant, and more specific grants precede the broad "public use".
_GRANT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"free\s+for\s+non[- ]?commercial", re.IGNORECASE), "Non-commercial use only"),
    (re.compile(r"non[- ]?commercial\s+use\s+only", re.IGNORECASE), "Non-commercial use only"),
    (re.compile(
        r"not\s+(?:for|permitted\s+for)\s+commercial\s+use",
        re.IGNORECASE,
    ), "Non-commercial use only"),
    (re.compile(
        r"free\s+for\s+(?:personal\s+and\s+)?commercial\s+use",
        re.IGNORECASE,
    ), "Free for commercial use"),
    (re.compile(
        r"commercial\s+use\s+(?:is\s+)?(?:permitted|allowed)",
        re.IGNORECASE,
    ), "Commercial use permitted"),
    (re.compile(
        r"(?:permitted|allowed)\s+for\s+commercial(?:\s+(?:use|purposes?))?",
        re.IGNORECASE,
    ), "Commercial use permitted"),
    (re.compile(
        r"may\s+be\s+used\s+(?:freely\s+)?for\s+(?:any\s+)?commercial",
        re.IGNORECASE,
    ), "Commercial use permitted"),
    (re.compile(r"royalty[- ]free", re.IGNORECASE), "Royalty-free"),
    (re.compile(r"free\s+of\s+charge", re.IGNORECASE), "Free to use"),
    (re.compile(r"free\s+to\s+use", re.IGNORECASE), "Free to use"),
    (re.compile(r"free\s+for\s+(?:any|all)\s+(?:use|purposes?)", re.IGNORECASE), "Free to use"),
    (re.compile(r"free\s+for\s+public\s+use", re.IGNORECASE), "Public use"),
    (re.compile(r"\bpublic\s+use\b", re.IGNORECASE), "Public use"),
]


def usage_grant_from_text(html: str) -> str:
    """Map explicit usage-grant / terms-of-use prose to a canonical label (or '').

    Best-effort: scans the page text for a stated permission (commercial /
    non-commercial / royalty-free / free / public use) and returns the first
    canonical label that matches, in specificity order. ``''`` when the page
    states no usage terms at all.
    """
    if not html:
        return ""
    for rx, label in _GRANT_PATTERNS:
        if rx.search(html):
            return label
    return ""


def _cc_from_url(low: str) -> str:
    """Map a creativecommons.org URL to ``CC <CODE> <ver>`` (or CC0 / Public Domain)."""
    if "publicdomain/zero" in low or "/cc0" in low:
        return "CC0-1.0"
    if "publicdomain/mark" in low or "publicdomain" in low:
        return "Public Domain"
    m = re.search(r"/licenses/([a-z0-9\-]+)/(\d+\.\d+)", low)
    if not m:
        return ""
    code = m.group(1).upper()
    return f"CC {code} {m.group(2)}"


def _cc_from_text(low: str) -> str:
    """Map Creative-Commons text to ``CC ...``.

    Handles both prose ('Attribution-ShareAlike v4.0') and the short code form
    ('cc-by-nc-4.0' / 'cc by sa').
    """
    order = {"BY": 0, "NC": 1, "SA": 2, "ND": 3}
    parts = [suffix for needle, suffix in _CC_ELEMENTS if needle in low]
    if not parts:
        # Short code form: cc-by-nc-sa, "cc by 4.0", ...
        m = re.search(r"cc[ \-]?(by(?:[ \-]?(?:nc|sa|nd))*)", low)
        if m:
            code = {"by": "BY", "nc": "NC", "sa": "SA", "nd": "ND"}
            parts = [code[tok] for tok in re.split(r"[ \-]+", m.group(1)) if tok in code]
    parts = sorted(dict.fromkeys(parts), key=lambda p: order.get(p, 9))
    ver = re.search(r"v?(\d\.\d)", low)
    version = f" {ver.group(1)}" if ver else " 4.0"
    if parts:
        return "CC " + "-".join(parts) + version
    if "cc0" in low or "zero" in low:
        return "CC0-1.0"
    return ""


def normalize_license(raw: str | None) -> str:
    """Normalize a found license (URL or free text) to a canonical string.

    Returns ``""`` for an empty / unusable value. Leaves an already-canonical SPDX
    id essentially unchanged. Deliberately lenient: downstream classification
    (``ingestion.license_gate``) only needs the deny/allow keywords to survive, so
    a close-enough form is fine.
    """
    s = str(raw or "").strip()
    if not s:
        return ""
    low = s.lower()

    if "creativecommons.org" in low:
        cc = _cc_from_url(low)
        if cc:
            return cc
    if "creative commons" in low or re.match(r"cc[ \-]?by", low) or low.startswith("cc "):
        cc = _cc_from_text(low)
        if cc:
            return cc

    for needle, canonical in _TEXT_MAP:
        if needle in low:
            return canonical

    # An SPDX-looking id (e.g. "PDDL-1.0", "EPL-2.0") - keep as-is, trimmed.
    if re.fullmatch(r"[A-Za-z0-9.\-+ ]{2,40}", s) and "noassertion" not in low:
        return s
    return ""


# ------------------------------------------------------------------- host parses

def license_from_hf_info(info) -> str:
    """License from an already-fetched ``HfApi().dataset_info`` object (or '')."""
    card = getattr(info, "cardData", None) or {}
    lic = None
    try:
        lic = card.get("license")
    except AttributeError:
        lic = getattr(card, "license", None)
    if isinstance(lic, (list, tuple)):
        lic = next((x for x in lic if x), "")
    if not lic:
        for t in getattr(info, "tags", None) or []:
            if isinstance(t, str) and t.startswith("license:"):
                lic = t.split(":", 1)[1]
                break
    return normalize_license(lic)


def license_from_github_json(d: dict) -> str:
    """License from an already-fetched GitHub ``/repos`` API dict (or '')."""
    spdx = (d.get("license") or {}).get("spdx_id")
    if spdx and spdx != "NOASSERTION":
        return normalize_license(spdx)
    return ""


# ------------------------------------------------------------------- HTTP helper

_HTML_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8")


def _get_text(url: str, *, client=None, timeout: float, accept: str = _HTML_ACCEPT,
              user_agent: str = _BROWSER_UA) -> str:
    import httpx

    # A browser-realistic Accept header: some hosts (e.g. Kaggle) serve a bare JS
    # shell with no embedded metadata to clients whose Accept looks non-browser.
    # Kaggle's JSON API, conversely, serves that same shell to a full browser
    # User-Agent - it returns JSON only to a minimal UA (see ``_detect_kaggle``).
    headers = {"User-Agent": user_agent, "Accept": accept,
               "Accept-Language": "en-US,en;q=0.9"}
    resp = (client.get(url, headers=headers, timeout=timeout, follow_redirects=True)
            if client else
            httpx.get(url, headers=headers, timeout=timeout, follow_redirects=True))
    if resp.status_code >= 400:
        return ""
    return resp.text


def _license_from_html(html: str) -> str:
    """Best-effort license from arbitrary page HTML (machine tags first, then prose)."""
    if not html:
        return ""
    # 1. <link rel="license" href="..."> (rel/href order-independent)
    for m in re.finditer(r"<link\b[^>]*>", html, re.IGNORECASE):
        tag = m.group(0)
        if re.search(r'rel=["\']?license', tag, re.IGNORECASE):
            href = re.search(r'href=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if href:
                lic = normalize_license(href.group(1))
                if lic:
                    return lic
    # 2. JSON-LD "license": {"name": ...} or "license": "..."
    m = re.search(r'"license"\s*:\s*\{[^}]*?"name"\s*:\s*"([^"]+)"', html, re.IGNORECASE)
    if m:
        lic = normalize_license(m.group(1))
        if lic:
            return lic
    m = re.search(r'"license"\s*:\s*"([^"]+)"', html, re.IGNORECASE)
    if m:
        lic = normalize_license(m.group(1))
        if lic:
            return lic
    # 3. <meta name="license"|"dc.rights" content="...">
    for m in re.finditer(r"<meta\b[^>]*>", html, re.IGNORECASE):
        tag = m.group(0)
        if re.search(r'name=["\'](?:license|dc\.rights|copyright)["\']', tag, re.IGNORECASE):
            c = re.search(r'content=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if c:
                lic = normalize_license(c.group(1))
                if lic:
                    return lic
    # 4. A creativecommons.org link anywhere in the body.
    m = re.search(r'creativecommons\.org/(?:licenses|publicdomain)/[a-z0-9\-]+(?:/\d\.\d)?',
                  html, re.IGNORECASE)
    if m:
        lic = _cc_from_url(m.group(0).lower())
        if lic:
            return lic
    # 5. "Creative Commons ... v4.0" prose.
    m = re.search(r'creative commons[^.<]{0,60}', html, re.IGNORECASE)
    if m:
        lic = _cc_from_text(m.group(0).lower())
        if lic:
            return lic
    # 6. Stated usage terms in prose (free for commercial use / free to use /
    # public use / non-commercial only): capture the policy as the license so a
    # page with no machine-readable tag is not left blank.
    grant = usage_grant_from_text(html)
    if grant:
        return grant
    # 7. Explicit proprietary copyright (last resort - genuine "red" signal).
    if re.search(r'all rights reserved', html, re.IGNORECASE):
        return "All Rights Reserved"
    return ""


# ------------------------------------------------------------------- detectors

def _detect_hf(ref: str) -> str:
    from huggingface_hub import HfApi

    info = HfApi().dataset_info(ref)
    return license_from_hf_info(info)


def _detect_github(owner: str, repo: str, *, client=None, token=None,
                   timeout: float) -> str:
    import httpx

    repo = re.sub(r"\.git$", "", repo)
    # Prefer the API (authoritative SPDX id) when a token lifts the rate limit.
    if token:
        headers = {"Accept": "application/vnd.github+json",
                   "Authorization": f"Bearer {token}"}
        url = f"https://api.github.com/repos/{owner}/{repo}"
        resp = (client.get(url, headers=headers, timeout=timeout) if client
                else httpx.get(url, headers=headers, timeout=timeout))
        if resp.status_code < 400:
            lic = license_from_github_json(resp.json())
            if lic:
                return lic
    # HTML fallback: the repo page's license sidebar (">MIT license<"), so an
    # unauthenticated / rate-limited run still resolves the common OSS licenses.
    html = _get_text(f"https://github.com/{owner}/{repo}", client=client, timeout=timeout)
    m = re.search(r'>\s*([A-Za-z0-9.\- ]{2,40}?)\s+[Ll]icense\s*<', html)
    if m:
        return normalize_license(m.group(1))
    return ""


def _detect_kaggle(url: str, *, client=None, timeout: float) -> str:
    # Kaggle's HTML page is served as a bare JS shell to non-browser / rate-limited
    # clients (no embedded metadata), but the public dataset-view API endpoint
    # returns the license reliably as "licenseName". Prefer it, fall back to HTML.
    m = _KAGGLE_SLUG_RE.search(url)
    if m:
        api = f"https://www.kaggle.com/api/v1/datasets/view/{m.group(1)}/{m.group(2)}"
        body = _get_text(api, client=client, timeout=timeout,
                         accept="application/json", user_agent="Mozilla/5.0")
        lic = _kaggle_license_name(body)
        if lic:
            return lic
    html = _get_text(url, client=client, timeout=timeout)
    lic = _kaggle_license_name(html)
    if lic:
        return lic
    m2 = re.search(r'"license"\s*:\s*\{[^}]*?"name"\s*:\s*"([^"]+)"', html, re.IGNORECASE)
    if m2:
        return normalize_license(m2.group(1))
    return _license_from_html(html)


# Kaggle placeholders that mean "no usable license", not a real license.
_KAGGLE_UNKNOWN = {"unknown", "other", "other (specified in description)"}


def _kaggle_license_name(body: str) -> str:
    m = re.search(r'"licenseName"\s*:\s*"([^"]+)"', body, re.IGNORECASE)
    if not m:
        return ""
    raw = m.group(1).strip()
    if raw.lower() in _KAGGLE_UNKNOWN:
        return ""
    return normalize_license(raw)


def _detect_arxiv(arxiv_id: str, *, client=None, timeout: float) -> str:
    html = _get_text(f"https://arxiv.org/abs/{arxiv_id}", client=client, timeout=timeout)
    m = re.search(r'(creativecommons\.org/(?:licenses|publicdomain)/[a-z0-9\-]+(?:/\d\.\d)?)',
                  html, re.IGNORECASE)
    if m:
        lic = _cc_from_url(m.group(1).lower())
        if lic:
            return lic
    # arXiv's own default grant is a non-exclusive redistribution license (not a
    # deny keyword, so it stays "unknown" for the gate rather than blacklisted).
    if re.search(r'nonexclusive-distrib|arxiv\.org/licenses', html, re.IGNORECASE):
        return "arXiv (non-exclusive)"
    return ""


def _detect_generic(url: str, *, client=None, timeout: float) -> str:
    return _license_from_html(_get_text(url, client=client, timeout=timeout))


def detect_license(url: str, *, client=None, github_token: str | None = None,
                   timeout: float = 8.0) -> str:
    """Deep-detect the license for ``url``; return a canonical string or ``''``.

    Dispatches by host to the most authoritative source available, falling back to
    generic HTML parsing. Never raises: any failure is logged at debug and yields
    ``''`` (nothing found), so a caller can safely run it over the whole catalog.
    """
    url = (url or "").strip()
    if not url:
        return ""
    try:
        hf = _HF_RE.search(url)
        if hf:
            return _detect_hf(hf.group(1))
        gh = _GH_RE.search(url)
        if gh and gh.group(1).lower() not in _GH_SKIP:
            return _detect_github(gh.group(1), gh.group(2), client=client,
                                  token=github_token, timeout=timeout)
        if _KAGGLE_RE.search(url):
            return _detect_kaggle(url, client=client, timeout=timeout)
        ax = _ARXIV_RE.search(url)
        if ax:
            return _detect_arxiv(ax.group(1), client=client, timeout=timeout)
        return _detect_generic(url, client=client, timeout=timeout)
    except Exception as e:                              # noqa: BLE001 - best-effort
        logger.debug(f"detect_license: {url}: {type(e).__name__}: {e}")
        return ""
