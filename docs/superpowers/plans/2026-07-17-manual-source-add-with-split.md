# Manual Source Add With Per-Part Sub-Domain Assignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Paste a repo/dataset link into the Sourcing page, have each of its top-level folders classified into its own sub-domain, review the proposal, and append one catalog row per part that ingestion fetches correctly.

**Architecture:** A new `sourcing/split.py` answers "what parts does this link have and where does each belong", reusing the existing vocab classifier. The sub-path rides in the link (`tree/<branch>/<folder>`) rather than in a new catalog column, so dedup and the catalog schema are untouched. `ingestion/fetch.py` learns to honor that sub-path, which also fixes a standing bug where such a link silently ingests the whole repo.

**Tech Stack:** Python 3.13, Streamlit (dashboard), httpx (GitHub REST), huggingface_hub, pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-07-17-manual-source-add-with-split-design.md`

## Global Constraints

- Run tests with the venv interpreter via PowerShell: `.\.venv\Scripts\python.exe -m pytest`. The Bash tool's python is msys2 and has no pytest.
- ruff `line-length = 100`, `target-version = "py313"`. Keep every line under 100 chars.
- No em dashes anywhere: not in code, comments, docstrings, docs, or commit messages.
- No emoji or symbols in dashboard UI copy. Plain text only.
- No Claude co-author or attribution line in commits. Commit as `vaibhavshiroorkar <vaibhavjtgz@gmail.com>`.
- Never overwrite a value the caller already set. `enrich` and `build_manual_row` both follow this; keep it.
- Network failures in sourcing are best-effort: swallow, log at debug, degrade. Never raise into the UI. This mirrors `sourcing/enrich.py`'s existing contract.
- `git` works through the PowerShell tool, not Bash.

---

### Task 1: Score a sub-domain match

`classify.refine_domain` returns a winning sub-domain but not its score, and the
split UI must distinguish "matched something" from "matched nothing" to decide
between proposing, inheriting, and asking. Add a scoring helper alongside it.
`refine_domain` keeps its own tie-breaking semantics (the default wins ties) and
is left untouched, so discovery behaviour cannot regress.

**Files:**
- Modify: `src/cybersec_slm/sourcing/classify.py`
- Test: `tests/sourcing/test_sourcing.py`

**Interfaces:**
- Consumes: `classify._score(text, vocab) -> int` (existing, private to the module).
- Produces: `classify.best_domain(text: str, vocab: dict[str, set[str]]) -> tuple[str, int]`. Returns the highest-scoring sub-domain and its score. Returns `("", 0)` when nothing matches or vocab is empty. Ties break on sorted name order for determinism.

- [ ] **Step 1: Write the failing tests**

Append to `tests/sourcing/test_sourcing.py`:

```python
# ------------------------------------------------------- best_domain scoring ---
def test_best_domain_returns_the_winner_and_its_score():
    from cybersec_slm.sourcing.classify import best_domain

    vocab = {"Network Security": {"pcap", "firewall"},
             "Cloud Security": {"kubernetes", "aws"}}
    assert best_domain("pcaps from a firewall", vocab) == ("Network Security", 2)


def test_best_domain_scores_zero_when_nothing_matches():
    from cybersec_slm.sourcing.classify import best_domain

    vocab = {"Network Security": {"pcap"}, "Cloud Security": {"kubernetes"}}
    assert best_domain("k8s-configs", vocab) == ("", 0)


def test_best_domain_is_deterministic_on_a_tie():
    from cybersec_slm.sourcing.classify import best_domain

    vocab = {"Zebra Domain": {"shared"}, "Alpha Domain": {"shared"}}
    # Both score 1. Sorted name order wins, so the result never flips between runs.
    assert best_domain("shared", vocab) == ("Alpha Domain", 1)


def test_best_domain_handles_empty_vocab_and_text():
    from cybersec_slm.sourcing.classify import best_domain

    assert best_domain("anything", {}) == ("", 0)
    assert best_domain("", {"Network Security": {"pcap"}}) == ("", 0)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.\.venv\Scripts\python.exe -m pytest tests/sourcing/test_sourcing.py -k best_domain -v`
Expected: FAIL with `ImportError: cannot import name 'best_domain'`

- [ ] **Step 3: Write the implementation**

In `src/cybersec_slm/sourcing/classify.py`, add after `_score`:

```python
def best_domain(text: str, vocab: dict[str, set[str]]) -> tuple[str, int]:
    """The highest-scoring sub-domain for ``text``, and its score.

    Unlike :func:`refine_domain`, this has no default to fall back on: a score of
    0 means nothing matched, which is what lets a caller tell a real match apart
    from a guess. Ties break on sorted sub-domain name so the result is stable
    across runs (dict order would otherwise leak into the UI).
    """
    text = (text or "").lower()
    winner, top = "", 0
    for domain in sorted(vocab):
        s = _score(text, vocab[domain])
        if s > top:
            winner, top = domain, s
    return winner, top
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.\.venv\Scripts\python.exe -m pytest tests/sourcing/test_sourcing.py -k best_domain -v`
Expected: 4 passed

- [ ] **Step 5: Check nothing else regressed**

Run: `.\.venv\Scripts\python.exe -m pytest tests/sourcing/ -q`
Expected: all pass

- [ ] **Step 6: Commit**

```powershell
git add src/cybersec_slm/sourcing/classify.py tests/sourcing/test_sourcing.py
git -c user.name="vaibhavshiroorkar" -c user.email="vaibhavjtgz@gmail.com" commit -m "Add best_domain: score a sub-domain match, not just pick one"
```

---

### Task 2: List a source's parts

The heart of the feature: turn a link into its top-level data folders. Grouping
uses `ingestion.common.EXT_PRIORITY`, so folders holding no data files (`docs/`,
`.github/`) vanish without a skip list.

**Files:**
- Create: `src/cybersec_slm/sourcing/split.py`
- Test: `tests/sourcing/test_split.py`

**Interfaces:**
- Consumes: `ingestion.common.EXT_PRIORITY`, `ingestion.common.SKIP_SUBSTRINGS`, `core.logger`.
- Produces:
  - `split.Part` frozen dataclass: `path: str` (top-level folder, `""` for repo root), `file_count: int`, `size_mb: float`, `sample_names: tuple[str, ...]`.
  - `split.Scan` frozen dataclass: `parts: tuple[Part, ...]`, `title: str`, `description: str`, `topics: tuple[str, ...]`, `branch: str`, `splittable: bool`.
  - `split.list_parts(link: str, *, client=None, github_token: str | None = None, timeout: float = 8.0) -> Scan`.
- Used by: Task 3 (`part_link` reads `Scan.branch`), Task 4 (`propose` reads `Scan.parts`/`title`/`description`/`topics`), Task 7 (the page).

- [ ] **Step 1: Write the failing tests**

Create `tests/sourcing/test_split.py`:

```python
"""Splitting a source link into its parts.

No test hits the network: GitHub goes through a fake httpx-shaped client and
HuggingFace through a monkeypatched HfApi.
"""

import pytest

from cybersec_slm.sourcing import split


class _Resp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _Client:
    """An httpx-shaped stub: maps a URL substring to a response."""

    def __init__(self, routes):
        self._routes = routes
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(url)
        for frag, resp in self._routes.items():
            if frag in url:
                return resp
        raise AssertionError(f"unexpected GET {url}")


def _repo_client(tree, *, description="", topics=(), branch="main"):
    return _Client({
        "/git/trees/": _Resp({"tree": tree}),
        "/repos/": _Resp({"default_branch": branch, "description": description,
                          "topics": list(topics), "name": "big-repo"}),
    })


def _blob(path, size=1024):
    return {"path": path, "type": "blob", "size": size}


# ------------------------------------------------------------------ github -----
def test_github_groups_data_files_by_top_level_folder():
    client = _repo_client([
        _blob("malware-samples/a.json"),
        _blob("malware-samples/b.json"),
        _blob("pcaps/x.csv"),
    ])
    scan = split.list_parts("https://github.com/org/big-repo", client=client)

    assert scan.splittable
    assert scan.branch == "main"
    assert [(p.path, p.file_count) for p in scan.parts] == [
        ("malware-samples", 2), ("pcaps", 1)]


def test_github_drops_folders_with_no_data_files():
    client = _repo_client([
        _blob("pcaps/x.csv"),
        _blob("docs/guide.rst"),          # .rst is not a data extension
        _blob(".github/workflows/ci.yml"),   # .yml is, but see below
    ])
    scan = split.list_parts("https://github.com/org/big-repo", client=client)

    assert [p.path for p in scan.parts] == [".github", "pcaps"]
    # docs/ is gone: it held no file with a data extension.


def test_github_root_files_become_one_part_with_an_empty_path():
    client = _repo_client([_blob("data.csv"), _blob("pcaps/x.csv")])
    scan = split.list_parts("https://github.com/org/big-repo", client=client)

    assert [p.path for p in scan.parts] == ["", "pcaps"]


def test_github_part_carries_size_and_sample_names():
    client = _repo_client([
        _blob("pcaps/x.csv", size=1048576),
        _blob("pcaps/y.csv", size=1048576),
    ])
    scan = split.list_parts("https://github.com/org/big-repo", client=client)

    part = scan.parts[0]
    assert part.size_mb == pytest.approx(2.0)
    assert part.sample_names == ("x.csv", "y.csv")


def test_github_carries_repo_description_and_topics_for_classification():
    client = _repo_client([_blob("pcaps/x.csv")],
                          description="Network capture corpus",
                          topics=("pcap", "security"))
    scan = split.list_parts("https://github.com/org/big-repo", client=client)

    assert scan.description == "Network capture corpus"
    assert scan.topics == ("pcap", "security")
    assert scan.title == "big-repo"


def test_github_uses_the_repos_default_branch():
    client = _repo_client([_blob("pcaps/x.csv")], branch="trunk")
    scan = split.list_parts("https://github.com/org/big-repo", client=client)

    assert scan.branch == "trunk"
    assert any("/git/trees/trunk" in c for c in client.calls)


def test_github_sample_names_are_capped():
    client = _repo_client([_blob(f"pcaps/f{i}.csv") for i in range(20)])
    scan = split.list_parts("https://github.com/org/big-repo", client=client)

    assert len(scan.parts[0].sample_names) == split.MAX_SAMPLES
    assert scan.parts[0].file_count == 20


def test_github_skips_the_skip_substrings():
    client = _repo_client([_blob("vectors/embedding_index.json"),
                           _blob("pcaps/x.csv")])
    scan = split.list_parts("https://github.com/org/big-repo", client=client)

    # "embedding" is in common.SKIP_SUBSTRINGS, so vectors/ holds no data file.
    assert [p.path for p in scan.parts] == ["pcaps"]


# ------------------------------------------------- failure degrades, never raises
def test_a_github_failure_degrades_to_an_unsplittable_scan():
    class _Boom:
        def get(self, url, **kw):
            raise RuntimeError("network down")

    scan = split.list_parts("https://github.com/org/big-repo", client=_Boom())

    assert not scan.splittable
    assert [p.path for p in scan.parts] == [""]


def test_a_rate_limited_github_degrades_to_an_unsplittable_scan():
    client = _Client({"/repos/": _Resp({}, status_code=403)})
    scan = split.list_parts("https://github.com/org/big-repo", client=client)

    assert not scan.splittable


# ------------------------------------------------------------ huggingface ------
def test_huggingface_groups_siblings_by_top_level_folder(monkeypatch):
    class _Sib:
        def __init__(self, rfilename, size):
            self.rfilename, self.size = rfilename, size

    class _Info:
        siblings = [_Sib("train/a.parquet", 1048576), _Sib("test/b.parquet", 1048576)]
        tags = ["cve", "security"]
        id = "dk/cloud"

    class _Api:
        def dataset_info(self, ref, files_metadata=False):
            assert ref == "dk/cloud"
            return _Info()

    monkeypatch.setattr(split, "_hf_api", lambda: _Api())
    scan = split.list_parts("https://huggingface.co/datasets/dk/cloud")

    assert scan.splittable
    assert [p.path for p in scan.parts] == ["test", "train"]
    assert scan.topics == ("cve", "security")


# -------------------------------------------------------------- other links ----
def test_a_website_is_unsplittable_with_a_single_whole_source_part():
    scan = split.list_parts("https://example.test/guide.html")

    assert not scan.splittable
    assert [p.path for p in scan.parts] == [""]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.\.venv\Scripts\python.exe -m pytest tests/sourcing/test_split.py -v`
Expected: FAIL, collection error `ModuleNotFoundError: No module named 'cybersec_slm.sourcing.split'`

- [ ] **Step 3: Write the implementation**

Create `src/cybersec_slm/sourcing/split.py`:

```python
#!/usr/bin/env python3
"""Split one source link into the parts a catalog row can be written for.

A big repo or dataset rarely belongs to a single sub-domain: one folder holds
malware samples, another holds cloud configs. This module answers "what parts
does this link have", so each can be filed under its own sub-domain
(:func:`propose` does the filing).

A part is one top-level folder containing data files. Deeper is noisier and one
row per file drowns the catalog; the whole point is a handful of honest rows.

Best-effort by contract, like :mod:`.enrich`: every network or parse failure is
swallowed (logged at debug) and degrades to an unsplittable scan, so a GitHub
outage costs the caller the split, never the add.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core import logger
from ..ingestion.common import EXT_PRIORITY, SKIP_SUBSTRINGS

# File names shown under a part as classifier signal and as a hint to the human
# reviewing the split. Enough to recognize the folder, not enough to fill the UI.
MAX_SAMPLES = 5

_GH_RE = re.compile(r"github\.com/([^/?#]+)/([^/?#]+)", re.IGNORECASE)
_HF_RE = re.compile(r"huggingface\.co/datasets/([^/?#]+/[^/?#]+)", re.IGNORECASE)
_GH_SKIP = {"orgs", "search", "topics", "about", "features", "marketplace"}
_ONE_MB = 1048576


@dataclass(frozen=True)
class Part:
    """One top-level folder of a source. ``path`` is "" for files at the root."""

    path: str
    file_count: int = 0
    size_mb: float = 0.0
    sample_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class Scan:
    """What :func:`list_parts` found: the parts plus signal for classifying them."""

    parts: tuple[Part, ...] = ()
    title: str = ""
    description: str = ""
    topics: tuple[str, ...] = ()
    branch: str = ""
    splittable: bool = False


def _is_data_file(name: str) -> bool:
    """True when ingestion would read this file (mirrors fetch.py's own filter)."""
    low = name.lower()
    return (low.endswith(EXT_PRIORITY)
            and not any(s in low for s in SKIP_SUBSTRINGS))


def _whole(link: str = "") -> Scan:
    """An unsplittable scan: one part standing for the entire source."""
    return Scan(parts=(Part(path=""),), splittable=False)


def _group(files: list[tuple[str, int]]) -> tuple[Part, ...]:
    """Group ``(path, size_bytes)`` data files by their top-level folder.

    Files at the root collapse into one part with an empty path. Folders holding
    no data file never appear, since non-data files are dropped before grouping.
    """
    buckets: dict[str, list[tuple[str, int]]] = {}
    for path, size in files:
        rel = path.strip("/")
        if not rel or not _is_data_file(rel):
            continue
        top = rel.split("/")[0] if "/" in rel else ""
        buckets.setdefault(top, []).append((rel, size))

    parts = []
    for top in sorted(buckets):
        members = sorted(buckets[top])
        total = sum(size for _p, size in members)
        names = tuple(os.path.basename(p) for p, _s in members[:MAX_SAMPLES])
        parts.append(Part(path=top, file_count=len(members),
                          size_mb=round(total / _ONE_MB, 3), sample_names=names))
    return tuple(parts)


def _hf_api():
    """The HuggingFace API client. Indirected so tests can replace it."""
    from huggingface_hub import HfApi
    return HfApi()


def _github_scan(owner: str, repo: str, *, client, token, timeout) -> Scan:
    import httpx

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def _get(url):
        resp = (client.get(url, headers=headers, timeout=timeout) if client
                else httpx.get(url, headers=headers, timeout=timeout))
        resp.raise_for_status()
        return resp.json()

    meta = _get(f"https://api.github.com/repos/{owner}/{repo}")
    branch = str(meta.get("default_branch") or "main")
    tree = _get(f"https://api.github.com/repos/{owner}/{repo}"
                f"/git/trees/{branch}?recursive=1")
    files = [(str(n.get("path") or ""), int(n.get("size") or 0))
             for n in (tree.get("tree") or []) if n.get("type") == "blob"]
    return Scan(parts=_group(files), title=str(meta.get("name") or repo),
                description=str(meta.get("description") or ""),
                topics=tuple(meta.get("topics") or []), branch=branch,
                splittable=True)


def _hf_scan(ref: str) -> Scan:
    info = _hf_api().dataset_info(ref, files_metadata=True)
    files = [(str(getattr(s, "rfilename", "") or ""), int(getattr(s, "size", 0) or 0))
             for s in (getattr(info, "siblings", None) or [])]
    return Scan(parts=_group(files), title=ref.split("/")[-1],
                description=str(getattr(info, "description", "") or ""),
                topics=tuple(getattr(info, "tags", None) or []), branch="main",
                splittable=True)


def list_parts(link: str, *, client=None, github_token: str | None = None,
               timeout: float = 8.0) -> Scan:
    """The parts of ``link``, or an unsplittable scan when it has none.

    Only repos and datasets have a file tree to split. A website, PDF or feed
    scans as a single part standing for the whole source, so callers need no
    branch for the unsplittable case.
    """
    link = (link or "").strip()
    if not link:
        return _whole()
    token = github_token or os.getenv("GITHUB_TOKEN") or None
    try:
        hf = _HF_RE.search(link)
        if hf:
            return _hf_scan(hf.group(1))
        gh = _GH_RE.search(link)
        if gh and gh.group(1).lower() not in _GH_SKIP:
            repo = re.sub(r"\.git$", "", gh.group(2))
            return _github_scan(gh.group(1), repo, client=client, token=token,
                                timeout=timeout)
    except Exception as e:                       # noqa: BLE001 - best-effort
        logger.debug(f"split: {link}: {type(e).__name__}: {e}")
        return _whole(link)
    return _whole(link)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.\.venv\Scripts\python.exe -m pytest tests/sourcing/test_split.py -v`
Expected: 12 passed

- [ ] **Step 5: Lint**

Run: `.\.venv\Scripts\python.exe -m ruff check src/cybersec_slm/sourcing/split.py tests/sourcing/test_split.py`
Expected: no findings. Fix any unused import or long line.

- [ ] **Step 6: Commit**

```powershell
git add src/cybersec_slm/sourcing/split.py tests/sourcing/test_split.py
git -c user.name="vaibhavshiroorkar" -c user.email="vaibhavjtgz@gmail.com" commit -m "List a source link's parts, grouped by top-level data folder"
```

---

### Task 3: Build part links and names, and refuse unfetchable links

The sub-path rides in the link. This task builds those links, and gates the
kinds no fetcher supports. Verified against `worker._fetch_one`: the supported
kinds are `hf`, `kaggle`, `github`/`url`, `pdf`, `website`, plus `feed` (JSON
only), `api` (NVD only) and `xml` (MITRE CWE only).

**Files:**
- Modify: `src/cybersec_slm/sourcing/split.py`
- Test: `tests/sourcing/test_split.py`

**Interfaces:**
- Consumes: `split.Part` (Task 2).
- Produces:
  - `split.part_link(link: str, part: Part, branch: str) -> str`. Returns `link` unchanged for a root part or a non-repo link.
  - `split.part_name(base_name: str, part: Part) -> str`.
  - `split.unsupported_reason(link: str) -> str`. Empty string when a fetcher exists; a human sentence naming the supported kinds when not.
- Used by: Task 7 (the page).

- [ ] **Step 1: Write the failing tests**

Append to `tests/sourcing/test_split.py`:

```python
# --------------------------------------------------------- links and names -----
def test_part_link_points_at_the_folder_inside_the_repo():
    part = split.Part(path="pcaps", file_count=1)
    assert (split.part_link("https://github.com/org/big-repo", part, "main")
            == "https://github.com/org/big-repo/tree/main/pcaps")


def test_part_link_honors_a_non_default_branch():
    part = split.Part(path="pcaps", file_count=1)
    assert (split.part_link("https://github.com/org/big-repo", part, "trunk")
            == "https://github.com/org/big-repo/tree/trunk/pcaps")


def test_part_link_for_a_huggingface_folder():
    part = split.Part(path="train", file_count=1)
    assert (split.part_link("https://huggingface.co/datasets/dk/cloud", part, "main")
            == "https://huggingface.co/datasets/dk/cloud/tree/main/train")


def test_part_link_of_a_root_part_is_the_link_itself():
    part = split.Part(path="", file_count=1)
    for link in ("https://github.com/org/big-repo", "https://example.test/x.csv"):
        assert split.part_link(link, part, "main") == link


def test_part_link_of_a_non_repo_link_is_the_link_itself():
    part = split.Part(path="whatever", file_count=1)
    assert (split.part_link("https://example.test/x.csv", part, "main")
            == "https://example.test/x.csv")


def test_part_name_qualifies_the_base_name_with_the_folder():
    assert split.part_name("big-repo", split.Part(path="pcaps")) == "big-repo/pcaps"
    assert split.part_name("big-repo", split.Part(path="")) == "big-repo"


# ------------------------------------------------------ unsupported links ------
@pytest.mark.parametrize("link", [
    "https://huggingface.co/datasets/dk/cloud",
    "https://www.kaggle.com/datasets/dk/cloud",
    "https://github.com/org/big-repo",
    "https://raw.githubusercontent.com/org/repo/main/x.csv",
    "https://arxiv.org/pdf/2401.00001",
    "https://example.test/paper.pdf",
    "https://example.test/records.json",
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    "https://example.test/guide.html",
    "https://example.test/some/page",
])
def test_supported_links_have_no_reason_to_refuse(link):
    assert split.unsupported_reason(link) == ""


@pytest.mark.parametrize("link", [
    "https://blog.example.test/feed.xml",
    "https://blog.example.test/rss",
    "https://blog.example.test/feed/",
    "https://blog.example.test/index.atom",
])
def test_rss_and_atom_feeds_are_refused_by_name(link):
    reason = split.unsupported_reason(link)
    assert "RSS" in reason
    assert "JSON feeds" in reason           # names what does work


@pytest.mark.parametrize("link", [
    "https://api.example.test/v2/threats",
    "https://example.test/api/v1/indicators",
])
def test_generic_rest_apis_are_refused_by_name(link):
    reason = split.unsupported_reason(link)
    assert "REST" in reason


def test_the_nvd_api_is_not_mistaken_for_a_generic_one():
    # It has a real fetcher (fetch_nvd), despite living under /rest/json/.
    assert split.unsupported_reason(
        "https://services.nvd.nist.gov/rest/json/cves/2.0") == ""
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.\.venv\Scripts\python.exe -m pytest tests/sourcing/test_split.py -k "part_link or part_name or refuse or supported or nvd" -v`
Expected: FAIL with `AttributeError: module ... has no attribute 'part_link'`

- [ ] **Step 3: Write the implementation**

Append to `src/cybersec_slm/sourcing/split.py`:

```python
# The kinds ingestion can actually fetch, named for a human. Keep in step with
# worker._fetch_one: this sentence is the only place the UI explains itself.
_SUPPORTED = ("Supported: HuggingFace, Kaggle, GitHub, PDFs, websites, and "
              "JSON feeds.")


def part_link(link: str, part: Part, branch: str) -> str:
    """The link for one part: the folder inside the repo/dataset.

    The sub-path rides in the link rather than in a catalog column, so dedup
    (:func:`.sheet.normalize_url` keeps host + path) tells two parts apart for
    free, and ingestion recovers the sub-path from the URL it was given.
    """
    if not part.path:
        return link
    hf = _HF_RE.search(link)
    if hf:
        return f"https://huggingface.co/datasets/{hf.group(1)}/tree/{branch}/{part.path}"
    gh = _GH_RE.search(link)
    if gh and gh.group(1).lower() not in _GH_SKIP:
        repo = re.sub(r"\.git$", "", gh.group(2))
        return f"https://github.com/{gh.group(1)}/{repo}/tree/{branch}/{part.path}"
    return link


def part_name(base_name: str, part: Part) -> str:
    """A catalog Name unique per part, so their raw folders cannot collide."""
    return f"{base_name}/{part.path}" if part.path else base_name


def unsupported_reason(link: str) -> str:
    """Why ingestion could not fetch ``link``, or "" when it can.

    A row no fetcher supports would sit in the catalog until the ingest stage
    failed on it, an hour later and far from the paste that caused it. Say no at
    the point of entry instead.
    """
    low = (link or "").strip().lower()
    if not low:
        return ""
    p = urlparse(low if "://" in low else "//" + low)
    host, path = p.netloc.removeprefix("www."), p.path

    # Everything with a handler, in worker._fetch_one's dispatch order.
    if "services.nvd.nist.gov" in host:                       # api -> fetch_nvd
        return ""
    if low.endswith(".xml.zip") or ("cwe.mitre.org" in host and ".xml" in low):
        return ""                                             # xml -> scrape_cwe
    if "huggingface.co/datasets/" in low or "kaggle.com/datasets/" in low:
        return ""
    if "github.com" in host or "raw.githubusercontent.com" in host:
        return ""
    if low.endswith(".pdf") or "arxiv.org/pdf/" in low:
        return ""
    if low.endswith(".json"):                                 # feed -> scrape_feed
        return ""

    if (low.endswith((".xml", ".rss", ".atom"))
            or re.search(r"/(feed|rss|atom)(/|$)", path)):
        return ("No fetcher supports RSS or Atom feeds, so this row would fail "
                f"at ingest. {_SUPPORTED}")
    if host.startswith("api.") or "/api/" in path:
        return ("No fetcher supports general REST APIs (only the NVD CVE API), "
                f"so this row would fail at ingest. {_SUPPORTED}")
    return ""                                    # a website or a direct file
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.\.venv\Scripts\python.exe -m pytest tests/sourcing/test_split.py -v`
Expected: all pass (Task 2's tests included)

- [ ] **Step 5: Commit**

```powershell
git add src/cybersec_slm/sourcing/split.py tests/sourcing/test_split.py
git -c user.name="vaibhavshiroorkar" -c user.email="vaibhavjtgz@gmail.com" commit -m "Build per-part links and refuse links no fetcher supports"
```

---

### Task 4: Propose a sub-domain per part

The three-case rule from the spec. A domain is only ever invented when something
actually matched; when nothing matched anywhere, the form asks.

| Part score | Repo score | Proposal |
|---|---|---|
| > 0 | any | the part's own match |
| 0 | > 0 | inherited repo-level domain |
| 0 | 0 | none, the UI asks |

**Files:**
- Modify: `src/cybersec_slm/sourcing/split.py`
- Test: `tests/sourcing/test_split.py`

**Interfaces:**
- Consumes: `classify.best_domain` (Task 1), `classify.build_domain_vocab`, `catalog.load`, `split.Scan`/`split.Part` (Task 2).
- Produces: `split.propose(scan: Scan, cat: dict | None = None) -> list[Proposal]` where `Proposal` is a frozen dataclass with `part: Part`, `domain: str` (`""` means undecidable), `score: int`, `inherited: bool`.
- Used by: Task 7 (the page renders one editor row per Proposal).

- [ ] **Step 1: Write the failing tests**

Append to `tests/sourcing/test_split.py`:

```python
# ------------------------------------------------------------- proposals -------
_VOCAB = {"Network Security": {"pcap", "firewall"},
          "Cloud Security": {"kubernetes", "aws"},
          "Threat Intelligence": {"malware", "ioc"}}


def _cat(vocab=None):
    return {name: {"datasets": [], "text": [], "code": "", "vocab": sorted(terms)}
            for name, terms in (vocab or _VOCAB).items()}


def test_a_part_that_matches_vocab_keeps_its_own_domain():
    scan = split.Scan(parts=(split.Part(path="pcaps", file_count=3,
                                        sample_names=("x.csv",)),),
                      title="big-repo", description="malware corpus",
                      splittable=True, branch="main")
    [prop] = split.propose(scan, cat=_cat())

    assert prop.domain == "Network Security"      # "pcap" beat the repo's "malware"
    assert prop.score > 0
    assert not prop.inherited


def test_a_part_that_matches_nothing_inherits_the_repo_domain():
    scan = split.Scan(parts=(split.Part(path="k8s-configs", file_count=2,
                                        sample_names=("a.yaml",)),),
                      title="big-repo", description="a malware corpus",
                      splittable=True, branch="main")
    [prop] = split.propose(scan, cat=_cat())

    # The built-in vocab has "kubernetes" and not "k8s", so the part misses. It
    # takes the repo's domain rather than having one invented for it.
    assert prop.domain == "Threat Intelligence"
    assert prop.inherited
    assert prop.score == 0


def test_a_part_matching_nothing_whose_repo_matches_nothing_proposes_no_domain():
    scan = split.Scan(parts=(split.Part(path="k8s-configs", file_count=2),),
                      title="big-repo", description="assorted files",
                      splittable=True, branch="main")
    [prop] = split.propose(scan, cat=_cat())

    assert prop.domain == ""          # the UI must ask
    assert not prop.inherited


def test_the_repo_domain_comes_from_its_topics_too():
    scan = split.Scan(parts=(split.Part(path="misc", file_count=1),),
                      title="big-repo", description="", topics=("aws",),
                      splittable=True, branch="main")
    [prop] = split.propose(scan, cat=_cat())

    assert prop.domain == "Cloud Security"
    assert prop.inherited


def test_sample_file_names_classify_a_part_whose_folder_name_says_nothing():
    scan = split.Scan(parts=(split.Part(path="dumps", file_count=1,
                                        sample_names=("firewall-log.csv",)),),
                      title="big-repo", description="assorted", splittable=True,
                      branch="main")
    [prop] = split.propose(scan, cat=_cat())

    assert prop.domain == "Network Security"
    assert not prop.inherited


def test_every_part_gets_exactly_one_proposal_in_order():
    scan = split.Scan(parts=(split.Part(path="pcaps", file_count=1),
                             split.Part(path="k8s", file_count=1),
                             split.Part(path="malware", file_count=1)),
                      title="r", description="", splittable=True, branch="main")
    props = split.propose(scan, cat=_cat())

    assert [p.part.path for p in props] == ["pcaps", "k8s", "malware"]
    assert [p.domain for p in props] == ["Network Security", "", "Threat Intelligence"]


def test_an_empty_taxonomy_proposes_nothing_rather_than_raising():
    scan = split.Scan(parts=(split.Part(path="pcaps", file_count=1),),
                      splittable=True, branch="main")
    [prop] = split.propose(scan, cat={})

    assert prop.domain == ""
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.\.venv\Scripts\python.exe -m pytest tests/sourcing/test_split.py -k propose -v`
Expected: FAIL with `AttributeError: module ... has no attribute 'propose'`

- [ ] **Step 3: Write the implementation**

Append to `src/cybersec_slm/sourcing/split.py` (and add `Proposal` next to the
other dataclasses at the top of the module):

```python
@dataclass(frozen=True)
class Proposal:
    """Where one part is proposed to be filed, and how much to trust it.

    ``domain`` is "" when neither the part nor its source matched any vocab: the
    caller must ask rather than guess. ``inherited`` marks a part that matched
    nothing itself and took its source's domain.
    """

    part: Part
    domain: str
    score: int
    inherited: bool


def propose(scan: Scan, cat: dict | None = None) -> list[Proposal]:
    """Propose a sub-domain for every part of ``scan``.

    The source as a whole is classified first (title, description, topics); each
    part is then classified on its folder name and sample file names. A part that
    matches nothing inherits the source's domain, and when the source matched
    nothing either, no domain is proposed at all.

    Classification is only as good as the taxonomy's vocab, which is short terms:
    ``pcaps/`` matches ``pcap``, but ``k8s-configs/`` misses because the vocab has
    ``kubernetes``. That is why every proposal is reviewed before it is written.
    """
    from . import catalog as _catalog
    from .classify import best_domain, build_domain_vocab

    cat = cat if cat is not None else _catalog.load()
    vocab = build_domain_vocab(cat)
    repo_domain, repo_score = best_domain(
        f"{scan.title} {scan.description} {' '.join(scan.topics)}", vocab)

    out: list[Proposal] = []
    for part in scan.parts:
        text = f"{part.path} {' '.join(part.sample_names)}"
        domain, score = best_domain(text, vocab)
        if score > 0:
            out.append(Proposal(part=part, domain=domain, score=score,
                                inherited=False))
        elif repo_score > 0:
            out.append(Proposal(part=part, domain=repo_domain, score=0,
                                inherited=True))
        else:
            out.append(Proposal(part=part, domain="", score=0, inherited=False))
    return out
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.\.venv\Scripts\python.exe -m pytest tests/sourcing/test_split.py -v`
Expected: all pass

- [ ] **Step 5: Commit**

```powershell
git add src/cybersec_slm/sourcing/split.py tests/sourcing/test_split.py
git -c user.name="vaibhavshiroorkar" -c user.email="vaibhavjtgz@gmail.com" commit -m "Propose a sub-domain per part, inheriting rather than guessing"
```

---

### Task 5: Fetch only the sub-path of a repo

The change that makes a split row honest. Today `_github_target` parses
`tree/<branch>/<subdir>` and throws the subdir away, then `fetch_url` extracts
the zip and walks every file in it. Three part rows would each download the whole
repo and ingest all of it. This is also a standing bug for any discovered
`tree/main/subdir` link.

**Files:**
- Modify: `src/cybersec_slm/ingestion/fetch.py:30-54` (`_github_target`), `:230-265` (`fetch_url`)
- Test: `tests/ingestion/test_fetch.py` (create)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `fetch._github_target(url) -> tuple[str, str, str] | None`, now `(download_url, name, subdir)`. `subdir` is `""` except for a `tree/<branch>/<subdir>` link. **Breaking change to a private helper with exactly one caller** (`fetch_url:231`), verified by grep.
  - `fetch.fetch_url(url, domain, desc, lic, folder, log, kind="url", subset="")`. An empty `subset` reproduces today's behaviour byte for byte.
- Used by: Task 6 (`fetch_hf` mirrors the `subset` parameter name).

- [ ] **Step 1: Write the failing tests**

Create `tests/ingestion/test_fetch.py`:

```python
"""Fetching a source, and fetching only part of one.

The zip tests build a real archive in tmp_path and stub the download, so no test
hits the network.
"""

import os
import zipfile

import pytest

from cybersec_slm.ingestion import fetch


# ------------------------------------------------------------ github target ----
def test_github_target_of_a_repo_root_has_no_subdir():
    url, name, subdir = fetch._github_target("https://github.com/org/repo")
    assert url == "https://github.com/org/repo/archive/HEAD.zip"
    assert name == "repo.zip"
    assert subdir == ""


def test_github_target_of_a_tree_link_returns_the_subdir():
    url, name, subdir = fetch._github_target(
        "https://github.com/org/repo/tree/main/pcaps")
    assert url == "https://github.com/org/repo/archive/refs/heads/main.zip"
    assert name == "repo.zip"
    assert subdir == "pcaps"


def test_github_target_of_a_nested_tree_link_keeps_the_whole_subdir():
    _url, _name, subdir = fetch._github_target(
        "https://github.com/org/repo/tree/main/data/pcaps")
    assert subdir == "data/pcaps"


def test_github_target_of_a_branch_root_tree_link_has_no_subdir():
    _url, _name, subdir = fetch._github_target(
        "https://github.com/org/repo/tree/main")
    assert subdir == ""


def test_github_target_of_a_blob_link_is_the_raw_file_with_no_subdir():
    url, name, subdir = fetch._github_target(
        "https://github.com/org/repo/blob/main/data/x.csv")
    assert url == "https://raw.githubusercontent.com/org/repo/main/data/x.csv"
    assert name == "x.csv"
    assert subdir == ""


def test_github_target_of_a_non_github_url_is_none():
    assert fetch._github_target("https://example.test/x.csv") is None


# ------------------------------------------------------- subset extraction -----
@pytest.fixture
def repo_zip(tmp_path):
    """A GitHub-shaped archive: everything under a single repo-branch root dir."""
    z = tmp_path / "repo.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("repo-main/README.md", "# readme")
        zf.writestr("repo-main/pcaps/a.csv", "col\nnet-a\n")
        zf.writestr("repo-main/pcaps/b.csv", "col\nnet-b\n")
        zf.writestr("repo-main/k8s/c.csv", "col\ncloud-c\n")
    return z


@pytest.fixture
def fake_download(monkeypatch, repo_zip):
    """Replace the network download with a copy of the prepared archive."""
    import shutil

    def _download(url, dest, **kw):
        shutil.copyfile(repo_zip, dest)

    monkeypatch.setattr(fetch, "download", _download)


class _Log:
    def __init__(self):
        self.records = []

    def record(self, **kw):
        self.records.append(kw)


def _rows_written(tmp_path, folder):
    """Every text line of every jsonl the fetch produced."""
    lines = []
    for root, _d, files in os.walk(folder):
        for f in files:
            if f.endswith(".jsonl"):
                with open(os.path.join(root, f), encoding="utf-8") as fh:
                    lines.extend(fh.read().splitlines())
    return lines


def test_a_tree_link_ingests_only_its_subdir(tmp_path, fake_download):
    folder = str(tmp_path / "out")
    os.makedirs(folder)
    log = _Log()

    fetch.fetch_url("https://github.com/org/repo/tree/main/pcaps", "Network Security",
                    "desc", "MIT", folder, log, kind="github")

    body = "\n".join(_rows_written(tmp_path, folder))
    assert "net-a" in body and "net-b" in body
    assert "cloud-c" not in body          # the k8s folder is not this row's data


def test_a_repo_root_link_still_ingests_everything(tmp_path, fake_download):
    """Regression guard: every catalog row that exists today takes this path."""
    folder = str(tmp_path / "out")
    os.makedirs(folder)
    log = _Log()

    fetch.fetch_url("https://github.com/org/repo", "Network Security", "desc",
                    "MIT", folder, log, kind="github")

    body = "\n".join(_rows_written(tmp_path, folder))
    assert "net-a" in body and "cloud-c" in body


def test_a_subset_matching_no_file_writes_nothing_and_says_so(tmp_path,
                                                              fake_download, caplog):
    folder = str(tmp_path / "out")
    os.makedirs(folder)
    log = _Log()

    fetch.fetch_url("https://github.com/org/repo/tree/main/nope", "Network Security",
                    "desc", "MIT", folder, log, kind="github")

    assert _rows_written(tmp_path, folder) == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.\.venv\Scripts\python.exe -m pytest tests/ingestion/test_fetch.py -v`
Expected: FAIL. The `_github_target` tests fail with `ValueError: not enough values to unpack (expected 3, got 2)`, and `test_a_tree_link_ingests_only_its_subdir` fails because `cloud-c` is present.

- [ ] **Step 3: Rewrite `_github_target`**

Replace `src/cybersec_slm/ingestion/fetch.py:30-54` with:

```python
def _github_target(url: str) -> tuple[str, str, str] | None:
    """Resolve a github.com URL to something downloadable, a filename, a subdir.

    Repo root / tree URLs point at a *page*, not a file, so rewrite them to the
    branch archive zip (processed by the zip path below). ``/blob/`` URLs become
    their raw-file equivalent. Direct ``raw.githubusercontent.com`` links and
    file URLs return None (handled as-is).

    The third element is the sub-path of a ``/tree/<branch>/<subdir>`` URL, which
    the archive zip cannot express: the zip is always the whole branch, so the
    caller filters its members down to this prefix. Empty for every other shape.
    Returns ``(download_url, name, subdir)``.
    """
    p = urlparse(url)
    if p.netloc not in ("github.com", "www.github.com"):
        return None
    parts = [x for x in p.path.split("/") if x]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    if len(parts) == 2:                       # owner/repo  -> default branch zip
        return f"https://github.com/{owner}/{repo}/archive/HEAD.zip", f"{repo}.zip", ""
    if parts[2] == "tree" and len(parts) >= 4:   # .../tree/<branch>[/subdir]
        return (f"https://github.com/{owner}/{repo}/archive/refs/heads/{parts[3]}.zip",
                f"{repo}.zip", "/".join(parts[4:]))
    if parts[2] == "blob" and len(parts) >= 5:   # .../blob/<branch>/<path> -> raw
        branch, rest = parts[3], "/".join(parts[4:])
        return (f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rest}",
                os.path.basename(rest), "")
    return None
```

- [ ] **Step 4: Add the subset filter and use it in `fetch_url`**

Add above `fetch_url` in `src/cybersec_slm/ingestion/fetch.py`:

```python
def _under_subset(zdir: str, paths: list[str], subset: str) -> list[str]:
    """Keep only the extracted ``paths`` that live under ``subset``.

    A GitHub archive wraps everything in a single root directory named
    ``<repo>-<branch>``, whose name depends on the branch the zip came from.
    Strip that wrapper (when every entry shares one) before matching, so
    ``subset`` is compared against repo-relative paths and does not have to guess
    the wrapper's name.
    """
    rels = {p: os.path.relpath(p, zdir).replace(os.sep, "/") for p in paths}
    tops = {r.split("/")[0] for r in rels.values()}
    wrapped = len(tops) == 1 and all("/" in r for r in rels.values())
    prefix = subset.strip("/") + "/"
    keep = []
    for path, rel in rels.items():
        inner = rel.split("/", 1)[1] if wrapped else rel
        if inner.startswith(prefix):
            keep.append(path)
    return keep
```

Then change `fetch_url`'s signature and the zip branch. Replace
`src/cybersec_slm/ingestion/fetch.py:230-263` with:

```python
def fetch_url(url, domain, desc, lic, folder, log, kind="url", subset=""):
    """Fetch one URL into ``folder``.

    ``subset`` limits a repo archive to one sub-path. It is normally carried by
    the URL itself (a ``/tree/<branch>/<subdir>`` link), which is how a catalog
    row for one folder of a big repo stays honest: without it the row would
    ingest the whole repo. Empty means the whole source, which is every row that
    predates splitting.
    """
    gh = _github_target(url)
    if gh:
        url, name, gh_subset = gh   # repo page -> archive zip / raw file
        subset = subset or gh_subset
    else:
        name = _download_name(url)
    stem, fext = os.path.splitext(name)
    orig = os.path.join(folder, name)
    download(url, orig)
    if orig.lower().endswith(".zip") or _is_zipfile(orig):
        import zipfile
        zdir = os.path.join(folder, "_z"); os.makedirs(zdir, exist_ok=True)
        with zipfile.ZipFile(orig) as z:
            z.extractall(zdir)
        os.remove(orig)
        data = [os.path.join(r, f) for r, _d, fs in os.walk(zdir) for f in fs
                if f.lower().endswith(EXT_PRIORITY)
                and not any(s in f.lower() for s in SKIP_SUBSTRINGS)]
        if subset:
            data = _under_subset(zdir, data, subset)
        for ext in EXT_PRIORITY:
            data = [f for f in data if f.lower().endswith(ext)] or data
            if any(f.lower().endswith(ext) for f in data):
                break
        # Concatenate every matching file into ONE jsonl per source. A repo that
        # stores its data across thousands of small files otherwise explodes into
        # thousands of outputs; collapse it to a single <source>.jsonl.
        if data:
            origin_fmt = os.path.splitext(data[0])[1].lstrip(".")
            _combine_to_jsonl(sorted(data), os.path.join(folder, stem + ".jsonl"), log,
                              kind=kind, name=stem, domain=domain, desc=desc, url=url,
                              lic=lic, origin_fmt=origin_fmt)
        elif subset:
            logger.warning(f"  no data files under {subset!r} in {stem}.zip")
        else:
            logger.warning(f"  no data files inside {stem}.zip")
        shutil.rmtree(zdir, ignore_errors=True)
        return
    _convert_and_log(orig, os.path.join(folder, stem + ".jsonl"), log,
                     kind=kind, name=stem, domain=domain, desc=desc, url=url, lic=lic)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.\.venv\Scripts\python.exe -m pytest tests/ingestion/test_fetch.py -v`
Expected: 10 passed

- [ ] **Step 6: Check nothing else regressed**

Run: `.\.venv\Scripts\python.exe -m pytest tests/ingestion/ -q`
Expected: all pass. `test_worker.py` and `test_worker_fetch_only.py` exercise
`fetch_url`'s callers; if either fails, `_github_target`'s new arity has a caller
the grep missed. Fix the caller, do not revert the tuple.

- [ ] **Step 7: Commit**

```powershell
git add src/cybersec_slm/ingestion/fetch.py tests/ingestion/test_fetch.py
git -c user.name="vaibhavshiroorkar" -c user.email="vaibhavjtgz@gmail.com" commit -m @'
Fetch only the subdir of a tree link, instead of the whole repo

_github_target parsed tree/<branch>/<subdir> and dropped the subdir, so
fetch_url extracted the branch archive and ingested every file in it. A row
pointing at one folder quietly ingested the whole repo, and three such rows
produced three identical corpora under three sub-domains.

The subdir now rides through to fetch_url, which filters the extracted
members to it. An empty subset is unchanged behaviour, which is every row
that exists today.
'@
```

---

### Task 6: Fetch only the sub-path of a HuggingFace dataset

Same idea for HF, where the file list comes from `dataset_info` rather than a
zip. Unlike GitHub, the URL does not reach `fetch_hf` (the worker passes a `ref`),
so the sub-path travels on the descriptor.

**Files:**
- Modify: `src/cybersec_slm/ingestion/fetch.py:142-195` (`fetch_hf`), `src/cybersec_slm/ingestion/sources.py:304-310` (hf/kaggle descriptor), `src/cybersec_slm/ingestion/worker.py:41-42`
- Test: `tests/ingestion/test_fetch.py`, `tests/ingestion/test_domain_mapping.py`

**Interfaces:**
- Consumes: `fetch_url`'s `subset` naming (Task 5).
- Produces:
  - `fetch.fetch_hf(ref, domain, desc, lic, folder, log, subset="")`.
  - `sources._row_to_descriptor` now returns `subset: str` on `hf`/`kaggle` descriptors (`""` when the link names no sub-path). Every other descriptor shape is unchanged.
  - `worker._fetch_one` passes `descriptor.get("subset", "")` to `fetch_hf` only. Kaggle carries the key but ignores it: `dataset_download_file` has no folder concept, and no Kaggle row needs splitting today.

- [ ] **Step 1: Write the failing tests**

Append to `tests/ingestion/test_fetch.py`:

```python
# ------------------------------------------------------------ hf subset --------
def test_fetch_hf_downloads_only_the_subset(tmp_path, monkeypatch):
    class _Sib:
        def __init__(self, rfilename, size):
            self.rfilename, self.size = rfilename, size

    class _Info:
        siblings = [_Sib("train/a.parquet", 10), _Sib("test/b.parquet", 10)]

    class _Api:
        def dataset_info(self, ref, files_metadata=False):
            return _Info()

    import sys
    import types
    mod = types.ModuleType("huggingface_hub")
    mod.HfApi = _Api
    monkeypatch.setitem(sys.modules, "huggingface_hub", mod)

    wanted = []
    monkeypatch.setattr(fetch, "download", lambda url, dest, **kw: wanted.append(url))
    monkeypatch.setattr(fetch, "to_jsonl", lambda *a, **kw: 0)
    monkeypatch.setattr(fetch, "count_lines", lambda p: 0)
    monkeypatch.setattr(fetch, "sha256_file", lambda p: "x")

    folder = str(tmp_path / "out")
    os.makedirs(folder)
    fetch.fetch_hf("dk/cloud", "Cloud Security", "desc", "MIT", folder, _Log(),
                   subset="train")

    assert any("train/a.parquet" in u for u in wanted)
    assert not any("test/b.parquet" in u for u in wanted)
```

Append to `tests/ingestion/test_domain_mapping.py`:

```python
def test_an_hf_tree_link_carries_its_subset_onto_the_descriptor(tmp_path):
    from cybersec_slm.ingestion import sources as srcs

    csv = tmp_path / "Sources.csv"
    csv.write_text(
        "Name,Sub-Domain,Dataset Link,License\n"
        "A,Cloud Security,https://huggingface.co/datasets/dk/cloud/tree/main/train,MIT\n",
        encoding="utf-8")

    [d] = srcs.load_descriptors(str(csv), order_by_size=False)
    assert d["kind"] == "hf"
    assert d["ref"] == "dk/cloud"        # the tree suffix is not part of the ref
    assert d["subset"] == "train"


def test_a_plain_hf_link_has_an_empty_subset(tmp_path):
    from cybersec_slm.ingestion import sources as srcs

    csv = tmp_path / "Sources.csv"
    csv.write_text(
        "Name,Sub-Domain,Dataset Link,License\n"
        "A,Cloud Security,https://huggingface.co/datasets/dk/cloud,MIT\n",
        encoding="utf-8")

    [d] = srcs.load_descriptors(str(csv), order_by_size=False)
    assert d["subset"] == ""
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.\.venv\Scripts\python.exe -m pytest tests/ingestion/test_fetch.py -k hf_subset tests/ingestion/test_domain_mapping.py -k subset -v`
Expected: FAIL with `TypeError: fetch_hf() got an unexpected keyword argument 'subset'` and `KeyError: 'subset'`

- [ ] **Step 3: Add `subset` to `fetch_hf`**

In `src/cybersec_slm/ingestion/fetch.py`, change the signature at line 142 and
filter the candidates. The first lines of the function become:

```python
def fetch_hf(ref, domain, desc, lic, folder, log, subset=""):
    """Fetch a HuggingFace dataset into ``folder``.

    ``subset`` limits the fetch to one folder of the dataset, so a row for one
    part of a many-domain dataset does not pull the whole thing. Empty means the
    whole dataset.
    """
    from huggingface_hub import HfApi
    info = HfApi().dataset_info(ref, files_metadata=True)
    sib = {s.rfilename: (s.size or 0) for s in info.siblings}
    cand = [f for f in sib if f.lower().endswith(EXT_PRIORITY)
            and not any(s in f.lower() for s in SKIP_SUBSTRINGS)]
    if subset:
        pre = subset.strip("/") + "/"
        cand = [f for f in cand if f.startswith(pre)]
```

Leave the rest of the function exactly as it is.

- [ ] **Step 4: Carry `subset` on the descriptor**

In `src/cybersec_slm/ingestion/sources.py`, replace the `hf`/`kaggle` branch of
`_row_to_descriptor` (lines 304-310) with:

```python
    if kind in ("hf", "kaggle"):
        ref = _val(row, "ref")
        if not ref:
            m = re.search(r"/datasets/([^/]+/[^/?#]+)", url)
            ref = m.group(1) if m else slug
        # A /tree/<branch>/<sub> link names one folder of the dataset. The ref
        # regex above already stops at the dataset, so the sub-path would be lost
        # and the row would pull the whole dataset instead of its part.
        subset = _val(row, "subset", default="") or ""
        if not subset:
            m = re.search(r"/datasets/[^/]+/[^/?#]+/tree/[^/?#]+/(.+)$", url)
            subset = m.group(1).rstrip("/") if m else ""
        return dict(kind=kind, ref=ref, domain=domain, description=desc,
                    license=lic, url=url, subset=subset)
```

- [ ] **Step 5: Pass it through the worker**

In `src/cybersec_slm/ingestion/worker.py`, change line 42 to:

```python
        if kind == "hf":
            fetch.fetch_hf(ref, domain, desc, lic, folder, log,
                           subset=descriptor.get("subset", ""))
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.\.venv\Scripts\python.exe -m pytest tests/ingestion/ -v`
Expected: all pass

- [ ] **Step 7: Commit**

```powershell
git add src/cybersec_slm/ingestion/fetch.py src/cybersec_slm/ingestion/sources.py src/cybersec_slm/ingestion/worker.py tests/ingestion/
git -c user.name="vaibhavshiroorkar" -c user.email="vaibhavjtgz@gmail.com" commit -m "Fetch only the named folder of a HuggingFace dataset"
```

---

### Task 7: Scan, review, and add the parts

The UI. Scanning is optional: pressing Add without scanning adds one row exactly
as it does today, so a simple add costs no network call and the existing
`test_add_source_*` tests keep passing unchanged.

**Files:**
- Modify: `src/cybersec_slm/dashboard/pages/1_Sourcing.py:385-474`
- Test: `tests/dashboard/test_sourcing_page.py`

**Interfaces:**
- Consumes: `split.list_parts`, `split.propose`, `split.part_link`, `split.part_name`, `split.unsupported_reason` (Tasks 2-4), `row_builder.build_manual_row`, `sheet.append_rows`, `sheet.existing_links`, `sheet.normalize_url`, `enrich.enrich_row`.
- Produces: catalog rows. No new public API.
- Session state: `_ms_scan` holds `{"link": str, "scan": Scan, "proposals": list[Proposal], "meta": dict}`. It is keyed on the link so editing the link after a scan drops back to manual mode rather than adding rows for a link the user has moved on from.

- [ ] **Step 1: Write the failing tests**

Append to `tests/dashboard/test_sourcing_page.py`:

```python
# ------------------------------------------------- add a source, split by part --
def _fake_scan(monkeypatch, parts, *, branch="main", title="big-repo",
               description="", topics=()):
    """Make the page's scan return ``parts`` without touching the network.

    Both halves matter: ``list_parts`` reaches GitHub/HuggingFace, and the Add
    path calls ``enrich_row`` for the source's License and Author. Leave either
    real and this test hits the network.
    """
    from cybersec_slm.sourcing import enrich, split

    def _list_parts(link, **kw):
        return split.Scan(parts=tuple(parts), title=title, description=description,
                          topics=tuple(topics), branch=branch, splittable=True)

    monkeypatch.setattr(split, "list_parts", _list_parts)
    monkeypatch.setattr(enrich, "enrich_row", lambda row, **kw: row)


def test_scanning_a_repo_proposes_a_subdomain_per_part(page, monkeypatch):
    from cybersec_slm.sourcing import split

    _taxonomy(**{"Network Security": {"datasets": ["n"], "vocab": ["pcap"]},
                 "Cloud Security": {"datasets": ["c"], "vocab": ["kubernetes"]}})
    _fake_scan(monkeypatch, [
        split.Part(path="pcaps", file_count=3, sample_names=("a.csv",)),
        split.Part(path="kubernetes-cfg", file_count=2, sample_names=("b.yaml",)),
    ])

    page.run()
    page.text_input(key="ms_name").set_value("big-repo")
    page.text_input(key="ms_link").set_value("https://github.com/org/big-repo").run()
    page.button(key="ms_scan").click().run()
    assert not page.exception

    df = page.session_state["_ms_scan"]
    assert [p.part.path for p in df["proposals"]] == ["pcaps", "kubernetes-cfg"]
    assert [p.domain for p in df["proposals"]] == ["Network Security", "Cloud Security"]


def test_adding_a_scanned_repo_appends_one_row_per_part(page, catalog_csv,
                                                        monkeypatch):
    from cybersec_slm.sourcing import split

    _taxonomy(**{"Network Security": {"datasets": ["n"], "vocab": ["pcap"]},
                 "Cloud Security": {"datasets": ["c"], "vocab": ["kubernetes"]}})
    _fake_scan(monkeypatch, [
        split.Part(path="pcaps", file_count=3, sample_names=("a.csv",)),
        split.Part(path="kubernetes-cfg", file_count=2, sample_names=("b.yaml",)),
    ])

    page.run()
    page.text_input(key="ms_name").set_value("big-repo")
    page.text_input(key="ms_link").set_value("https://github.com/org/big-repo").run()
    page.button(key="ms_scan").click().run()
    page.button(key="ms_add").click().run()
    assert not page.exception

    import pandas as pd
    df = pd.read_csv(catalog_csv, dtype=str, keep_default_na=False)
    rows = df[df["Name"].str.startswith("big-repo")].reset_index(drop=True)
    assert len(rows) == 2

    by_name = {r["Name"]: r for _i, r in rows.iterrows()}
    assert by_name["big-repo/pcaps"]["Sub-Domain"] == "Network Security"
    assert (by_name["big-repo/pcaps"]["Dataset Link"]
            == "https://github.com/org/big-repo/tree/main/pcaps")
    assert by_name["big-repo/kubernetes-cfg"]["Sub-Domain"] == "Cloud Security"
    assert (by_name["big-repo/kubernetes-cfg"]["Dataset Link"]
            == "https://github.com/org/big-repo/tree/main/kubernetes-cfg")


def test_each_split_row_is_ingestable_and_fetches_only_its_folder(page, catalog_csv,
                                                                  monkeypatch):
    """The rows must map to descriptors whose URL names their own folder, or the
    split would be a lie: each row would ingest the whole repo."""
    from cybersec_slm.ingestion import fetch
    from cybersec_slm.ingestion import sources as srcs
    from cybersec_slm.sourcing import split

    _taxonomy(**{"Network Security": {"datasets": ["n"], "vocab": ["pcap"]},
                 "Cloud Security": {"datasets": ["c"], "vocab": ["kubernetes"]}})
    _fake_scan(monkeypatch, [
        split.Part(path="pcaps", file_count=3, sample_names=("a.csv",)),
        split.Part(path="kubernetes-cfg", file_count=2, sample_names=("b.yaml",)),
    ])

    page.run()
    page.text_input(key="ms_name").set_value("big-repo")
    page.text_input(key="ms_link").set_value("https://github.com/org/big-repo").run()
    page.button(key="ms_scan").click().run()
    page.button(key="ms_add").click().run()

    descs = {d["url"]: d for d in srcs.load_descriptors(catalog_csv,
                                                        order_by_size=False)
             if "big-repo" in d.get("url", "")}
    assert len(descs) == 2
    for url, d in descs.items():
        assert d["kind"] == "github"
        _dl, _name, subdir = fetch._github_target(url)
        assert subdir in ("pcaps", "kubernetes-cfg")


def test_a_part_matching_nothing_blocks_add_until_a_subdomain_is_picked(
        page, monkeypatch):
    from cybersec_slm.sourcing import split

    # No vocab matches "mystery", and the repo has nothing to inherit from.
    _taxonomy(**{"Network Security": {"datasets": ["n"], "vocab": ["pcap"]}})
    _fake_scan(monkeypatch, [split.Part(path="mystery", file_count=1)],
               title="repo", description="")

    page.run()
    page.text_input(key="ms_name").set_value("repo")
    page.text_input(key="ms_link").set_value("https://github.com/org/repo").run()
    page.button(key="ms_scan").click().run()
    assert not page.exception
    assert page.button(key="ms_add").disabled


def test_an_rss_link_is_refused_with_a_reason(page):
    _taxonomy(**{"Network Security": {"datasets": ["n"]}})

    page.run()
    page.text_input(key="ms_name").set_value("blog")
    page.text_input(key="ms_link").set_value("https://blog.test/feed.xml").run()
    assert not page.exception
    assert page.button(key="ms_add").disabled
    assert any("RSS" in w.value for w in page.warning)


def test_editing_the_link_after_a_scan_drops_the_stale_parts(page, monkeypatch):
    from cybersec_slm.sourcing import split

    _taxonomy(**{"Network Security": {"datasets": ["n"], "vocab": ["pcap"]}})
    _fake_scan(monkeypatch, [split.Part(path="pcaps", file_count=1)])

    page.run()
    page.text_input(key="ms_name").set_value("big-repo")
    page.text_input(key="ms_link").set_value("https://github.com/org/big-repo").run()
    page.button(key="ms_scan").click().run()
    # Point at a different source without rescanning.
    page.text_input(key="ms_link").set_value(
        "https://huggingface.co/datasets/dk/other").run()
    assert not page.exception
    # Back to the single-row form: the Sub-Domain picker is showing again.
    assert page.selectbox(key="ms_dom")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.\.venv\Scripts\python.exe -m pytest tests/dashboard/test_sourcing_page.py -v`
Expected: the new tests FAIL (no `ms_scan` button); the existing `test_add_source_*` tests PASS.

- [ ] **Step 3: Rewrite the Add tab**

Replace `src/cybersec_slm/dashboard/pages/1_Sourcing.py:385-474` with the
following. Note the import of `split` goes with the other sourcing imports at the
top of the file; check what is already imported before adding it.

```python
# ============================================================== Add source =====
with add_tab:
    with ui.section("Add a source by hand",
                    "Appends rows to `sources/Sources.csv`, identical in shape "
                    "to a discovered one, so the ingest stage picks them up on "
                    "the next run. Scan a repo or dataset to file each of its "
                    "folders under its own sub-domain."):
        if not all_domains:
            st.info("No sub-domains configured yet. Add one in the Sub-domains tab "
                    "first, so this source has somewhere to be filed.")
        else:
            a1, a2 = st.columns(2)
            m_name = a1.text_input(
                "Name *", key="ms_name",
                help="Short label for the source. Scanned parts are named "
                     "`<name>/<folder>`, so each part keeps its own raw folder.")
            m_link = a2.text_input(
                "Dataset Link *", key="ms_link",
                help="The source URL. It decides how ingestion fetches this "
                     "source (HuggingFace / Kaggle / GitHub / direct file / site).")

            # A link no handler supports would sit in the catalog until ingest
            # failed on it an hour later, so say no here instead.
            _unsupported = split.unsupported_reason(m_link)
            if _unsupported:
                st.warning(_unsupported)

            # The scan is optional: without it this is the single-row form it has
            # always been, and no network call is made.
            scan_state = st.session_state.get("_ms_scan")
            if scan_state and scan_state.get("link") != m_link.strip():
                scan_state = None
                st.session_state.pop("_ms_scan", None)

            if st.button("Scan for parts", key="ms_scan", type="secondary",
                         disabled=not m_link.strip() or bool(_unsupported),
                         help="Look inside a repo or dataset and propose a "
                              "sub-domain for each of its folders."):
                with st.spinner("Scanning the source..."):
                    _scan = split.list_parts(m_link.strip())
                if not _scan.splittable:
                    st.info("This source has no folders to split: it will be "
                            "added as one row.")
                    st.session_state.pop("_ms_scan", None)
                else:
                    st.session_state["_ms_scan"] = {
                        "link": m_link.strip(), "scan": _scan,
                        "proposals": split.propose(_scan)}
                    st.rerun()

            m_desc = st.text_area("Description", key="ms_desc", height=80)

            b1, b2, b3 = st.columns(3)
            m_cat = b1.selectbox("Category", ["(infer from link)",
                                              *row_builder.CATEGORIES],
                                 key="ms_cat")
            m_fmt = b2.selectbox("Original Format", ["(infer from link)",
                                                     *row_builder.FORMATS],
                                 key="ms_fmt")
            m_lic = b3.text_input(
                "License", key="ms_lic",
                help="Free text (e.g. `MIT`, `Apache-2.0`, `CC0-1.0`). Ingestion "
                     "fetches a source only when its license is clearly "
                     "commercial-use; blank or unrecognised is turned away.")
            m_syn = st.checkbox(
                "Is Synthetic?", key="ms_syn",
                help="Model-generated content. Synthetic sources are cleaned but "
                     "excluded from the final dataset by the schema stage.")

            # ------------------------------------------------ scanned parts ----
            picked: list[dict] = []
            _needs_domain = False
            if scan_state:
                props = scan_state["proposals"]
                st.caption(f"{sum(p.part.file_count for p in props)} data files in "
                           f"{len(props)} folders. Each row below becomes its own "
                           f"catalog row under its own sub-domain.")
                _PICK = "(pick a sub-domain)"
                rows = [{"Add": True,
                         "Part": p.part.path or "(whole source)",
                         "Files": p.part.file_count,
                         "Size (MB)": p.part.size_mb,
                         "Sub-Domain": p.domain or _PICK,
                         "Why": ("inherited from the source" if p.inherited
                                 else "matched" if p.domain else "no match")}
                        for p in props]
                edited = st.data_editor(
                    rows, use_container_width=True, hide_index=True,
                    key="ms_parts", disabled=("Part", "Files", "Size (MB)", "Why"),
                    column_config={
                        "Add": st.column_config.CheckboxColumn("Add", width="small"),
                        "Sub-Domain": st.column_config.SelectboxColumn(
                            "Sub-Domain", options=[_PICK, *all_domains],
                            required=True, width="medium"),
                        "Why": st.column_config.TextColumn("Why", width="medium"),
                    })
                _already = sheet.existing_links(data.catalog_path())
                _dupe_parts = []
                for prop, edit in zip(props, edited):
                    if not edit["Add"]:
                        continue
                    if edit["Sub-Domain"] == _PICK:
                        _needs_domain = True
                        continue
                    _plink = split.part_link(m_link, prop.part,
                                             scan_state["scan"].branch)
                    # A part already catalogued (a rescan, or one added by hand
                    # earlier) must not be appended twice.
                    if sheet.normalize_url(_plink) in _already:
                        _dupe_parts.append(prop.part.path or "(whole source)")
                        continue
                    picked.append({"part": prop.part, "domain": edit["Sub-Domain"]})
                if _dupe_parts:
                    st.info("Already in the catalog, so not added again: "
                            + ", ".join(_dupe_parts))
                if _needs_domain:
                    st.warning("Every part being added needs a sub-domain. The "
                               "classifier had no match for one, so pick it by "
                               "hand or untick it.")
                if st.button("Clear scan", key="ms_clear", type="tertiary"):
                    st.session_state.pop("_ms_scan", None)
                    st.rerun()
            else:
                m_dom = st.selectbox("Sub-Domain *", all_domains, key="ms_dom")

            with st.expander("More fields (optional)"):
                st.caption("Left blank, these are filled in by the ingest and "
                           "clean stages as they measure the source.")
                e1, e2, e3 = st.columns(3)
                m_files = e1.text_input("File Count", key="ms_files")
                m_osize = e2.text_input("Original Size (MB)", key="ms_osize")
                m_lines = e3.text_input("Total Lines", key="ms_lines")
                f1, f2, f3 = st.columns(3)
                m_author = f1.text_input("Author", key="ms_author")
                m_updated = f2.text_input("Last Updated", key="ms_updated")
                m_tags = f3.text_input("Tags", key="ms_tags")
                m_note = st.text_input("Note", key="ms_note")

            _required = [m_name.strip(), m_link.strip()]
            if not scan_state:
                _required.append(m_dom)

            # Reject a link the catalog already has: normalize_url matches the same
            # source linked slightly differently, which is what discovery dedups on.
            _existing = sheet.existing_links(data.catalog_path()) if m_link.strip() \
                else set()
            _dupe = ""
            if m_link.strip() and not scan_state:
                if sheet.normalize_url(m_link) in _existing:
                    _dupe = ("This link is already in the catalog. Delete the "
                             "existing row first if you want to re-add it.")
                    st.warning(_dupe)
            elif scan_state and sheet.normalize_url(m_link) in _existing:
                # The whole repo is already catalogued. The parts do not collide
                # with it (different links), but they would overlap its data.
                st.warning("The whole source is already in the catalog. Adding "
                           "parts of it as well would ingest the same data twice.")

            _blocked = (not all(_required) or bool(_dupe) or bool(_unsupported)
                        or _needs_domain or (scan_state is not None and not picked))
            _label = f"Add {len(picked)} sources" if scan_state else "Add source"
            if ui.right_slot().button(_label, key="ms_add", type="primary",
                                      disabled=_blocked, use_container_width=True):
                _extra = {"File Count": m_files, "Original Size (MB)": m_osize,
                          "Total Lines": m_lines, "Author": m_author,
                          "Last Updated": m_updated, "Tags": m_tags,
                          "Note": m_note}
                try:
                    if scan_state:
                        branch = scan_state["scan"].branch
                        new_rows = [
                            row_builder.build_manual_row(
                                name=split.part_name(m_name, p["part"]),
                                subdomain=p["domain"],
                                link=split.part_link(m_link, p["part"], branch),
                                description=m_desc,
                                category="" if m_cat.startswith("(") else m_cat,
                                original_format=("" if m_fmt.startswith("(")
                                                 else m_fmt),
                                license=m_lic, is_synthetic=m_syn,
                                extra={**_extra,
                                       "File Count": str(p["part"].file_count),
                                       "Original Size (MB)": str(p["part"].size_mb)})
                            for p in picked]
                    else:
                        new_rows = [row_builder.build_manual_row(
                            name=m_name, subdomain=m_dom, link=m_link,
                            description=m_desc,
                            category="" if m_cat.startswith("(") else m_cat,
                            original_format="" if m_fmt.startswith("(") else m_fmt,
                            license=m_lic, is_synthetic=m_syn, extra=_extra)]
                except ValueError as ex:
                    st.error(str(ex))
                else:
                    # One metadata lookup for the whole source, copied onto every
                    # part row, filling only what was left blank.
                    if scan_state:
                        with st.spinner("Fetching the source's metadata..."):
                            _meta = _source_meta(m_link)
                        new_rows = [_fill_blanks(r, _meta) for r in new_rows]
                    sheet.append_rows(data.catalog_path(), new_rows)
                    st.session_state.pop("_ms_scan", None)
                    if len(new_rows) == 1:
                        st.success(f"Added '{new_rows[0]['Name']}' to "
                                   f"sources/Sources.csv under "
                                   f"{new_rows[0]['Sub-Domain']}")
                    else:
                        st.success(f"Added {len(new_rows)} sources to "
                                   f"sources/Sources.csv: "
                                   + ", ".join(f"{r['Name']} -> {r['Sub-Domain']}"
                                               for r in new_rows))
                    st.rerun()
            if not all(_required):
                st.caption("Name, Sub-Domain, and Dataset Link are required.")
```

Add these helpers near the top of the page module, under the imports:

```python
def _source_meta(link: str) -> dict:
    """Metadata for the source as a whole, fetched once. Never raises.

    Called once per scan and copied onto every part, rather than once per part:
    the parts share a repo, so enriching each would be the same lookup N times.
    A dead host must cost the add nothing, which is why this swallows: a blank
    License is exactly what the form produces without it.
    """
    try:
        probe = enrich.enrich_row({"Dataset Link": link})
    except Exception:                      # noqa: BLE001 - best-effort
        return {}
    return {k: v for k, v in probe.items()
            if k != "Dataset Link" and str(v or "").strip()}


def _fill_blanks(row: dict, meta: dict) -> dict:
    """Fill only the columns the human left blank, never overwrite one they set.

    Mirrors enrich.Enricher's own contract. The part's own File Count and size
    are already set by the caller, so the source-wide figures cannot clobber them.
    """
    for col, val in meta.items():
        if col in row and not str(row.get(col) or "").strip():
            row[col] = str(val)
    return row
```

- [ ] **Step 4: Wire the imports**

At the top of `src/cybersec_slm/dashboard/pages/1_Sourcing.py`, ensure the
sourcing imports include `enrich` and `split`. Check the existing import line
first (it already pulls `row` as `row_builder` and `sheet`) and extend it rather
than adding a second import of the same package.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.\.venv\Scripts\python.exe -m pytest tests/dashboard/test_sourcing_page.py -v`
Expected: all pass, including the four pre-existing `test_add_source_*` tests.

If `test_add_source_appends_a_row_to_the_catalog` now fails on `License`, the
enrich call is overwriting a typed value: it must not. Check `enrich.Enricher.enrich`'s
"never overwrite" contract rather than deleting the assertion.

- [ ] **Step 6: Lint and check the whole dashboard suite**

Run: `.\.venv\Scripts\python.exe -m ruff check src/cybersec_slm/dashboard/pages/1_Sourcing.py`
Run: `.\.venv\Scripts\python.exe -m pytest tests/dashboard/ -q`
Expected: no findings, all pass.

- [ ] **Step 7: Commit**

```powershell
git add src/cybersec_slm/dashboard/pages/1_Sourcing.py tests/dashboard/test_sourcing_page.py
git -c user.name="vaibhavshiroorkar" -c user.email="vaibhavjtgz@gmail.com" commit -m @'
Scan a source and file each of its folders under its own sub-domain

Add a source by hand still adds one row when you just fill the form in.
Press Scan and the page lists the source's top-level data folders, proposes a
sub-domain for each, and writes one row per folder pointing at that folder.

Proposals are reviewable because they are only as good as the taxonomy vocab:
a folder that matches nothing inherits the source's sub-domain, and one whose
source matched nothing either has to be picked by hand.
'@
```

---

### Task 8: Drop the duplicate ingest bar and show the release token count

Two small, independent dashboard fixes.

**Files:**
- Modify: `src/cybersec_slm/dashboard/app.py:61-74`
- Modify: `src/cybersec_slm/dashboard/pages/5_Schema.py:29-34`
- Test: `tests/dashboard/test_stage_pages.py`

**Interfaces:**
- Consumes: `data.manifest()` (existing; `5_Schema.py:23` already calls it and binds it to `man`), `charts.fmt_int` (existing).
- Produces: no API change.

Only the token metric gets a test. The duplicate bar cannot honestly get one: it
renders only inside `_live()`, an `st.fragment(run_every=1)` that only draws the
bar `if running`, and AppTest cannot drive a live run. A test assering "no
progress bar on an idle page" would pass before the change as well as after,
which is theater. That deletion is verified by eye in Task 9 instead.

Append to `tests/dashboard/test_stage_pages.py`. The file already has
`_REPO`/`_PAGES` module constants and imports `AppTest` at the top; use those
rather than re-deriving them inside the test.

```python
def test_schema_normalize_shows_the_release_token_count(tmp_path, monkeypatch):
    """The manifest's token_total is the number the Normalize tab is read for."""
    import json

    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    final = tmp_path / "final"
    final.mkdir(parents=True, exist_ok=True)
    (final / "manifest.json").write_text(json.dumps({
        "record_count": 10, "token_total": 12345, "unique_content_hashes": 10,
    }), encoding="utf-8")

    page = AppTest.from_file(os.path.join(_PAGES, "5_Schema.py"), default_timeout=30)
    page.run()
    assert not page.exception

    metrics = {m.label: m.value for m in page.metric}
    assert metrics["Tokens"] == "12,345"


def test_schema_tokens_read_n_a_before_the_stage_has_run(tmp_path, monkeypatch):
    """No manifest yet must read as unknown, not as zero tokens."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))

    page = AppTest.from_file(os.path.join(_PAGES, "5_Schema.py"), default_timeout=30)
    page.run()
    assert not page.exception

    metrics = {m.label: m.value for m in page.metric}
    assert metrics["Tokens"] == "n/a"
```

Check where the manifest is expected to live before writing the fixture above:
confirm `data.manifest()` reads `<data root>/final/manifest.json`. If it resolves
somewhere else, put the file where the code looks, not where this plan guessed.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.\.venv\Scripts\python.exe -m pytest tests/dashboard/test_stage_pages.py -k "token_count or repeat_the_ingest" -v`
Expected: the token test FAILs (no such metric). The overview test may already
pass when no run is active, since the bar renders only while running; if it
passes, keep it as the regression guard it is and move on.

- [ ] **Step 3: Delete the duplicate bar**

In `src/cybersec_slm/dashboard/app.py`, replace lines 61-74 with:

```python
    # "Stage N of 5" only. The sources-checked bar lives in the corpus funnel
    # below, which is the one place it belongs; this strip is state and timing.
    if running:
        idx, tot = phase.get("index"), phase.get("total")
        if idx and tot:
            st.caption(f"Stage {idx} of {tot}  ·  {phase.get('label', '')}")

        # Rolling history of sources-checked is tracked in session state
        # for future diagnostics or replay, but the Overview page does not
        # render it as a chart.
        ip = data.ingest_progress()
        checked = ip.get("checked") or 0
        pid = status.get("pid")
        hist = st.session_state.get("_live_history")
        if not hist or hist.get("pid") != pid:
            hist = {"pid": pid, "checked": []}
        hist["checked"] = (hist["checked"] + [checked])[-600:]
        st.session_state["_live_history"] = hist
```

- [ ] **Step 4: Add the token metric**

In `src/cybersec_slm/dashboard/pages/5_Schema.py`, replace lines 29-34 with:

```python
    with ui.section("Normalization"):
        appended = cached.data_funnel(data.data_root())["appended"]
        c = st.columns(4)
        c[0].metric("Sources", charts.fmt_int(appended["sources"]))
        c[1].metric("Records written", charts.fmt_int(appended["lines"]))
        c[2].metric("Size", charts.fmt_size(appended["size_mb"]))
        # Tokens come from the manifest rather than the funnel: the funnel counts
        # what is on disk, and only the schema stage counts tokens as it writes.
        c[3].metric("Tokens", charts.fmt_int(man.get("token_total")) if man
                    else "n/a",
                    help="Total tokens in `data/final/dataset.jsonl`, from the "
                         "release manifest. Written by this stage.")
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.\.venv\Scripts\python.exe -m pytest tests/dashboard/ -q`
Expected: all pass

- [ ] **Step 6: Commit**

```powershell
git add src/cybersec_slm/dashboard/app.py src/cybersec_slm/dashboard/pages/5_Schema.py tests/dashboard/test_stage_pages.py
git -c user.name="vaibhavshiroorkar" -c user.email="vaibhavjtgz@gmail.com" commit -m @'
Show the release token count on Schema, drop the repeated ingest bar

The Overview drew the same sources-checked bar twice, once in the run-status
strip and once in the corpus funnel right below it. The funnel keeps it.

The Normalize tab reported sources, records and size but not tokens, which is
the number the release is actually measured in. It comes from the manifest,
where the Manifest tab already reads it.
'@
```

---

### Task 9: Verify the whole flow end to end

Tests pass in isolation; this checks the pieces meet.

**Files:** none (verification only)

- [ ] **Step 1: Run the full suite**

Run: `.\.venv\Scripts\python.exe -m pytest -q`
Expected: all pass, no errors

- [ ] **Step 2: Lint everything touched**

Run: `.\.venv\Scripts\python.exe -m ruff check src/ tests/`
Expected: no findings

- [ ] **Step 3: Drive the real dashboard**

Use the `verify` skill, or launch it directly:

Run: `.\.venv\Scripts\python.exe -m streamlit run src/cybersec_slm/dashboard/app.py`

Check, on the Sourcing page's "Add source" tab:
1. Paste a real multi-folder repo link and press "Scan for parts". Parts appear with proposed sub-domains.
2. A part reading "inherited from the source" can be corrected via its dropdown.
3. Paste `https://blog.example.test/feed.xml`. Add is disabled and the RSS reason shows.
4. Add without scanning still writes one row.
5. Overview shows one progress bar, not two.
6. Schema's Normalize tab shows Tokens.

- [ ] **Step 4: Confirm a split row fetches only its folder**

The one claim tests alone cannot make: that a real repo's part row pulls only
its folder. With a real link added by the split flow:

Run: `.\.venv\Scripts\python.exe -m cybersec_slm.cli ingest --only <slug>`

Check `data/raw/<sub-domain>/<slug>/` holds only that folder's data. Confirm the
CLI's actual flag name with `--help` first; `--only` is a guess and may not exist.

---

## Notes for the implementer

**Why the sub-path is in the link and not a new column.** `sources.py:64`
declares `CATALOG_COLUMNS` as the catalog's contract, shared by the crawler that
appends rows and the cleaning driver that writes columns back. Adding a column
touches all of it. The link already carries the sub-path in a form GitHub and
HuggingFace both use, `sheet.normalize_url` already keys dedup on host + path so
two parts differ for free, and `fetch.py` was already parsing the sub-path and
discarding it. The column would be a second source of truth for something the URL
already says.

**Why scanning is optional.** Forcing a scan would put a network call in front of
the simplest possible add (paste a link to one CSV, pick a sub-domain, done), and
would break four existing tests that encode that flow. The scan earns its network
call only when there is something to look inside.

**What this does not fix.** `classify._score` substring-matches short vocab terms,
so `k8s-configs/` misses Cloud Security because the vocab has `kubernetes`. The
review step covers for it. If it grates, add `k8s` and friends to the sub-domain's
`vocab` in `sources/profiles/cybersec/keywords.yaml`, which is a data change
needing no code.
