# Manual source add with per-part sub-domain assignment

Date: 2026-07-17

## Problem

Three unrelated asks, grouped here because two are trivial and one is a feature.

1. Add websites, APIs, feed links, repos and datasets by hand, and have the
   sub-domain assigned automatically, splitting a source across sub-domains when
   its parts belong in different ones.
2. The Overview page shows an "Ingest / N sources" progress bar twice.
3. The Schema page does not show the final dataset's token count where it is
   looked for.

## Scope

Items 2 and 3 are a few lines each and depend on nothing. Item 1 is the feature
and drives the rest of this document.

## What already exists

The starting point is better than it looks; most of this is wiring, not new
machinery.

| Piece | Where | State |
|---|---|---|
| Manual add form | `dashboard/pages/1_Sourcing.py:386` | One link at a time, Sub-Domain picked by hand from a dropdown |
| Manual row builder | `sourcing/row.py:75` `build_manual_row` | Complete. Infers Category/Format from the link |
| Sub-domain classifier | `sourcing/classify.py:53` `refine_domain` | Complete. Scores title+snippet against per-sub-domain vocab |
| Vocab source | `sourcing/catalog.py:118` | `keywords.yaml` omits `vocab`, so it is backfilled from the taxonomy's built-in `_VOCAB` (short terms: `pcap`, `owasp`, `kubernetes`) |
| Metadata enrichment | `sourcing/enrich.py:240` `enrich_row` | Complete. Fills License, Author, Tags, Last Updated for HF / GitHub / plain URLs |
| Link dedup | `sourcing/sheet.py:27` `normalize_url` | Keeps host + path, so sub-path links are distinct |
| HF file listing | `ingestion/fetch.py:144` | `dataset_info(files_metadata=True).siblings` |

## Constraints discovered

These are load-bearing and were verified in the code, not assumed.

**A sub-path of a repo cannot currently be fetched.** `fetch.py:47` parses a
`tree/<branch>/<subdir>` GitHub URL and discards the subdir, returning the whole
repo's archive zip. `fetch_url` (`fetch.py:239-262`) then extracts the zip and
walks every file in it, combining all data files into one JSONL. So three rows
pointing at three subfolders of one repo would each download the entire repo and
ingest all of it, producing three identical corpora filed under three different
sub-domains. Splitting requires a fetcher change; a smarter form is not enough.

This is also a latent bug independent of this feature: a discovered
`tree/main/subdir` link silently ingests the whole repo today.

**Feeds and APIs are narrower than the words suggest.** Worker dispatch
(`worker.py:41-67`) supports `hf`, `kaggle`, `github`/`url`, `pdf`, `website`,
and three narrow kinds: `feed` is JSON only (`scrape_feed`, needs a `json_key`),
`api` routes to `fetch_nvd` (hardcoded to the NVD CVE 2.0 API), and `xml` routes
to `scrape_cwe` (hardcoded to MITRE CWE). RSS/Atom feeds and generic REST APIs
have no handler.

**Classification on folder names is weak.** `classify._score` substring-matches
vocab terms against text. The built-in vocab is short terms, so `pcaps/` matches
`pcap` and lands in Network Security, but `k8s-configs/` misses because the vocab
has `kubernetes` and not `k8s`. Proposals must be reviewable, not authoritative.

## Design

### Decisions

| Decision | Choice | Why |
|---|---|---|
| What is a part | One top-level folder containing data files | A handful of rows per repo. Deeper walking multiplies rows and noise; per-file rows turn a 400-file repo into 400 rows |
| Sub-path carrier | The link itself (`tree/<branch>/<folder>`) | No new catalog column, dedup works unchanged, and it fixes the latent bug above |
| Review | Proposed split is shown and edited before any write | Given the `k8s` gap, a silent misclassification would land in the catalog unnoticed |
| RSS/Atom and generic APIs | Refused with a reason | No fetcher exists. A row that can never be fetched fails 40 minutes later at ingest, far from its cause |

### New module: `sourcing/split.py`

Owns "what parts does this link have, and where does each belong". Knows nothing
about Streamlit or the catalog CSV.

```
@dataclass(frozen=True)
class Part:
    path: str            # top-level folder, "" for files at the root
    file_count: int
    size_mb: float
    sample_names: list[str]   # a few file names, used as classifier signal

@dataclass(frozen=True)
class Scan:
    parts: list[Part]
    title: str
    description: str
    topics: list[str]
    branch: str
    splittable: bool

list_parts(link, *, github_token=None) -> Scan
propose(scan, cat=None) -> list[tuple[Part, str, int]]   # (part, sub-domain, score)
part_link(link, part, branch) -> str
part_name(base_name, part) -> str
```

`list_parts` dispatches on host:

- GitHub: `/repos/{o}/{r}` for description, topics and default branch, then
  `/repos/{o}/{r}/git/trees/{branch}?recursive=1` for the file list. Honors
  `$GITHUB_TOKEN` the way `enrich.py` already does.
- HuggingFace: `HfApi().dataset_info(ref, files_metadata=True).siblings`.
- Anything else: `Scan(splittable=False)` with a single `Part(path="")`, so the
  UI flow is uniform for a website or a PDF.

Files are filtered to `ingestion.common.EXT_PRIORITY` and grouped by their first
path segment. Folders with no data files (`docs/`, `.github/`) disappear on their
own rather than needing a skip list. Files at the repo root collapse into one
`Part(path="")`.

Network and parse failures follow `enrich.py`'s contract: swallowed and logged,
returning an unsplittable scan, so a GitHub outage degrades to the current
single-row behaviour instead of breaking the form.

`propose` reuses `classify.refine_domain` as-is rather than growing a second
classifier. Its signature already fits:

1. The source as a whole is classified from its title, description and topics.
   That result is the `default_domain`, carrying its own score.
2. Each part is refined with `refine_domain(default_domain, part.path,
   " ".join(part.sample_names), vocab)`.

The score decides how the proposal is presented, and there are exactly three
cases:

| Part score | Repo score | Proposal | UI |
|---|---|---|---|
| > 0 | any | the part's own match | pre-selected |
| 0 | > 0 | inherited repo-level domain | pre-selected, marked "inherited" |
| 0 | 0 | none | "(pick a sub-domain)", blocks Add |

So a domain is only ever invented when something actually matched. When nothing
matched anywhere, the form asks rather than guesses.

Vocab is built once per scan via `classify.build_domain_vocab`, not per part.

### Ingestion: honor a sub-path

- `_github_target(url)` returns `(url, name, subdir)`; `subdir` is `""` except
  for `tree/<branch>/<subdir>` links. Callers updated.
- `fetch_url` filters extracted members to `subdir` before combining. The filter
  is applied to each file's path relative to the archive's single root directory
  (`{repo}-{branch}/`), so it does not depend on guessing that directory's name.
- `fetch_hf` takes `subset: str = ""` and filters `siblings` by prefix.
  `sources._row_to_descriptor` parses `/tree/<branch>/<sub>` out of an HF link
  into `descriptor["subset"]`, and `worker._fetch_one` passes it through.

An empty `subdir`/`subset` reproduces today's behaviour exactly, so every
existing catalog row is unaffected.

### UI: `1_Sourcing.py` Add tab

Paste a link, press Scan, review, Add. Nothing is written before Add.

```
Link  [https://github.com/org/big-repo            ]  [ Scan ]

  org/big-repo - 531 data files in 3 folders

  [x] malware-samples/   412 files   [ Threat Intelligence  v ]
  [x] k8s-configs/        88 files   [ Threat Intelligence  v ]   inherited
  [x] pcaps/              31 files   [ Network Security     v ]

  License Apache-2.0, Author org, Tags cve, malware   (fetched)

                                          [ Add 3 sources ]
```

- An unsplittable link renders as one row reading "(whole source)".
- A row is marked "inherited" when the part itself matched no vocab and took the
  repo-level domain. The mockup above shows the real `k8s` gap: `k8s-configs/`
  inherits Threat Intelligence and a human corrects it to Cloud Security in one
  click. This is the case the review step exists for.
- When neither the part nor the repo matched anything, the row shows "(pick a
  sub-domain)" and blocks Add until chosen, rather than defaulting to something
  plausible-looking.
- An unsupported link (RSS/Atom, unknown API host) disables Add and names the
  supported kinds.
- `enrich.enrich_row` runs once per scan; License, Author, Tags and Last Updated
  are copied onto every part row.
- Each row is built by the existing `row.build_manual_row` and appended with
  `sheet.append_rows`, so hand-added rows stay indistinguishable from discovered
  ones.
- A part link colliding with an existing catalog row is rejected by the existing
  `sheet.existing_links` check. Adding a part when the whole repo is already
  catalogued is a warning, not an error: they overlap but are not identical.

Per the UI convention, plain text only, no emoji or symbols.

### Items 2 and 3

- `app.py:67-71`: delete the `st.progress(...)` call in `_live()`. The "Stage N
  of 5" caption and the session-state history stay. The funnel's own bar
  (`app.py:270-274`) is the survivor.
- `5_Schema.py:31-34`: the Normalize tab's metric row gains a fourth metric,
  Tokens, from `manifest["token_total"]`, which the Manifest tab already reads at
  line 80. Renders "n/a" when no manifest exists yet.

## Testing

Written first, per the repo's TDD practice. Network is faked; no test hits
GitHub or HuggingFace.

`tests/sourcing/test_split.py`
- groups a fake recursive tree into top-level parts, dropping non-data folders
- files at the repo root become one `Part(path="")`
- a non-repo link scans as unsplittable with a single part
- a network failure degrades to an unsplittable scan rather than raising
- `propose` covers all three score cases: a part matching vocab keeps its own
  domain, a part matching nothing inherits the repo-level domain, and a part
  matching nothing whose repo also matched nothing proposes no domain
- `part_link` builds `tree/<branch>/<folder>` links; `part_name` stays unique per
  part

`tests/ingestion/test_fetch.py`
- `_github_target` returns the subdir for a `tree/<branch>/<subdir>` link and
  `""` for a plain repo link
- `fetch_url` on a zip built in `tmp_path` ingests only the members under the
  subdir, and ingests everything when the subdir is empty (regression guard for
  existing rows)
- `fetch_hf` filters siblings by `subset`

`tests/dashboard/test_sourcing_page.py` (existing file)
- scan then add appends one row per included part, each with its own sub-domain
- Add is blocked while any included part has no sub-domain
- an RSS/Atom link is refused with a reason
- the existing `test_add_source_*` tests keep passing

## Out of scope

- RSS/Atom and generic REST API fetchers. Their own spec if wanted; each needs a
  new kind, worker dispatch, and for APIs a pagination/auth story.
- Deeper-than-top-level splitting.
- Reclassifying rows already in the catalog.
