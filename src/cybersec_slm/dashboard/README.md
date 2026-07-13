# Dashboard

A local-first web dashboard for the five-stage pipeline (source → ingest → clean →
eda → schema): an Overview of all stats, one page per stage (run it + inspect it),
and a corpus explorer. Built with Streamlit. Reads are the norm; the run controls
launch the pipeline (or a single stage) as a local subprocess.

```bash
uv sync --extra dashboard          # pulls in streamlit (opt-in; core stays lean)
cybersec-slm dashboard             # -> http://localhost:8501
# or: uv run streamlit run src/cybersec_slm/dashboard/app.py
```

It reads whatever the pipeline has written under the current data root
(`CYBERSEC_SLM_DATA_ROOT`, default: cwd) - so pointing the root at a synced/mounted
location is all it takes to serve a hosted deploy later, no code change.

## Layout
| File | Role |
|---|---|
| `data.py` | **The read layer.** The only code that touches disk/SQLite; pure functions -> plain data, no Streamlit import, fully unit-tested. `run_phase` / `stage_states` read the canonical `cybersec_slm.stages` registry. |
| `control.py` | The control plane: `build_command` + `start(stage, settings)` launch a stage (or `all`) as a detached subprocess; `stop` / `reset`. No Streamlit import, unit-tested. |
| `ui.py` | Shared presentation helpers (status pill, scrollable `log_box`, `stat_grid`, `stage_run_control`, `advanced_settings`, one CSS injection). Streamlit imported lazily. |
| `charts.py` | Formatting + trend-series helpers (no Streamlit). |
| `agent_tools.py` / `agent_client.py` | Read-only tool wrappers + NVIDIA NIM client for the Agent page; no Streamlit import, unit-tested. |
| `app.py` | Overview: all headline stats + the full-pipeline launcher. |
| `pages/1_Sourcing.py` … `5_Schema.py` | One page per stage: run it (with stage-scoped advanced settings), a scrollable stage log, and that stage's detail. |
| `pages/6_Dataset.py` | Explore: filter/search/paginate the corpus + rejected/duplicate sinks. |
| `pages/7_Agent.py` | Ask: a chat agent that answers pipeline/dataset questions via tool-calling. |

## Pages
- **Overview** - a fixed-skeleton live strip (auto-refreshing ~3s: state, current
  stage, elapsed/ETA) with a five-stage status strip, the corpus funnel, the EDA
  gate summary, the release headline, and the full-pipeline launcher (Start /
  Resume / Stop / Reset + advanced settings).
- **Sourcing / Ingest / Clean / EDA / Schema** - one page per stage. Each has a
  `Run this stage` control with only that stage's advanced flags, a fixed-height
  scrollable stage log, and the stage's inputs/outputs (catalog, raw ledger, clean
  + loss breakdown, sufficiency gate + trends, normalize report + manifest). The
  Sourcing page also runs SearXNG discovery on its own: pick sub-domains, preview
  every keyword that will run, set per-domain and total caps, and add or remove
  sub-domains and keywords (persisted to `sources/keywords.yaml`).
- **Dataset** - filter by domain/subdomain/source/type/lang (facets from the
  manifest), full-text substring search, a paginated results table with a full
  record detail, and previews of what was rejected or de-duplicated.
- **Agent** - a chat box that answers questions about run status, the EDA gate,
  sources, the manifest, and corpus content by calling read-only tools over the
  same data the other pages show. Every answer comes with a "what I looked up"
  trace. Needs `uv sync --extra dashboard --extra agent` and `NVIDIA_API_KEY`; shows setup
  instructions instead of a chat box until both are present.

## Notes
- The stage pages can launch a run; everything else reflects the pipeline's
  artifacts. Layout is deliberately stable: auto-refresh regions live in
  fixed-height containers so values change in place without the page jumping, and
  logs scroll inside a fixed box rather than growing.
- Large `dataset.jsonl` is streamed, never loaded whole; a single query scans up to
  `data.DATASET_SCAN_CAP` records (the count then reads "N+"). If that ceiling ever
  bites, the `dataset_page` implementation can move to DuckDB behind the same
  signature with no UI change.
- The ingest-log SQLite is written at run end, so the **Sources** table and stage
  reports populate once a run finishes; the live strip covers the in-flight view.
- The Agent page is the one exception to "no network": it calls NVIDIA NIM.
  It still writes nothing to disk - chat history lives only in the browser
  session and is lost on reload.
