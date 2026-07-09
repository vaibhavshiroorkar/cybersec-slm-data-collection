# Dashboard

A local-first, **read-only** web dashboard for the pipeline: monitor a run
(live and historical) and explore the resulting corpus. Built with Streamlit and
styled as a security-operations console: a deep slate theme, monospace instrument
readouts, and status-coloured tiles.

```bash
uv sync --extra dashboard          # pulls in streamlit (opt-in; core stays lean)
cybersec-slm dashboard             # -> http://localhost:8501
# or: uv run streamlit run src/cybersec_slm/dashboard/app.py
```

It reads whatever the pipeline has written under the current data root
(`CYBERSEC_SLM_DATA_ROOT`, default: cwd), so pointing the root at a synced or
mounted location is all it takes to serve a hosted deploy later, no code change.

## Layout
| File | Role |
|---|---|
| `data.py` | **The read layer.** The only code that touches disk; pure functions to plain data, no Streamlit import, fully unit-tested. |
| `charts.py` | Formatting + trend-series shaping helpers (no Streamlit). |
| `theme.py` | Console CSS injection + reusable components: hero, KPI instrument tiles, status pills, section markers. Presentation (imports Streamlit). |
| `viz.py` | Altair chart builders (domain distribution, funnel, trend lines), styled to the theme. Presentation (imports Altair). |
| `agent_tools.py` | Read-only tool wrappers over `data.py` for the Agent page; no Streamlit import, fully unit-tested. |
| `agent_client.py` | NVIDIA NIM client + tool-calling loop; no Streamlit import, tested against a fake client. |
| `app.py` | Streamlit entrypoint: the console landing with live state, KPI tiles, and the catalog/corpus distribution. |
| `pages/1_Pipeline.py` | Monitor: live strip + data funnel + EDA gate + trends + sources + manifest. |
| `pages/2_Dataset.py` | Explore: filter/search/paginate the corpus + rejected/duplicate sinks. |
| `pages/3_Agent.py` | Ask: a chat agent that answers pipeline/dataset questions via tool-calling. |

The split matters: `data.py` and `charts.py` stay Streamlit-free and unit-tested,
while `theme.py` and `viz.py` hold everything visual. Pages are thin: they read
from `data.py` and render with `theme.py` / `viz.py`.

## Pages
- **Landing** (`app.py`): a console hero with live pipeline state, a row of KPI
  instrument tiles (records, sources done, domains, size, gate), and a horizontal
  bar of the corpus distribution when a manifest exists, or the source-catalog
  distribution before the first run.
- **Pipeline**: a live strip (auto-refreshing about every 3s while a run is
  detected, from `completed_sources.txt` plus the newest per-PID log), the data
  funnel (raw to cleaned to final, as tiles and a bar chart), the EDA sufficiency
  gate (pass/fail pill + blockers/warnings + metric tiles), trend charts over past
  EDA runs, the per-source table, and the release manifest.
- **Dataset**: filter by domain/subdomain/source/type/lang (facets from the
  manifest), full-text substring search, a paginated results table with the full
  22-field record detail, and previews of what was rejected or de-duplicated.
- **Agent**: a chat box that answers questions about run status, the EDA gate,
  sources, the manifest, and corpus content by calling read-only tools over the
  same data the other pages show. Every answer comes with a "what I looked up"
  trace. Needs `uv sync --extra dashboard --extra agent` and `NVIDIA_API_KEY`; it
  shows setup instructions instead of a chat box until both are present.

## Notes
- **Read-only** by design: no triggering runs, no auth, no editing. It reflects the
  pipeline's artifacts.
- Large `dataset.jsonl` is streamed, never loaded whole; a single query scans up to
  `data.DATASET_SCAN_CAP` records (the count then reads "N+"). If that ceiling ever
  bites, the `dataset_page` implementation can move to DuckDB behind the same
  signature with no UI change.
- The **Sources** table and stage reports populate once a run finishes; the live
  strip covers the in-flight view.
- The Agent page is the one exception to "no network": it calls NVIDIA NIM. It
  still writes nothing to disk; chat history lives only in the browser session and
  is lost on reload.
