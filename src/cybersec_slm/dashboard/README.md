# Dashboard

A local-first, **read-only** web dashboard for the pipeline: monitor a run
(live + historical) and explore the resulting corpus. Built with Streamlit.

```bash
uv sync --extra dashboard          # pulls in streamlit (opt-in; core stays lean)
cybersec-slm dashboard             # -> http://localhost:8501
# or: uv run streamlit run src/cybersec_slm/dashboard/app.py
```

It reads whatever the pipeline has written under the current data root
(`CYBERSEC_SLM_DATA_ROOT`, default: cwd) — so pointing the root at a synced/mounted
location is all it takes to serve a hosted deploy later, no code change.

## Layout
| File | Role |
|---|---|
| `data.py` | **The read layer.** The only code that touches disk/SQLite; pure functions -> plain data, no Streamlit import, fully unit-tested. |
| `charts.py` | Formatting + trend-series helpers (no Streamlit). |
| `agent_tools.py` | Read-only tool wrappers over `data.py` for the Agent page; no Streamlit import, fully unit-tested. |
| `agent_client.py` | NVIDIA NIM client + tool-calling loop; no Streamlit import, tested against a fake client. |
| `app.py` | Streamlit entrypoint / landing overview. |
| `pages/1_Pipeline.py` | Monitor: live strip + EDA gate + trends + sources + reports + manifest. |
| `pages/2_Dataset.py` | Explore: filter/search/paginate the corpus + rejected/duplicate sinks. |
| `pages/3_Agent.py` | Ask: a chat agent that answers pipeline/dataset questions via tool-calling. |

## Pages
- **Pipeline** — a live strip (auto-refreshing ~3s while a run is detected, from
  `completed_sources.txt` + the newest per-PID log), the EDA sufficiency gate
  (pass/fail + blockers/warnings + metrics), trend charts over past EDA runs, the
  per-source table, clean/normalize stage reports, and the release manifest.
- **Dataset** — filter by domain/subdomain/source/type/lang (facets from the
  manifest), full-text substring search, a paginated results table with a full
  22-field record detail, and previews of what was rejected or de-duplicated.
- **Agent** — a chat box that answers questions about run status, the EDA gate,
  sources, the manifest, and corpus content by calling read-only tools over the
  same data the other pages show. Every answer comes with a "what I looked up"
  trace. Needs `uv sync --extra agent` and `NVIDIA_API_KEY`; shows setup
  instructions instead of a chat box until both are present.

## Notes
- **Read-only** by design: no triggering runs, no auth, no editing. It reflects the
  pipeline's artifacts.
- Large `dataset.jsonl` is streamed, never loaded whole; a single query scans up to
  `data.DATASET_SCAN_CAP` records (the count then reads "N+"). If that ceiling ever
  bites, the `dataset_page` implementation can move to DuckDB behind the same
  signature with no UI change.
- The ingest-log SQLite is written at run end, so the **Sources** table and stage
  reports populate once a run finishes; the live strip covers the in-flight view.
- The Agent page is the one exception to "no network": it calls NVIDIA NIM.
  It still writes nothing to disk — chat history lives only in the browser
  session and is lost on reload.
