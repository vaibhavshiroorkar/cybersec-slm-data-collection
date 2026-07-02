"""Local-first, read-only dashboard: pipeline monitor + dataset explorer.

Thin Streamlit pages (``app.py`` + ``pages/``) over a tested, Streamlit-free read
layer (:mod:`cybersec_slm.dashboard.data`). Launch with ``cybersec-slm dashboard``
or ``streamlit run src/cybersec_slm/dashboard/app.py`` after
``uv sync --extra dashboard``.
"""
