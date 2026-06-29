#!/usr/bin/env python3
"""Exploratory Data Analysis stage (flowchart Stage 3).

Validations + a sufficiency gate that sits between cleaning and normalization:
pass -> advance to normalize; blocker -> SufficiencyError -> loop back to ingestion.
"""

from .metrics import compute_metrics
from .pipeline import EDA_DIR, SufficiencyError, evaluate_gate, run_eda

__all__ = ["run_eda", "compute_metrics", "evaluate_gate", "SufficiencyError", "EDA_DIR"]
