#!/usr/bin/env python3
"""Bulk-harvest backends + the driver that grows a catalog from one.

See :mod:`cybersec_slm.sourcing.harvest.base` for the backend protocol and
:mod:`cybersec_slm.sourcing.harvest.run` for the catalog-growing driver the CLI
calls. The active profile's ``harvest.yaml`` (see
:mod:`cybersec_slm.sourcing.harvest.spec`) selects which backends run and with what
queries, license stamp, and quality filters.
"""

from __future__ import annotations

from .run import run_harvest

__all__ = ["run_harvest"]
