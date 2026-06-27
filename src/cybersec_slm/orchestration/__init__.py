#!/usr/bin/env python3
"""Prefect orchestration for the end-to-end corpus build (optional extra)."""

from .flows import build_corpus

__all__ = ["build_corpus"]
