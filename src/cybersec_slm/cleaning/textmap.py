#!/usr/bin/env python3
"""Record -> text mapping — runs before the anomaly gate.

Extraction emits two record shapes: scrape/crawl outputs already carry a
``text`` field, while dataset rows keep their original column names
(``{question, answer}``, ``{instruction, output}``, ``{body, label}``, ...).
The cleaning stages all operate on ``text``, so this step builds a ``text``
value for records that lack one by pulling recognized natural-language columns.

Pure feature tables (malware PE features, IDS flows, label-only rows) have no
prose column; for those ``to_text`` returns ``None`` and the caller excludes the
record from the text corpus rather than feeding noise into an SLM.

Auto-detection uses the priority lists below. A future per-source override
(a ``text_field`` column in the sources sheet) can be layered on top by passing
``hint`` to :func:`to_text`.

Public API:
    text, field = to_text(rec)            # (None, None) -> exclude
    text, field = to_text(rec, hint=...)  # hint: explicit field name(s)
"""

from __future__ import annotations

# Multi-column shapes (checked first; more specific than single columns).
# Each tuple lists the columns to combine, labeled, when 2+ are present.
_COMBOS = (
    ("instruction", "input", "output"),
    ("instruction", "output"),
    ("question", "answer"),
    ("prompt", "completion"),
    ("prompt", "response"),
    ("query", "response"),
    ("input", "output"),
    ("title", "abstract"),
    ("title", "body"),
)

# Single prose columns, highest-confidence first. Deliberately excludes short /
# non-prose fields (title, name, label, payload, hash) so feature tables fall
# through to exclusion instead of producing junk text.
_SINGLE = (
    "text", "content", "body", "article", "page_content", "passage",
    "document", "fulltext", "full_text", "raw_text", "message", "email",
    "email_text", "email_body", "mail", "comment", "post", "abstract",
    "summary", "description", "shortdescription", "short_description",
    "details", "definition", "explanation", "rationale", "analysis",
    "response", "completion", "answer", "output", "transcript", "dialogue",
    "conversation", "story", "essay", "instruction", "question", "sentence",
    "review", "caption", "notes", "playbook",
    # source/code columns (e.g. slither-audited-smart-contracts.source_code) —
    # kept last so a prose column is always preferred over raw code.
    "source_code", "code_snippet", "func", "code",
)


def _keymap(rec: dict) -> dict:
    """Map lowercased key -> actual key, so matching is case-insensitive."""
    return {str(k).lower(): k for k in rec}


def _get(rec: dict, km: dict, name: str):
    """Return the stripped string value for column `name`, or None."""
    actual = km.get(name)
    if actual is None:
        return None
    v = rec.get(actual)
    return v.strip() if isinstance(v, str) and v.strip() else None


def _from_hint(rec: dict, km: dict, hint):
    """Build text from an explicit field-name hint (str or list of str)."""
    names = [hint] if isinstance(hint, str) else list(hint)
    parts = []
    for n in names:
        v = _get(rec, km, str(n).lower())
        if v:
            parts.append(v if len(names) == 1 else f"{str(n).capitalize()}: {v}")
    if parts:
        return "\n\n".join(parts), "+".join(str(n).lower() for n in names)
    return None, None


def to_text(rec: dict, hint=None) -> tuple[str | None, str | None]:
    """Return ``(text, field_used)`` for `rec`, or ``(None, None)`` to exclude.

    A record that already has a non-empty ``text`` is returned unchanged. Else an
    explicit `hint` is tried, then known multi-column combos, then single prose
    columns. Feature-table rows (no recognized prose column) return ``None``.
    """
    t = rec.get("text")
    if isinstance(t, str) and t.strip():
        return t, "text"

    km = _keymap(rec)

    if hint:
        text, field = _from_hint(rec, km, hint)
        if text:
            return text, field

    for combo in _COMBOS:
        present = [(n, _get(rec, km, n)) for n in combo]
        present = [(n, v) for n, v in present if v]
        if len(present) >= 2:
            parts = [f"{n.capitalize()}: {v}" for n, v in present]
            return "\n\n".join(parts), "+".join(n for n, _ in present)

    for name in _SINGLE:
        v = _get(rec, km, name)
        if v:
            return v, name

    return None, None
