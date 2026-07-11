#!/usr/bin/env python3
"""Record -> text mapping — runs before the anomaly gate.

Ingestion emits two record shapes: scrape/crawl outputs already carry a
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
#
# Chat / preference (DPO) turn shapes are included here: the training signal is
# the user turn plus the *preferred* answer. The ``system`` field is deliberately
# omitted from the combos — chat datasets repeat an identical multi-hundred-token
# system prompt across every row, and folding that boilerplate into the text of
# 100k records both bloats the corpus and makes near-dedup falsely collapse
# distinct exchanges that merely share the prefix. Likewise ``rejected`` (the
# worse DPO response) is never used.
_COMBOS = (
    ("instruction", "input", "output"),
    ("instruction", "output"),
    ("question", "answer"),
    ("prompt", "completion"),
    ("prompt", "response"),
    ("query", "response"),
    ("user", "assistant"),          # chat: {system?, user, assistant}
    ("prompt", "chosen"),           # DPO: prefer the chosen response
    ("question", "chosen"),
    ("instruction", "chosen"),
    ("input", "output"),
    ("title", "abstract"),
    ("title", "body"),
)

# List-of-turns shapes (ShareGPT ``conversations`` / OpenAI ``messages``). Each
# element is a dict carrying a role and content under varying key names.
_MSG_LIST_FIELDS = ("messages", "conversations", "conversation", "dialog",
                    "dialogue", "turns")
_ROLE_LABELS = {"user": "User", "human": "User", "prompter": "User",
                "assistant": "Assistant", "gpt": "Assistant", "bot": "Assistant",
                "model": "Assistant", "system": "System"}

# Single prose columns, highest-confidence first. Deliberately excludes short /
# non-prose fields (title, name, label, payload, hash) so feature tables fall
# through to exclusion instead of producing junk text.
_SINGLE = (
    "text", "content", "body", "article", "page_content", "passage",
    "document", "fulltext", "full_text", "raw_text", "message", "email",
    "email_text", "email_body", "mail", "comment", "post", "abstract",
    "summary", "description", "shortdescription", "short_description",
    "details", "definition", "explanation", "rationale", "analysis",
    "response", "completion", "answer", "output", "chosen", "assistant",
    "transcript", "dialogue", "conversation", "story", "essay", "instruction",
    "question", "sentence", "review", "caption", "notes", "playbook",
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


def _from_messages(rec: dict, km: dict):
    """Build text from a list-of-turns field (ShareGPT / OpenAI messages).

    Concatenates the turns as ``Role: content``, skipping ``system`` turns
    (boilerplate) and any turn without string content. Returns ``(text, field)``
    or ``(None, None)`` when no usable turn is present.
    """
    for name in _MSG_LIST_FIELDS:
        actual = km.get(name)
        if actual is None:
            continue
        turns = rec.get(actual)
        if not isinstance(turns, list) or not turns:
            continue
        parts: list[str] = []
        for turn in turns:
            if isinstance(turn, str):
                if turn.strip():
                    parts.append(turn.strip())
                continue
            if not isinstance(turn, dict):
                continue
            role = str(turn.get("role") or turn.get("from") or "").strip().lower()
            content = turn.get("content") or turn.get("value") or turn.get("text")
            if not isinstance(content, str) or not content.strip():
                continue
            if role == "system":       # skip repeated system-prompt boilerplate
                continue
            label = _ROLE_LABELS.get(role, role.capitalize() if role else "")
            parts.append(f"{label}: {content.strip()}" if label else content.strip())
        if parts:
            return "\n\n".join(parts), name
    return None, None


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

    # List-of-turns shapes before flat combos: a record may carry both a
    # ``messages`` list and stray scalar columns, and the conversation is the
    # higher-fidelity signal.
    text, field = _from_messages(rec, km)
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
