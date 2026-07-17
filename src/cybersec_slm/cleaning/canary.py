#!/usr/bin/env python3
"""Canary tokens: unique strings planted in the corpus so leaks can be proved.

A canary is a high-entropy string that exists nowhere else. Plant a handful in the
release, and two questions become answerable that otherwise are not:

  * **Did this model train on our corpus?** If it emits a canary, yes. Nothing
    else about a trained model attributes it back to the data it ate.
  * **Did the release survive the pipeline intact?** :func:`verify` re-reads the
    dataset and checks every planted token is still there. A dedup or rebalance
    pass that quietly ate them means the release can no longer be traced.

This is the missing half of poisoning detection. :mod:`.anomaly` and the EDA gate
catch corrupt or skewed *input*; a canary is the only thing here that says
anything about the *output* once it has left.

Two design choices worth stating, because the obvious alternatives are worse:

**Canaries are added as their own records, never spliced into real ones.**
Editing a real record's text to carry a token would corrupt the corpus in order
to detect corruption of the corpus. They are appended instead, and their ids are
recorded.

**They are labelled, not disguised.** A planted record says ``source="canary"``.
Hiding them would make the dataset a liar about its own contents, and the point
of a canary is that *the model* cannot tell it apart from real text, not that the
operator cannot.

Planting is opt-in: it changes the deliverable, and silently altering what ships
is not a decision this module gets to make on its own.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import uuid

from ..core import iter_jsonl, json_dumps, logger

# Recognizable on sight in a log, a diff or a model's output, and impossible to
# collide with real prose.
TOKEN_PREFIX = "CANARY"
_TOKEN_BODY_LEN = 32
_TOKEN_RE = re.compile(rf"{TOKEN_PREFIX}-[0-9a-f]{{{_TOKEN_BODY_LEN}}}")

# The `source` a planted record declares. Real, and visible in the manifest's
# source counts, so the corpus never misrepresents what is in it.
CANARY_SOURCE = "canary"

# The sentence a token rides in. Prose rather than a bare token: a model memorizes
# sequences in context, and a floating hex string is both easier to filter out and
# less like anything else in the corpus.
_CARRIER = ("Provenance marker for this corpus release. If a model reproduces "
            "the following identifier it was trained on this dataset: {token}. "
            "This record carries no security content and is not training signal.")


def mint(count: int, *, seed: str | None = None) -> list[str]:
    """``count`` unique canary tokens.

    With a ``seed`` the tokens are reproducible, so a release can re-derive its own
    canaries from something recorded in the manifest rather than keeping a copy of
    every secret. Without one they come from :mod:`secrets` and are unguessable,
    which is what you want when the corpus may be handed to someone who would
    rather it were not traceable.
    """
    if count <= 0:
        return []
    out: list[str] = []
    for i in range(count):
        if seed is None:
            body = secrets.token_hex(_TOKEN_BODY_LEN // 2)
        else:
            digest = hashlib.sha256(f"{seed}:{i}".encode()).hexdigest()
            body = digest[:_TOKEN_BODY_LEN]
        out.append(f"{TOKEN_PREFIX}-{body}")
    return out


def scan(text) -> list[str]:
    """Every canary token in ``text``, in order of appearance.

    Matches a whole token, never the bare prefix: the prefix appears in this
    module, its tests and its docs, and a scanner that fires on its own
    documentation is a scanner nobody trusts.
    """
    if not isinstance(text, str) or not text:
        return []
    return _TOKEN_RE.findall(text)


def carrier_text(token: str) -> str:
    """The record text a canary token rides in."""
    return _CARRIER.format(token=token)


def _record(token: str) -> dict:
    """One planted record. Shaped like the dataset's, and honest about itself."""
    text = carrier_text(token)
    return {
        "id": str(uuid.uuid4()),
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "text": text,
        "source": CANARY_SOURCE,
        "source_file": CANARY_SOURCE,
        "record_type": "other",
        "lang": "en",
        "token_count": len(text.split()),
        "char_count": len(text),
        "is_canary": True,
    }


def plant(dataset_path: str, *, count: int = 4, out: str | None = None,
          seed: str | None = None) -> dict:
    """Append ``count`` canary records to ``dataset_path``; record them in ``out``.

    Returns ``{tokens, record_ids, count}``. Existing records are never touched:
    the file is opened for append, so every real record stays byte for byte as it
    was.
    """
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(dataset_path)
    out = out or os.path.join(os.path.dirname(dataset_path), "canaries.json")

    tokens = mint(count, seed=seed)
    records = [_record(t) for t in tokens]
    if records:
        with open(dataset_path, "a", encoding="utf-8") as f:
            for rec in records:
                f.write(json_dumps(rec) + "\n")

    info = {
        "tokens": tokens,
        "record_ids": [r["id"] for r in records],
        "count": len(tokens),
        "dataset": os.path.basename(dataset_path),
    }
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)
    if tokens:
        logger.info(f"canary: planted {len(tokens)} token(s) into "
                    f"{os.path.basename(dataset_path)} -> {out}")
    return info


def load(sidecar: str) -> dict:
    """The recorded canaries, or an empty record when none were planted."""
    try:
        with open(sidecar, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {"tokens": [], "record_ids": [], "count": 0}
    return data if isinstance(data, dict) else {"tokens": [], "record_ids": [],
                                                "count": 0}


def verify(dataset_path: str, *, sidecar: str | None = None) -> dict:
    """Check every planted canary is still in the dataset.

    Returns ``{planted, found, missing, ok}``. ``ok`` is False when nothing was
    planted: no evidence is not evidence of success, and a release that believes
    it is traceable when it is not is worse off than one that knows it is not.
    """
    sidecar = sidecar or os.path.join(os.path.dirname(dataset_path), "canaries.json")
    info = load(sidecar)
    planted = list(info.get("tokens") or [])
    if not planted:
        return {"planted": 0, "found": 0, "missing": [], "ok": False}

    want = set(planted)
    seen: set[str] = set()
    if os.path.exists(dataset_path):
        for rec in iter_jsonl(dataset_path):
            if rec.get("_parse_error"):
                continue
            for token in scan(rec.get("text")):
                if token in want:
                    seen.add(token)
            if len(seen) == len(want):
                break                      # every one accounted for; stop reading

    missing = sorted(want - seen)
    return {"planted": len(planted), "found": len(seen), "missing": missing,
            "ok": not missing}
