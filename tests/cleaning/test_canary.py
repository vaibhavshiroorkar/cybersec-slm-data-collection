"""Canary tokens: proving what a model was trained on, and what leaked.

A canary is a unique string planted in the corpus. If a model later emits it, the
model saw this corpus. That only works if the token is genuinely in the training
data and genuinely unique, so both properties are tested here.
"""

import json

import pytest

from cybersec_slm.cleaning import canary


# ------------------------------------------------------------------- mint -----
def test_minting_gives_the_asked_for_number_of_tokens():
    assert len(canary.mint(5)) == 5


def test_tokens_are_unique():
    tokens = canary.mint(200)

    assert len(set(tokens)) == 200


def test_a_seed_makes_minting_reproducible():
    """A release has to be able to re-derive its own canaries from the manifest
    without keeping a copy of every secret."""
    assert canary.mint(4, seed="release-1") == canary.mint(4, seed="release-1")


def test_different_seeds_give_different_tokens():
    assert canary.mint(4, seed="a") != canary.mint(4, seed="b")


def test_unseeded_minting_is_not_reproducible():
    """Without a seed the tokens must be unguessable, not merely unlikely."""
    assert canary.mint(4) != canary.mint(4)


def test_a_token_is_high_entropy_and_recognizable():
    [token] = canary.mint(1)

    assert token.startswith(canary.TOKEN_PREFIX)
    assert len(token) >= 32          # enough that it cannot collide with real text


# ------------------------------------------------------------------- scan -----
def test_scan_finds_a_planted_token():
    [token] = canary.mint(1, seed="s")

    assert canary.scan(f"some text {token} more text") == [token]


def test_scan_finds_several_tokens():
    tokens = canary.mint(3, seed="s")
    text = " ".join(["noise", *tokens, "noise"])

    assert sorted(canary.scan(text)) == sorted(tokens)


def test_scan_reports_nothing_for_ordinary_text():
    assert canary.scan("A heap overflow in the parser allows code execution") == []


def test_scan_tolerates_empty_and_non_string():
    assert canary.scan("") == []
    assert canary.scan(None) == []


def test_scan_does_not_match_the_prefix_alone():
    """The prefix appears in this repo's own source and docs; only a full token
    counts, or the scanner cries wolf on its own documentation."""
    assert canary.scan(f"the {canary.TOKEN_PREFIX} format is described here") == []


# ------------------------------------------------------------------ plant -----
def _dataset(tmp_path, n=3):
    p = tmp_path / "dataset.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        for i in range(n):
            f.write(json.dumps({
                "id": f"r{i}", "text": "Rotate service account keys every ninety days",
                "source": "real-source", "content_hash": "a" * 64}) + "\n")
    return str(p)


def test_planting_appends_records_and_leaves_the_real_ones_alone(tmp_path):
    """Never mutate a real record's text. Corrupting the corpus to detect leaks of
    the corpus defeats the point; canaries are additional records."""
    ds = _dataset(tmp_path, n=3)
    before = [json.loads(x) for x in open(ds, encoding="utf-8")]

    info = canary.plant(ds, count=2, out=str(tmp_path / "canaries.json"))

    after = [json.loads(x) for x in open(ds, encoding="utf-8")]
    assert len(after) == 5
    assert after[:3] == before                  # untouched, byte for byte
    assert len(info["tokens"]) == 2


def test_planted_records_are_findable_by_their_recorded_ids(tmp_path):
    ds = _dataset(tmp_path)

    info = canary.plant(ds, count=2, out=str(tmp_path / "canaries.json"))

    ids = {r["id"] for r in (json.loads(x) for x in open(ds, encoding="utf-8"))}
    assert set(info["record_ids"]) <= ids


def test_the_sidecar_records_the_tokens(tmp_path):
    ds = _dataset(tmp_path)
    out = str(tmp_path / "canaries.json")

    info = canary.plant(ds, count=2, out=out)

    with open(out, encoding="utf-8") as f:
        saved = json.load(f)
    assert saved["tokens"] == info["tokens"]
    assert saved["count"] == 2


def test_every_planted_record_carries_its_token_in_its_text(tmp_path):
    ds = _dataset(tmp_path)

    info = canary.plant(ds, count=3, out=str(tmp_path / "canaries.json"))

    planted = [r for r in (json.loads(x) for x in open(ds, encoding="utf-8"))
               if r["id"] in set(info["record_ids"])]
    assert len(planted) == 3
    for rec in planted:
        assert canary.scan(rec["text"])


def test_planted_records_are_marked_as_canaries_not_disguised(tmp_path):
    """They are part of the release, so they must be identifiable in it. Hiding
    them would make the corpus a liar about its own contents."""
    ds = _dataset(tmp_path)

    info = canary.plant(ds, count=1, out=str(tmp_path / "canaries.json"))

    [rec] = [r for r in (json.loads(x) for x in open(ds, encoding="utf-8"))
             if r["id"] in set(info["record_ids"])]
    assert rec["source"] == canary.CANARY_SOURCE


def test_planting_zero_is_a_no_op(tmp_path):
    ds = _dataset(tmp_path, n=2)

    info = canary.plant(ds, count=0, out=str(tmp_path / "canaries.json"))

    assert info["tokens"] == []
    assert len(open(ds, encoding="utf-8").readlines()) == 2


def test_planting_into_a_missing_dataset_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        canary.plant(str(tmp_path / "nope.jsonl"), count=1,
                     out=str(tmp_path / "c.json"))


# ----------------------------------------------------------------- verify -----
def test_verify_finds_every_planted_canary(tmp_path):
    ds = _dataset(tmp_path)
    out = str(tmp_path / "canaries.json")
    canary.plant(ds, count=3, out=out)

    result = canary.verify(ds, sidecar=out)

    assert result["planted"] == 3
    assert result["found"] == 3
    assert result["missing"] == []
    assert result["ok"] is True


def test_verify_reports_a_canary_that_went_missing(tmp_path):
    """A dedup or rebalance pass that silently ate the canaries is exactly what
    this catches: it means the release cannot be traced."""
    ds = _dataset(tmp_path)
    out = str(tmp_path / "canaries.json")
    info = canary.plant(ds, count=3, out=out)

    kept = [x for x in open(ds, encoding="utf-8")
            if info["record_ids"][0] not in x]
    with open(ds, "w", encoding="utf-8") as f:
        f.writelines(kept)

    result = canary.verify(ds, sidecar=out)

    assert result["found"] == 2
    assert result["ok"] is False
    assert len(result["missing"]) == 1


def test_verify_without_a_sidecar_says_nothing_was_planted(tmp_path):
    ds = _dataset(tmp_path)

    result = canary.verify(ds, sidecar=str(tmp_path / "none.json"))

    assert result["planted"] == 0
    assert result["ok"] is False        # no evidence is not evidence of success
