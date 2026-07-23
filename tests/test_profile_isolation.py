"""Profiles keep their own corpus, logs and run.

The bug this closes: switching from cybersec to ubi kept showing cybersec's
corpus, EDA report and manifest, because data/ and logs/ were shared. Only
sources/ and the settings file were ever namespaced.
"""

import json
import os

import pytest

from cybersec_slm import core


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    for name in ("cybersec", "ubi"):
        (tmp_path / "sources" / "profiles" / name).mkdir(parents=True)
    return tmp_path


def _use(monkeypatch, name):
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", name)


# ------------------------------------------------------------ the paths ------
def test_each_profile_gets_its_own_data_and_logs(root, monkeypatch):
    _use(monkeypatch, "cybersec")
    cy_data, cy_logs = core.data_dir(), core.logs_dir()
    _use(monkeypatch, "ubi")
    ubi_data, ubi_logs = core.data_dir(), core.logs_dir()

    assert cy_data != ubi_data
    assert cy_logs != ubi_logs
    assert cy_data.endswith(os.path.join("data", "cybersec"))
    assert ubi_logs.endswith(os.path.join("logs", "ubi"))


def test_the_dashboard_sees_the_switch_without_a_restart(root, monkeypatch):
    """The actual bug. data.py must resolve per call: core's constants freeze at
    import, and the dashboard is one process that outlives a switch."""
    from cybersec_slm.dashboard import data

    _use(monkeypatch, "cybersec")
    before = (data._clean(), data._final(), data._logs())
    _use(monkeypatch, "ubi")
    after = (data._clean(), data._final(), data._logs())

    assert before != after
    for p in after:
        assert "ubi" in p
        assert "cybersec" not in p


def test_the_cache_key_changes_with_the_profile(root, monkeypatch):
    """Both profiles share a root, so a root-only cache key served the other
    profile's counts after a switch: a second way to show the wrong corpus."""
    from cybersec_slm.dashboard import data

    _use(monkeypatch, "cybersec")
    a = data.scope()
    _use(monkeypatch, "ubi")

    assert data.scope() != a


def test_one_profiles_corpus_is_invisible_to_the_other(root, monkeypatch):
    from cybersec_slm.dashboard import data

    _use(monkeypatch, "cybersec")
    clean = os.path.join(data._clean(), "Network Security", "src")
    os.makedirs(clean)
    with open(os.path.join(clean, "a.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"text": "cybersec record"}) + "\n")

    assert data._count_jsonl_records(data._clean()) == 1
    _use(monkeypatch, "ubi")
    assert data._count_jsonl_records(data._clean()) == 0


def test_an_unknown_profile_falls_back_rather_than_inventing_a_directory(root,
                                                                         monkeypatch):
    _use(monkeypatch, "not-a-real-profile")

    assert core.active_profile() == core.DEFAULT_PROFILE


def test_core_and_profiles_agree_on_which_profile_is_active(root, monkeypatch):
    """Two answers to 'which profile am I' that can disagree is how the catalog
    comes from one profile while the corpus is written under another's name."""
    from cybersec_slm.sourcing import profiles

    for name in ("cybersec", "ubi"):
        _use(monkeypatch, name)
        assert profiles.active() == core.active_profile() == name


def test_cores_builtin_list_matches_the_taxonomies(root):
    """core duplicates the built-in names to avoid an import cycle; pin them."""
    from cybersec_slm.sourcing import taxonomies

    assert set(core.BUILTIN_PROFILES) == set(taxonomies.TAXONOMIES)
    assert core.DEFAULT_PROFILE == taxonomies.DEFAULT_PROFILE


# ------------------------------------------------------------ migration ------
def test_a_pre_profile_corpus_moves_under_the_active_profile(root, monkeypatch):
    _use(monkeypatch, "cybersec")
    old_raw = root / "data" / "raw" / "Network Security" / "src"
    old_raw.mkdir(parents=True)
    (old_raw / "a.jsonl").write_text('{"text": "x"}\n', encoding="utf-8")
    (root / "logs" / "eda").mkdir(parents=True)
    (root / "logs" / "eda" / "latest.json").write_text("{}", encoding="utf-8")

    moved = core.migrate_layout()

    assert sorted(moved) == ["data", "logs"]
    assert (root / "data" / "cybersec" / "raw" / "Network Security" / "src"
            / "a.jsonl").exists()
    assert (root / "logs" / "cybersec" / "eda" / "latest.json").exists()
    assert not (root / "data" / "raw").exists()


def test_migrating_is_a_no_op_the_second_time(root, monkeypatch):
    _use(monkeypatch, "cybersec")
    (root / "data" / "raw").mkdir(parents=True)

    assert core.migrate_layout() == ["data"]
    assert core.migrate_layout() == []


def test_a_corpus_already_under_a_profile_is_left_alone(root, monkeypatch):
    _use(monkeypatch, "cybersec")
    (root / "data" / "cybersec" / "raw").mkdir(parents=True)

    assert core.migrate_layout() == []


def test_nothing_to_migrate_is_not_an_error(root, monkeypatch):
    _use(monkeypatch, "ubi")

    assert core.migrate_layout() == []


def test_migration_moves_rather_than_copies(root, monkeypatch):
    """A copy of a 100GB corpus would take hours and need the space twice; the
    rename is what makes an automatic move acceptable at all."""
    _use(monkeypatch, "cybersec")
    src = root / "data" / "raw"
    src.mkdir(parents=True)
    (src / "big.jsonl").write_text("x" * 4096, encoding="utf-8")
    inode_before = (src / "big.jsonl").stat().st_ino

    core.migrate_layout()

    moved = root / "data" / "cybersec" / "raw" / "big.jsonl"
    assert moved.exists()
    assert moved.stat().st_ino == inode_before      # same file, not a copy


# ---------------------------------------------------------------- reset ------
def test_reset_spares_the_other_profiles_corpus(root, monkeypatch):
    """It used to delete <root>/data wholesale: resetting ubi destroyed
    cybersec's 1.9M records from a button that said nothing about it."""
    from cybersec_slm.dashboard import control

    _use(monkeypatch, "cybersec")
    cy = os.path.join(core.data_dir(), "clean")
    os.makedirs(cy)
    with open(os.path.join(cy, "keep.jsonl"), "w", encoding="utf-8") as f:
        f.write("{}\n")

    _use(monkeypatch, "ubi")
    os.makedirs(os.path.join(core.data_dir(), "clean"))
    monkeypatch.setattr(control, "status", lambda: {"running": False})

    out = control.reset()

    assert out["ok"] and out["profile"] == "ubi"
    assert not os.path.isdir(core.data_dir())              # ubi is gone
    assert os.path.isfile(os.path.join(cy, "keep.jsonl"))  # cybersec is not


def test_an_empty_profile_stub_does_not_look_like_a_finished_migration(root,
                                                                       monkeypatch):
    """Importing core creates logs/<profile> before anything has run
    (_make_logger does os.makedirs(LOGS) at import). Reading that stub as "already
    migrated" stranded the real logs at the top level, visible to no profile."""
    _use(monkeypatch, "cybersec")
    (root / "logs" / "eda").mkdir(parents=True)
    (root / "logs" / "eda" / "latest.json").write_text("{}", encoding="utf-8")
    (root / "logs" / "cybersec").mkdir()          # the import-time stub

    assert core.migrate_layout() == ["logs"]
    assert (root / "logs" / "cybersec" / "eda" / "latest.json").exists()


def test_the_stub_does_not_end_up_nested_inside_the_moved_tree(root, monkeypatch):
    _use(monkeypatch, "cybersec")
    (root / "logs" / "eda").mkdir(parents=True)
    (root / "logs" / "cybersec").mkdir()

    core.migrate_layout()

    assert not (root / "logs" / "cybersec" / "cybersec").exists()


def test_the_suite_never_points_at_a_real_checkout(root):
    """The guard for the accident this caused: a test called cli.main() with no
    data root, so it defaulted to the cwd, and the CLI's migration moved a real
    5GB corpus under the pinned test profile. Nothing here may reach a checkout."""
    import tempfile

    active = core.data_root()
    tmp = tempfile.gettempdir()

    assert active.startswith(tmp) or "pytest" in active or "Temp" in active, (
        f"the suite is pointed at {active!r}, which is not a temp directory")
    assert not os.path.exists(os.path.join(active, "pyproject.toml")), (
        f"the suite is pointed at a real checkout: {active!r}")
