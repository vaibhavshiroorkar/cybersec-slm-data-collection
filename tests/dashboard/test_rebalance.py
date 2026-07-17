"""Deciding what an EDA fix round should do.

Pure decisions over an EDA report: which sub-domains are short, whether the
corpus is balanced enough to stop, how many catalog rows to aim for, and the
stages one round runs. No process is started here.
"""

from cybersec_slm.dashboard import rebalance


def _report(subs, *, topic_cv=0.0, feedback=None):
    total = sum(subs.values())
    dist = {k: (v / total if total else 0.0) for k, v in subs.items()}
    report = {
        "metrics": {"total": total, "subdomains": dict(subs),
                    "subdomain_distribution": dist, "topic_cv": topic_cv},
        "violations": [],
    }
    if feedback is not None:
        report["feedback"] = feedback
    return report


# --------------------------------------------------------------- lacking ------
def test_a_subdomain_far_below_the_average_is_lacking():
    # Cloud is 10 against an average of ~2530, far under the quarter-average bar.
    r = _report({"Network Security": 5000, "Threat Intelligence": 2580,
                 "Cloud Security": 10})

    assert rebalance.lacking(r) == ["Cloud Security"]


def test_a_subdomain_below_the_minimum_share_is_lacking():
    # 40 of 10040 is 0.4%, under the 1% minimum share, but not under a quarter
    # of the average, so only the share rule catches it.
    r = _report({"A": 3340, "B": 3330, "C": 3330, "D": 40})

    assert "D" in rebalance.lacking(r)


def test_a_balanced_corpus_has_nothing_lacking():
    r = _report({"A": 1000, "B": 1000, "C": 1000})

    assert rebalance.lacking(r) == []


def test_lacking_prefers_the_gates_own_feedback_when_present():
    """The gate already computed this; agreeing with it beats recomputing it."""
    r = _report({"A": 1000, "B": 1000},
                feedback={"under_represented": [{"subdomain": "B", "records": 1000}]})

    assert rebalance.lacking(r) == ["B"]


def test_lacking_falls_back_to_metrics_when_feedback_is_absent():
    """Older reports predate the feedback block."""
    r = _report({"A": 5000, "B": 10})
    r.pop("feedback", None)

    assert rebalance.lacking(r) == ["B"]


def test_lacking_is_empty_for_an_empty_or_missing_report():
    assert rebalance.lacking({}) == []
    assert rebalance.lacking({"metrics": {"subdomains": {}}}) == []


def test_lacking_reads_the_post_rebalance_metrics_when_the_gate_capped():
    """A capped run's real state is metrics_after_rebalance, not metrics."""
    r = _report({"A": 5000, "B": 10})
    r["rebalanced"] = True
    r["metrics_after_rebalance"] = {
        "total": 2000, "subdomains": {"A": 1000, "B": 1000},
        "subdomain_distribution": {"A": 0.5, "B": 0.5}, "topic_cv": 0.0}

    assert rebalance.lacking(r) == []


def test_lacking_is_sorted_so_a_round_is_reproducible():
    r = _report({"Zeta": 5000, "Alpha": 10, "Mid": 12})

    assert rebalance.lacking(r) == ["Alpha", "Mid"]


# ------------------------------------------------------------- is_balanced ----
def test_a_corpus_with_nothing_lacking_and_a_low_cv_is_balanced():
    assert rebalance.is_balanced(_report({"A": 1000, "B": 1000}, topic_cv=0.1))


def test_a_corpus_with_a_lacking_subdomain_is_not_balanced():
    assert not rebalance.is_balanced(_report({"A": 5000, "B": 10}))


def test_a_skewed_corpus_is_not_balanced_even_with_nothing_lacking():
    """Every domain clears the bars, but the spread itself is still the problem."""
    r = _report({"A": 1000, "B": 1000}, topic_cv=9.9)

    assert not rebalance.is_balanced(r)


def test_an_empty_report_is_not_balanced():
    """No evidence is not the same as balanced; a fix run should still look."""
    assert not rebalance.is_balanced({})


# -------------------------------------------------------------- row_target ----
def test_the_target_aims_at_parity_with_the_best_covered_domain():
    counts = {"A": 100, "B": 90, "C": 5}

    assert rebalance.row_target(counts, ["C"], step=25) == 100


def test_the_target_always_asks_for_more_than_the_lacking_domain_has():
    """Otherwise a round asks the fill for a target it already meets and no
    source is discovered, so the loop spins without adding anything."""
    counts = {"A": 100, "B": 100}

    assert rebalance.row_target(counts, ["A"], step=25) == 125


def test_the_target_of_an_empty_catalog_is_one_step():
    assert rebalance.row_target({}, ["A"], step=25) == 25


def test_the_target_with_no_domains_is_zero():
    assert rebalance.row_target({"A": 10}, [], step=25) == 0


# -------------------------------------------------------------- plan_round ----
def test_a_round_sources_ingests_and_cleans_only_the_lacking_domains(monkeypatch):
    monkeypatch.setattr(rebalance.settings_store, "get_stage", lambda k: {})

    plan = rebalance.plan_round(["Cloud Security"], 120)

    assert [argv[0] for argv in plan] == ["source", "ingest", "clean"]
    for argv in plan:
        assert "--domains" in argv
        assert "Cloud Security" in argv


def test_a_round_tells_the_fill_what_to_top_up_to(monkeypatch):
    monkeypatch.setattr(rebalance.settings_store, "get_stage", lambda k: {})

    [src, _ing, _cln] = rebalance.plan_round(["Cloud Security"], 120)

    assert "--target-per-domain" in src
    assert src[src.index("--target-per-domain") + 1] == "120"


def test_a_round_resumes_ingest_and_clean_so_it_only_does_the_new_work(monkeypatch):
    """Without --resume a selective run wipes the domain's folders and redoes it
    all, which would throw away the corpus the round is supposed to be growing."""
    monkeypatch.setattr(rebalance.settings_store, "get_stage", lambda k: {})

    [_src, ing, cln] = rebalance.plan_round(["Cloud Security"], 120)

    assert "--resume" in ing
    assert "--resume" in cln


def test_a_round_keeps_each_stages_saved_settings(monkeypatch):
    monkeypatch.setattr(rebalance.settings_store, "get_stage",
                        lambda k: {"workers": 8} if k == "clean" else {})

    [_src, _ing, cln] = rebalance.plan_round(["Cloud Security"], 120)

    assert "--workers" in cln and cln[cln.index("--workers") + 1] == "8"


def test_round_overrides_beat_saved_settings(monkeypatch):
    monkeypatch.setattr(rebalance.settings_store, "get_stage", lambda k: {"workers": 8})

    [_src, _ing, cln] = rebalance.plan_round(["Cloud Security"], 120,
                                             settings={"workers": 2})

    assert cln[cln.index("--workers") + 1] == "2"


def test_a_round_never_caps_the_over_represented(monkeypatch):
    """The fix balances by adding data, never by deleting it: apply_cap randomly
    downsamples data/clean in place. Over-representation is only ever a warning,
    so nothing is blocked by leaving it alone."""
    monkeypatch.setattr(rebalance.settings_store, "get_stage", lambda k: {})

    plan = rebalance.plan_round(["Cloud Security"], 120)

    for argv in plan:
        assert "--cap" not in argv
        assert "balance" not in argv
