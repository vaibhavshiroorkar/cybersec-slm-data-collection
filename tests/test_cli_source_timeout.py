from cybersec_slm.cli import build_parser


def test_run_has_source_timeout_default():
    args = build_parser().parse_args(["run"])
    assert args.source_timeout == 1800.0


def test_all_accepts_source_timeout():
    args = build_parser().parse_args(["all", "--source-timeout", "60"])
    assert args.source_timeout == 60.0
