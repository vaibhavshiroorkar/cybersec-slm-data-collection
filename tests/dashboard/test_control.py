import sys
import time

from cybersec_slm.dashboard import control

DUMMY = [sys.executable, "-c", "import time; time.sleep(30)"]


def _use_root(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))


def test_status_idle_on_fresh_root(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    st = control.status()
    assert st["running"] is False
    assert st["pid"] is None


def test_start_status_stop(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    try:
        res = control.start(_command=DUMMY)
        assert res["ok"] is True and res["pid"]
        # control file written under logs/
        assert (tmp_path / "logs" / control.CONTROL_NAME).exists()
        st = control.status()
        assert st["running"] is True and st["pid"] == res["pid"]
        # double start is refused
        again = control.start(_command=DUMMY)
        assert again["ok"] is False and "already active" in again["error"]
    finally:
        stopped = control.stop()
    assert stopped["ok"] is True
    # allow the OS a moment to reap, then confirm idle
    for _ in range(20):
        if not control.status()["running"]:
            break
        time.sleep(0.1)
    assert control.status()["running"] is False


def test_stale_control_reads_idle(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / control.CONTROL_NAME).write_text(
        '{"pid": 999999, "started_at": "x", "resume": false}', encoding="utf-8")
    st = control.status()
    assert st["running"] is False
    assert st["stale"] is True


def test_reset_deletes_data_and_logs(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    (tmp_path / "data" / "clean").mkdir(parents=True)
    (tmp_path / "data" / "clean" / "x.jsonl").write_text("{}", encoding="utf-8")
    (tmp_path / "logs" / "eda").mkdir(parents=True)
    (tmp_path / "logs" / "clean_report.csv").write_text("a", encoding="utf-8")
    res = control.reset()
    assert res["ok"] is True
    assert set(res["removed"]) == {"data", "logs"}
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "logs").exists()


def test_reset_refused_while_running(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    try:
        control.start(_command=DUMMY)
        res = control.reset()
        assert res["ok"] is False
        assert "stop the running pipeline" in res["error"]
        assert (tmp_path / "logs" / control.CONTROL_NAME).exists()
    finally:
        control.stop()
