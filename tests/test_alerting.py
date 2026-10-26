import json
import subprocess
from datetime import timedelta

from netguard.alerting import Dispatcher, run_hook
from netguard.engine import ScanResult, process_scan
from netguard.models import Alert, Event
from tests.conftest import T0, obs

ALERT = Alert("new_device", "warning", "Unknown device joined: x", T0, "de:ad:be:ef:00:01", "192.168.1.66")
LEFT = Event("left", "My phone left", T0, "aa:aa:aa:aa:aa:01", "192.168.1.10")
FIRST = Event("first_seen", "First time seen: y", T0, "aa:aa:aa:aa:aa:02", "192.168.1.20")


def result(alerts=(), events=()):
    return ScanResult(observations=[], alerts=list(alerts), events=list(events), baseline=False)


def test_dispatcher_prints_and_writes_json_lines(tmp_path, capsys):
    log = tmp_path / "logs" / "events.jsonl"
    Dispatcher(log_path=log).emit(result([ALERT], [LEFT, FIRST]))

    out = capsys.readouterr().out
    assert "[i] My phone left" in out
    assert "[!] Unknown device joined: x" in out
    assert "First time seen" not in out  # only logged

    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [(r["type"], r["kind"]) for r in records] == [
        ("event", "left"),
        ("event", "first_seen"),
        ("alert", "new_device"),
    ]
    assert records[2] == {
        "type": "alert",
        "time": "2026-10-01T12:00:00+00:00",
        "kind": "new_device",
        "severity": "warning",
        "message": "Unknown device joined: x",
        "mac": "de:ad:be:ef:00:01",
        "ip": "192.168.1.66",
    }


def test_dispatcher_runs_the_hook_for_alerts_only(monkeypatch):
    calls = []
    monkeypatch.setattr("netguard.alerting.run_hook", lambda cmd, alert: calls.append((cmd, alert)))
    Dispatcher(command=["notify-send", "NetGuard"], quiet=True).emit(result([ALERT], [LEFT]))
    assert calls == [(["notify-send", "NetGuard"], ALERT)]


def test_hook_gets_the_message_as_last_argument():
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"], seen["kwargs"] = argv, kwargs
        return subprocess.CompletedProcess(argv, 0)

    assert run_hook(["notify-send", "NetGuard"], ALERT, run=fake_run) is True
    assert seen["argv"] == ["notify-send", "NetGuard", "[WARNING] Unknown device joined: x"]
    assert seen["kwargs"]["timeout"] == 10
    assert "shell" not in seen["kwargs"]


def test_hook_failures_never_raise():
    def missing(argv, **kwargs):
        raise FileNotFoundError(argv[0])

    def times_out(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 10)

    def exits_1(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1)

    for run in (missing, times_out, exits_1):
        assert run_hook(["notify-send"], ALERT, run=run) is False


def test_repeated_alert_is_dropped_inside_the_dedup_window(store):
    net = "192.168.1.0/24"
    stranger = "de:ad:be:ef:00:01"
    process_scan(store, [obs("192.168.1.10", "aa:aa:aa:aa:aa:01")], "arp-scan", net, T0)
    first = process_scan(store, [obs("192.168.1.66", stranger)], "arp-scan", net, T0)
    assert len(first.alerts) == 1

    # Forget the device, so the detector sees it as new again.
    store.conn.execute("DELETE FROM devices WHERE mac = ?", (stranger,))
    again = T0 + timedelta(minutes=10)
    assert process_scan(store, [obs("192.168.1.66", stranger, again)], "arp-scan", net, again).alerts == []

    store.conn.execute("DELETE FROM devices WHERE mac = ?", (stranger,))
    much_later = T0 + timedelta(hours=2)
    late = process_scan(store, [obs("192.168.1.66", stranger, much_later)], "arp-scan", net, much_later)
    assert len(late.alerts) == 1
