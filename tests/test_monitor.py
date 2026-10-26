import threading

import pytest

from netguard.discovery import ScanPermissionError
from netguard.monitor import run_monitor


class FakeStop(threading.Event):
    """Records the waits instead of sleeping."""

    def __init__(self):
        super().__init__()
        self.waits = []

    def wait(self, timeout=None):
        self.waits.append(timeout)
        return self.is_set()


def test_runs_the_requested_number_of_scans_without_a_final_wait():
    stop, calls = FakeStop(), []
    stats = run_monitor(calls.append, interval=60, max_scans=3, stop=stop)
    assert calls == [1, 2, 3]
    assert stop.waits == [60, 60]
    assert (stats.scans, stats.failed) == (3, 0)


def test_a_failing_scan_does_not_stop_the_monitor():
    def scan(number):
        if number == 2:
            raise OSError("Network is down")

    stats = run_monitor(scan, interval=60, max_scans=3, stop=FakeStop())
    assert (stats.scans, stats.failed) == (2, 1)


def test_missing_permissions_stop_the_monitor():
    def scan(number):
        raise ScanPermissionError("needs root")

    with pytest.raises(ScanPermissionError):
        run_monitor(scan, interval=60, stop=FakeStop())


def test_stop_event_ends_the_loop():
    stop = FakeStop()

    def scan(number):
        if number == 2:
            stop.set()  # what Ctrl+C or SIGTERM does

    stats = run_monitor(scan, interval=60, stop=stop)
    assert stats.scans == 2
