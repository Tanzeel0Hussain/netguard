"""Run scans on a fixed interval until stopped."""

from __future__ import annotations

import logging
import signal
import threading
from collections.abc import Callable
from dataclasses import dataclass

from netguard.discovery import ScanPermissionError

log = logging.getLogger(__name__)


@dataclass
class MonitorStats:
    scans: int = 0
    failed: int = 0


def run_monitor(
    scan_once: Callable[[int], None],
    interval: float,
    max_scans: int | None = None,
    stop: threading.Event | None = None,
) -> MonitorStats:
    """Call `scan_once(n)` every `interval` seconds until `stop` is set.

    A failing scan (Wi-Fi dropped for a moment, a DHCP hiccup) is logged and
    the monitor keeps going. Missing permissions will not fix themselves, so
    those stop it.
    """
    stop = stop or threading.Event()
    stats = MonitorStats()
    while not stop.is_set():
        number = stats.scans + stats.failed + 1
        try:
            scan_once(number)
            stats.scans += 1
        except ScanPermissionError:
            raise
        except Exception as exc:  # noqa: BLE001 - one bad scan must not kill the monitor
            stats.failed += 1
            log.error("scan #%d failed: %s", number, exc)
        if max_scans is not None and number >= max_scans:
            break
        stop.wait(interval)
    return stats


def stop_on_sigterm(stop: threading.Event) -> None:
    """Let `systemctl stop` end the monitor as cleanly as Ctrl+C does."""
    signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
