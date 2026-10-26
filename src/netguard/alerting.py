"""Send alerts and events to the console, a JSON-lines log and a command hook."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from netguard.config import hand_back_to_sudo_user
from netguard.engine import ScanResult
from netguard.models import Alert, Event

log = logging.getLogger(__name__)

HOOK_TIMEOUT = 10  # seconds


class Dispatcher:
    def __init__(
        self,
        log_path: Path | None = None,
        command: list[str] | None = None,
        quiet: bool = False,
    ):
        self.log_path = log_path
        self.command = command
        self.quiet = quiet

    def emit(self, result: ScanResult) -> None:
        for event in result.events:
            # New devices are already on screen (scan table or a new_device
            # alert), so "first_seen" only goes to the log.
            if event.kind != "first_seen":
                self._print(f"[i] {event.message}")
            self._log(_event_record(event))
        for alert in result.alerts:
            self._print(f"[!] {alert.message}")
            self._log(_alert_record(alert))
            if self.command:
                run_hook(self.command, alert)

    def _print(self, line: str) -> None:
        if not self.quiet:
            # Look sys.stdout up on every call: it may have been redirected.
            print(line, file=sys.stdout, flush=True)

    def _log(self, record: dict) -> None:
        if not self.log_path:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        hand_back_to_sudo_user(self.log_path)


def _alert_record(alert: Alert) -> dict:
    return {
        "type": "alert",
        "time": alert.created_at.isoformat(),
        "kind": alert.kind,
        "severity": alert.severity,
        "message": alert.message,
        "mac": alert.mac,
        "ip": alert.ip,
    }


def _event_record(event: Event) -> dict:
    return {
        "type": "event",
        "time": event.created_at.isoformat(),
        "kind": event.kind,
        "message": event.message,
        "mac": event.mac,
        "ip": event.ip,
    }


def run_hook(command: list[str], alert: Alert, run=subprocess.run) -> bool:
    """Run `command` with the alert text as its last argument. Never raises.

    Under sudo the hook runs as the real user, with that user's desktop session
    bus, so `notify-send` pops up on their screen instead of root's.
    """
    argv = [*command, f"[{alert.severity.upper()}] {alert.message}"]
    kwargs: dict = {"timeout": HOOK_TIMEOUT, "check": False, "capture_output": True}
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() == 0 and uid and gid:
        kwargs.update(
            user=int(uid),
            group=int(gid),
            env={**os.environ, "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus"},
        )
    try:
        completed = run(argv, **kwargs)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("alert command %s failed: %s", command[0], exc)
        return False
    if completed.returncode != 0:
        log.warning("alert command %s exited with %s", command[0], completed.returncode)
        return False
    return True
