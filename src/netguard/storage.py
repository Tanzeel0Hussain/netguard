"""SQLite storage for the device inventory, scans and alerts."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from netguard.models import Alert, Device, Observation

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac        TEXT PRIMARY KEY,
    ip         TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    trusted    INTEGER NOT NULL DEFAULT 0,
    label      TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    source       TEXT NOT NULL,
    network      TEXT NOT NULL,
    device_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    kind       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    message    TEXT NOT NULL,
    mac        TEXT,
    ip         TEXT
);
CREATE INDEX IF NOT EXISTS alerts_created_at ON alerts (created_at);
"""


def _ts(value: datetime) -> str:
    return value.isoformat()


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


class Store:
    def __init__(self, path: Path | str):
        self.path = path
        if path != ":memory:":
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        with self.conn:
            self.conn.executescript(SCHEMA)
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        if path != ":memory:":
            _hand_back_to_sudo_user(Path(path))

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- devices ---------------------------------------------------------

    def known_macs(self) -> set[str]:
        return {row["mac"] for row in self.conn.execute("SELECT mac FROM devices")}

    def is_first_scan(self) -> bool:
        return self.conn.execute("SELECT 1 FROM scans LIMIT 1").fetchone() is None

    def record_scan(
        self,
        observations: Iterable[Observation],
        source: str,
        network: str,
        started_at: datetime,
    ) -> None:
        observations = list(observations)
        with self.conn:
            self.conn.executemany(
                """
                INSERT INTO devices (mac, ip, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (mac) DO UPDATE SET
                    ip = excluded.ip,
                    last_seen = excluded.last_seen
                """,
                [(o.mac, o.ip, _ts(o.seen_at), _ts(o.seen_at)) for o in observations],
            )
            self.conn.execute(
                "INSERT INTO scans (started_at, source, network, device_count) VALUES (?, ?, ?, ?)",
                (_ts(started_at), source, network, len(observations)),
            )

    def devices(self, untrusted_only: bool = False) -> list[Device]:
        query = "SELECT * FROM devices"
        if untrusted_only:
            query += " WHERE trusted = 0"
        return [_device(row) for row in self.conn.execute(query)]

    def device(self, mac: str) -> Device | None:
        row = self.conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
        return _device(row) if row else None

    def set_trusted(self, mac: str, trusted: bool, label: str | None = None) -> bool:
        """Mark a device as (un)trusted. Returns False if the MAC is unknown."""
        with self.conn:
            cursor = self.conn.execute(
                "UPDATE devices SET trusted = ?, label = COALESCE(?, label) WHERE mac = ?",
                (int(trusted), label, mac),
            )
        return cursor.rowcount == 1

    def set_label(self, mac: str, label: str | None) -> bool:
        """Name a device (None clears it). Returns False if the MAC is unknown."""
        with self.conn:
            cursor = self.conn.execute(
                "UPDATE devices SET label = ? WHERE mac = ?", (label, mac)
            )
        return cursor.rowcount == 1

    # --- alerts ----------------------------------------------------------

    def add_alerts(self, alerts: Iterable[Alert]) -> None:
        with self.conn:
            self.conn.executemany(
                "INSERT INTO alerts (created_at, kind, severity, message, mac, ip) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [(_ts(a.created_at), a.kind, a.severity, a.message, a.mac, a.ip) for a in alerts],
            )

    def alerts(self, limit: int = 50) -> list[Alert]:
        rows = self.conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
        )
        return [
            Alert(
                kind=row["kind"],
                severity=row["severity"],
                message=row["message"],
                created_at=_dt(row["created_at"]),
                mac=row["mac"],
                ip=row["ip"],
            )
            for row in rows
        ]


def _device(row: sqlite3.Row) -> Device:
    return Device(
        mac=row["mac"],
        ip=row["ip"],
        first_seen=_dt(row["first_seen"]),
        last_seen=_dt(row["last_seen"]),
        trusted=bool(row["trusted"]),
        label=row["label"],
    )


def _hand_back_to_sudo_user(path: Path) -> None:
    """When run with sudo, keep the database owned by the real user.

    Otherwise a later scan without sudo (e.g. --passive) could not write to it.
    """
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid or not gid:
        return
    for target in (path.parent, path):
        if target.exists() and target.stat().st_uid == 0:
            os.chown(target, int(uid), int(gid))
