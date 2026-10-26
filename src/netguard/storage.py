"""SQLite storage for the device inventory, scans and alerts."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from netguard.audit.report import AuditedHost, AuditResult
from netguard.audit.rules import Finding
from netguard.audit.scanner import OpenPort
from netguard.config import hand_back_to_sudo_user
from netguard.models import Alert, Device, Event, Observation

# Each entry upgrades the database by one version. Never edit a released
# migration: add a new one, so existing databases upgrade in place.
MIGRATIONS = [
    # 1: devices, scans and alerts
    """
    CREATE TABLE devices (
        mac        TEXT PRIMARY KEY,
        ip         TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen  TEXT NOT NULL,
        trusted    INTEGER NOT NULL DEFAULT 0,
        label      TEXT
    );
    CREATE TABLE scans (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at   TEXT NOT NULL,
        source       TEXT NOT NULL,
        network      TEXT NOT NULL,
        device_count INTEGER NOT NULL
    );
    CREATE TABLE alerts (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        kind       TEXT NOT NULL,
        severity   TEXT NOT NULL,
        message    TEXT NOT NULL,
        mac        TEXT,
        ip         TEXT
    );
    CREATE INDEX alerts_created_at ON alerts (created_at);
    """,
    # 2: presence tracking and the event timeline
    """
    ALTER TABLE devices ADD COLUMN present INTEGER NOT NULL DEFAULT 1;
    CREATE TABLE events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        kind       TEXT NOT NULL,
        message    TEXT NOT NULL,
        mac        TEXT,
        ip         TEXT
    );
    CREATE INDEX events_created_at ON events (created_at);
    """,
    # 3: gateway MACs accepted per Wi-Fi access point, for ARP spoofing detection
    """
    CREATE TABLE gateway_macs (
        bssid      TEXT NOT NULL,  -- access point, or "wired"
        gateway_ip TEXT NOT NULL,
        mac        TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        PRIMARY KEY (bssid, gateway_ip, mac)
    );
    """,
    # 4: device audits (open ports and findings)
    """
    CREATE TABLE audits (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at    TEXT NOT NULL,
        ports_checked INTEGER NOT NULL
    );
    CREATE TABLE audit_hosts (
        audit_id INTEGER NOT NULL REFERENCES audits (id),
        ip       TEXT NOT NULL,
        mac      TEXT NOT NULL,
        name     TEXT NOT NULL
    );
    CREATE TABLE audit_ports (
        audit_id INTEGER NOT NULL REFERENCES audits (id),
        ip       TEXT NOT NULL,
        port     INTEGER NOT NULL,
        banner   TEXT NOT NULL,
        tls      INTEGER NOT NULL
    );
    CREATE TABLE audit_findings (
        audit_id INTEGER NOT NULL REFERENCES audits (id),
        ip       TEXT NOT NULL,
        port     INTEGER,
        severity TEXT NOT NULL,
        title    TEXT NOT NULL,
        detail   TEXT NOT NULL
    );
    """,
]
SCHEMA_VERSION = len(MIGRATIONS)


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
        self._migrate()
        if path != ":memory:":
            hand_back_to_sudo_user(Path(path))

    def _migrate(self) -> None:
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"{self.path} was written by a newer NetGuard (schema v{version})"
            )
        for number, script in enumerate(MIGRATIONS[version:], start=version + 1):
            # executescript() commits on its own, so the version bump is part of
            # the same script: a failed migration leaves the old version number.
            try:
                self.conn.executescript(
                    f"BEGIN; {script}; PRAGMA user_version = {number}; COMMIT;"
                )
            except sqlite3.Error:
                self.conn.rollback()
                raise

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
                    last_seen = excluded.last_seen,
                    present = 1
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

    def mark_absent(self, macs: Iterable[str]) -> None:
        with self.conn:
            self.conn.executemany(
                "UPDATE devices SET present = 0 WHERE mac = ?", [(mac,) for mac in macs]
            )

    # --- gateways --------------------------------------------------------

    def gateway_macs(self, bssid: str, gateway_ip: str) -> set[str]:
        rows = self.conn.execute(
            "SELECT mac FROM gateway_macs WHERE bssid = ? AND gateway_ip = ?", (bssid, gateway_ip)
        )
        return {row["mac"] for row in rows}

    def add_gateway_mac(self, bssid: str, gateway_ip: str, mac: str, at: datetime) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO gateway_macs (bssid, gateway_ip, mac, first_seen) "
                "VALUES (?, ?, ?, ?)",
                (bssid, gateway_ip, mac, _ts(at)),
            )

    def all_gateway_macs(self) -> list[tuple[str, str, str, datetime]]:
        rows = self.conn.execute(
            "SELECT * FROM gateway_macs ORDER BY bssid, gateway_ip, first_seen"
        )
        return [(r["bssid"], r["gateway_ip"], r["mac"], _dt(r["first_seen"])) for r in rows]

    # --- audits ----------------------------------------------------------

    def save_audit(self, result: AuditResult) -> int:
        with self.conn:
            audit_id = self.conn.execute(
                "INSERT INTO audits (started_at, ports_checked) VALUES (?, ?)",
                (_ts(result.started_at), result.ports_checked),
            ).lastrowid
            self.conn.executemany(
                "INSERT INTO audit_hosts VALUES (?, ?, ?, ?)",
                [(audit_id, h.ip, h.mac, h.name) for h in result.hosts],
            )
            self.conn.executemany(
                "INSERT INTO audit_ports VALUES (?, ?, ?, ?, ?)",
                [(audit_id, p.ip, p.port, p.banner, int(p.tls)) for p in result.open_ports],
            )
            self.conn.executemany(
                "INSERT INTO audit_findings VALUES (?, ?, ?, ?, ?, ?)",
                [(audit_id, f.ip, f.port, f.severity, f.title, f.detail) for f in result.findings],
            )
        return audit_id

    def latest_audit(self) -> AuditResult | None:
        row = self.conn.execute("SELECT * FROM audits ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        audit_id = row["id"]

        def query(table: str) -> sqlite3.Cursor:
            # `table` is always one of our own constant names, never user input.
            return self.conn.execute(f"SELECT * FROM {table} WHERE audit_id = ?", (audit_id,))

        return AuditResult(
            started_at=_dt(row["started_at"]),
            ports_checked=row["ports_checked"],
            hosts=[AuditedHost(r["ip"], r["mac"], r["name"]) for r in query("audit_hosts")],
            open_ports=[
                OpenPort(r["ip"], r["port"], r["banner"], bool(r["tls"])) for r in query("audit_ports")
            ],
            findings=[
                Finding(r["ip"], r["port"], r["severity"], r["title"], r["detail"])
                for r in query("audit_findings")
            ],
        )

    # --- events ----------------------------------------------------------

    def add_events(self, events: Iterable[Event]) -> None:
        with self.conn:
            self.conn.executemany(
                "INSERT INTO events (created_at, kind, message, mac, ip) VALUES (?, ?, ?, ?, ?)",
                [(_ts(e.created_at), e.kind, e.message, e.mac, e.ip) for e in events],
            )

    def events(self, limit: int = 50, mac: str | None = None) -> list[Event]:
        query, params = "SELECT * FROM events", []
        if mac:
            query, params = query + " WHERE mac = ?", [mac]
        rows = self.conn.execute(
            query + " ORDER BY created_at DESC, id DESC LIMIT ?", [*params, limit]
        )
        return [
            Event(
                kind=row["kind"],
                message=row["message"],
                created_at=_dt(row["created_at"]),
                mac=row["mac"],
                ip=row["ip"],
            )
            for row in rows
        ]

    def timeline(self, limit: int = 50, mac: str | None = None) -> list[TimelineEntry]:
        """Events and alerts together, newest first."""
        entries = [
            TimelineEntry(e.created_at, e.kind, e.message, e.mac, e.ip, is_alert=False)
            for e in self.events(limit=limit, mac=mac)
        ] + [
            TimelineEntry(a.created_at, a.severity, a.message, a.mac, a.ip, is_alert=True)
            for a in self.alerts(limit=limit, mac=mac)
        ]
        # An alert goes above an event from the same moment.
        entries.sort(key=lambda e: (e.at, e.is_alert), reverse=True)
        return entries[:limit]

    # --- alerts ----------------------------------------------------------

    def has_recent_alert(self, alert: Alert, since: datetime) -> bool:
        """True if the same kind of alert for the same MAC and IP was raised after `since`."""
        row = self.conn.execute(
            "SELECT 1 FROM alerts WHERE kind = ? AND mac IS ? AND ip IS ? AND created_at >= ? LIMIT 1",
            (alert.kind, alert.mac, alert.ip, _ts(since)),
        ).fetchone()
        return row is not None

    def add_alerts(self, alerts: Iterable[Alert]) -> None:
        with self.conn:
            self.conn.executemany(
                "INSERT INTO alerts (created_at, kind, severity, message, mac, ip) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [(_ts(a.created_at), a.kind, a.severity, a.message, a.mac, a.ip) for a in alerts],
            )

    def alerts(self, limit: int = 50, mac: str | None = None) -> list[Alert]:
        query, params = "SELECT * FROM alerts", []
        if mac:
            query, params = query + " WHERE mac = ?", [mac]
        rows = self.conn.execute(
            query + " ORDER BY created_at DESC, id DESC LIMIT ?", [*params, limit]
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


@dataclass(frozen=True)
class TimelineEntry:
    at: datetime
    what: str  # event kind, or alert severity
    message: str
    mac: str | None
    ip: str | None
    is_alert: bool


def _device(row: sqlite3.Row) -> Device:
    return Device(
        mac=row["mac"],
        ip=row["ip"],
        first_seen=_dt(row["first_seen"]),
        last_seen=_dt(row["last_seen"]),
        trusted=bool(row["trusted"]),
        label=row["label"],
        present=bool(row["present"]),
    )
