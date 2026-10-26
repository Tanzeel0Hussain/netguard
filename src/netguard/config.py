"""Load settings from a TOML file. Every setting has a sensible default."""

from __future__ import annotations

import os
import pwd
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


def user_home() -> Path:
    """The real user's home, even when NetGuard is started with sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user:
        return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


def default_config_path() -> Path:
    return user_home() / ".config" / "netguard" / "netguard.toml"


def hand_back_to_sudo_user(path: Path) -> None:
    """When run with sudo, keep NetGuard's files owned by the real user.

    Otherwise a later run without sudo (e.g. `scan --passive`) could not write to them.
    """
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid or not gid:
        return
    for target in (path.parent, path):
        if target.exists() and target.stat().st_uid == 0:
            os.chown(target, int(uid), int(gid))


def data_dir() -> Path:
    return user_home() / ".local" / "share" / "netguard"


def default_db_path() -> Path:
    return data_dir() / "netguard.db"


def default_oui_path() -> Path:
    return data_dir() / "manuf"


def default_log_path() -> Path:
    return data_dir() / "events.jsonl"


@dataclass
class Config:
    iface: str | None = None
    network: str | None = None
    db_path: Path = field(default_factory=default_db_path)
    oui_path: Path = field(default_factory=default_oui_path)
    log_path: Path | None = field(default_factory=default_log_path)
    scan_timeout: float = 2.0
    monitor_interval: float = 300
    away_after: float = 900  # seconds unseen before a device counts as gone
    dedup_window: float = 3600  # seconds during which a repeated alert is dropped
    alert_command: list[str] | None = None  # e.g. ["notify-send", "NetGuard"]
    arp_window: float = 60  # seconds, for the many-IPs and reply-flood checks
    arp_many_ips: int = 3
    arp_flood_replies: int = 15
    portscan_window: float = 60  # seconds
    portscan_ports: int = 15  # distinct ports on one host within the window
    portscan_hosts: int = 10  # distinct hosts on one port within the window
    portscan_allow: list[str] = field(default_factory=list)  # source IPs never flagged


def load_config(path: Path | None = None) -> Config:
    """Read `path`, or the default config file if it exists."""
    if path is None:
        path = default_config_path()
        if not path.exists():
            return Config()
    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    network = data.get("network", {})
    storage = data.get("storage", {})
    scan = data.get("scan", {})
    monitor = data.get("monitor", {})
    alerts = data.get("alerts", {})
    arp = data.get("arp", {})
    portscan = data.get("portscan", {})
    config = Config(
        iface=network.get("iface"),
        network=network.get("cidr"),
        scan_timeout=float(scan.get("timeout", 2.0)),
        monitor_interval=float(monitor.get("interval", 300)),
        away_after=float(monitor.get("away_after", 900)),
        dedup_window=float(alerts.get("dedup_window", 3600)),
        alert_command=alerts.get("command"),
        arp_window=float(arp.get("window", 60)),
        arp_many_ips=int(arp.get("many_ips", 3)),
        arp_flood_replies=int(arp.get("flood_replies", 15)),
        portscan_window=float(portscan.get("window", 60)),
        portscan_ports=int(portscan.get("ports", 15)),
        portscan_hosts=int(portscan.get("hosts", 10)),
        portscan_allow=[str(ip) for ip in portscan.get("allow", [])],
    )
    if config.alert_command is not None and (
        not isinstance(config.alert_command, list)
        or not all(isinstance(arg, str) for arg in config.alert_command)
    ):
        raise ValueError('[alerts] command must be a list of strings, e.g. ["notify-send", "NetGuard"]')
    if "db_path" in storage:
        config.db_path = Path(storage["db_path"]).expanduser()
    if "oui_path" in storage:
        config.oui_path = Path(storage["oui_path"]).expanduser()
    if "log_path" in alerts:
        # An empty string turns the log file off.
        config.log_path = Path(alerts["log_path"]).expanduser() if alerts["log_path"] else None
    return config
