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


def data_dir() -> Path:
    return user_home() / ".local" / "share" / "netguard"


def default_db_path() -> Path:
    return data_dir() / "netguard.db"


def default_oui_path() -> Path:
    return data_dir() / "manuf"


@dataclass
class Config:
    iface: str | None = None
    network: str | None = None
    db_path: Path = field(default_factory=default_db_path)
    oui_path: Path = field(default_factory=default_oui_path)
    scan_timeout: float = 2.0


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
    config = Config(
        iface=network.get("iface"),
        network=network.get("cidr"),
        scan_timeout=float(scan.get("timeout", 2.0)),
    )
    if "db_path" in storage:
        config.db_path = Path(storage["db_path"]).expanduser()
    if "oui_path" in storage:
        config.oui_path = Path(storage["oui_path"]).expanduser()
    return config
