"""The `netguard` command line."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
import threading
from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path

from netguard import __version__
from netguard.alerting import Dispatcher
from netguard.config import Config, load_config
from netguard.discovery import ScanPermissionError, discover
from netguard.engine import ScanResult, process_scan
from netguard.models import is_randomized_mac, normalize_mac
from netguard.netinfo import UnsafeTargetError, detect_netinfo, validate_scan_target
from netguard.oui import MANUF_URL, VendorDB, download
from netguard.monitor import run_monitor, stop_on_sigterm
from netguard.storage import Store

VENDOR_WIDTH = 28
MIN_INTERVAL = 10  # seconds; scanning more often only adds noise to the network


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netguard",
        description="Home network security monitor. Only use it on networks you own.",
    )
    parser.add_argument("--version", action="version", version=f"netguard {__version__}")
    parser.add_argument("--config", type=Path, help="path to a netguard.toml file")
    parser.add_argument("--db", type=Path, help="path to the SQLite database")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    sub.add_parser("info", help="show the detected interface, subnet and gateway")

    scan = sub.add_parser("scan", help="discover devices and update the inventory")
    _add_target_args(scan)

    monitor = sub.add_parser("monitor", help="scan on an interval and report changes (Ctrl+C stops)")
    _add_target_args(monitor)
    monitor.add_argument("--interval", type=float, help="seconds between scans (default 300)")
    monitor.add_argument("--count", type=int, help="stop after this many scans")

    devices = sub.add_parser("devices", help="list the device inventory")
    devices.add_argument("--untrusted", action="store_true", help="only untrusted devices")

    trust = sub.add_parser("trust", help="mark a device as one of yours")
    trust.add_argument("mac")
    trust.add_argument("--label", help='a name for it, e.g. "Ali\'s phone"')

    untrust = sub.add_parser("untrust", help="remove the trusted mark from a device")
    untrust.add_argument("mac")

    label = sub.add_parser("label", help="give a device a name")
    label.add_argument("mac")
    label.add_argument("name", nargs="?", help='e.g. "Living room TV"')
    label.add_argument("--clear", action="store_true", help="remove the name")

    oui = sub.add_parser("oui", help="MAC vendor list")
    oui_sub = oui.add_subparsers(dest="oui_command", required=True, metavar="ACTION")
    update = oui_sub.add_parser("update", help="download the vendor list (resumes if interrupted)")
    update.add_argument("--url", default=MANUF_URL, help="where to download it from")
    lookup = oui_sub.add_parser("lookup", help="show the vendor of a MAC address")
    lookup.add_argument("mac")

    alerts = sub.add_parser("alerts", help="show recent alerts")
    alerts.add_argument("--limit", type=int, default=20)

    timeline = sub.add_parser("timeline", help="what happened on the network, newest first")
    timeline.add_argument("--limit", type=int, default=30)
    timeline.add_argument("--mac", help="only this device")
    return parser


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--passive",
        action="store_true",
        help="read the kernel ARP cache instead of sending packets (no root needed)",
    )
    parser.add_argument("--network", help="subnet to scan, e.g. 192.168.1.0/24")
    parser.add_argument("--iface", help="network interface, e.g. wlan0")
    parser.add_argument("--timeout", type=float, help="seconds to wait for ARP replies")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        if args.db:
            config.db_path = args.db
        return COMMANDS[args.command](args, config)
    except (UnsafeTargetError, ScanPermissionError, ValueError, RuntimeError, OSError) as exc:
        print(f"netguard: error: {exc}", file=sys.stderr)
        return 1


# --- commands ------------------------------------------------------------


def cmd_info(args: argparse.Namespace, config: Config) -> int:
    info = detect_netinfo(iface=config.iface)
    print(f"Interface: {info.iface}")
    print(f"Network:   {info.network}")
    print(f"Gateway:   {info.gateway or '-'}")
    print(f"Database:  {config.db_path}")
    return 0


def cmd_scan(args: argparse.Namespace, config: Config) -> int:
    network, iface = _resolve_target(args, config)
    validate_scan_target(network)
    print(f"Scanning {network} on {iface or 'default interface'} ({_mode(args)})...")

    vendors = VendorDB.load(config.oui_path)
    with Store(config.db_path) as store:
        result = _scan_once(args, config, store, network, iface)
        new_macs = {a.mac for a in result.alerts}
        rows = []
        for obs in result.observations:
            device = store.device(obs.mac)
            status = "NEW" if obs.mac in new_macs else _trust_word(device.trusted)
            rows.append([obs.ip, obs.mac, _vendor(vendors, obs.mac), status, device.label or ""])

    print(f"Found {len(rows)} device(s).")
    if rows:
        print(_table(["IP", "MAC", "VENDOR", "STATUS", "LABEL"], rows))
    Dispatcher(config.log_path, config.alert_command).emit(result)
    if result.baseline:
        print(BASELINE_HINT)
    _vendor_hint(vendors)
    return 0


def cmd_monitor(args: argparse.Namespace, config: Config) -> int:
    network, iface = _resolve_target(args, config)
    validate_scan_target(network)
    interval = args.interval if args.interval is not None else config.monitor_interval
    if interval < MIN_INTERVAL:
        raise ValueError(f"--interval must be at least {MIN_INTERVAL} seconds")
    logging.basicConfig(format="netguard: %(levelname)s: %(message)s")

    dispatcher = Dispatcher(config.log_path, config.alert_command)
    print(
        f"Monitoring {network} on {iface or 'default interface'} every {interval:g}s "
        f"({_mode(args)}). Press Ctrl+C to stop."
    )
    if config.log_path:
        print(f"Events are logged to {config.log_path}")

    stop = threading.Event()
    stop_on_sigterm(stop)
    with Store(config.db_path) as store:

        def scan_once(number: int) -> None:
            result = _scan_once(args, config, store, network, iface)
            online = sum(d.present for d in store.devices())
            print(
                f"[{_when(datetime.now())}] scan #{number}: {len(result.observations)} seen, "
                f"{online} online, {len(result.alerts)} new alert(s)",
                flush=True,
            )
            dispatcher.emit(result)
            if result.baseline:
                print(BASELINE_HINT, flush=True)

        try:
            stats = run_monitor(scan_once, interval, max_scans=args.count, stop=stop)
        except KeyboardInterrupt:
            print("\nStopped.")
            return 0
    print(f"Stopped after {stats.scans} scan(s), {stats.failed} failed.")
    return 0


def cmd_devices(args: argparse.Namespace, config: Config) -> int:
    with Store(config.db_path) as store:
        devices = store.devices(untrusted_only=args.untrusted)
    if not devices:
        print("No devices yet. Run `netguard scan` first.")
        return 0
    vendors = VendorDB.load(config.oui_path)
    devices.sort(key=lambda d: ipaddress.ip_address(d.ip))
    rows = [
        [
            d.ip,
            d.mac,
            _vendor(vendors, d.mac),
            _trust_word(d.trusted),
            "online" if d.present else "away",
            d.label or "",
            _when(d.first_seen),
            _when(d.last_seen),
        ]
        for d in devices
    ]
    headers = ["IP", "MAC", "VENDOR", "STATUS", "PRESENCE", "LABEL", "FIRST SEEN", "LAST SEEN"]
    print(_table(headers, rows))
    _vendor_hint(vendors)
    return 0


def cmd_trust(args: argparse.Namespace, config: Config) -> int:
    return _set_trust(config, args.mac, True, args.label)


def cmd_untrust(args: argparse.Namespace, config: Config) -> int:
    return _set_trust(config, args.mac, False, None)


def cmd_label(args: argparse.Namespace, config: Config) -> int:
    if args.clear == bool(args.name):
        print("netguard: error: give a NAME or --clear (not both)", file=sys.stderr)
        return 1
    mac = normalize_mac(args.mac)
    with Store(config.db_path) as store:
        if not store.set_label(mac, None if args.clear else args.name):
            print(f"netguard: error: {mac} is not in the inventory", file=sys.stderr)
            return 1
    print(f"{mac} label cleared." if args.clear else f"{mac} is now labelled {args.name!r}.")
    return 0


def cmd_oui(args: argparse.Namespace, config: Config) -> int:
    if args.oui_command == "update":
        print(f"Downloading the vendor list from {args.url} ...")
        download(args.url, config.oui_path)
        print(f"Saved {len(VendorDB.load(config.oui_path))} vendor prefixes to {config.oui_path}.")
        return 0

    mac = normalize_mac(args.mac)
    vendors = VendorDB.load(config.oui_path)
    print(f"{mac}  {_vendor(vendors, mac, width=None) or 'unknown vendor'}")
    _vendor_hint(vendors)
    return 0


def cmd_alerts(args: argparse.Namespace, config: Config) -> int:
    with Store(config.db_path) as store:
        alerts = store.alerts(limit=args.limit)
    if not alerts:
        print("No alerts.")
        return 0
    rows = [[_when(a.created_at), a.severity.upper(), a.message] for a in alerts]
    print(_table(["TIME", "SEVERITY", "MESSAGE"], rows))
    return 0


def cmd_timeline(args: argparse.Namespace, config: Config) -> int:
    mac = normalize_mac(args.mac) if args.mac else None
    with Store(config.db_path) as store:
        # The middle value puts an alert above an event from the same moment.
        entries = [
            (e.created_at, 0, e.kind, e.message) for e in store.events(limit=args.limit, mac=mac)
        ] + [
            (a.created_at, 1, a.severity.upper(), a.message)
            for a in store.alerts(limit=args.limit, mac=mac)
        ]
    if not entries:
        print("Nothing on the timeline yet. Run `netguard scan` or `netguard monitor`.")
        return 0
    entries.sort(key=lambda entry: entry[:2], reverse=True)
    rows = [[_when(at), kind, message] for at, _, kind, message in entries[: args.limit]]
    print(_table(["TIME", "WHAT", "DETAILS"], rows))
    return 0


COMMANDS = {
    "info": cmd_info,
    "scan": cmd_scan,
    "monitor": cmd_monitor,
    "timeline": cmd_timeline,
    "devices": cmd_devices,
    "trust": cmd_trust,
    "untrust": cmd_untrust,
    "label": cmd_label,
    "oui": cmd_oui,
    "alerts": cmd_alerts,
}


# --- helpers -------------------------------------------------------------

BASELINE_HINT = (
    "\nFirst scan: these devices are now your baseline. Mark the ones you "
    "recognise with `netguard trust <mac> --label NAME`."
)


def _scan_once(
    args: argparse.Namespace,
    config: Config,
    store: Store,
    network: ipaddress.IPv4Network,
    iface: str | None,
) -> ScanResult:
    timeout = args.timeout if args.timeout is not None else config.scan_timeout
    observations = discover(network, iface=iface, passive=args.passive, timeout=timeout)
    return process_scan(
        store,
        observations,
        source="arp-table" if args.passive else "arp-scan",
        network=str(network),
        away_after=timedelta(seconds=config.away_after),
        dedup_window=timedelta(seconds=config.dedup_window),
    )


def _mode(args: argparse.Namespace) -> str:
    return "kernel ARP cache" if args.passive else "active ARP scan"


def _resolve_target(
    args: argparse.Namespace, config: Config
) -> tuple[ipaddress.IPv4Network, str | None]:
    iface = args.iface or config.iface
    cidr = args.network or config.network
    if cidr:
        network = ipaddress.ip_network(cidr, strict=False)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("only IPv4 networks are supported (ARP is IPv4-only)")
        return network, iface
    info = detect_netinfo(iface=iface)
    return info.network, info.iface


def _set_trust(config: Config, mac: str, trusted: bool, label: str | None) -> int:
    mac = normalize_mac(mac)
    with Store(config.db_path) as store:
        if not store.set_trusted(mac, trusted, label):
            print(f"netguard: error: {mac} is not in the inventory", file=sys.stderr)
            return 1
    print(f"{mac} marked as {_trust_word(trusted)}.")
    return 0


def _vendor(vendors: VendorDB, mac: str, width: int | None = VENDOR_WIDTH) -> str:
    vendor = vendors.lookup(mac)
    if vendor is None:
        return "(randomised MAC)" if is_randomized_mac(mac) else ""
    if width and len(vendor) > width:
        vendor = vendor[: width - 1] + "…"
    return vendor


def _vendor_hint(vendors: VendorDB) -> None:
    if not len(vendors):
        print("\nTip: run `netguard oui update` once to show device vendors.")


def _trust_word(trusted: bool) -> str:
    return "trusted" if trusted else "untrusted"


def _when(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M")


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max(len(str(cell)) for cell in column) for column in zip(headers, *rows)]
    lines = [headers, ["-" * w for w in widths], *rows]
    return "\n".join(
        "  ".join(str(cell).ljust(w) for cell, w in zip(line, widths)).rstrip() for line in lines
    )
