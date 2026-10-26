"""The `netguard` command line."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import sys
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from netguard import __version__
from netguard.alerting import Dispatcher
from netguard.audit.report import AuditedHost, AuditResult, to_html, to_markdown
from netguard.audit.rules import assess, service_name
from netguard.audit.scanner import COMMON_PORTS, scan_hosts
from netguard.config import Config, load_config
from netguard.detectors.arp_spoof import ArpFindings, ArpWatch, ArpWatchSettings
from netguard.detectors.portscan import PortScanSettings, PortScanWatch, TcpSyn
from netguard.discovery import ScanPermissionError, discover
from netguard.discovery.arp_table import read_arp_table
from netguard.engine import ScanResult, process_scan, record_findings
from netguard.models import Event, is_randomized_mac, normalize_mac, utcnow
from netguard.netinfo import (
    UnsafeTargetError,
    current_bssid,
    detect_netinfo,
    own_macs,
    validate_scan_target,
)
from netguard.oui import MANUF_URL, VendorDB, download
from netguard.monitor import run_monitor, stop_on_sigterm
from netguard.sensor.sniffer import capture, open_capture, read_pcap
from netguard.storage import Store

VENDOR_WIDTH = 28
MAX_AUDIT_PORTS = 1024  # per device; a full 65535-port sweep is not what a home audit needs
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

    watch = sub.add_parser(
        "watch", help="watch for ARP spoofing and port scans (Ctrl+C stops)"
    )
    watch.add_argument("--iface", help="network interface, e.g. wlan0")
    watch.add_argument(
        "--pcap", type=Path, help="analyse a capture file instead (no root; nothing is saved)"
    )
    watch.add_argument("--gateway", help="gateway IP (default: detected)")
    watch.add_argument("--duration", type=float, help="stop after this many seconds")

    gateway = sub.add_parser("gateway", help="gateway MACs accepted per Wi-Fi access point")
    gateway_sub = gateway.add_subparsers(dest="gateway_command", required=True, metavar="ACTION")
    gateway_sub.add_parser("list", help="show accepted gateway MACs")
    allow = gateway_sub.add_parser("allow", help="accept a MAC as the gateway on the current network")
    allow.add_argument("mac")

    audit = sub.add_parser("audit", help="check your devices for open ports and risky services")
    audit.add_argument(
        "--target", action="append", metavar="IP_OR_MAC",
        help="device to audit (repeatable; default: every device that is online)",
    )
    audit.add_argument("--ports", default="common", help='"common" (default), "1-1024" or "22,80,443"')
    audit.add_argument("--report", type=Path, help="write a report: .md or .html")
    audit.add_argument("--timeout", type=float, default=1.0, help="seconds per connection")
    audit.add_argument("--concurrency", type=int, default=100, help="connections open at once")

    web = sub.add_parser("web", help="open the read-only dashboard in your browser")
    web.add_argument("--host", default="127.0.0.1", help="loopback address to listen on")
    web.add_argument("--port", type=int, default=8080)

    demo = sub.add_parser("demo", help="create made-up data and attack captures to try NetGuard")
    demo.add_argument("folder", nargs="?", type=Path, default=Path("netguard-demo"))

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


def cmd_watch(args: argparse.Namespace, config: Config) -> int:
    arp_settings = ArpWatchSettings(
        window=timedelta(seconds=config.arp_window),
        many_ips=config.arp_many_ips,
        flood_replies=config.arp_flood_replies,
    )
    scan_settings = PortScanSettings(
        window=timedelta(seconds=config.portscan_window),
        ports=config.portscan_ports,
        hosts=config.portscan_hosts,
    )
    if args.pcap:
        return _watch_pcap(args, config, arp_settings, scan_settings)

    info = detect_netinfo(iface=args.iface or config.iface)
    sock = open_capture(info.iface)  # first, so a missing permission changes nothing
    gateway = args.gateway or (str(info.gateway) if info.gateway else None)
    bssid = current_bssid(info.iface) or "wired"
    mine = own_macs()
    logging.basicConfig(format="netguard: %(levelname)s: %(message)s")
    dispatcher = Dispatcher(config.log_path, config.alert_command)
    dedup = timedelta(seconds=config.dedup_window)
    counts = _WatchCounts()

    with Store(config.db_path) as store:
        arp_watch = ArpWatch(
            bindings={d.ip: d.mac for d in store.devices() if d.present},
            gateway_ip=gateway,
            gateway_macs=store.gateway_macs(bssid, gateway) if gateway else (),
            own_macs=mine,
            settings=arp_settings,
        )
        scan_watch = PortScanWatch(own_macs=mine, allow_ips=config.portscan_allow, settings=scan_settings)

        def handle(findings: ArpFindings) -> None:
            for event in findings.events:
                if event.kind == "gateway_learned":
                    store.add_gateway_mac(bssid, event.ip, event.mac, event.created_at)
            kept = record_findings(store, findings.alerts, findings.events, utcnow(), dedup)
            counts.alerts += len(kept)
            dispatcher.emit_all(kept, findings.events)

        print(
            f"Watching ARP and TCP SYNs on {info.iface} (gateway {gateway or 'unknown'}, "
            f"access point {bssid}). Press Ctrl+C to stop."
        )
        # Check what this machine already believes: a poisoned cache shows up here first.
        for obs in read_arp_table(info.iface):
            if obs.ip == gateway:
                handle(arp_watch.check_binding(obs.ip, obs.mac, obs.seen_at, source="the kernel ARP cache"))

        stop = threading.Event()
        stop_on_sigterm(stop)
        if args.duration:
            timer = threading.Timer(args.duration, stop.set)
            timer.daemon = True
            timer.start()
        try:
            capture(sock, lambda pkt: handle(_feed(pkt, arp_watch, scan_watch, counts)), stop)
        except KeyboardInterrupt:
            print()
    print(f"Stopped. {counts.summary()}.")
    return 0


def _watch_pcap(
    args: argparse.Namespace,
    config: Config,
    arp_settings: ArpWatchSettings,
    scan_settings: PortScanSettings,
) -> int:
    """Offline analysis: report what the capture shows, without touching the database."""
    if not args.pcap.exists():
        raise ValueError(f"{args.pcap} does not exist")
    arp_watch = ArpWatch(gateway_ip=args.gateway, settings=arp_settings)
    scan_watch = PortScanWatch(allow_ips=config.portscan_allow, settings=scan_settings)
    dispatcher = Dispatcher()
    counts = _WatchCounts()
    print(f"Analysing {args.pcap} (gateway {args.gateway or 'not set: use --gateway'})...")
    for pkt in read_pcap(args.pcap):
        findings = _feed(pkt, arp_watch, scan_watch, counts)
        counts.alerts += len(findings.alerts)
        dispatcher.emit_all(findings.alerts, findings.events)
    print(f"Done. {counts.summary()}.")
    return 0


@dataclass
class _WatchCounts:
    arp: int = 0
    syn: int = 0
    alerts: int = 0

    def summary(self) -> str:
        return f"{self.arp} ARP packet(s), {self.syn} TCP SYN(s), {self.alerts} alert(s)"


def _feed(pkt, arp_watch: ArpWatch, scan_watch: PortScanWatch, counts: _WatchCounts) -> ArpFindings:
    """Send a captured packet to the detector that understands it."""
    if isinstance(pkt, TcpSyn):
        counts.syn += 1
        return ArpFindings(alerts=scan_watch.feed(pkt))
    counts.arp += 1
    return arp_watch.feed(pkt)


def cmd_gateway(args: argparse.Namespace, config: Config) -> int:
    with Store(config.db_path) as store:
        if args.gateway_command == "list":
            rows = [[b, ip, mac, _when(at)] for b, ip, mac, at in store.all_gateway_macs()]
            if not rows:
                print("No gateway learned yet. Run `netguard watch`.")
                return 0
            print(_table(["ACCESS POINT", "GATEWAY", "MAC", "FIRST SEEN"], rows))
            return 0

        mac = normalize_mac(args.mac)
        info = detect_netinfo(iface=config.iface)
        if not info.gateway:
            raise RuntimeError("no gateway on the current network")
        bssid = current_bssid(info.iface) or "wired"
        store.add_gateway_mac(bssid, str(info.gateway), mac, utcnow())
    print(f"{mac} accepted as gateway {info.gateway} on access point {bssid}.")
    return 0


def cmd_audit(args: argparse.Namespace, config: Config) -> int:
    ports = parse_ports(args.ports)
    if not 1 <= args.concurrency <= 500:
        raise ValueError("--concurrency must be between 1 and 500")
    if args.report and args.report.suffix.lower() not in (".md", ".html"):
        raise ValueError("--report must end in .md or .html")

    vendors = VendorDB.load(config.oui_path)
    with Store(config.db_path) as store:
        devices = _audit_targets(store, args.target)
        hosts = [
            AuditedHost(d.ip, d.mac, d.label or vendors.lookup(d.mac) or "") for d in devices
        ]
        try:
            gateway = detect_netinfo(iface=config.iface).gateway
        except (OSError, RuntimeError):
            gateway = None

        print(f"Auditing {len(hosts)} device(s), {len(ports)} port(s) each...", flush=True)
        started = utcnow()
        open_ports = asyncio.run(
            scan_hosts([h.ip for h in hosts], ports, timeout=args.timeout, concurrency=args.concurrency)
        )
        result = AuditResult(
            started_at=started,
            hosts=hosts,
            ports_checked=len(ports),
            open_ports=open_ports,
            findings=assess(open_ports, gateway_ip=str(gateway) if gateway else None),
        )
        store.save_audit(result)
        counts = result.counts()
        summary = ", ".join(f"{counts[s]} {s}" for s in ("high", "medium", "low") if counts[s])
        store.add_events(
            [Event("audit", f"Audited {len(hosts)} device(s): {summary or 'no findings'}", started)]
        )

    if open_ports:
        rows = [
            [p.ip, str(p.port), service_name(p.port) + (" (TLS)" if p.tls else ""), p.banner[:60]]
            for p in sorted(open_ports, key=lambda p: (ipaddress.ip_address(p.ip), p.port))
        ]
        print(_table(["IP", "PORT", "SERVICE", "BANNER"], rows))
    else:
        print("No open ports found.")
    for f in result.findings:
        print(f"[{f.severity.upper()}] {f.ip}:{f.port or ''} {f.title}")
    print(f"\n{len(open_ports)} open port(s), {summary or 'no findings'}.")

    if args.report:
        text = to_html(result) if args.report.suffix.lower() == ".html" else to_markdown(result)
        args.report.write_text(text, encoding="utf-8")
        print(f"Report written to {args.report}")
    return 0


def parse_ports(spec: str) -> list[int]:
    """'common', '1-1024', '22,80,443' or a mix like '22,8000-8100'."""
    if spec == "common":
        return list(COMMON_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        low, sep, high = part.partition("-")
        try:
            start, end = int(low), int(high) if sep else int(low)
        except ValueError:
            raise ValueError(f"bad port list {spec!r}; use e.g. 22,80,443 or 1-1024") from None
        if not 1 <= start <= end <= 65535:
            raise ValueError(f"bad port range {part!r}; ports go from 1 to 65535")
        ports.update(range(start, end + 1))
    if len(ports) > MAX_AUDIT_PORTS:
        raise ValueError(f"{len(ports)} ports is too many; the limit is {MAX_AUDIT_PORTS} per device")
    return sorted(ports)


def _audit_targets(store: Store, targets: list[str] | None) -> list:
    """Devices to audit. Only devices in the inventory: this is for your own network."""
    devices = store.devices()
    if not targets:
        chosen = [d for d in devices if d.present]
        if not chosen:
            raise RuntimeError("no online devices in the inventory; run `netguard scan` first")
        return sorted(chosen, key=lambda d: ipaddress.ip_address(d.ip))

    by_ip = {d.ip: d for d in devices}
    by_mac = {d.mac: d for d in devices}
    chosen = []
    for target in targets:
        try:
            device = by_mac.get(normalize_mac(target))
        except ValueError:
            device = by_ip.get(target)
        if device is None:
            raise ValueError(
                f"{target} is not in the inventory. NetGuard only audits devices it has "
                "discovered on your network; run `netguard scan` first."
            )
        validate_scan_target(ipaddress.ip_network(device.ip))
        chosen.append(device)
    return chosen


def cmd_web(args: argparse.Namespace, config: Config) -> int:
    try:
        from netguard.web import create_app, is_loopback
    except ImportError:
        raise RuntimeError('the dashboard needs Flask: pip install -e ".[web]"') from None
    if not is_loopback(args.host):
        # The dashboard has no login: anyone who can reach it sees your network.
        raise ValueError(f"{args.host} is not a loopback address; the dashboard only runs on 127.0.0.1")

    app = create_app(config.db_path, config.oui_path)
    host = f"[{args.host}]" if ":" in args.host else args.host
    print(f"NetGuard dashboard on http://{host}:{args.port}/ (Ctrl+C to stop)")
    from werkzeug.serving import run_simple

    run_simple(args.host, args.port, app, threaded=True)
    return 0


def cmd_demo(args: argparse.Namespace, config: Config) -> int:
    from netguard.demo import GATEWAY_IP, build_demo

    paths = build_demo(args.folder)
    print(f"Demo data written to {args.folder}/. Try:\n")
    print(f"  netguard --db {paths['db']} web")
    print(f"  netguard --db {paths['db']} timeline")
    print(f"  netguard watch --pcap {paths['arp_pcap']} --gateway {GATEWAY_IP}")
    print(f"  netguard watch --pcap {paths['scan_pcap']}")
    return 0


def cmd_timeline(args: argparse.Namespace, config: Config) -> int:
    mac = normalize_mac(args.mac) if args.mac else None
    with Store(config.db_path) as store:
        entries = store.timeline(limit=args.limit, mac=mac)
    if not entries:
        print("Nothing on the timeline yet. Run `netguard scan` or `netguard monitor`.")
        return 0
    rows = [[_when(e.at), e.what.upper() if e.is_alert else e.what, e.message] for e in entries]
    print(_table(["TIME", "WHAT", "DETAILS"], rows))
    return 0


COMMANDS = {
    "info": cmd_info,
    "scan": cmd_scan,
    "monitor": cmd_monitor,
    "watch": cmd_watch,
    "gateway": cmd_gateway,
    "audit": cmd_audit,
    "web": cmd_web,
    "demo": cmd_demo,
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
