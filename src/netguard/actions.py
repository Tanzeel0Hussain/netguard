"""The things NetGuard does, shared by the command line and the dashboard."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Iterable, Sequence
from datetime import timedelta

from netguard.audit.report import AuditedHost, AuditResult
from netguard.audit.rules import assess
from netguard.audit.scanner import COMMON_PORTS, scan_hosts
from netguard.config import Config
from netguard.discovery import discover
from netguard.engine import ScanResult, process_scan
from netguard.models import Device, Event, Observation, normalize_mac, utcnow
from netguard.names import find_names
from netguard.netinfo import detect_netinfo, validate_scan_target
from netguard.oui import VendorDB
from netguard.storage import Store


def resolve_target(
    config: Config, iface: str | None = None, cidr: str | None = None
) -> tuple[ipaddress.IPv4Network, str | None]:
    """The network to scan: given, from the config, or detected."""
    iface = iface or config.iface
    cidr = cidr or config.network
    if cidr:
        network = ipaddress.ip_network(cidr, strict=False)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("only IPv4 networks are supported (ARP is IPv4-only)")
    else:
        info = detect_netinfo(iface=iface)
        network, iface = info.network, info.iface
    validate_scan_target(network)
    return network, iface


def scan(
    config: Config,
    store: Store,
    network: ipaddress.IPv4Network,
    iface: str | None,
    passive: bool,
    timeout: float | None = None,
    names: bool = True,
) -> ScanResult:
    """Discover devices, run the detectors, save everything, then look up new names."""
    observations = discover(
        network, iface=iface, passive=passive, timeout=timeout or config.scan_timeout
    )
    result = process_scan(
        store,
        observations,
        source="arp-table" if passive else "arp-scan",
        network=str(network),
        away_after=timedelta(seconds=config.away_after),
        dedup_window=timedelta(seconds=config.dedup_window),
    )
    if names:
        look_up_names(store, observations)
    return result


def look_up_names(store: Store, observations: Iterable[Observation]) -> None:
    """Find names for devices that do not have one yet."""
    # process_scan() has just saved every observed device, so store.device() finds it.
    unnamed = {o.ip: o.mac for o in observations if not store.device(o.mac).hostname}
    found = find_names(unnamed)
    store.set_hostnames({unnamed[ip]: (n.name, n.source) for ip, n in found.items() if ip in unnamed})


def audit_targets(store: Store, targets: Sequence[str] | None) -> list[Device]:
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


def audit(
    config: Config,
    store: Store,
    devices: Sequence[Device],
    ports: Sequence[int] = COMMON_PORTS,
    timeout: float = 1.0,
    concurrency: int = 100,
) -> AuditResult:
    """Scan the devices, judge what is open, save the audit and note it on the timeline."""
    vendors = VendorDB.load(config.oui_path)
    hosts = [
        AuditedHost(d.ip, d.mac, d.label or d.hostname or vendors.lookup(d.mac) or "")
        for d in devices
    ]
    try:
        gateway = detect_netinfo(iface=config.iface).gateway
    except (OSError, RuntimeError):
        gateway = None

    started = utcnow()
    open_ports = asyncio.run(
        scan_hosts([h.ip for h in hosts], ports, timeout=timeout, concurrency=concurrency)
    )
    result = AuditResult(
        started_at=started,
        hosts=hosts,
        ports_checked=len(ports),
        open_ports=open_ports,
        findings=assess(open_ports, gateway_ip=str(gateway) if gateway else None),
    )
    store.save_audit(result)
    store.add_events([Event("audit", f"Audited {len(hosts)} device(s): {summary(result)}", started)])
    return result


def summary(result: AuditResult) -> str:
    counts = result.counts()
    text = ", ".join(f"{counts[s]} {s}" for s in ("high", "medium", "low") if counts[s])
    return text or "no findings"
