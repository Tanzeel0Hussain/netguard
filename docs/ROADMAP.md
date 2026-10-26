# Roadmap

Each milestone is one small, reviewable pull request with its own tests.

## M1: Skeleton and device discovery ✅

- Project layout, packaging, config file, CI.
- Active ARP scan (Scapy) and passive ARP cache discovery.
- SQLite inventory: first/last seen, trust flag, labels.
- `new_device` alert after the baseline scan.
- CLI: `info`, `scan`, `devices`, `trust`, `untrust`, `alerts`.
- Scope checks: private networks only, at most a /20.

## M2: Device identity ✅

- MAC vendor lookup from the IEEE OUI list (optional download with resume;
  works offline without it): `netguard oui update`, `netguard oui lookup`.
- Flag randomised (locally administered) MACs, which phones use for privacy.
- `netguard label` and a vendor column in `scan` and `devices`.

## M3: Monitor and alert engine ✅

- `netguard monitor`: scan every N minutes; Ctrl+C or SIGTERM stops it, and a
  single failed scan does not.
- Presence timeline: `first_seen`, `left` and `returned` events, with an
  `away_after` grace period; `netguard timeline`.
- Only active scans can mark a device as gone (found in real testing: the
  passive ARP cache misses idle devices).
- Alert de-duplication window; every alert and event in a JSON-lines log.
- Optional command hook per alert (`notify-send`), run as the real user under sudo.
- Versioned SQLite migrations (schema v2), upgrading existing databases in place.

## M4: ARP spoofing / MITM detection ✅

- `netguard watch`: live ARP capture with a kernel BPF filter; `--pcap` replays
  a capture file offline.
- Alerts: gateway MAC changed (critical), IP moved to another MAC, one MAC
  claiming many IPs, flood of unsolicited ARP replies; each raised once per run.
- Gateway MACs accepted per Wi-Fi access point (BSSID), so roaming between two
  routers on one subnet is not an alert (the false positive found in M1
  testing). `netguard gateway list|allow`.
- Start-up check of the kernel ARP cache for an already poisoned gateway entry.
- Schema v3: `gateway_macs` table.
- Tests replay generated pcaps, including an arpspoof-style attack.

## M5: Port-scan detection

- Sniffer filter for TCP SYN to local hosts.
- Sliding-window counter per source: more than *Y* distinct ports (or hosts)
  within *X* seconds raises `port_scan`; thresholds in config.
- Allow-list so NetGuard's own audit (M6) does not alert.

## M6: Device audit report

- TCP connect scan of common ports on inventory devices only.
- Banner grab and service guess; flag risky services (Telnet, FTP, SMB, RDP,
  UPnP, exposed admin panels).
- Markdown and HTML report: `netguard audit --report report.html`.

## M7: Web dashboard

- Flask app bound to 127.0.0.1: devices, alerts, timeline.
- Read-only, JSON API underneath (`/api/devices`, `/api/alerts`).

## M8: Polish and release

- systemd unit for running the monitor at boot.
- Screenshots, demo pcaps, docs; tag `v0.1.0`.
