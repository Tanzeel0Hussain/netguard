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

## M3: Monitor and alert engine

- `netguard monitor`: scan every N minutes, Ctrl+C to stop.
- Alert de-duplication and severities; alerts to a JSON-lines log file.
- "Device left / came back" events for the timeline.
- Optional desktop notification (`notify-send`) hook.

## M4: ARP spoofing / MITM detection

- Live sniffer (Scapy `AsyncSniffer`, filter `arp`) feeding detectors.
- Alerts: known IP answered by a new MAC, gateway MAC changed, one MAC
  claiming many IPs, burst of unsolicited (gratuitous) ARP replies.
- Avoid a known false positive found in real testing: roaming to another
  access point on the same subnet changes the gateway MAC. Remember the gateway
  MAC per Wi-Fi network (SSID/BSSID) instead of globally.
- Tests replay small pcap files in `tests/data/`.

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
