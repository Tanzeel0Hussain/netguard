# Changelog

## 0.1.0

First release.

- **Discovery:** active ARP scan and passive ARP cache, SQLite inventory with
  trust flags and labels, alert when an unknown device joins.
- **Identity:** MAC vendor lookup (resumable download), randomised-MAC
  detection.
- **Monitoring:** `netguard monitor`, presence timeline (joined, left,
  returned), alert de-duplication, JSON-lines log, notification hook.
- **ARP spoofing / MITM detection:** `netguard watch`, gateway MAC per Wi-Fi
  access point, unsolicited reply floods, one MAC claiming many IPs; pcap
  replay.
- **Port-scan detection:** vertical scans and horizontal sweeps from TCP SYNs.
- **Device audit:** TCP connect scan of inventory devices, banners, risk rules
  with advice, Markdown and HTML reports.
- **GUI:** `netguard gui` opens the dashboard in the browser: scan, run an
  audit, trust and name devices; CSRF and DNS-rebinding protection, JSON API.
- **Device names** from reverse DNS, mDNS and NetBIOS.
- **Operations:** systemd services, `netguard demo`, usage guide, releases
  built and published from tags.
