# NetGuard

**A home network security monitor written in Python and Scapy.**

NetGuard watches your own local network the way a small blue-team sensor would:
it keeps an inventory of every device, warns you when an unknown device joins,
and (in upcoming milestones) detects ARP spoofing / man-in-the-middle attempts
and port scans, audits your own devices for risky open services, and shows it
all on a local web dashboard.

> **Scope:** NetGuard is a defensive tool for networks you own or administer.
> It refuses to scan public IP ranges or networks larger than a /20.

## Status

| Feature | Status |
|---|---|
| Device discovery (active ARP scan + passive ARP cache) | ✅ v0.1 |
| Device inventory in SQLite, trust/label devices | ✅ v0.1 |
| Alert when an unknown device joins | ✅ v0.1 |
| MAC vendor lookup, randomised-MAC detection, device labels | ✅ M2 |
| Continuous monitoring, presence timeline, JSON-lines log, notify hook | ✅ M3 |
| ARP spoofing / MITM detection (live or from a pcap) | ✅ M4 |
| Port-scan detection | 🔜 M5 |
| Device audit report (open ports, risky services) | 🔜 M6 |
| Web dashboard | 🔜 M7 |

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full plan.

## Install

Requires Linux and Python 3.11+.

```bash
git clone https://github.com/Tanzeel0Hussain/netguard.git
cd netguard
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Usage

```bash
# What network will NetGuard watch?
.venv/bin/netguard info

# Passive discovery: read the kernel's ARP cache (no root needed)
.venv/bin/netguard scan --passive

# Active ARP scan of the whole subnet (needs root or CAP_NET_RAW)
sudo .venv/bin/netguard scan

# Inventory, trust your own devices, and review alerts
.venv/bin/netguard devices
.venv/bin/netguard trust 52:54:00:a1:b2:c3 --label "My phone"
.venv/bin/netguard label 8c:6d:77:ab:cd:01 "Router"
.venv/bin/netguard devices --untrusted
.venv/bin/netguard alerts

# Keep watching: scan every 5 minutes, report devices joining, leaving, returning
sudo .venv/bin/netguard monitor --interval 300
.venv/bin/netguard timeline

# Watch ARP traffic for spoofing / man-in-the-middle
sudo .venv/bin/netguard watch
.venv/bin/netguard watch --pcap capture.pcap --gateway 192.168.1.1   # offline, no root
.venv/bin/netguard gateway list

# Optional: download the MAC vendor list once (resumes if the connection drops)
.venv/bin/netguard oui update
.venv/bin/netguard oui lookup 8c:6d:77:ab:cd:01
```

Example:

```
$ sudo .venv/bin/netguard scan
Scanning 192.168.100.0/24 on wlp0s20f3 (active ARP scan)...
Found 3 device(s).
IP              MAC                VENDOR                        STATUS   LABEL
--------------  -----------------  ----------------------------  -------  --------
192.168.100.1   8c:6d:77:ab:cd:01  Huawei Technologies Co.,Ltd   trusted  Router
192.168.100.73  6e:11:22:33:44:73  (randomised MAC)              trusted  My phone
192.168.100.66  de:ad:be:ef:00:01                                NEW
[!] Unknown device joined: de:ad:be:ef:00:01 at 192.168.100.66
```

The first scan is a **baseline**: everything it finds is recorded without
alerts. From then on, any MAC address that is not in the inventory raises a
`new_device` alert.

### Monitoring

`netguard monitor` scans on an interval until you press Ctrl+C (or systemd
sends SIGTERM). One failed scan, for example while Wi-Fi reconnects, is logged
and the monitor carries on.

- A device counts as **left** only after it has not answered for
  `away_after` (15 minutes by default), so a phone that skips one ARP reply in
  power-saving mode does not flap. Only an active scan can say that a device
  left; the passive ARP cache can only show that one is there.
- Every alert and event is appended to `~/.local/share/netguard/events.jsonl`,
  one JSON object per line, ready for `jq` or a SIEM such as Splunk or ELK.
- The same alert for the same device is not repeated within `dedup_window`.
- Set `[alerts] command = ["notify-send", "NetGuard"]` to get a desktop
  notification per alert. Under sudo the command runs as you, not as root.

### ARP spoofing detection

ARP has no authentication: any host can answer "the gateway is at my MAC",
and victims then send their traffic through it (man-in-the-middle).
`netguard watch` captures ARP packets and raises:

| Alert | Severity | Meaning |
|---|---|---|
| `gateway_mac_changed` | critical | The gateway IP is claimed by a MAC not accepted for this access point |
| `ip_mac_changed` | warning | An IP that belonged to one device is claimed by another |
| `mac_claims_many_ips` | warning | One MAC answers for several IPs within a minute |
| `arp_reply_flood` | warning | One MAC keeps sending ARP replies nobody asked for (how `arpspoof` keeps a cache poisoned) |

At start-up it also checks the gateway entry already in the kernel's ARP cache,
so a cache that was poisoned before NetGuard started is caught too.

**Roaming without false alarms.** Homes with two routers or mesh access points
share one gateway IP across different MACs. The accepted gateway MACs are
stored per Wi-Fi access point (BSSID, read with `iw` or `nmcli`), so moving to
another floor is not an attack. The first MAC seen as the gateway on a new
access point is learned (trust on first use, like SSH's `known_hosts`); use
`netguard gateway allow <mac>` to accept another one.

**What one sensor can see.** On Wi-Fi and switched networks, ARP replies are
unicast. A laptop running NetGuard sees broadcasts, gratuitous ARP and the
replies sent to itself, so it reliably detects attacks against itself and
broadcast poisoning, but not an attack between two other devices. Run it on an
always-on machine, or use a mirror port, to watch more.

`--pcap` replays a capture (e.g. from `tcpdump -w`) through the same detector.
It needs no root and writes nothing, which makes it handy for forensics.

### Configuration

Everything is auto-detected, but you can pin settings in
`~/.config/netguard/netguard.toml` (see
[netguard.example.toml](netguard.example.toml)) or pass `--config`.
The database lives in `~/.local/share/netguard/netguard.db` by default (also
when run with `sudo`, and the file stays owned by you).

## How it works

```
 Sources                    Core                        Output
 ARP scan (Scapy) ─┐   ┌─ detectors (pure functions) ─┐
 /proc/net/arp ────┼──▶│                              ├──▶ CLI / alerts / dashboard
 sniffer (M4+) ────┘   └─ SQLite inventory & alerts ──┘
```

- **Active discovery** broadcasts one ARP "who-has" request per address in the
  subnet with Scapy and records every reply. ARP works below IP, so devices
  with a firewall that drops ping still answer.
- **Passive discovery** reads `/proc/net/arp`, the kernel's cache of hosts it
  has recently talked to. It sends no packets and needs no root.
- **Vendor lookup** matches the MAC against the IEEE OUI assignments
  (Wireshark's `manuf` list), longest prefix first, because the IEEE hands out
  24-, 28- and 36-bit blocks. MACs with the *locally administered* bit set are
  shown as randomised: phones make these up per Wi-Fi network for privacy, so
  they have no vendor.
- **Detectors** are pure functions (observations in, alerts out). They do no
  I/O, so they are tested with fake data and recorded packets, without root or
  a live network.
- **Safety checks** reject public or oversized targets before any packet is sent.

## Project layout

```
src/netguard/
  cli.py          command line (argparse)
  config.py       TOML config
  models.py       Observation, Device, Alert
  netinfo.py      interface/subnet detection and scope checks
  storage.py      SQLite inventory, scans and alerts
  engine.py       runs detectors on a scan and saves the results
  monitor.py      the scan loop behind `netguard monitor`
  alerting.py     console output, JSON-lines log and command hook
  sensor/         arp_sniffer.py: live ARP capture and pcap replay (Scapy)
  oui.py          MAC vendor lookup and resumable download
  discovery/      arp_scan.py (active), arp_table.py (passive)
  detectors/      new_device.py, presence.py, arp_spoof.py
tests/            pytest suite, no root or network needed
```

## Development

```bash
.venv/bin/pytest
```

## License

MIT © Tanzeel Hussain
