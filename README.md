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
| MAC vendor lookup | 🔜 M2 |
| Continuous monitoring daemon | 🔜 M3 |
| ARP spoofing / MITM detection | 🔜 M4 |
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
.venv/bin/netguard devices --untrusted
.venv/bin/netguard alerts
```

Example:

```
$ sudo .venv/bin/netguard scan
Scanning 192.168.100.0/24 on wlp0s20f3 (active ARP scan)...
Found 3 device(s).
IP              MAC                STATUS     LABEL
--------------  -----------------  ---------  --------
192.168.100.1   04:88:5f:12:34:56  trusted    Router
192.168.100.11  52:54:00:a1:b2:c3  trusted    My phone
192.168.100.66  de:ad:be:ef:00:01  NEW
[!] Unknown device joined: de:ad:be:ef:00:01 at 192.168.100.66
```

The first scan is a **baseline**: everything it finds is recorded without
alerts. From then on, any MAC address that is not in the inventory raises a
`new_device` alert.

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
  discovery/      arp_scan.py (active), arp_table.py (passive)
  detectors/      new_device.py (more coming)
tests/            pytest suite, no root or network needed
```

## Development

```bash
.venv/bin/pytest
```

## License

MIT © Tanzeel Hussain
