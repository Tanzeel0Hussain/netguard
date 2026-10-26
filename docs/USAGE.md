# Using NetGuard

A step-by-step guide: what NetGuard can do for you, and how to do each thing.
Use it only on networks you own or look after.

## What NetGuard can do

| You want to… | Command |
|---|---|
| See every device on your Wi-Fi or LAN | `netguard scan`, `netguard devices` |
| Know who made each device (Apple, Samsung, TP-Link…) | `netguard oui update` once, then `netguard devices` |
| Name your devices and mark the ones you know | `netguard trust`, `netguard label` |
| Be told when an unknown device joins | `netguard monitor` |
| See when devices left and came back | `netguard timeline` |
| Catch ARP spoofing / man-in-the-middle attacks | `netguard watch` |
| Catch someone port-scanning your machine | `netguard watch` |
| Check your router and devices for risky open services | `netguard audit --report audit.html` |
| Analyse a capture file from Wireshark or tcpdump | `netguard watch --pcap file.pcap` |
| See everything in the browser | `netguard web` |
| Feed alerts into another tool (jq, Splunk, ELK) | `~/.local/share/netguard/events.jsonl` |

## 1. Install

You need Linux and Python 3.11 or newer.

```bash
git clone https://github.com/Tanzeel0Hussain/netguard.git
cd netguard
python3 -m venv .venv
.venv/bin/pip install -e .
```

The commands below are written as `netguard …`. Either activate the virtual
environment first (`source .venv/bin/activate`) or type `.venv/bin/netguard`.

Some commands send or capture raw packets and need root. Those are marked
**(sudo)**. Run them as `sudo .venv/bin/netguard …`. Your data stays in your
own home folder and is owned by you, even with sudo.

## 2. The first ten minutes

**Check which network NetGuard will watch:**

```bash
netguard info
```

It prints the interface (e.g. `wlan0`), your subnet (e.g. `192.168.1.0/24`)
and the gateway (your router).

**Find the devices (sudo):**

```bash
sudo .venv/bin/netguard scan
```

This asks every address on your subnet "who are you?" (an ARP request). Every
device answers, even ones with a firewall that ignores ping. The first scan is
your **baseline**: everything found is saved, and nothing is reported as new.

No root? `netguard scan --passive` reads the list of devices your computer has
talked to recently. It finds fewer devices but sends nothing.

**Show vendor names (one-time download, about 3 MB):**

```bash
netguard oui update
```

If the connection drops, run it again and it continues where it stopped.

**Look at the list and mark what you recognise:**

```bash
netguard devices
netguard trust 8c:6d:77:12:34:56 --label "Router"
netguard label 6e:11:22:33:44:73 "My phone"
netguard devices --untrusted        # what is left: devices you have not checked yet
```

`(randomised MAC)` in the vendor column is normal for phones and laptops. They
make up a new MAC address for each Wi-Fi network for privacy.

## 3. Everyday tasks

### "Tell me when an unknown device joins my Wi-Fi" (sudo)

```bash
sudo .venv/bin/netguard monitor --interval 300
```

It scans every 5 minutes until you press Ctrl+C. You see lines like:

```
[2026-10-26 22:44] scan #12: 6 seen, 6 online, 1 new alert(s)
[!] Unknown device joined: de:ad:be:ef:00:01 at 192.168.1.66
[i] My phone (6e:11:22:33:44:73) left (last seen at 192.168.1.73)
```

For a desktop pop-up as well, add this to `~/.config/netguard/netguard.toml`:

```toml
[alerts]
command = ["notify-send", "NetGuard"]
```

### "What happened while I was away?"

```bash
netguard timeline                       # devices joining, leaving, returning, alerts, audits
netguard timeline --mac 6e:11:22:33:44:73
netguard alerts
```

### "Is someone attacking my connection?" (sudo)

```bash
sudo .venv/bin/netguard watch
```

This listens for two kinds of attack until you press Ctrl+C:

- **ARP spoofing / man-in-the-middle:** someone claims to be your router so
  your traffic goes through them.
- **Port scans:** someone checks which services your computer runs, as an
  attacker does before breaking in.

On a normal network it stays quiet and ends with something like
`Stopped. 6 ARP packet(s), 15 TCP SYN(s), 0 alert(s).`

If you have two routers or mesh access points, NetGuard remembers the router's
MAC for each access point, so moving between them is not an alert. To accept
another router MAC on the current access point:

```bash
netguard gateway list
netguard gateway allow 04:88:5f:12:34:56
```

### "How secure are my router and devices?"

```bash
netguard audit --report audit.html                 # every online device, 30 common ports
netguard audit --target 192.168.1.1 --report router.html
netguard audit --target 192.168.1.20 --ports 1-1024
```

Open the HTML file in a browser. Each finding says what is wrong and what to
do. Example from a real home router:

```
[MEDIUM] 192.168.1.1:80 Router admin page only over plain HTTP
```

This one means the router password travels unencrypted when you log in.

The audit only connects to devices already in your inventory. Only audit
devices that are yours or that you have permission to check.

### "I have a capture file from Wireshark or tcpdump"

```bash
netguard watch --pcap capture.pcap --gateway 192.168.1.1
```

This needs no root and saves nothing. It is useful to check a recording later.

### "Show me everything in the browser"

```bash
netguard web
```

Open <http://127.0.0.1:8080/>. The dashboard shows how many devices are
online, alerts from the last 24 hours, the device list, the timeline and the
latest audit. It refreshes itself every 30 seconds. It only works on this
computer: there is no login, so it never listens on the network.

### "I want the alerts in another tool"

Every alert and event is one JSON line in `~/.local/share/netguard/events.jsonl`:

```bash
jq 'select(.type == "alert")' ~/.local/share/netguard/events.jsonl
```

## 4. What each alert means and what to do

| Alert | Severity | What it means | What to do |
|---|---|---|---|
| `new_device` | warning | A MAC address never seen before joined | If you do not know it, change the Wi-Fi password and check the router's device list |
| `gateway_mac_changed` | critical | Something else is answering as your router | Possible man-in-the-middle. Disconnect, check `netguard gateway list`, and if it was not a new router, find the device with that MAC |
| `ip_mac_changed` | warning | An IP moved to a different device | Often harmless (DHCP gave the address to another device); suspicious if it keeps happening |
| `mac_claims_many_ips` | warning | One device answers for several addresses | Typical of ARP spoofing tools |
| `arp_reply_flood` | warning | One device keeps sending ARP answers nobody asked for | Typical of `arpspoof`-style tools |
| `port_scan` | warning | One device tried 15+ ports on one host within a minute | Find out who owns that device; scanning is often the first step of an attack |
| `host_sweep` | warning | One device tried the same port on 10+ hosts | Something is looking for a service (e.g. SSH) across the network |

Events such as `left`, `returned`, `first_seen`, `gateway_learned` and
`audit` are information for the timeline, not alarms.

## 5. Settings

Everything works without a config file. To change something, copy
[netguard.example.toml](../netguard.example.toml) to
`~/.config/netguard/netguard.toml`. It lists every setting: the scan interval,
how long before a device counts as "left", alert thresholds, the notification
command and scanners to allow.

## 6. Troubleshooting

| Problem | Fix |
|---|---|
| `needs root (or CAP_NET_RAW)` | Run that command with `sudo .venv/bin/netguard …`, or use `scan --passive` / `watch --pcap` |
| `scan --passive` finds only one or two devices | Normal: it only knows devices your computer talked to recently. Use the sudo scan |
| A phone shows up as "left" and "back" a lot | Phones sleep. Raise `away_after` in `[monitor]` |
| `is not in the inventory` when auditing | Run `netguard scan` first, so NetGuard knows the device |
| `gateway_mac_changed` every time you change rooms | You have more than one access point. Check with `netguard gateway list` and accept the router with `netguard gateway allow <mac>` |
| Vendor column is empty | Run `netguard oui update` once |

## Limits

- On Wi-Fi a laptop mainly sees traffic sent to itself. `watch` reliably
  detects attacks against the machine it runs on, not between two other
  devices.
- Very slow port scans (one probe every few seconds) stay under the alert
  threshold.
- Only IPv4 and TCP are covered. UDP services (e.g. UPnP on port 1900) are not
  audited.
