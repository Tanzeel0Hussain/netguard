"""Name the service behind each open port and judge how risky it is.

These are rules of thumb for a home network, not a vulnerability scanner:
they say "this is worth a look", and why, so the owner can decide.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass

from netguard.audit.scanner import OpenPort

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    554: "RTSP", 631: "IPP (printing)", 1883: "MQTT", 2323: "Telnet (alt)",
    3306: "MySQL", 3389: "RDP", 5000: "HTTP (UPnP / alt)", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 7547: "TR-069 (CWMP)", 8000: "HTTP (alt)",
    8080: "HTTP (alt)", 8443: "HTTPS (alt)", 8888: "HTTP (alt)",
    9100: "Raw printing (JetDirect)", 9200: "Elasticsearch", 27017: "MongoDB",
    49152: "UPnP",
}

# port -> (severity, title, why it matters / what to do)
RISKS = {
    23: ("high", "Telnet is open",
         "Telnet sends passwords in clear text and is a favourite target of IoT botnets. "
         "Turn it off and use SSH instead."),
    2323: ("high", "Telnet on port 2323 is open",
           "A second Telnet port often found on cheap IoT devices; Mirai-style botnets scan it. "
           "Turn it off or update the firmware."),
    5900: ("high", "VNC remote desktop is open",
           "VNC is often set up with a weak or no password, and the screen is sent unencrypted. "
           "Disable it or tunnel it through SSH."),
    6379: ("high", "Redis database is reachable",
           "Redis has no password by default and can be abused to run commands. "
           "Bind it to 127.0.0.1 or set a password."),
    27017: ("high", "MongoDB database is reachable",
            "Older MongoDB setups accept connections without a password. Bind it to 127.0.0.1."),
    9200: ("high", "Elasticsearch is reachable",
           "Elasticsearch without authentication exposes all its data. Bind it to 127.0.0.1."),
    21: ("medium", "FTP is open",
         "FTP sends passwords and files in clear text. Prefer SFTP."),
    445: ("medium", "SMB file sharing is open",
          "Make sure sharing is intended, SMBv1 is disabled and guest access is off."),
    139: ("medium", "NetBIOS (old SMB) is open",
          "Legacy Windows file sharing. Disable it if nothing needs it."),
    3389: ("medium", "RDP remote desktop is open",
           "Keep it patched, require Network Level Authentication and a strong password."),
    554: ("medium", "RTSP video stream (camera) is open",
          "Camera streams often have default passwords. Check that a strong one is set."),
    7547: ("medium", "TR-069 remote management is open",
           "Used by ISPs to manage routers; it has had serious bugs. It should not be open to the LAN "
           "on most setups. Ask your ISP or check the router settings."),
    3306: ("medium", "MySQL database is reachable",
           "Databases rarely need to be reachable from other devices. Bind it to 127.0.0.1."),
    5432: ("medium", "PostgreSQL database is reachable",
           "Databases rarely need to be reachable from other devices. Bind it to 127.0.0.1."),
    1883: ("medium", "MQTT broker without TLS is open",
           "Smart-home messages travel in clear text and brokers often allow anonymous clients."),
    49152: ("low", "UPnP device description is open",
            "UPnP lets devices open ports on the router by themselves. Turn it off on the router if "
            "nothing needs it."),
    5000: ("low", "UPnP / alternative web service is open",
           "Often UPnP or a device's web interface. Check what it is."),
    9100: ("low", "Raw printing port is open",
           "Anyone on the network can print. Usually fine at home."),
    25: ("low", "SMTP mail server is open",
         "An unexpected mail server on a home device is worth a look."),
}

_OPENSSH = re.compile(r"OpenSSH_(\d+)\.(\d+)")
OPENSSH_OLD_BEFORE = (8, 0)


@dataclass(frozen=True)
class Finding:
    ip: str
    port: int | None
    severity: str  # "high", "medium", "low" or "info"
    title: str
    detail: str


def service_name(port: int) -> str:
    return SERVICES.get(port, "unknown")


def assess(open_ports: Iterable[OpenPort], gateway_ip: str | None = None) -> list[Finding]:
    """Findings for a set of open ports, most severe first."""
    open_ports = list(open_ports)
    findings: list[Finding] = []
    by_host: dict[str, set[int]] = {}
    for p in open_ports:
        by_host.setdefault(p.ip, set()).add(p.port)
        if p.port in RISKS:
            severity, title, detail = RISKS[p.port]
            findings.append(Finding(p.ip, p.port, severity, title, detail))

        version = _OPENSSH.search(p.banner)
        if version and (int(version[1]), int(version[2])) < OPENSSH_OLD_BEFORE:
            findings.append(
                Finding(
                    p.ip, p.port, "low", f"Old OpenSSH {version[1]}.{version[2]}",
                    "OpenSSH older than 8.0 misses years of security fixes. Update the device.",
                )
            )

    for ip, ports in by_host.items():
        plain_web = ports & {80, 8080}
        if ip == gateway_ip and plain_web and not ports & {443, 8443}:
            findings.append(
                Finding(
                    ip, min(plain_web), "medium", "Router admin page only over plain HTTP",
                    "The router password is sent unencrypted to the admin page. Use a strong, "
                    "unique password and enable HTTPS if the router offers it.",
                )
            )

    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER[f.severity], ipaddress.ip_address(f.ip), f.port or 0),
    )
