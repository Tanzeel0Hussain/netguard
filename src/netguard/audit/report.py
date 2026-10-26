"""Render an audit as Markdown or as a standalone HTML page."""

from __future__ import annotations

import html
import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from netguard import __version__
from netguard.audit.rules import SEVERITY_ORDER, Finding, service_name
from netguard.audit.scanner import OpenPort


@dataclass(frozen=True)
class AuditedHost:
    ip: str
    mac: str
    name: str = ""  # label or vendor, if known


@dataclass
class AuditResult:
    started_at: datetime
    hosts: list[AuditedHost]
    ports_checked: int
    open_ports: list[OpenPort] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def counts(self) -> Counter:
        return Counter(f.severity for f in self.findings)


def _ip_key(ip: str):
    return ipaddress.ip_address(ip)


def _summary_line(result: AuditResult) -> str:
    counts = result.counts()
    parts = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s]]
    return ", ".join(parts) if parts else "no findings"


def to_markdown(result: AuditResult) -> str:
    lines = [
        "# NetGuard device audit",
        "",
        f"- **Date:** {result.started_at.astimezone().strftime('%Y-%m-%d %H:%M')}",
        f"- **Devices:** {len(result.hosts)}, **ports checked per device:** {result.ports_checked}",
        f"- **Open ports:** {len(result.open_ports)}",
        f"- **Findings:** {_summary_line(result)}",
        "",
        "## Findings",
        "",
    ]
    if result.findings:
        lines += ["| Severity | Device | Port | Finding | Why / what to do |", "|---|---|---|---|---|"]
        for f in result.findings:
            lines.append(
                f"| {f.severity.upper()} | {f.ip} | {f.port or ''} | {_md(f.title)} | {_md(f.detail)} |"
            )
    else:
        lines.append("Nothing risky found on the ports that were checked.")

    lines += ["", "## Open ports per device", ""]
    by_ip = _ports_by_ip(result)
    for host in sorted(result.hosts, key=lambda h: _ip_key(h.ip)):
        title = f"{host.ip} ({host.mac}{', ' + host.name if host.name else ''})"
        lines += [f"### {_md(title)}", ""]
        ports = by_ip.get(host.ip, [])
        if not ports:
            lines += ["No open ports found.", ""]
            continue
        lines += ["| Port | Service | Banner |", "|---|---|---|"]
        for p in ports:
            lines.append(f"| {p.port} | {service_name(p.port)}{' (TLS)' if p.tls else ''} | {_md(p.banner)} |")
        lines.append("")

    lines += [_footnote(), ""]
    return "\n".join(lines)


def to_html(result: AuditResult) -> str:
    e = html.escape
    rows = "".join(
        f'<tr class="{e(f.severity)}"><td>{e(f.severity.upper())}</td><td>{e(f.ip)}</td>'
        f"<td>{f.port or ''}</td><td>{e(f.title)}</td><td>{e(f.detail)}</td></tr>"
        for f in result.findings
    ) or '<tr><td colspan="5">Nothing risky found on the ports that were checked.</td></tr>'

    by_ip = _ports_by_ip(result)
    hosts = []
    for host in sorted(result.hosts, key=lambda h: _ip_key(h.ip)):
        ports = by_ip.get(host.ip, [])
        body = "".join(
            f"<tr><td>{p.port}</td><td>{e(service_name(p.port))}{' (TLS)' if p.tls else ''}</td>"
            f"<td><code>{e(p.banner)}</code></td></tr>"
            for p in ports
        ) or '<tr><td colspan="3">No open ports found.</td></tr>'
        name = f", {e(host.name)}" if host.name else ""
        hosts.append(
            f"<h3>{e(host.ip)} <small>({e(host.mac)}{name})</small></h3>"
            f"<table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>{body}</table>"
        )

    date = result.started_at.astimezone().strftime("%Y-%m-%d %H:%M")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetGuard device audit</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 960px; padding: 0 1rem;
         color: #1f2328; background: #fff; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }}
  th, td {{ border: 1px solid #d0d7de; padding: .4rem .6rem; text-align: left; vertical-align: top; }}
  th {{ background: #f6f8fa; }}
  tr.high td:first-child {{ color: #fff; background: #cf222e; font-weight: 600; }}
  tr.medium td:first-child {{ background: #fff1c2; font-weight: 600; }}
  tr.low td:first-child {{ background: #ddf4ff; }}
  code {{ font-size: .85em; word-break: break-all; }}
  small {{ color: #59636e; font-weight: normal; }}
</style>
</head>
<body>
<h1>NetGuard device audit</h1>
<p>{e(date)} &middot; {len(result.hosts)} device(s) &middot; {result.ports_checked} ports checked per device
&middot; {len(result.open_ports)} open port(s) &middot; <strong>{e(_summary_line(result))}</strong></p>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Device</th><th>Port</th><th>Finding</th><th>Why / what to do</th></tr>{rows}</table>
<h2>Open ports per device</h2>
{''.join(hosts)}
<p><small>{e(_footnote())}</small></p>
</body>
</html>
"""


def _ports_by_ip(result: AuditResult) -> dict[str, list[OpenPort]]:
    by_ip: dict[str, list[OpenPort]] = {}
    for p in sorted(result.open_ports, key=lambda p: p.port):
        by_ip.setdefault(p.ip, []).append(p)
    return by_ip


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _footnote() -> str:
    return (
        f"Generated by NetGuard {__version__}. TCP connect scan of common ports only; "
        "UDP services (e.g. UPnP/SSDP on 1900) are not checked."
    )
