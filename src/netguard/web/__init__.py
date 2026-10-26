"""A small read-only dashboard: devices, alerts, timeline and the latest audit.

It has no login, so it only ever listens on the loopback interface. The Host
check below also blocks DNS rebinding, where a web page tricks the browser
into sending requests to 127.0.0.1 under the page's own domain name.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request
from flask.json.provider import DefaultJSONProvider

from netguard import __version__
from netguard.models import is_randomized_mac, utcnow
from netguard.oui import VendorDB
from netguard.storage import Store

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "[::1]"}
REFRESH_SECONDS = 30


def hostname(host_header: str) -> str:
    """'127.0.0.1:8080' -> '127.0.0.1', '[::1]:8080' -> '[::1]'."""
    if host_header.startswith("["):
        return host_header[: host_header.find("]") + 1]
    return host_header.split(":", 1)[0]


class IsoJSONProvider(DefaultJSONProvider):
    """Send times as ISO 8601 ('2026-10-26T17:19:05+00:00'), not HTTP dates."""

    @staticmethod
    def default(o):
        if isinstance(o, datetime):
            return o.isoformat()
        return DefaultJSONProvider.default(o)


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def create_app(db_path: Path, oui_path: Path) -> Flask:
    app = Flask(__name__)
    app.json = IsoJSONProvider(app)
    vendors = VendorDB.load(oui_path)

    def store() -> Store:
        return Store(db_path)

    def vendor(mac: str) -> str:
        found = vendors.lookup(mac)
        if found:
            return found
        return "(randomised MAC)" if is_randomized_mac(mac) else ""

    @app.before_request
    def only_local_host_header():
        if hostname(request.host) not in LOOPBACK_NAMES:
            abort(403)

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.context_processor
    def common():
        return {"version": __version__, "refresh": REFRESH_SECONDS, "page": request.endpoint}

    # --- pages ------------------------------------------------------------

    @app.get("/")
    def overview():
        with store() as s:
            devices = s.devices()
            alerts = s.alerts(limit=500)
            timeline = s.timeline(limit=10)
            audit = s.latest_audit()
        day_ago = utcnow() - timedelta(days=1)
        return render_template(
            "overview.html",
            online=sum(d.present for d in devices),
            total=len(devices),
            untrusted=sum(not d.trusted for d in devices),
            alerts_today=sum(a.created_at >= day_ago for a in alerts),
            critical_today=sum(a.created_at >= day_ago and a.severity == "critical" for a in alerts),
            timeline=timeline,
            audit=audit,
            audit_counts=audit.counts() if audit else Counter(),
        )

    @app.get("/devices")
    def devices():
        with store() as s:
            rows = sorted(s.devices(), key=lambda d: ipaddress.ip_address(d.ip))
        return render_template("devices.html", devices=rows, vendor=vendor)

    @app.get("/timeline")
    def timeline():
        with store() as s:
            entries = s.timeline(limit=200)
        return render_template("timeline.html", entries=entries)

    @app.get("/audit")
    def audit():
        with store() as s:
            result = s.latest_audit()
        return render_template("audit.html", audit=result)

    # --- JSON API ----------------------------------------------------------

    @app.get("/api/devices")
    def api_devices():
        with store() as s:
            return jsonify([{**asdict(d), "vendor": vendor(d.mac)} for d in s.devices()])

    @app.get("/api/alerts")
    def api_alerts():
        with store() as s:
            return jsonify([asdict(a) for a in s.alerts(limit=200)])

    @app.get("/api/timeline")
    def api_timeline():
        with store() as s:
            return jsonify([asdict(e) for e in s.timeline(limit=200)])

    @app.get("/api/audit")
    def api_audit():
        with store() as s:
            result = s.latest_audit()
        return jsonify(asdict(result) if result else None)

    return app
