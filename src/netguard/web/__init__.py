"""The dashboard: devices, alerts, timeline and audits, with buttons to act on them.

It has no login, so it only ever listens on the loopback interface. Three
more guards keep other web pages from using it through your browser:

- the Host check blocks DNS rebinding, where a page makes its own domain name
  point to 127.0.0.1;
- every form carries a secret token (CSRF protection), and requests from
  another origin are refused;
- responses carry a strict Content-Security-Policy and may not be framed.
"""

from __future__ import annotations

import hmac
import ipaddress
import secrets
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, url_for
from flask.json.provider import DefaultJSONProvider

from netguard import __version__, actions
from netguard.config import Config
from netguard.discovery import ScanPermissionError
from netguard.models import is_randomized_mac, normalize_mac, utcnow
from netguard.oui import VendorDB
from netguard.storage import Store

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "[::1]"}
REFRESH_SECONDS = 30
MAX_LABEL = 64


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


def create_app(config: Config, read_only: bool = False) -> Flask:
    app = Flask(__name__)
    app.json = IsoJSONProvider(app)
    # A new secret every start: flash messages and the CSRF token only need to
    # live as long as this process.
    app.secret_key = secrets.token_bytes(32)
    app.config.update(SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_HTTPONLY=True)
    csrf_token = secrets.token_urlsafe(32)
    vendors = VendorDB.load(config.oui_path)

    def store() -> Store:
        return Store(config.db_path)

    def vendor(mac: str) -> str:
        found = vendors.lookup(mac)
        if found:
            return found
        return "(randomised MAC)" if is_randomized_mac(mac) else ""

    @app.before_request
    def guard():
        if hostname(request.host) not in LOOPBACK_NAMES:
            abort(403)
        if request.method == "POST":
            if read_only:
                abort(403)
            origin = request.headers.get("Origin")
            if origin and hostname(urlsplit(origin).netloc) not in LOOPBACK_NAMES:
                abort(403)
            if not hmac.compare_digest(request.form.get("csrf_token", ""), csrf_token):
                abort(403)

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Not "no-referrer": with that, browsers send "Origin: null" on our own
        # form posts, which the origin check above must refuse.
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    @app.context_processor
    def common():
        return {
            "version": __version__,
            "refresh": REFRESH_SECONDS,
            "page": request.endpoint,
            "csrf_token": csrf_token,
            "read_only": read_only,
        }

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
        # No auto-refresh here: it would wipe a name while you type it.
        return render_template("devices.html", devices=rows, vendor=vendor, refresh=None)

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

    # --- actions ------------------------------------------------------------

    def device_or_404(s: Store, mac: str):
        try:
            device = s.device(normalize_mac(mac))
        except ValueError:
            device = None
        if device is None:
            abort(404)
        return device

    @app.post("/devices/<mac>/trust")
    def set_trust(mac):
        trusted = request.form.get("trusted") == "1"
        with store() as s:
            device = device_or_404(s, mac)
            s.set_trusted(device.mac, trusted)
        flash(f"{device.name} marked as {'trusted' if trusted else 'untrusted'}.", "ok")
        return redirect(url_for("devices"))

    @app.post("/devices/<mac>/label")
    def set_label(mac):
        label = request.form.get("label", "").strip()[:MAX_LABEL] or None
        with store() as s:
            device = device_or_404(s, mac)
            s.set_label(device.mac, label)
        flash(f"{device.mac} is now called {label!r}." if label else f"Name of {device.mac} cleared.", "ok")
        return redirect(url_for("devices"))

    @app.post("/scan")
    def scan():
        try:
            network, iface = actions.resolve_target(config)
            with store() as s:
                try:
                    result = actions.scan(config, s, network, iface, passive=False)
                    mode = "active ARP scan"
                except ScanPermissionError:
                    # The dashboard usually runs without root: read the ARP cache instead.
                    result = actions.scan(config, s, network, iface, passive=True)
                    mode = "kernel ARP cache; run as root for a full scan"
        except (OSError, RuntimeError, ValueError) as exc:
            flash(f"Scan failed: {exc}", "bad")
            return redirect(url_for("overview"))
        new = len(result.alerts)
        flash(
            f"Scanned {network} ({mode}): {len(result.observations)} device(s) seen"
            + (f", {new} new alert(s)." if new else "."),
            "warn" if new else "ok",
        )
        return redirect(url_for("overview"))

    @app.post("/audit/run")
    def run_audit():
        try:
            with store() as s:
                result = actions.audit(config, s, actions.audit_targets(s, None))
        except (OSError, RuntimeError, ValueError) as exc:
            flash(f"Audit failed: {exc}", "bad")
            return redirect(url_for("audit"))
        flash(f"Audited {len(result.hosts)} device(s): {actions.summary(result)}.", "ok")
        return redirect(url_for("audit"))

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
