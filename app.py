"""
app.py
======
Flask entry point. Serves the dashboard page and a small JSON API the frontend
polls. Filtering and sorting happen client-side so the UI stays responsive; the
API just returns the current normalized findings plus per-site scan status.

Routes:
  GET  /                     dashboard page
  GET  /api/findings         all findings + summary + per-site scan status
  POST /api/scan             start a WPScan batch over SITES_FILE (background)
  POST /api/ingest-samples   load the bundled sample reports (no wpscan needed)
  GET  /api/export.json      full audit report as JSON (download)
  GET  /api/export.pdf       full audit report as PDF (download)
  POST /api/clear            wipe all stored scans and findings

Security model: there is no login. The dashboard is meant to be bound to
loopback and used by one operator, so the browser is the only thing that can
reach it — which makes the browser the attack surface. Three guards keep a
hostile web page from driving the API through the operator's own browser:

  * Every state-changing request must carry `X-Requested-With`. A cross-site
    form or no-cors fetch cannot set custom headers, and a CORS preflight for
    one is never answered, so drive-by POSTs (clear the DB, launch a scan of
    the real targets) are refused.
  * `Origin` / `Sec-Fetch-Site`, when the browser sends them, must match.
  * `TRUSTED_HOSTS` rejects requests whose Host header is not the dashboard's
    own, which defeats DNS rebinding (a page resolving its own name to
    127.0.0.1 to read findings about client sites).

Every scan/ingest/clear/settings action is appended to AUDIT_LOG with the
caller's address, so there is a record of what was run against which target.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from urllib.parse import urlparse

from flask import Flask, jsonify, make_response, render_template, request

import enrich
import remediation
import report
import scanner
from config import CONFIG
from db import Database
from parser import SEVERITY_ORDER, SEVERITY_RANK, summarize

app = Flask(__name__)
db = Database(CONFIG["DATABASE"])
# CVE enrichment (NVD / EPSS / KEV) runs on its own background thread and
# reports progress through the same event log the scan toasts use.
enricher = enrich.Enricher(db, CONFIG)
manager = scanner.ScanManager(db, CONFIG, enricher=enricher)
enricher.events = manager.events

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]")


def _trusted_hosts() -> list[str]:
    hosts = list(_LOOPBACK_HOSTS)
    bind = (CONFIG.get("HOST") or "").strip()
    if bind and bind not in ("0.0.0.0", "::", "[::]"):
        hosts.append(bind)
    for extra in (CONFIG.get("TRUSTED_HOSTS") or "").split(","):
        extra = extra.strip()
        if extra:
            hosts.append(extra)
    return hosts


# Werkzeug compares the Host header (port stripped) against this list and
# answers 400 to anything else.
app.config["TRUSTED_HOSTS"] = _trusted_hosts()
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024  # API bodies are tiny


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #
_audit = logging.getLogger("wpscan.audit")
_audit.setLevel(logging.INFO)
_audit.propagate = False
if CONFIG.get("AUDIT_LOG") and not _audit.handlers:
    try:
        _h = logging.FileHandler(CONFIG["AUDIT_LOG"], encoding="utf-8")
        _h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        _audit.addHandler(_h)
    except OSError as exc:  # unwritable path: keep running, say so once
        print(f" ! audit log {CONFIG['AUDIT_LOG']} not writable: {exc}",
              file=sys.stderr)


def audit(action: str, **fields) -> None:
    """One line per operator action: who (remote address), what, on which
    targets. The log is append-only evidence of what this tool was told to do."""
    who = request.remote_addr if request else "-"
    detail = " ".join(f"{k}={json.dumps(v, default=str)}" for k, v in fields.items())
    _audit.info(f"{action} from={who} {detail}".rstrip())


# --------------------------------------------------------------------------- #
# Request guards and response headers
# --------------------------------------------------------------------------- #
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@app.before_request
def _reject_cross_site_writes():
    if request.method in _SAFE_METHODS:
        return None
    if request.headers.get("X-Requested-With") != "XMLHttpRequest":
        return jsonify({"error": "Cross-site request blocked: missing "
                                 "X-Requested-With header."}), 403
    origin = request.headers.get("Origin")
    if origin and origin != "null":
        if urlparse(origin).netloc.lower() != request.host.lower():
            return jsonify({"error": "Cross-site request blocked: Origin "
                                     "does not match."}), 403
    elif origin == "null":
        return jsonify({"error": "Cross-site request blocked: opaque Origin."}), 403
    fetch_site = request.headers.get("Sec-Fetch-Site")
    if fetch_site and fetch_site not in ("same-origin", "none"):
        return jsonify({"error": "Cross-site request blocked."}), 403
    return None


@app.after_request
def _security_headers(resp):
    # The dashboard checks targets for these; it should pass its own audit.
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; img-src 'self' data:; "
                            "object-src 'none'; base-uri 'none'; "
                            "frame-ancestors 'none'; form-action 'self'")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy",
                            "camera=(), microphone=(), geolocation=()")
    if request.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/findings")
def api_findings():
    findings = db.all_findings()
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.get("severity"), 99),
                                 f.get("site") or ""))
    remediation.attach(findings)   # derived, never stored
    statuses = db.latest_scan_status()

    # Configured targets that have never been scanned still deserve a row.
    configured = scanner.read_sites(CONFIG["SITES_FILE"])
    sites: dict[str, dict] = {}
    for site in configured:
        sites[site] = statuses.get(site, {"site": site, "status": "not scanned"})
    for site, st in statuses.items():
        sites.setdefault(site, st)

    # Progress events newer than the client's cursor, so toasts never repeat.
    try:
        since = int(request.args.get("since", 0))
    except (TypeError, ValueError):
        since = 0

    return jsonify({
        "findings": findings,
        "summary": summarize(findings),
        "severities": SEVERITY_ORDER,
        "sites": list(sites.values()),
        "scanning": manager.is_running(),
        "paused": manager.is_paused(),
        "paused_site": manager.paused_site(),
        "current_site": manager.current_site(),
        "progress": manager.progress(),
        "events": manager.events.since(since),
        "last_event_id": manager.events.latest_id(),
        "wpscan_keys_configured": scanner.configured_key_count(CONFIG),
        "enrichment": enricher.status(),
    })


@app.route("/api/history")
def api_history():
    """Findings that disappeared from a later scan (fixed), newest first.
    `?site=` narrows to one target."""
    site = request.args.get("site") or None
    if site:
        site = scanner.normalize_site(site)
    return jsonify({"resolved": db.resolved_findings(site, limit=200)})


@app.route("/api/enrich", methods=["POST"])
def api_enrich():
    """Fetch CVSS/EPSS/KEV data for any CVEs not yet cached (background)."""
    if not enricher.enabled():
        return jsonify({"error": "Enrichment is disabled (ENRICHMENT=false)."}), 400
    started = enricher.schedule()
    audit("enrich", started=started)
    return jsonify({"started": started, "status": enricher.status()})


_MAX_BATCH = 1000


@app.route("/api/scan", methods=["POST"])
def api_scan():
    body = request.get_json(silent=True)
    body = body if isinstance(body, dict) else {}
    requested = body.get("sites")
    if not requested and body.get("site"):
        requested = [body["site"]]

    configured = scanner.read_sites(CONFIG["SITES_FILE"])
    if requested:
        if not isinstance(requested, list) or len(requested) > _MAX_BATCH:
            return jsonify({"error": "sites must be a list of at most "
                                     f"{_MAX_BATCH} URLs."}), 400
        # Normalize the same way sites.txt is read, so a retry matches the
        # stored target exactly (scheme added, trailing slash trimmed).
        sites = [scanner.normalize_site(s) for s in requested
                 if isinstance(s, str) and s.strip()]
        # Only targets the operator has already listed (sites.txt) or
        # previously scanned may be retried. Without this, anyone who can reach
        # the port could point WPScan at arbitrary hosts.
        allowed = set(configured) | set(db.latest_scan_status())
        unknown = [s for s in sites if s not in allowed]
        if unknown:
            return jsonify({"error": "Target(s) not in sites.txt or scan "
                                     "history; add them to sites.txt first.",
                            "rejected": unknown}), 400
    else:
        sites = configured
    if not sites:
        return jsonify({"error": f"No sites found in {CONFIG['SITES_FILE']}."}), 400
    if not manager.start_batch(sites):
        return jsonify({"error": "A scan batch is already running."}), 409
    audit("scan_start", count=len(sites), targets=sites)
    return jsonify({"started": True, "count": len(sites)})


@app.route("/api/ingest-samples", methods=["POST"])
def api_ingest_samples():
    count = scanner.ingest_directory(db, CONFIG["SAMPLE_DIR"], enricher=enricher)
    audit("ingest_samples", directory=CONFIG["SAMPLE_DIR"], ingested=count)
    if count == 0:
        return jsonify({"error": f"No JSON reports found in {CONFIG['SAMPLE_DIR']}."}), 400
    return jsonify({"ingested": count})


# Runtime-editable settings and the validation each one gets. Values are
# handed to the wpscan argv and to socket timeouts, so bounds matter: a
# negative timeout raises inside the batch thread and an unknown --format
# just fails every scan.
_ENUMERATE_RE = re.compile(r"^[a-z]{1,3}(?:\d+(?:-\d+)?)?(?:,[a-z]{1,3}(?:\d+(?:-\d+)?)?)*$")
_SETTING_RULES: dict[str, tuple] = {
    "SCAN_TIMEOUT":             ("int", 60, 86400),
    "PREFLIGHT_CHECK":          ("bool",),
    "PREFLIGHT_TIMEOUT":        ("int", 1, 120),
    "WPSCAN_ENUMERATE":         ("regex", _ENUMERATE_RE),
    "WPSCAN_PLUGINS_DETECTION": ("choice", ("passive", "mixed", "aggressive")),
    "EXTRA_CHECKS":             ("bool",),
    "WPSCAN_FORMAT":            ("choice", ("cli-no-colour", "cli-no-color",
                                            "cli", "json")),
    "WPSCAN_THROTTLE":          ("int", 0, 60000),
    "WPSCAN_MAX_THREADS":       ("int", 0, 50),
}


def _validate_setting(key: str, raw) -> tuple[object | None, str | None]:
    """Return (value, None) or (None, reason)."""
    rule = _SETTING_RULES[key]
    kind = rule[0]
    if kind == "int":
        try:
            val = int(raw)
        except (TypeError, ValueError):
            return None, "must be an integer"
        if not rule[1] <= val <= rule[2]:
            return None, f"must be between {rule[1]} and {rule[2]}"
        return val, None
    if kind == "bool":
        if isinstance(raw, bool):
            return ("true" if raw else "false"), None
        txt = str(raw).strip().lower()
        if txt in ("true", "1", "yes", "on"):
            return "true", None
        if txt in ("false", "0", "no", "off"):
            return "false", None
        return None, "must be true or false"
    if kind == "choice":
        txt = str(raw).strip().lower()
        if txt not in rule[1]:
            return None, f"must be one of {', '.join(rule[1])}"
        return txt, None
    if kind == "regex":
        txt = str(raw).strip().lower()
        if not rule[1].match(txt):
            return None, "must be WPScan enumerate flags, e.g. vp,vt,u,cb,dbe"
        return txt, None
    return None, "unknown setting"


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    """Read or update runtime scan settings without restarting the server."""
    if request.method == "POST":
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        accepted: dict[str, object] = {}
        invalid: dict[str, str] = {}
        for key in _SETTING_RULES:
            if key in body:
                val, why = _validate_setting(key, body[key])
                if why:
                    invalid[key] = why
                else:
                    accepted[key] = val
        if invalid:
            # All-or-nothing: a half-applied settings change is confusing.
            return jsonify({"error": "Invalid settings.", "invalid": invalid}), 400
        CONFIG.update(accepted)
        if accepted:
            audit("settings", changed=accepted)
        return jsonify({"saved": True,
                        "settings": {k: CONFIG[k] for k in _SETTING_RULES}})
    return jsonify({k: CONFIG[k] for k in _SETTING_RULES})


@app.route("/api/pause", methods=["POST"])
def api_pause():
    """Pause the batch after the current site finishes."""
    if not manager.is_running():
        return jsonify({"error": "No scan running."}), 400
    manager.pause()
    audit("pause")
    return jsonify({"paused": True})


@app.route("/api/resume", methods=["POST"])
def api_resume():
    """Resume a paused batch."""
    manager.resume()
    audit("resume")
    return jsonify({"resumed": True})


@app.route("/api/cancel", methods=["POST"])
def api_cancel():
    """Cancel the batch after the current site finishes."""
    manager.cancel()
    audit("cancel")
    return jsonify({"cancelled": True})


@app.route("/api/pause-site", methods=["POST"])
def api_pause_site():
    """Pause before scanning a specific site (queues a hold for that site)."""
    site = (request.get_json(silent=True) or {}).get("site", "")
    if not site or not isinstance(site, str):
        return jsonify({"error": "site required"}), 400
    manager.pause_site(scanner.normalize_site(site))
    audit("pause_site", site=site)
    return jsonify({"paused_site": site})


@app.route("/api/resume-site", methods=["POST"])
def api_resume_site():
    """Resume a per-site pause."""
    site = (request.get_json(silent=True) or {}).get("site", "")
    if not isinstance(site, str):
        return jsonify({"error": "site required"}), 400
    manager.resume_site(scanner.normalize_site(site))
    audit("resume_site", site=site)
    return jsonify({"resumed_site": site})


@app.route("/api/scan-log")
def api_scan_log():
    """Live verbose scan output for the console panel. Display-only — these
    lines are never stored or included in any exported report."""
    try:
        since = int(request.args.get("since", 0))
    except (TypeError, ValueError):
        since = 0
    return jsonify({
        "lines": manager.log.since(since),
        "last_log_id": manager.log.latest_id(),
        "scanning": manager.is_running(),
    })


@app.route("/api/export.json")
def api_export_json():
    payload = report.build_report(db, CONFIG)
    audit("export", format="json")
    resp = make_response(json.dumps(payload, indent=2, sort_keys=False))
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Content-Disposition"] = (
        f'attachment; filename="{report.suggested_filename("json")}"')
    return resp


@app.route("/api/export.pdf")
def api_export_pdf():
    payload = report.build_report(db, CONFIG)
    try:
        pdf_bytes = report.build_pdf(payload)
    except report.PdfUnavailable as exc:
        # Degrade with an actionable message rather than a 500.
        return jsonify({"error": str(exc)}), 501
    audit("export", format="pdf")
    resp = make_response(pdf_bytes)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = (
        f'attachment; filename="{report.suggested_filename("pdf")}"')
    return resp


@app.route("/api/clear", methods=["POST"])
def api_clear():
    db.clear()
    audit("clear")
    return jsonify({"cleared": True})


if __name__ == "__main__":
    host = CONFIG["HOST"]
    if host not in _LOOPBACK_HOSTS and not scanner._truthy(CONFIG.get("ALLOW_REMOTE_BIND")):
        print(f" ! Refusing to bind to {host}: the dashboard has no authentication "
              f"and exposes scan controls and client findings to anyone who can "
              f"reach it. Put it behind an authenticating reverse proxy and set "
              f"ALLOW_REMOTE_BIND=true to override.", file=sys.stderr)
        sys.exit(2)
    print(f" * WPScan dashboard on http://{host}:{CONFIG['PORT']}")
    _key_count = scanner.build_keyring(CONFIG).count()
    if _key_count:
        print(f" * {_key_count} WPScan API key(s) loaded from "
              f"{CONFIG['API_KEYS_FILE']} — rotating on rate-limit (25 req/day each).")
    else:
        print(f" * No WPScan API keys — add them to {CONFIG['API_KEYS_FILE']} for "
              f"full vuln data (free keys at https://wpscan.com/profile).")
        print(" * Tip: click 'Load sample data' in the UI to try it immediately.")
    app.run(host=host, port=CONFIG["PORT"], debug=False, threaded=True)
