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
"""

from __future__ import annotations

import json

from flask import Flask, jsonify, make_response, render_template, request

import report
import scanner
from config import CONFIG
from db import Database
from parser import SEVERITY_ORDER, SEVERITY_RANK, summarize

app = Flask(__name__)
db = Database(CONFIG["DATABASE"])
manager = scanner.ScanManager(db, CONFIG)


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/findings")
def api_findings():
    findings = db.all_findings()
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.get("severity"), 99),
                                 f.get("site") or ""))
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
        "progress": manager.progress(),
        "events": manager.events.since(since),
        "last_event_id": manager.events.latest_id(),
        "wpscan_keys_configured": scanner.build_keyring(CONFIG).count(),
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    body = request.json if request.is_json else None
    sites = None
    if body:
        # Accept either {"sites": [...]} or {"site": "..."} (single retry).
        sites = body.get("sites")
        if not sites and body.get("site"):
            sites = [body["site"]]
    if sites:
        # Normalize the same way sites.txt is read, so a retry matches the
        # stored target exactly (scheme added, trailing slash trimmed).
        sites = [scanner.normalize_site(s) for s in sites if s and s.strip()]
    else:
        sites = scanner.read_sites(CONFIG["SITES_FILE"])
    if not sites:
        return jsonify({"error": f"No sites found in {CONFIG['SITES_FILE']}."}), 400
    if not manager.start_batch(sites):
        return jsonify({"error": "A scan batch is already running."}), 409
    return jsonify({"started": True, "count": len(sites)})


@app.route("/api/ingest-samples", methods=["POST"])
def api_ingest_samples():
    count = scanner.ingest_directory(db, CONFIG["SAMPLE_DIR"])
    if count == 0:
        return jsonify({"error": f"No JSON reports found in {CONFIG['SAMPLE_DIR']}."}), 400
    return jsonify({"ingested": count})


@app.route("/api/export.json")
def api_export_json():
    payload = report.build_report(db, CONFIG)
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
    resp = make_response(pdf_bytes)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = (
        f'attachment; filename="{report.suggested_filename("pdf")}"')
    return resp


@app.route("/api/clear", methods=["POST"])
def api_clear():
    db.clear()
    return jsonify({"cleared": True})


if __name__ == "__main__":
    print(f" * WPScan dashboard on http://{CONFIG['HOST']}:{CONFIG['PORT']}")
    _key_count = scanner.build_keyring(CONFIG).count()
    if _key_count:
        print(f" * {_key_count} WPScan API key(s) loaded from "
              f"{CONFIG['API_KEYS_FILE']} — rotating on rate-limit (25 req/day each).")
    else:
        print(f" * No WPScan API keys — add them to {CONFIG['API_KEYS_FILE']} for "
              f"full vuln data (free keys at https://wpscan.com/profile).")
        print(" * Tip: click 'Load sample data' in the UI to try it immediately.")
    app.run(host=CONFIG["HOST"], port=CONFIG["PORT"], debug=False, threaded=True)
