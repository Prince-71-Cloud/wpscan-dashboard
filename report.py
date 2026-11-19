"""
report.py
=========
Turns the stored findings into a shareable security audit report.

Two outputs, one shared payload:
  * build_report()  -> dict, serialized directly as the JSON export. Machine
    readable, so it can be diffed between runs or fed into a ticket tracker.
  * build_pdf()     -> bytes, a paginated PDF for handing to a client or
    attaching to a report. Requires reportlab (optional dependency); callers
    should catch PdfUnavailable and fall back to JSON.

The PDF is deliberately structured like an audit deliverable rather than a
screenshot of the dashboard: summary first, then per-target coverage (including
targets that FAILED to scan, which is itself a finding), then the detail table
ordered by severity.
"""

from __future__ import annotations

import datetime as _dt
import io
from typing import Any

from parser import SEVERITY_ORDER, SEVERITY_RANK, summarize


class PdfUnavailable(RuntimeError):
    """reportlab is not installed."""


SEVERITY_DEFINITIONS = [
    ("critical", "Remote code execution or equivalent full compromise. Patch immediately."),
    ("high", "Authentication bypass, SQL injection, arbitrary file upload or similar. Patch urgently."),
    ("medium", "Cross-site scripting, CSRF, SSRF or meaningful information disclosure."),
    ("low", "Limited impact: outdated components, enumeration, minor disclosure."),
    ("info", "Observations with no direct impact; useful for hardening."),
]

# Print-friendly severity colours (the dashboard's dark-theme scale is too
# light to read on white paper).
_PDF_SEV_COLORS = {
    "critical": "#c0182b",
    "high":     "#d2601a",
    "medium":   "#b58900",
    "low":      "#1f6fb2",
    "info":     "#5c6879",
}


def _now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def build_report(db, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Assemble the full audit payload from the database."""
    findings = db.all_findings()
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.get("severity"), 99),
                                 f.get("site") or "",
                                 f.get("component_name") or ""))
    statuses = db.latest_scan_status()

    targets = []
    for site, st in sorted(statuses.items()):
        targets.append({
            "site": site,
            "status": st.get("status"),
            "wp_version": st.get("wp_version"),
            "target_ip": st.get("target_ip"),
            "started_at": st.get("started_at"),
            "finished_at": st.get("finished_at"),
            "error": st.get("error"),
            "findings": sum(1 for f in findings if f.get("site") == site),
        })

    summary = summarize(findings)
    scanned_ok = sum(1 for t in targets if t["status"] == "success")
    # A timed-out scan saved real findings, so it is partially assessed — not
    # a failure, but not a complete result either.
    partial = sum(1 for t in targets if t["status"] == "partial")
    failed = [t for t in targets if t["status"] not in ("success", "partial", None)]

    return {
        "report_type": "WordPress security audit",
        "generated_at": _now_iso(),
        "generator": "WPScan Console",
        "scope": {
            "targets_total": len(targets),
            "targets_scanned": scanned_ok,
            "targets_partial": partial,
            "targets_failed": len(failed),
        },
        "summary": summary,
        "targets": targets,
        "findings": findings,
        "severity_definitions": {k: v for k, v in SEVERITY_DEFINITIONS},
        "notes": [
            "Findings reflect the most recent successful scan of each target.",
            "Severity is taken from the published CVSS score where one is "
            "available; otherwise it is classified from the vulnerability type.",
            "A target that failed to scan has NOT been assessed — treat its "
            "status as unknown rather than clean.",
            "A 'partial' target timed out mid-scan: its findings are real but "
            "incomplete, so absence of a finding there proves nothing.",
        ],
    }


def _fmt_ts(ts: Any) -> str:
    if not ts:
        return "—"
    try:
        return _dt.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OSError):
        return "—"


def suggested_filename(ext: str) -> str:
    return f"wpscan-audit-{_dt.datetime.now().strftime('%Y%m%d-%H%M')}.{ext}"


# --------------------------------------------------------------------------- #
# PDF rendering
# --------------------------------------------------------------------------- #
def build_pdf(report: dict[str, Any]) -> bytes:
    """Render the report payload as a PDF. Raises PdfUnavailable if reportlab
    is missing so the caller can degrade gracefully."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise PdfUnavailable(
            "PDF export needs reportlab. Install it with: pip install reportlab"
        ) from exc

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title="WordPress Security Audit", author="WPScan Console",
        subject="Aggregated WordPress vulnerability findings",
    )

    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontSize=20, spaceAfter=2,
                        alignment=TA_LEFT, textColor=colors.HexColor("#14202e"))
    sub = ParagraphStyle("sub", parent=ss["Normal"], fontSize=9,
                         textColor=colors.HexColor("#5c6879"), spaceAfter=12)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12.5, spaceBefore=14,
                        spaceAfter=6, textColor=colors.HexColor("#14202e"))
    body = ParagraphStyle("body", parent=ss["Normal"], fontSize=9, leading=12.5)
    small = ParagraphStyle("small", parent=ss["Normal"], fontSize=7.6, leading=9.6)
    cell = ParagraphStyle("cell", parent=ss["Normal"], fontSize=7.8, leading=9.8)
    note = ParagraphStyle("note", parent=ss["Normal"], fontSize=8, leading=11,
                          textColor=colors.HexColor("#5c6879"))

    story: list[Any] = []
    summary = report.get("summary", {})
    scope = report.get("scope", {})

    # ---- Header ---------------------------------------------------------- #
    story.append(Paragraph("WordPress Security Audit", h1))
    n_partial = scope.get("targets_partial", 0)
    story.append(Paragraph(
        f"Generated {report.get('generated_at', '')} &nbsp;·&nbsp; "
        f"{scope.get('targets_scanned', 0)} of {scope.get('targets_total', 0)} "
        f"target(s) assessed"
        + (f" ({n_partial} more partially)" if n_partial else "")
        + f" &nbsp;·&nbsp; {summary.get('total', 0)} finding(s)",
        sub))

    # ---- Severity summary ------------------------------------------------ #
    story.append(Paragraph("Summary", h2))
    head = [Paragraph("<b>Severity</b>", cell), Paragraph("<b>Count</b>", cell),
            Paragraph("<b>Meaning</b>", cell)]
    rows = [head]
    for sev, desc in SEVERITY_DEFINITIONS:
        rows.append([
            Paragraph(f"<b><font color='{_PDF_SEV_COLORS[sev]}'>"
                      f"{sev.upper()}</font></b>", cell),
            Paragraph(str(summary.get(sev, 0)), cell),
            Paragraph(desc, cell),
        ])
    t = Table(rows, colWidths=[24 * mm, 16 * mm, 138 * mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f6")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d3de")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    # ---- Coverage -------------------------------------------------------- #
    story.append(Paragraph("Scope and coverage", h2))
    rows = [[Paragraph(f"<b>{c}</b>", cell) for c in
             ("Target", "Status", "WP version", "Last scan", "Findings")]]
    for tgt in report.get("targets", []):
        status = tgt.get("status")
        status_txt = (status or "not scanned").replace("_", " ")
        color = {"success": "#1a7f4b", "partial": "#b58900"}.get(status, "#c0182b")
        rows.append([
            Paragraph(tgt.get("site", ""), cell),
            Paragraph(f"<font color='{color}'>{status_txt}</font>", cell),
            Paragraph(tgt.get("wp_version") or "—", cell),
            Paragraph(_fmt_ts(tgt.get("finished_at")), cell),
            Paragraph(str(tgt.get("findings", 0)), cell),
        ])
    t = Table(rows, colWidths=[62 * mm, 26 * mm, 24 * mm, 36 * mm, 20 * mm],
              repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f6")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d3de")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    # A failed scan is a coverage gap, not a clean bill of health.
    failed = [t_ for t_ in report.get("targets", [])
              if t_.get("status") not in ("success", "partial", None)]
    partial = [t_ for t_ in report.get("targets", [])
               if t_.get("status") == "partial"]
    if partial:
        story.append(Spacer(1, 5))
        story.append(Paragraph(
            "<b>Note:</b> the following target(s) timed out mid-scan; their "
            "findings are real but coverage is incomplete.", note))
        for t_ in partial:
            story.append(Paragraph(
                f"• {t_.get('site')} — {(t_.get('error') or 'scan timed out')[:220]}",
                small))
    if failed:
        story.append(Spacer(1, 5))
        story.append(Paragraph(
            "<b>Note:</b> the following target(s) could not be assessed; their "
            "security posture is unknown, not clean.", note))
        for t_ in failed:
            story.append(Paragraph(
                f"• {t_.get('site')} — {(t_.get('error') or 'scan failed')[:220]}",
                small))

    # ---- Findings -------------------------------------------------------- #
    story.append(Paragraph("Findings", h2))
    findings = report.get("findings", [])
    if not findings:
        story.append(Paragraph("No findings recorded.", body))
    else:
        rows = [[Paragraph(f"<b>{c}</b>", cell) for c in
                 ("Sev", "Finding", "Target", "Component", "Version",
                  "Fixed in", "Reference")]]
        for f in findings:
            sev = f.get("severity", "info")
            cves = ", ".join(f.get("cves") or [])
            refs = f.get("references") or []
            ref_txt = cves or (refs[0] if refs else "—")
            cvss = f.get("cvss")
            title = f.get("title", "")
            if cvss:
                title += f" <font color='#5c6879'>(CVSS {cvss})</font>"
            comp = f.get("component_name") or "—"
            ctype = (f.get("component_type") or "").strip()
            if ctype:
                comp = f"{comp}<br/><font color='#5c6879' size='6.5'>{ctype}</font>"
            rows.append([
                Paragraph(f"<b><font size='6.8' color='"
                          f"{_PDF_SEV_COLORS.get(sev, '#5c6879')}'>"
                          f"{sev.upper()}</font></b>", cell),
                Paragraph(title, cell),
                Paragraph(f.get("site", ""), cell),
                Paragraph(comp, cell),
                Paragraph(f.get("component_version") or "—", cell),
                Paragraph(f.get("fixed_in") or "no fix", cell),
                Paragraph(ref_txt, small),
            ])
        t = Table(rows, repeatRows=1,
                  colWidths=[16 * mm, 49 * mm, 29 * mm, 25 * mm, 15 * mm,
                             15 * mm, 29 * mm])
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f6")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d3de")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ]
        # Tint critical/high rows so triage order is obvious on paper.
        for i, f in enumerate(findings, start=1):
            if f.get("severity") == "critical":
                style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fdecee")))
            elif f.get("severity") == "high":
                style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fdf1e8")))
        t.setStyle(TableStyle(style))
        story.append(t)

    # ---- Method notes ---------------------------------------------------- #
    story.append(Paragraph("Method and caveats", h2))
    for n in report.get("notes", []):
        story.append(Paragraph(f"• {n}", note))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Scanning was performed with WPScan against targets supplied by the "
        "operator. Only scan systems you own or are authorised to test.", note))

    def _footer(canv, doc_):
        canv.saveState()
        canv.setFont("Helvetica", 7.5)
        canv.setFillColor(colors.HexColor("#8b98a9"))
        canv.drawString(16 * mm, 10 * mm, "WordPress Security Audit — WPScan Console")
        canv.drawRightString(A4[0] - 16 * mm, 10 * mm, f"Page {doc_.page}")
        canv.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
