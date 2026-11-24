"""
parser.py
=========
Normalizes raw WPScan JSON output into a flat list of unified "finding"
dictionaries that the dashboard can aggregate, filter and sort.

WPScan's JSON is deeply nested and inconsistent: the same "vulnerability"
shape appears under the core `version`, under `main_theme`, and under every
entry of `plugins` / `themes`. On top of that, "interesting_findings" surface
exposures (config backups, DB dumps, debug logs, directory listings) that are
not modelled as vulnerabilities at all. This module flattens all of that into
one predictable record type.

A finding looks like:
    {
        "site":              "https://example.com",
        "finding_kind":      "vulnerability" | "outdated" | "exposure" | "info",
        "component_type":    "core" | "plugin" | "theme" | "config" | "server" | "user",
        "component_name":    "contact-form-7",
        "component_version": "5.3.1",
        "title":             "Contact Form 7 <= 5.3.1 - Unrestricted File Upload",
        "severity":          "critical" | "high" | "medium" | "low" | "info",
        "cvss":              9.8 | None,
        "fixed_in":          "5.3.2" | None,
        "cves":              ["CVE-2020-35489"],
        "references":        ["https://wpscan.com/vulnerability/..."],
    }
"""

from __future__ import annotations

import re
from typing import Any


# Ordered worst -> best. Used everywhere we need a canonical ranking.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


# --------------------------------------------------------------------------- #
# Severity engine
# --------------------------------------------------------------------------- #
# WPScan's free feed rarely carries a CVSS score, so we use a layered approach:
#   1. Trust an explicit CVSS score when one is present.
#   2. Otherwise classify by keywords in the vulnerability title.
#   3. Fall back to "medium" — a vuln with a known reference is not "info".

_KEYWORD_SEVERITY: list[tuple[str, str]] = [
    # Most dangerous first; first match wins.
    ("critical", r"remote code execution|\brce\b|arbitrary file upload|"
                 r"unauthenticated arbitrary|object injection|deserializ|"
                 r"arbitrary file (download|read|deletion) \(unauth|"
                 # Pre-auth variants of what would otherwise be "high": these
                 # are the 9.8s in practice.
                 r"unauthenticated.*(sql injection|\bsqli\b|privilege "
                 r"escalation|account takeover|arbitrary file|password reset)|"
                 r"arbitrary (plugin|theme) installation|"
                 r"arbitrary (options?|settings?) update"),
    ("high",     r"sql injection|\bsqli\b|authentication bypass|auth bypass|"
                 r"privilege escalation|account takeover|arbitrary file|"
                 r"file inclusion|\blfi\b|\brfi\b|command injection|"
                 r"unrestricted (file )?upload"),
    ("medium",   r"cross[- ]site scripting|\bxss\b|cross[- ]site request forgery|"
                 r"\bcsrf\b|\bssrf\b|server[- ]side request|open redirect|"
                 r"information disclosure|sensitive data|path traversal|"
                 r"broken access control|idor"),
    ("low",      r"denial of service|\bdos\b|clickjacking|enumeration|"
                 r"full path disclosure|version disclosure"),
]


# A vulnerability that needs an Administrator (or Super Admin) account to
# trigger is rarely worth more than "medium": that role can already install
# arbitrary plugins. WPScan titles carry the role, e.g. "Admin+ Stored XSS" or
# "Authenticated (Admin+) SQL Injection".
_ADMIN_ONLY_RE = re.compile(r"\b(administrator|admin|super ?admin)\+")
_ADMIN_CAP = "medium"


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _extract_cvss(vuln: dict[str, Any]) -> float | None:
    """Pull a numeric CVSS base score out of the many shapes WPScan uses."""
    candidates: list[Any] = []
    if "cvss" in vuln:
        candidates.append(vuln["cvss"])
    refs = vuln.get("references") or {}
    if isinstance(refs, dict) and "cvss" in refs:
        candidates.append(refs["cvss"])

    for cand in candidates:
        score = None
        if isinstance(cand, dict):
            score = cand.get("score") or cand.get("base_score")
        elif isinstance(cand, (int, float, str)):
            score = cand
        if score is None:
            continue
        try:
            return float(str(score).split("/")[0].strip())
        except (ValueError, TypeError):
            continue
    return None


def classify_severity(title: str, vuln: dict[str, Any] | None = None) -> tuple[str, float | None]:
    """Return (severity, cvss_or_None) for a vulnerability."""
    cvss = _extract_cvss(vuln) if vuln else None
    if cvss is not None:
        return _cvss_to_severity(cvss), cvss

    lowered = (title or "").lower()
    severity = "medium"
    for sev, pattern in _KEYWORD_SEVERITY:
        if re.search(pattern, lowered):
            severity = sev
            break
    if (_ADMIN_ONLY_RE.search(lowered)
            and SEVERITY_RANK[severity] < SEVERITY_RANK[_ADMIN_CAP]):
        severity = _ADMIN_CAP
    return severity, None


# --------------------------------------------------------------------------- #
# Reference / CVE extraction
# --------------------------------------------------------------------------- #
# Public exploit references WPScan ships alongside advisories. Keeping them
# (as URLs, in the existing `references` list) lets the UI flag "exploit
# available", which changes triage order far more than a CVSS decimal does.
EXPLOIT_REF_KINDS = ("exploitdb", "metasploit", "packetstorm")
_EXPLOIT_URL_RE = re.compile(
    r"exploit-db\.com/exploits/|rapid7\.com/db/modules/|packetstormsecurity\.com/files/")


def reference_url(kind: str, value: Any) -> str | None:
    """Turn a WPScan reference (kind, value) into a URL, or None if unknown."""
    kind = (kind or "").lower()
    val = str(value).strip()
    if kind == "url":
        return val or None
    val = val.strip("/")
    if not val:
        return None
    if kind == "wpvulndb":
        return f"https://wpscan.com/vulnerability/{val}"
    if kind == "exploitdb":
        return f"https://www.exploit-db.com/exploits/{val}"
    if kind == "metasploit":
        return f"https://www.rapid7.com/db/modules/{val}/"
    if kind == "packetstorm":
        return f"https://packetstormsecurity.com/files/{val}/"
    if kind == "youtube":
        return f"https://www.youtube.com/watch?v={val}"
    return None


def has_exploit(references: list[str] | None) -> bool:
    return any(_EXPLOIT_URL_RE.search(str(r)) for r in (references or []))


def _split_refs(vuln: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Return (cves, reference_urls) for a vulnerability entry. Advisory URLs
    come first, public exploit URLs last, so the first URL is still the
    advisory."""
    refs = vuln.get("references") or {}
    cves: list[str] = []
    urls: list[str] = []
    exploits: list[str] = []

    if isinstance(refs, dict):
        for cve in refs.get("cve", []) or []:
            cve = str(cve).strip()
            cves.append(cve if cve.upper().startswith("CVE-") else f"CVE-{cve}")
        for kind in ("url", "wpvulndb"):
            for val in refs.get(kind, []) or []:
                u = reference_url(kind, val)
                if u:
                    urls.append(u)
        for kind in EXPLOIT_REF_KINDS:
            for val in refs.get(kind, []) or []:
                u = reference_url(kind, val)
                if u:
                    exploits.append(u)
    return cves, urls + exploits


# --------------------------------------------------------------------------- #
# Component vulnerability walker
# --------------------------------------------------------------------------- #
def _findings_from_vulns(
    site: str,
    component_type: str,
    component_name: str,
    component_version: str | None,
    vulns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for vuln in vulns or []:
        title = vuln.get("title") or f"Unnamed {component_type} vulnerability"
        severity, cvss = classify_severity(title, vuln)
        cves, urls = _split_refs(vuln)
        out.append({
            "site": site,
            "finding_kind": "vulnerability",
            "component_type": component_type,
            "component_name": component_name,
            "component_version": component_version,
            "title": title,
            "severity": severity,
            "cvss": cvss,
            "fixed_in": vuln.get("fixed_in"),
            "cves": cves,
            "references": urls,
        })
    return out


# Interesting-finding types that represent real exposures, with a severity.
_EXPOSURE_SEVERITY = {
    "db_exports": "critical",       # a downloadable database dump
    "config_backups": "high",       # wp-config backup can leak DB credentials
    "backup": "high",
    "debug_log": "medium",          # can leak paths / data
    "medias": "info",
    "directory_listing": "low",
    "listing": "low",
}


def _findings_from_interesting(site: str, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in entries or []:
        etype = (entry.get("type") or "").lower()
        title = entry.get("to_s") or entry.get("url") or etype or "Interesting finding"

        # Decide if this is a security exposure or just informational.
        severity = "info"
        kind = "info"
        for key, sev in _EXPOSURE_SEVERITY.items():
            if key in etype:
                severity, kind = sev, "exposure"
                break

        refs = entry.get("references") or {}
        urls: list[str] = []
        if isinstance(refs, dict):
            for group in refs.values():
                if isinstance(group, list):
                    urls.extend(str(u) for u in group)

        out.append({
            "site": site,
            "finding_kind": kind,
            "component_type": "config" if kind == "exposure" else "server",
            "component_name": etype or "-",
            "component_version": None,
            "title": title,
            "severity": severity,
            "cvss": None,
            "fixed_in": None,
            "cves": [],
            "references": [entry.get("url")] + urls if entry.get("url") else urls,
        })
    return out


# --------------------------------------------------------------------------- #
# Top-level: one WPScan report -> findings + a small site summary
# --------------------------------------------------------------------------- #
def parse_report(report: dict[str, Any], site_hint: str | None = None) -> dict[str, Any]:
    """
    Parse one WPScan JSON document.

    Returns:
        {
          "site":        "https://example.com",
          "wp_version":  "5.8" | None,
          "target_ip":   "1.2.3.4" | None,
          "findings":    [ ...finding dicts... ],
        }
    """
    site = (report.get("target_url") or report.get("effective_url")
            or site_hint or "unknown").rstrip("/")
    findings: list[dict[str, Any]] = []

    # --- WordPress core ---------------------------------------------------- #
    version = report.get("version") or {}
    wp_number = version.get("number")
    findings += _findings_from_vulns(
        site, "core", "WordPress core", wp_number, version.get("vulnerabilities", [])
    )
    if version.get("status") == "insecure" and not version.get("vulnerabilities"):
        findings.append({
            "site": site, "finding_kind": "outdated", "component_type": "core",
            "component_name": "WordPress core", "component_version": wp_number,
            "title": f"WordPress core {wp_number} is flagged insecure",
            "severity": "medium", "cvss": None, "fixed_in": None,
            "cves": [], "references": [],
        })

    # --- Main theme -------------------------------------------------------- #
    theme = report.get("main_theme") or {}
    if theme:
        tname = theme.get("slug") or theme.get("style_name") or "theme"
        tver = (theme.get("version") or {}).get("number")
        findings += _findings_from_vulns(site, "theme", tname, tver,
                                         theme.get("vulnerabilities", []))
        _maybe_outdated(findings, site, "theme", tname, tver, theme)

    # --- Additional themes ------------------------------------------------- #
    for slug, t in (report.get("themes") or {}).items():
        tver = (t.get("version") or {}).get("number")
        findings += _findings_from_vulns(site, "theme", slug, tver,
                                         t.get("vulnerabilities", []))
        _maybe_outdated(findings, site, "theme", slug, tver, t)

    # --- Plugins ----------------------------------------------------------- #
    for slug, p in (report.get("plugins") or {}).items():
        pver = (p.get("version") or {}).get("number")
        findings += _findings_from_vulns(site, "plugin", slug, pver,
                                         p.get("vulnerabilities", []))
        _maybe_outdated(findings, site, "plugin", slug, pver, p)

    # --- Interesting findings (exposures) ---------------------------------- #
    findings += _findings_from_interesting(site, report.get("interesting_findings", []))

    # --- Discrete exposure buckets WPScan sometimes reports separately ----- #
    for bucket, ctype, sev in [
        ("config_backups", "config", "high"),
        ("db_exports", "config", "critical"),
    ]:
        data = report.get(bucket) or {}
        for url in (data.keys() if isinstance(data, dict) else []):
            findings.append({
                "site": site, "finding_kind": "exposure", "component_type": ctype,
                "component_name": bucket, "component_version": None,
                "title": f"Exposed {bucket.replace('_', ' ')}: {url}",
                "severity": sev, "cvss": None, "fixed_in": None,
                "cves": [], "references": [url],
            })

    # --- Enumerated users (weak-but-useful signal) ------------------------- #
    users = report.get("users") or {}
    if isinstance(users, dict) and users:
        findings.append({
            "site": site, "finding_kind": "info", "component_type": "user",
            "component_name": "user enumeration", "component_version": None,
            "title": f"{len(users)} username(s) enumerable: {', '.join(list(users)[:5])}",
            "severity": "low", "cvss": None, "fixed_in": None,
            "cves": [], "references": [],
        })

    return {
        "site": site,
        "wp_version": wp_number,
        "target_ip": report.get("target_ip"),
        "findings": findings,
    }


def _maybe_outdated(findings, site, ctype, name, version, comp):
    """Emit a low-severity 'outdated' finding when a component is behind and clean."""
    if comp.get("outdated") and not comp.get("vulnerabilities"):
        latest = comp.get("latest_version")
        findings.append({
            "site": site, "finding_kind": "outdated", "component_type": ctype,
            "component_name": name, "component_version": version,
            "title": f"{name} {version or ''} is outdated"
                     + (f" (latest {latest})" if latest else ""),
            "severity": "low", "cvss": None, "fixed_in": latest,
            "cves": [], "references": [],
        })


def summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings by severity for the dashboard header band."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    counts["total"] = len(findings)
    return counts
