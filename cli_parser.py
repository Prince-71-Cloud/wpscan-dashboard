"""
cli_parser.py
=============
Parse WPScan's human-readable (cli-no-colour) output into the same structured
finding records that parser.py produces from JSON.

Why this exists: WPScan only streams live progress in its cli formats; with
--format json it runs silently and emits the report only at the end. To power
the live console *and* keep the dashboard's structured table (component,
version, fixed-in, CVE, severity), we run the scan in cli-no-colour and recover
the structure from the text here.

The cli format is stable and line-oriented. A component block looks like:

    [+] contact-form-7
     | Location: https://site/wp-content/plugins/contact-form-7/
     | Last Updated: 2023-01-01T00:00:00.000Z
     | [!] The version is out of date, the latest version is 5.9
     | Version: 5.3.1 (100% confidence)
     |
     | [!] Title: Contact Form 7 < 5.3.2 - Unrestricted File Upload
     |     Fixed in: 5.3.2
     |     References:
     |      - cve: 2020-35489
     |      - url: https://example.com/advisory

Sections are introduced by headers like "[i] Plugin(s) Identified:",
"[i] Theme(s) Identified:", "[i] User(s) Identified:", and the WordPress
version line. This parser walks those sections and emits findings whose shape
matches parser.parse_report so the rest of the pipeline is unchanged.
"""

from __future__ import annotations

import re
from typing import Any

from parser import classify_severity

# Section headers that change how following component blocks are interpreted.
_SECTION_RE = re.compile(r"^\[i\]\s+(.*?)\s+Identified", re.IGNORECASE)
_COMPONENT_RE = re.compile(r"^\[\+\]\s+(.+?)\s*$")
_VERSION_RE = re.compile(r"Version:\s*([0-9][^\s(]*)")
_WP_VERSION_RE = re.compile(r"WordPress version\s+([0-9][^\s]*)\s+identified", re.I)
_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
_TITLE_RE = re.compile(r"\[!\]\s*Title:\s*(.+?)\s*$")
_FIXED_RE = re.compile(r"Fixed in:\s*([0-9][^\s]*)")
_CVE_RE = re.compile(r"-\s*cve:\s*([0-9A-Za-z\-]+)", re.I)
_URL_REF_RE = re.compile(r"-\s*url:\s*(\S+)", re.I)

# Map a section label to the component_type stored on findings.
_SECTION_TYPE = {
    "plugin": "plugin",
    "plugins": "plugin",
    "theme": "theme",
    "themes": "theme",
    "main theme": "theme",
}

# Interesting findings (the "Interesting Finding(s):" section) and the severity
# we assign each. Matched by a keyword in the finding's first line.
_INTERESTING = [
    ("debug log", "medium", "Debug log exposed"),
    ("config backup", "high", "Config backup exposed"),
    ("database export", "critical", "Database export exposed"),
    ("db export", "critical", "Database export exposed"),
    ("xml-rpc", "low", "XML-RPC enabled"),
    ("xmlrpc", "low", "XML-RPC enabled"),
    ("readme", "info", "readme.html exposes WordPress version"),
    ("full path disclosure", "low", "Full Path Disclosure"),
    ("directory listing", "medium", "Directory listing enabled"),
    ("upload directory has listing", "medium", "Upload directory listing enabled"),
    ("wp-cron", "info", "wp-cron.php accessible"),
    ("registration", "info", "User registration enabled"),
]


def _clean(line: str) -> str:
    """Strip the leading ' | ' gutter WPScan uses inside a component block."""
    s = line.rstrip("\n")
    s = re.sub(r"^\s*\|\s?", "", s)
    return s.strip()


def _finding(site: str, title: str, ctype: str, cname: str,
             version: str | None, fixed_in: str | None,
             cves: list[str], refs: list[str],
             severity: str | None = None) -> dict[str, Any]:
    sev, cvss = classify_severity(title)
    if severity is not None:
        sev = severity
    severity = sev
    return {
        "site": site.rstrip("/"),
        "finding_kind": "vulnerability",
        "component_type": ctype,
        "component_name": cname,
        "component_version": version,
        "title": title,
        "severity": severity,
        "cvss": cvss,
        "fixed_in": fixed_in,
        "cves": cves,
        "references": refs,
    }


def parse_cli(text: str, site_hint: str | None = None) -> dict[str, Any]:
    """Parse cli-no-colour WPScan output into {site, wp_version, target_ip,
    findings}. Best-effort and defensive: unrecognized lines are ignored."""
    lines = (text or "").splitlines()
    site = site_hint or ""
    wp_version: str | None = None
    target_ip: str | None = None
    findings: list[dict[str, Any]] = []

    section_type: str | None = None   # "plugin" / "theme" / "user" / None
    # Current component being accumulated.
    cur_name: str | None = None
    cur_version: str | None = None
    cur_vulns: list[dict[str, Any]] = []
    cur_vuln: dict[str, Any] | None = None

    def flush_component() -> None:
        nonlocal cur_name, cur_version, cur_vulns, cur_vuln
        if cur_name and section_type in ("plugin", "theme", "core"):
            ctype = section_type if section_type != "core" else "core"
            if cur_vulns:
                for v in cur_vulns:
                    findings.append(_finding(
                        site, v["title"], ctype, cur_name,
                        cur_version, v.get("fixed_in"), v.get("cves", []),
                        v.get("refs", [])))
            # Outdated-but-no-CVE components are surfaced as a low finding so
            # they still show up as worth updating.
            elif cur_outdated["v"]:
                findings.append(_finding(
                    site, f"{cur_name} {cur_version or ''} is outdated".strip(),
                    ctype, cur_name, cur_version, None, [], [],
                    severity="low"))
        cur_name = None
        cur_version = None
        cur_vulns = []
        cur_vuln = None
        cur_outdated["v"] = False

    cur_outdated = {"v": False}

    for raw in lines:
        # URL / IP line (appears near the top, not guttered).
        if site_hint is None and raw.startswith("[+] URL:"):
            m = re.search(r"URL:\s*(\S+)", raw)
            if m:
                site = m.group(1).rstrip("/")
        ipm = _IP_RE.search(raw)
        if ipm and target_ip is None:
            target_ip = ipm.group(1)

        wpm = _WP_VERSION_RE.search(raw)
        if wpm:
            flush_component()
            wp_version = wpm.group(1)
            # Capture core vulnerabilities that follow under the version block.
            section_type = "core"
            cur_name = "WordPress core"
            cur_version = wp_version
            continue

        # "Interesting Finding(s):" section header.
        if raw.strip().lower().startswith("interesting finding"):
            flush_component()
            section_type = "interesting"
            continue

        # Section header?
        sm = _SECTION_RE.search(raw)
        if sm:
            flush_component()
            label = sm.group(1).strip().lower()
            if "plugin" in label:
                section_type = "plugin"
            elif "theme" in label:
                section_type = "theme"
            elif "user" in label:
                section_type = "user"
            else:
                section_type = None
            continue

        # Lines that end any section / component block.
        if (raw.startswith("[+] Finished") or raw.startswith("[+] Started")
                or raw.startswith("[+] URL") or raw.startswith("[+] Requests")
                or raw.startswith("[+] Data") or raw.startswith("[+] Elapsed")
                or raw.startswith("[+] Memory")):
            flush_component()
            if raw.startswith("[+] Finished"):
                section_type = None
            continue

        # New component within a plugin/theme/user section.
        cm = _COMPONENT_RE.match(raw)
        if cm:
            name = cm.group(1).strip()
            # In a user section each [+] is a username → a low finding.
            if section_type == "user":
                flush_component()
                findings.append(_finding(
                    site, f"User enumerated: {name}", "user", name,
                    None, None, [], [], severity="low"))
                continue
            if section_type == "interesting":
                flush_component()
                low = name.lower()
                matched = next((entry for entry in _INTERESTING
                                if entry[0] in low), None)
                if matched:
                    _, sev, label = matched
                    url_ref = re.search(r"(https?://\S+)", name)
                    findings.append(_finding(
                        site, f"{label}: {name}", "exposure", name.split(":")[0],
                        None, None, [], [url_ref.group(1)] if url_ref else [],
                        severity=sev))
                # Non-matching interesting entries (e.g. Headers) are skipped;
                # the passive checks module covers headers/CORS more precisely.
                continue
            if section_type in ("plugin", "theme"):
                flush_component()
                cur_name = name
                continue

        # Inside a component block (guttered lines).
        body = _clean(raw)
        if not body:
            continue

        vm = _VERSION_RE.search(body)
        if vm and cur_name and cur_version is None:
            cur_version = vm.group(1)

        if ("out of date" in body.lower()
                or "the latest version is" in body.lower()):
            cur_outdated["v"] = True

        tm = _TITLE_RE.search(body)
        if tm:
            cur_vuln = {"title": tm.group(1).strip(), "fixed_in": None,
                        "cves": [], "refs": []}
            cur_vulns.append(cur_vuln)
            continue

        if cur_vuln is not None:
            fm = _FIXED_RE.search(body)
            if fm:
                cur_vuln["fixed_in"] = fm.group(1)
            cvem = _CVE_RE.search(body)
            if cvem:
                cur_vuln["cves"].append("CVE-" + cvem.group(1)
                                        if not cvem.group(1).upper().startswith("CVE")
                                        else cvem.group(1))
            um = _URL_REF_RE.search(body)
            if um:
                cur_vuln["refs"].append(um.group(1))

    flush_component()

    return {
        "site": site.rstrip("/"),
        "wp_version": wp_version,
        "target_ip": target_ip,
        "findings": findings,
    }
