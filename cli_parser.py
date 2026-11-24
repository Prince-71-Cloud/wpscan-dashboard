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

from parser import EXPLOIT_REF_KINDS, classify_severity_ex, reference_url

# Section headers that change how following component blocks are interpreted.
_SECTION_RE = re.compile(r"^\[i\]\s+(.*?)\s+Identified", re.IGNORECASE)
# WPScan 4.x opens a section with "[+] Enumerating Vulnerable Plugins (...)"
# and prints the "[i] 2 plugin(s) Identified." count AFTER the list, so the
# count line must END a section, not start one.
_ENUM_RE = re.compile(r"^\[\+\]\s+Enumerating\s+(.*)", re.IGNORECASE)
_COUNT_RE = re.compile(r"^\[i\]\s+(\d+\s+.*Identified|No\s+.*Found)", re.IGNORECASE)
_REMAINING_RE = re.compile(r"Requests Remaining:\s*(\d+)", re.IGNORECASE)
_COMPONENT_RE = re.compile(r"^\[\+\]\s+(.+?)\s*$")
_VERSION_RE = re.compile(r"Version:\s*([0-9][^\s(]*)(?:\s*\((\d+)% confidence\))?")
_FOUND_BY_RE = re.compile(r"^(Found By|Confirmed By):\s*(.+)$")
_LOCATION_RE = re.compile(r"^Location:\s*(\S+)")
_WP_VERSION_RE = re.compile(r"WordPress version\s+([0-9][^\s]*)\s+identified", re.I)
_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
_TITLE_RE = re.compile(r"\[!\]\s*Title:\s*(.+?)\s*$")
_FIXED_RE = re.compile(r"Fixed in:\s*([0-9][^\s]*)")
_CVE_RE = re.compile(r"-\s*cve:\s*([0-9A-Za-z\-]+)", re.I)
_URL_REF_RE = re.compile(r"-\s*url:\s*(\S+)", re.I)
_OTHER_REF_RE = re.compile(r"-\s*(wpvulndb|exploitdb|metasploit|packetstorm):\s*(\S+)", re.I)
# "[+] WordPress theme in use: astra" — the main theme block follows the core
# block with no section header, so it needs its own trigger or its vulns get
# attributed to WordPress core.
_MAIN_THEME_RE = re.compile(r"^\[\+\]\s+WordPress theme in use:\s*(\S+)", re.I)
# Config backups / DB exports are listed as bare URL lines with a [!] icon
# ("[!] https://site/wp-config.php.bak"), never as "Title:" blocks.
_EXPOSED_URL_RE = re.compile(r"^\[!\]\s+(https?://\S+)")
# Same component_name / title shape as parser.py's JSON path, so a site scanned
# in both formats de-duplicates to one row.
_EXPOSURE_SECTIONS = {
    "config_backup": ("config_backups", "high"),
    "db_export":     ("db_exports", "critical"),
}

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
             severity: str | None = None,
             kind: str = "vulnerability",
             evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    sev, cvss, reason = classify_severity_ex(title)
    if severity is not None:
        sev = severity
        reason = f"fixed rating for this {kind} class"
    severity = sev
    return {
        "site": site.rstrip("/"),
        "finding_kind": kind,
        "component_type": ctype,
        "component_name": cname,
        "component_version": version,
        "title": title,
        "severity": severity,
        "cvss": cvss,
        "fixed_in": fixed_in,
        "cves": cves,
        "references": refs,
        "evidence": evidence or None,
        "severity_reason": reason,
    }


def _section_from_label(label: str) -> str | None:
    """Map an 'Enumerating ...' / '... Identified' label to a section type."""
    label = label.lower()
    if "plugin" in label:
        return "plugin"
    if "theme" in label:
        return "theme"
    if "user" in label:
        return "user"
    if "config backup" in label:
        return "config_backup"
    if "db export" in label:
        return "db_export"
    return None


class StreamingParser:
    """
    Incremental, line-by-line parser for WPScan cli-no-colour output.

    Feed one line at a time via `feed(line)`. Each time a complete finding is
    recognised it is immediately passed to `on_finding(finding_dict)` so it can
    be written to the database and appear in the UI *during* the scan rather than
    only after WPScan finishes.

    Call `result()` at the end to retrieve the full {site, wp_version, target_ip,
    findings} dict — the same shape that parse_cli returns.
    """

    def __init__(self, site_hint: str | None = None,
                 on_finding: "Callable[[dict], None] | None" = None):
        from typing import Callable  # noqa: F401 (type hint only)
        self.site        = site_hint or ""
        self.wp_version: str | None = None
        self.target_ip:  str | None = None
        self._findings:  list[dict[str, Any]] = []
        self._on_finding = on_finding

        self._section_type: str | None = None
        self._cur_name:    str | None = None
        self._cur_version: str | None = None
        self._cur_vulns:   list[dict[str, Any]] = []
        self._cur_vuln:    dict[str, Any] | None = None
        self._cur_outdated = False
        self._cur_evidence: dict[str, Any] = {}
        self.requests_remaining: int | None = None

    def _emit(self, f: dict[str, Any]) -> None:
        self._findings.append(f)
        if self._on_finding:
            self._on_finding(f)

    def _flush(self) -> None:
        ctype = self._section_type
        if self._cur_name and ctype in ("plugin", "theme", "core"):
            evidence = dict(self._cur_evidence) or None
            if self._cur_vulns:
                for v in self._cur_vulns:
                    self._emit(_finding(
                        self.site, v["title"], ctype, self._cur_name,
                        self._cur_version, v.get("fixed_in"),
                        v.get("cves", []),
                        v.get("refs", []) + v.get("exploits", []),
                        evidence=evidence))
            elif self._cur_outdated:
                f = _finding(
                    self.site,
                    f"{self._cur_name} {self._cur_version or ''} is outdated".strip(),
                    ctype, self._cur_name, self._cur_version,
                    None, [], [], severity="low", evidence=evidence)
                f["severity_reason"] = "outdated component with no known vulnerability"
                self._emit(f)
        self._cur_name    = None
        self._cur_version = None
        self._cur_vulns   = []
        self._cur_vuln    = None
        self._cur_outdated = False
        self._cur_evidence = {}

    def feed(self, raw: str) -> None:
        """Process one raw output line."""
        # URL / IP
        if self.site == "" and raw.startswith("[+] URL:"):
            m = re.search(r"URL:\s*(\S+)", raw)
            if m:
                self.site = m.group(1).rstrip("/")
        ipm = _IP_RE.search(raw)
        if ipm and self.target_ip is None:
            self.target_ip = ipm.group(1)

        # WordPress version line
        wpm = _WP_VERSION_RE.search(raw)
        if wpm:
            self._flush()
            self.wp_version      = wpm.group(1)
            self._section_type   = "core"
            self._cur_name       = "WordPress core"
            self._cur_version    = self.wp_version
            return

        # API quota left on the key ("| Requests Remaining: 23")
        rm = _REMAINING_RE.search(raw)
        if rm:
            self.requests_remaining = int(rm.group(1))

        # Interesting findings header
        if raw.strip().lower().startswith("interesting finding"):
            self._flush()
            self._section_type = "interesting"
            return

        # Main theme block (follows the core block without a section header)
        mt = _MAIN_THEME_RE.match(raw)
        if mt:
            self._flush()
            self._section_type = "theme"
            self._cur_name = mt.group(1).strip()
            return

        # "[+] Enumerating ..." starts a section (WPScan 4.x layout)
        em = _ENUM_RE.match(raw)
        if em:
            self._flush()
            self._section_type = _section_from_label(em.group(1))
            return

        # "[i] 2 plugin(s) Identified." / "[i] No themes Found." end a section
        if _COUNT_RE.match(raw):
            self._flush()
            self._section_type = None
            return

        # Section headers ("[i] Plugin(s) Identified:" — older layout, and
        # "[i] Config Backup(s) Identified:" in every layout)
        sm = _SECTION_RE.search(raw)
        if sm:
            self._flush()
            self._section_type = _section_from_label(sm.group(1))
            return

        # Exposed config backup / DB export URL lines
        if self._section_type in _EXPOSURE_SECTIONS:
            xm = _EXPOSED_URL_RE.match(raw)
            if xm:
                url = xm.group(1)
                bucket, sev = _EXPOSURE_SECTIONS[self._section_type]
                self._emit(_finding(
                    self.site, f"Exposed {bucket.replace('_', ' ')}: {url}",
                    "config", bucket, None, None, [], [url],
                    severity=sev, kind="exposure",
                    evidence={"url": url, "found_by": "Direct Access (Aggressive Detection)"}))
                return

        # End-of-section sentinels
        if (raw.startswith("[+] Finished") or raw.startswith("[+] Started")
                or raw.startswith("[+] URL") or raw.startswith("[+] Requests")
                or raw.startswith("[+] Data") or raw.startswith("[+] Elapsed")
                or raw.startswith("[+] Memory")
                or raw.startswith("[+] WPScan DB API")):
            self._flush()
            if raw.startswith(("[+] Finished", "[+] WPScan DB API")):
                self._section_type = None
            return

        # New component
        cm = _COMPONENT_RE.match(raw)
        if cm:
            name = cm.group(1).strip()
            if self._section_type == "user":
                self._flush()
                self._emit(_finding(self.site, f"User enumerated: {name}",
                                    "user", name, None, None, [], [],
                                    severity="low"))
                return
            if self._section_type == "interesting":
                self._flush()
                low = name.lower()
                matched = next((e for e in _INTERESTING if e[0] in low), None)
                if matched:
                    _, sev, label = matched
                    url_ref = re.search(r"(https?://\S+)", name)
                    self._emit(_finding(
                        self.site, f"{label}: {name}", "exposure",
                        name.split(":")[0], None, None, [],
                        [url_ref.group(1)] if url_ref else [], severity=sev,
                        evidence={"url": url_ref.group(1)} if url_ref else None))
                return
            if self._section_type in ("plugin", "theme"):
                self._flush()
                self._cur_name = name
                return

        # Guttered lines inside a component block
        body = _clean(raw)
        if not body:
            return

        vm = _VERSION_RE.search(body)
        if vm and self._cur_name and self._cur_version is None:
            self._cur_version = vm.group(1)
            if vm.group(2):
                self._cur_evidence["version_confidence"] = f"{vm.group(2)}%"
        if self._cur_name and self._cur_vuln is None:
            lm = _LOCATION_RE.match(body)
            if lm:
                self._cur_evidence["location"] = lm.group(1)
            fm0 = _FOUND_BY_RE.match(body)
            if fm0:
                key = "found_by" if fm0.group(1) == "Found By" else "confirmed_by"
                # the first Found By is the component's, a later one (after
                # Version:) belongs to the version detection
                if key == "found_by" and "found_by" in self._cur_evidence:
                    key = "version_found_by"
                self._cur_evidence.setdefault(key, fm0.group(2).strip())

        if ("out of date" in body.lower()
                or "the latest version is" in body.lower()):
            self._cur_outdated = True

        tm = _TITLE_RE.search(body)
        if tm:
            self._cur_vuln = {"title": tm.group(1).strip(),
                              "fixed_in": None, "cves": [], "refs": []}
            self._cur_vulns.append(self._cur_vuln)
            return

        if self._cur_vuln is not None:
            fm = _FIXED_RE.search(body)
            if fm:
                self._cur_vuln["fixed_in"] = fm.group(1)
            cvem = _CVE_RE.search(body)
            if cvem:
                cve = cvem.group(1)
                self._cur_vuln["cves"].append(
                    ("CVE-" + cve) if not cve.upper().startswith("CVE") else cve)
            um = _URL_REF_RE.search(body)
            if um:
                self._cur_vuln["refs"].append(um.group(1))
            om = _OTHER_REF_RE.search(body)
            if om:
                u = reference_url(om.group(1), om.group(2))
                if u:
                    # Exploit links go last so the first URL stays the advisory.
                    target = (self._cur_vuln.setdefault("exploits", [])
                              if om.group(1).lower() in EXPLOIT_REF_KINDS
                              else self._cur_vuln["refs"])
                    target.append(u)

    def finish(self) -> None:
        """Flush any component still in progress (call when output ends)."""
        self._flush()

    def result(self) -> dict[str, Any]:
        out = {
            "site":       self.site.rstrip("/"),
            "wp_version": self.wp_version,
            "target_ip":  self.target_ip,
            "findings":   self._findings,
        }
        if self.requests_remaining is not None:
            out["requests_remaining"] = self.requests_remaining
        return out


def parse_cli(text: str, site_hint: str | None = None) -> dict[str, Any]:
    """Parse a complete cli-no-colour WPScan output string. Delegates to
    StreamingParser so both paths share one implementation."""
    sp = StreamingParser(site_hint=site_hint)
    for line in (text or "").splitlines():
        sp.feed(line)
    sp.finish()
    return sp.result()
