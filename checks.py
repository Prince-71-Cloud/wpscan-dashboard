"""
checks.py
=========
Lightweight, *passive* web-hygiene checks that complement WPScan.

WPScan focuses on the WordPress core/plugin/theme vulnerability surface. It does
not, on its own, flag things like missing security headers, permissive CORS,
directory listing, or a handful of commonly-exposed sensitive files. These are
standard items on a WordPress review checklist, so this module adds them.

Scope and safety (deliberate limits):
  * Every check is an unauthenticated GET/HEAD to a small, fixed set of paths,
    plus inspection of response headers. No login attempts, no brute forcing,
    no fuzzing with large wordlists, no exploitation — this is assessment of a
    site you are authorised to test, not an attack tool.
  * Requests are capped, short-timeout, and run with a small delay so the check
    is gentle on the target.
  * Findings are emitted in the same shape as parser.py output, so they flow
    into the database, dashboard and report unchanged.

Only run this against systems you own or are explicitly authorised to test.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# Recommended response headers and the severity of their absence.
_SECURITY_HEADERS = {
    "content-security-policy": ("low", "Content-Security-Policy"),
    "x-frame-options": ("low", "X-Frame-Options (clickjacking)"),
    "x-content-type-options": ("info", "X-Content-Type-Options (MIME sniffing)"),
    "strict-transport-security": ("low", "Strict-Transport-Security (HSTS)"),
    "referrer-policy": ("info", "Referrer-Policy"),
    "permissions-policy": ("info", "Permissions-Policy"),
}

# Commonly-exposed sensitive paths. Kept small and curated on purpose — this is
# a hygiene check, not a backup-file brute-forcer. (site, severity, why).
_SENSITIVE_PATHS = [
    ("/wp-content/debug.log", "medium", "WordPress debug log is publicly readable"),
    ("/_wpeprivate/config.json", "high", "WP Engine private config exposed"),
    ("/wp-config.php.bak", "critical", "wp-config backup exposed (DB credentials)"),
    ("/wp-config.php~", "critical", "wp-config backup exposed (DB credentials)"),
    ("/wp-config.php.save", "critical", "wp-config backup exposed (DB credentials)"),
    ("/wp-config.txt", "critical", "wp-config copy exposed (DB credentials)"),
    ("/.env", "high", "Environment file exposed (may hold secrets)"),
    ("/wp-links-opml.php", "info", "wp-links-opml.php reachable (info disclosure)"),
    ("/readme.html", "info", "readme.html exposes the WordPress version"),
    ("/xmlrpc.php", "low", "xmlrpc.php enabled (pingback/brute-force surface)"),
]

# Directories to test for listing enabled.
_LISTING_DIRS = ["/wp-content/uploads/", "/wp-includes/", "/wp-content/plugins/"]


def _finding(site: str, title: str, severity: str, ctype: str = "web",
             cname: str = "", references: list[str] | None = None) -> dict[str, Any]:
    """Build a finding record matching parser.py's shape."""
    return {
        "site": site.rstrip("/"),
        "finding_kind": "hygiene",
        "component_type": ctype,
        "component_name": cname or "http",
        "component_version": None,
        "title": title,
        "severity": severity,
        "cvss": None,
        "fixed_in": None,
        "cves": [],
        "references": references or [],
    }


def _get(url: str, timeout: int, method: str = "GET"):
    """Single request. Returns (status, headers dict, body bytes) or raises."""
    req = urllib.request.Request(url, method=method, headers={"User-Agent": _UA})
    ctx = ssl.create_default_context()
    # We are assessing config, not validating trust; a self-signed cert should
    # not abort the hygiene scan (it becomes a TLS finding instead).
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        body = resp.read(65536) if method == "GET" else b""
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, headers, body


def run_passive_checks(
    url: str,
    timeout: int = 10,
    delay: float = 0.3,
    max_requests: int = 40,
) -> list[dict[str, Any]]:
    """Run the passive hygiene checks against `url`. Never raises; on network
    failure it simply returns whatever it managed to collect."""
    base = url.rstrip("/")
    parsed = urlparse(base)
    findings: list[dict[str, Any]] = []
    budget = {"n": 0}

    def request(path: str, method: str = "GET"):
        if budget["n"] >= max_requests:
            return None
        budget["n"] += 1
        time.sleep(delay)
        try:
            return _get(base + path, timeout=timeout, method=method)
        except urllib.error.HTTPError as e:
            return (e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, b"")
        except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
            return None

    # --- 1. Homepage: security headers + CORS -------------------------------
    home = request("/")
    if home:
        status, headers, _ = home
        for key, (sev, label) in _SECURITY_HEADERS.items():
            if key not in headers:
                findings.append(_finding(
                    base, f"Missing security header: {label}", sev,
                    ctype="headers", cname="response headers"))
        acao = headers.get("access-control-allow-origin")
        if acao == "*":
            acac = (headers.get("access-control-allow-credentials", "")
                    .lower() == "true")
            findings.append(_finding(
                base,
                "Permissive CORS: Access-Control-Allow-Origin is '*'"
                + (" with credentials allowed" if acac else ""),
                "medium" if acac else "low", ctype="cors", cname="CORS"))
        server = headers.get("server")
        powered = headers.get("x-powered-by")
        if powered:
            findings.append(_finding(
                base, f"Server technology disclosed via X-Powered-By: {powered}",
                "info", ctype="disclosure", cname="headers"))

    # --- 2. TLS / HTTPS posture ---------------------------------------------
    if parsed.scheme == "http":
        findings.append(_finding(
            base, "Site served over HTTP; traffic is unencrypted", "medium",
            ctype="tls", cname="transport"))
    elif parsed.scheme == "https":
        tls = _tls_summary(parsed.hostname, parsed.port or 443, timeout)
        findings.extend(_finding(base, t, sev, ctype="tls", cname="transport")
                        for sev, t in tls)

    # --- 3. Sensitive / commonly-exposed files ------------------------------
    for path, sev, why in _SENSITIVE_PATHS:
        r = request(path, method="GET")
        if not r:
            continue
        status, headers, body = r
        if status == 200 and body:
            # xmlrpc responds 200 to GET with a hint string; treat specially.
            if path == "/xmlrpc.php" and b"XML-RPC server accepts" not in body:
                continue
            findings.append(_finding(
                base, f"{why}: {path}", sev, ctype="exposure", cname=path,
                references=[base + path]))

    # --- 4. Directory listing -----------------------------------------------
    for d in _LISTING_DIRS:
        r = request(d, method="GET")
        if not r:
            continue
        status, headers, body = r
        if status == 200 and (b"Index of /" in body or b"<title>Index of" in body):
            findings.append(_finding(
                base, f"Directory listing enabled: {d}", "medium",
                ctype="exposure", cname=d, references=[base + d]))

    # --- 5. REST API user enumeration ---------------------------------------
    for path in ("/wp-json/wp/v2/users",
                 "/?rest_route=/wp/v2/users",
                 "/wp-json/wp/v2/users/1"):
        r = request(path, method="GET")
        if not r:
            continue
        status, headers, body = r
        ctype = headers.get("content-type", "")
        if status == 200 and "json" in ctype and (b'"slug"' in body or b'"name"' in body):
            findings.append(_finding(
                base, f"User enumeration via REST API: {path}", "low",
                ctype="enumeration", cname="wp-json",
                references=[base + path]))
            break  # one hit is enough; the endpoint is exposed

    # --- 6. Login page reachable --------------------------------------------
    r = request("/wp-login.php", method="GET")
    if r and r[0] == 200 and b"user_login" in r[2]:
        findings.append(_finding(
            base, "Admin login page reachable: /wp-login.php (no IP/WAF gating)",
            "info", ctype="exposure", cname="/wp-login.php",
            references=[base + "/wp-login.php"]))

    return findings


def _tls_summary(host: str | None, port: int, timeout: int) -> list[tuple[str, str]]:
    """Very small TLS posture check: reachable? expired? weak protocol?"""
    out: list[tuple[str, str]] = []
    if not host:
        return out
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                proto = ss.version()  # e.g. TLSv1.2 / TLSv1.3
                if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
                    out.append(("medium", f"Weak TLS protocol negotiated: {proto}"))
    except ssl.SSLCertVerificationError as e:
        out.append(("medium", f"TLS certificate problem: {e.verify_message}"))
    except (ssl.SSLError, socket.timeout, OSError):
        # Unreachable/handshake failure isn't itself a finding here.
        pass
    return out
