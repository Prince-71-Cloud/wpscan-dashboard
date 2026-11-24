"""
checks.py
=========
Lightweight, *passive* web-hygiene checks that complement WPScan.

WPScan focuses on the WordPress core/plugin/theme vulnerability surface. It does
not, on its own, flag things like missing security headers, permissive CORS,
directory listing, or a handful of commonly-exposed sensitive files. These are
standard items on a WordPress review checklist, so this module adds them.

Scope and safety (deliberate limits):
  * Every check is an unauthenticated GET to a small, fixed set of paths, plus
    inspection of response headers. No login attempts, no brute forcing, no
    fuzzing with large wordlists, no exploitation — this is assessment of a
    site you are authorised to test, not an attack tool.
  * Requests are capped, short-timeout, and run with a small delay so the check
    is gentle on the target.
  * File probes do NOT follow redirects, and every "exposed file" finding
    requires the body to look like the file it claims to be. A catch-all page
    that answers 200 to everything must not turn into a critical finding in a
    client report.
  * Findings are emitted in the same shape as parser.py output, so they flow
    into the database, dashboard and report unchanged.

Only run this against systems you own or are explicitly authorised to test.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Callable
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
_HSTS_MIN_AGE = 15552000  # 180 days, the usual preload floor

# An Origin that no real site would allow. If the REST API echoes it back the
# site reflects arbitrary origins.
_CORS_PROBE_ORIGIN = "https://wpscan-console-cors-probe.invalid"


def _looks_html(body: bytes) -> bool:
    head = body[:2048].lower()
    return b"<html" in head or b"<!doctype html" in head


def _is_wp_config(b: bytes) -> bool:
    return b"DB_PASSWORD" in b or b"DB_NAME" in b or b"table_prefix" in b


def _is_env_file(b: bytes) -> bool:
    return not _looks_html(b) and re.search(rb"(?m)^[A-Z][A-Z0-9_]*=", b) is not None


def _is_debug_log(b: bytes) -> bool:
    return not _looks_html(b) and (
        b"PHP " in b or b"Stack trace" in b
        or re.search(rb"(?m)^\[\d{2}-[A-Za-z]{3}-\d{4}", b) is not None)


# Commonly-exposed sensitive paths. Kept small and curated on purpose — this is
# a hygiene check, not a backup-file brute-forcer.
# (path, severity, why, body validator)
_SENSITIVE_PATHS: list[tuple[str, str, str, Callable[[bytes], bool]]] = [
    ("/wp-content/debug.log", "medium", "WordPress debug log is publicly readable", _is_debug_log),
    ("/_wpeprivate/config.json", "high", "WP Engine private config exposed",
     lambda b: b.lstrip().startswith(b"{") and not _looks_html(b)),
    ("/wp-config.php.bak", "critical", "wp-config backup exposed (DB credentials)", _is_wp_config),
    ("/wp-config.php~", "critical", "wp-config backup exposed (DB credentials)", _is_wp_config),
    ("/wp-config.php.save", "critical", "wp-config backup exposed (DB credentials)", _is_wp_config),
    ("/wp-config.php.old", "critical", "wp-config backup exposed (DB credentials)", _is_wp_config),
    ("/wp-config.php.orig", "critical", "wp-config backup exposed (DB credentials)", _is_wp_config),
    ("/wp-config.txt", "critical", "wp-config copy exposed (DB credentials)", _is_wp_config),
    ("/.env", "high", "Environment file exposed (may hold secrets)", _is_env_file),
    ("/.git/HEAD", "high", "Git repository exposed (source and history downloadable)",
     lambda b: b.startswith(b"ref:") or re.fullmatch(rb"[0-9a-f]{40}\s*", b) is not None),
    ("/wp-links-opml.php", "info", "wp-links-opml.php reachable (info disclosure)",
     lambda b: b"<opml" in b.lower()),
    ("/readme.html", "info", "readme.html exposes the WordPress version",
     lambda b: b"wordpress" in b.lower()),
    ("/xmlrpc.php", "low", "xmlrpc.php enabled (pingback/brute-force surface)",
     lambda b: b"XML-RPC server accepts" in b),
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Make urllib raise HTTPError on 3xx instead of following it, so a probe
    for /wp-config.php.bak can't be bounced to an internal address or to a
    200 page elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _get(url: str, timeout: int, follow: bool = False,
         extra_headers: dict[str, str] | None = None):
    """Single GET. Returns (status, headers dict, body bytes, set-cookie list)
    or raises. Redirects are only followed for the homepage header audit."""
    hdrs = {"User-Agent": _UA}
    if extra_headers:
        hdrs.update(extra_headers)
    req = urllib.request.Request(url, method="GET", headers=hdrs)
    ctx = ssl.create_default_context()
    # We are assessing config, not validating trust; a self-signed cert should
    # not abort the hygiene scan (it becomes a TLS finding instead).
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers: list[Any] = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read(65536)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = resp.headers.get_all("Set-Cookie") or []
        return resp.status, headers, body, cookies


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
    # Hard wall-clock cap so a slow/blocked host can't stall the whole batch:
    # at most max_requests requests, but also stop after this many seconds.
    deadline = time.monotonic() + min(timeout * 4, 90)

    def request(path_or_url: str, follow: bool = False,
                extra_headers: dict[str, str] | None = None):
        if budget["n"] >= max_requests or time.monotonic() > deadline:
            return None
        budget["n"] += 1
        time.sleep(delay)
        target = path_or_url if "://" in path_or_url else base + path_or_url
        try:
            return _get(target, timeout=timeout, follow=follow,
                        extra_headers=extra_headers)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(65536)
            except Exception:  # noqa: BLE001 — body is optional on errors
                body = b""
            hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
            cookies = (e.headers.get_all("Set-Cookie") if e.headers else None) or []
            e.close()
            return (e.code, hdrs, body, cookies)
        except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError,
                ValueError):
            return None

    # --- 1. Homepage: security headers + CORS + disclosure -------------------
    home = request("/", follow=True)
    if home:
        status, headers, _, _ = home
        for key, (sev, label) in _SECURITY_HEADERS.items():
            if key not in headers:
                findings.append(_finding(
                    base, f"Missing security header: {label}", sev,
                    ctype="headers", cname="response headers"))
        hsts = headers.get("strict-transport-security")
        if hsts:
            findings.extend(_hsts_findings(base, hsts))
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
        if server and re.search(r"\d", server):
            findings.append(_finding(
                base, f"Server software version disclosed via Server: {server}",
                "info", ctype="disclosure", cname="headers"))
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
        # Is the plain-HTTP origin still serving content instead of redirecting?
        plain = request(f"http://{parsed.netloc}/")
        if plain and plain[0] == 200:
            findings.append(_finding(
                base, "Plain HTTP is served without redirecting to HTTPS",
                "low", ctype="tls", cname="transport",
                references=[f"http://{parsed.netloc}/"]))

    # --- 3. Sensitive / commonly-exposed files ------------------------------
    for path, sev, why, looks_right in _SENSITIVE_PATHS:
        r = request(path)
        if not r:
            continue
        status, headers, body, _ = r
        if status == 200 and body and looks_right(body):
            findings.append(_finding(
                base, f"{why}: {path}", sev, ctype="exposure", cname=path,
                references=[base + path]))

    # --- 4. Directory listing -----------------------------------------------
    for d in _LISTING_DIRS:
        r = request(d)
        if not r:
            continue
        status, headers, body, _ = r
        if status == 200 and (b"Index of /" in body or b"<title>Index of" in body):
            findings.append(_finding(
                base, f"Directory listing enabled: {d}", "medium",
                ctype="exposure", cname=d, references=[base + d]))

    # --- 5. REST API user enumeration + CORS reflection ---------------------
    for path in ("/wp-json/wp/v2/users",
                 "/?rest_route=/wp/v2/users",
                 "/wp-json/wp/v2/users/1"):
        r = request(path)
        if not r:
            continue
        status, headers, body, _ = r
        ctype = headers.get("content-type", "")
        if status == 200 and "json" in ctype and (b'"slug"' in body or b'"name"' in body):
            findings.append(_finding(
                base, f"User enumeration via REST API: {path}", "low",
                ctype="enumeration", cname="wp-json",
                references=[base + path]))
            break  # one hit is enough; the endpoint is exposed

    # Does the REST API echo an arbitrary Origin? (The homepage check above
    # only sees a static '*'; reflection needs an Origin to reflect.)
    r = request("/wp-json/", extra_headers={"Origin": _CORS_PROBE_ORIGIN})
    if r:
        status, headers, _, _ = r
        acao = headers.get("access-control-allow-origin", "")
        if acao == _CORS_PROBE_ORIGIN:
            acac = headers.get("access-control-allow-credentials", "").lower() == "true"
            findings.append(_finding(
                base,
                "REST API reflects arbitrary Origin in Access-Control-Allow-Origin"
                + (" with credentials allowed" if acac else ""),
                "high" if acac else "medium", ctype="cors", cname="CORS",
                references=[base + "/wp-json/"]))

    # --- 6. Login page reachable + cookie flags -----------------------------
    r = request("/wp-login.php")
    if r and r[0] == 200 and b"user_login" in r[2]:
        findings.append(_finding(
            base, "Admin login page reachable: /wp-login.php (no IP/WAF gating)",
            "info", ctype="exposure", cname="/wp-login.php",
            references=[base + "/wp-login.php"]))
    if r:
        findings.extend(_cookie_findings(base, r[3], https=parsed.scheme == "https"))

    return findings


def _hsts_findings(base: str, value: str) -> list[dict[str, Any]]:
    out = []
    low = value.lower()
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    age = int(m.group(1)) if m else 0
    if age < _HSTS_MIN_AGE:
        out.append(_finding(
            base, f"HSTS max-age is too short ({age}s; recommended ≥ {_HSTS_MIN_AGE}s)",
            "low", ctype="headers", cname="response headers"))
    if "includesubdomains" not in low:
        out.append(_finding(
            base, "HSTS lacks includeSubDomains", "info",
            ctype="headers", cname="response headers"))
    return out


def _cookie_findings(base: str, set_cookies: list[str], https: bool) -> list[dict[str, Any]]:
    """Flag session-relevant cookies set without Secure / HttpOnly / SameSite."""
    missing: dict[str, list[str]] = {"Secure": [], "HttpOnly": [], "SameSite": []}
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        if not name:
            continue
        attrs = raw.lower()
        if https and "secure" not in attrs:
            missing["Secure"].append(name)
        if "httponly" not in attrs:
            missing["HttpOnly"].append(name)
        if "samesite" not in attrs:
            missing["SameSite"].append(name)
    out = []
    for flag, names in missing.items():
        if names:
            out.append(_finding(
                base, f"Cookie(s) set without {flag} flag: {', '.join(sorted(set(names))[:5])}",
                "low" if flag != "SameSite" else "info",
                ctype="headers", cname="cookies",
                references=[base + "/wp-login.php"]))
    return out


def _tls_summary(host: str | None, port: int, timeout: int) -> list[tuple[str, str]]:
    """TLS posture: certificate validity and expiry, and whether the server
    still accepts legacy protocol versions. The default client context refuses
    TLS 1.0/1.1 itself, so a plain handshake can never observe them — each
    legacy version is probed with a context pinned to that version."""
    out: list[tuple[str, str]] = []
    if not host:
        return out
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert() or {}
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        secs = ssl.cert_time_to_seconds(not_after) - time.time()
                        days = int(secs // 86400)
                        if days < 14:
                            out.append(("medium", f"TLS certificate expires in "
                                                  f"{days} day(s) ({not_after})"))
                        elif days < 30:
                            out.append(("low", f"TLS certificate expires in "
                                               f"{days} day(s) ({not_after})"))
                    except ValueError:
                        pass
    except ssl.SSLCertVerificationError as e:
        out.append(("medium", f"TLS certificate problem: {e.verify_message}"))
    except (ssl.SSLError, socket.timeout, OSError):
        # Unreachable/handshake failure isn't itself a finding here.
        return out

    for version, name in ((ssl.TLSVersion.TLSv1, "TLSv1.0"),
                          (ssl.TLSVersion.TLSv1_1, "TLSv1.1")):
        try:
            legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            legacy.check_hostname = False
            legacy.verify_mode = ssl.CERT_NONE
            legacy.minimum_version = version
            legacy.maximum_version = version
            try:
                legacy.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with legacy.wrap_socket(sock, server_hostname=host) as ss:
                    if ss.version():
                        out.append(("medium", f"Legacy TLS protocol accepted: {name}"))
        except (ssl.SSLError, ValueError, socket.timeout, OSError):
            pass  # refused (or unsupported by local OpenSSL) — that's the good case
    return out
