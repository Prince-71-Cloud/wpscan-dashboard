"""
remediation.py
==============
Turns a finding into something a developer can act on: one concrete action,
ordered steps, and copy-paste snippets for the usual stacks (WordPress /
PHP, Nginx, Apache, WP-CLI). Findings are also grouped into an *action plan*
("update contact-form-7" closes four rows at once) so a report reads as a
to-do list rather than a wall of CVEs.

Nothing here is stored: remediation is derived from the finding at read time
(`attach()`), so improving a rule improves every existing report. Rules are
matched in order; the first match wins; `_generic` is the fallback.

Each remediation dict has the same shape:
    {
      "action_key": "update:plugin:contact-form-7",   # grouping key
      "action":     "Update contact-form-7 to 5.3.2 or later",
      "steps":      ["...", "..."],
      "snippets":   {"WP-CLI": "wp plugin update contact-form-7"},
      "references": ["https://..."],
    }
"""

from __future__ import annotations

import re
from typing import Any, Callable

from parser import SEVERITY_RANK

# --------------------------------------------------------------------------- #
# Snippet library
# --------------------------------------------------------------------------- #
_HEADER_VALUES = {
    "content-security-policy": (
        "Content-Security-Policy-Report-Only",
        "default-src 'self'; img-src 'self' data: https:; script-src 'self' "
        "'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'",
        "Start in Report-Only mode: WordPress themes and plugins rely on inline "
        "scripts/styles, so tighten the policy from the violation reports before "
        "switching to the enforcing header name.",
    ),
    "x-frame-options": ("X-Frame-Options", "SAMEORIGIN",
                        "Or use CSP frame-ancestors, which supersedes it."),
    "x-content-type-options": ("X-Content-Type-Options", "nosniff", ""),
    "strict-transport-security": (
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains",
        "Only once every subdomain serves valid HTTPS; HSTS cannot be undone "
        "quickly for visitors who already received it."),
    "referrer-policy": ("Referrer-Policy", "strict-origin-when-cross-origin", ""),
    "permissions-policy": ("Permissions-Policy",
                           "camera=(), microphone=(), geolocation=()", ""),
}


def _header_snippets(name: str, value: str) -> dict[str, str]:
    return {
        "Nginx (server block)": f'add_header {name} "{value}" always;',
        "Apache (.htaccess or vhost)": f'Header always set {name} "{value}"',
        "PHP (theme functions.php / mu-plugin)":
            f"add_action('send_headers', function () {{\n"
            f"    header('{name}: {value}');\n}});",
    }


_DENY_SENSITIVE = {
    "Nginx (server block)":
        "location ~* (^|/)\\.(env|git|svn|htaccess)|\\.(bak|old|orig|save|swp|sql|"
        "sql\\.gz|zip|tar\\.gz|log)$ {\n    deny all;\n    return 404;\n}",
    "Apache (.htaccess)":
        "<FilesMatch \"(^\\.env|^\\.git|\\.(bak|old|orig|save|swp|sql|zip|tar\\.gz|log)$)\">\n"
        "    Require all denied\n</FilesMatch>",
}

_WP_CONFIG_HARDEN = (
    "// wp-config.php\n"
    "define('DISALLOW_FILE_EDIT', true);   // no code editor in wp-admin\n"
    "define('WP_DEBUG', false);\n"
    "define('WP_DEBUG_DISPLAY', false);\n"
    "define('WP_DEBUG_LOG', '/var/log/wordpress/debug.log'); // outside the web root"
)


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
def _rem(action_key: str, action: str, steps: list[str],
         snippets: dict[str, str] | None = None,
         references: list[str] | None = None) -> dict[str, Any]:
    return {"action_key": action_key, "action": action, "steps": steps,
            "snippets": snippets or {}, "references": references or []}


def _component_update(f: dict[str, Any]) -> dict[str, Any] | None:
    ctype = f.get("component_type")
    if ctype not in ("plugin", "theme", "core"):
        return None
    name = f.get("component_name") or ctype
    ver = f.get("component_version")
    fixed = f.get("fixed_in")
    installed = f" (installed: {ver})" if ver else " (version not detected)"
    refs = [r for r in (f.get("references") or []) if str(r).startswith("http")]
    if ctype == "core":
        key = "update:core"
        if fixed:
            action = f"Update WordPress core to {fixed} or later{installed}"
        else:
            action = f"Update WordPress core to the current release{installed}"
        return _rem(key, action, [
            "Back up the database and files, then update on staging first.",
            "Update from Dashboard → Updates, or with WP-CLI.",
            "Enable automatic minor/security updates so this does not recur.",
            "Re-scan to confirm the version WPScan detects has changed.",
        ], {
            "WP-CLI": "wp core update && wp core update-db",
            "wp-config.php": "define('WP_AUTO_UPDATE_CORE', 'minor');",
        }, refs)
    kind = "plugin" if ctype == "plugin" else "theme"
    key = f"update:{kind}:{name}"
    if f.get("finding_kind") == "outdated":
        action = f"Update {kind} {name}{installed}"
        if fixed:
            action = f"Update {kind} {name} to {fixed}{installed}"
    elif fixed:
        action = f"Update {kind} {name} to {fixed} or later{installed}"
    else:
        action = f"Remove or replace {kind} {name}: no fixed version is published{installed}"
    steps = [
        "Confirm the installed version in wp-admin (the scanner's version "
        "detection can lag) and read the advisory for the affected range.",
    ]
    if fixed:
        steps += [
            f"Update {name} to {fixed} or later on staging, run a smoke test, then "
            f"update production.",
            "If the update cannot be applied immediately, deactivate the "
            f"{kind} or virtual-patch the vulnerable request at the WAF.",
        ]
    else:
        steps += [
            f"Deactivate and delete {name}; a {kind} with an unfixed public "
            f"vulnerability is a standing liability.",
            "If it is business-critical, isolate it: WAF rule for the vulnerable "
            "endpoint, restrict the capability it needs, and track the vendor.",
        ]
    if (f.get("severity") in ("critical", "high")) or f.get("kev"):
        steps.append("Treat the site as possibly compromised: review recent admin "
                     "users, uploads and modified files, and rotate credentials "
                     "if anything looks wrong.")
    steps.append("Re-scan to confirm the finding is marked fixed.")
    snippets = {
        "WP-CLI": (f"wp {kind} update {name}" if fixed
                   else f"wp {kind} deactivate {name} && wp {kind} delete {name}"),
    }
    return _rem(key, action, steps, snippets, refs)


def _rule(pattern: str, ctypes: tuple[str, ...] | None = None):
    rx = re.compile(pattern, re.I)

    def match(f: dict[str, Any]) -> bool:
        if ctypes and f.get("component_type") not in ctypes:
            return False
        return bool(rx.search(f.get("title") or ""))
    return match


def _headers_rule(f: dict[str, Any]) -> dict[str, Any] | None:
    t = (f.get("title") or "").lower()
    if not t.startswith("missing security header"):
        return None
    for key, (name, value, note) in _HEADER_VALUES.items():
        if key in t:
            steps = [f"Send `{name}` on every response, ideally from the web "
                     f"server or CDN so it also covers static files."]
            if note:
                steps.append(note)
            steps.append("Verify with: curl -sI https://your-site/ | grep -i "
                         f"{name.split('-')[0]}")
            return _rem("headers", "Add the missing security response headers",
                        steps, _header_snippets(name, value),
                        ["https://owasp.org/www-project-secure-headers/"])
    return None


_RULES: list[tuple[Callable[[dict[str, Any]], bool], Callable[[dict[str, Any]], dict[str, Any]]]] = []


def rule(pattern: str, ctypes: tuple[str, ...] | None = None):
    def deco(fn):
        _RULES.append((_rule(pattern, ctypes), fn))
        return fn
    return deco


@rule(r"hsts (max-age|lacks)")
def _hsts_quality(f):
    return _rem("headers", "Add the missing security response headers", [
        "Raise HSTS to at least one year and include subdomains once every "
        "subdomain serves valid HTTPS.",
    ], _header_snippets("Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains"))


@rule(r"wp-config|_wpeprivate|config backups?")
def _wp_config_exposed(f):
    url = next((r for r in f.get("references") or [] if str(r).startswith("http")), None)
    return _rem("remove-exposed-files", "Remove exposed backup/config files and rotate the secrets they contain", [
        "Delete the file from the web root now (and from any backups that are "
        "served from it).",
        "Assume the database credentials, AUTH keys/salts and any API keys in "
        "it are compromised: rotate the DB password, regenerate salts "
        "(https://api.wordpress.org/secret-key/1.1/salt/) and rotate third-party keys.",
        "Check the database for unexpected admin users and the uploads "
        "directory for PHP files.",
        "Block editor/backup suffixes at the web server so the next stray copy "
        "is not served.",
        "Keep backups outside the web root; never let wp-config.php be copied "
        "with a .bak/.old/~ suffix in place.",
    ], _DENY_SENSITIVE, [url] if url else [])


@rule(r"db exports?|database export|\.sql\b")
def _db_export(f):
    url = next((r for r in f.get("references") or [] if str(r).startswith("http")), None)
    return _rem("remove-exposed-files", "Remove exposed backup/config files and rotate the secrets they contain", [
        "Delete the database dump from the web root immediately.",
        "Treat every credential in that database as leaked: force a password "
        "reset for all users, rotate API keys and tokens stored in options, "
        "regenerate salts to invalidate sessions.",
        "Review the dump's age: anything added since is still exposed if the "
        "export job keeps running — fix the backup job to write outside the web root.",
        "Block .sql/.zip/.tar.gz downloads at the web server.",
    ], _DENY_SENSITIVE, [url] if url else [])


@rule(r"\.env\b|environment file")
def _env_exposed(f):
    return _rem("remove-exposed-files", "Remove exposed backup/config files and rotate the secrets they contain", [
        "Move the .env file outside the document root (or delete it if unused).",
        "Rotate every secret it contains (database, mail, API keys).",
        "Deny dotfiles at the web server.",
    ], _DENY_SENSITIVE)


@rule(r"\.git|git repository")
def _git_exposed(f):
    return _rem("remove-exposed-files", "Remove exposed backup/config files and rotate the secrets they contain", [
        "Remove the .git directory from the document root (deploy from a build "
        "artifact, or point the web root at a subdirectory).",
        "Assume the full source and history are public: rotate any secret that "
        "was ever committed.",
        "Deny access to /.git at the web server.",
    ], _DENY_SENSITIVE)


@rule(r"debug\.?log|debug log")
def _debug_log(f):
    return _rem("remove-exposed-files", "Remove exposed backup/config files and rotate the secrets they contain", [
        "Delete /wp-content/debug.log and disable WP_DEBUG in production.",
        "If logging is needed, point WP_DEBUG_LOG at a path outside the web root "
        "and keep WP_DEBUG_DISPLAY off.",
        "Deny *.log at the web server.",
    ], {"wp-config.php": _WP_CONFIG_HARDEN, **_DENY_SENSITIVE})


@rule(r"directory listing|listing enabled")
def _listing(f):
    return _rem("directory-listing", "Disable directory listing", [
        "Turn off automatic indexes at the web server.",
        "Add an empty index.php to upload and plugin directories as a fallback "
        "(WordPress ships one for wp-content/plugins; check uploads).",
    ], {
        "Nginx": "autoindex off;",
        "Apache (.htaccess)": "Options -Indexes",
    })


@rule(r"xml-?rpc")
def _xmlrpc(f):
    return _rem("xmlrpc", "Disable XML-RPC unless Jetpack or a mobile app needs it", [
        "Disable XML-RPC in WordPress and block the endpoint at the web server "
        "(it is the usual brute-force and pingback-amplification surface).",
        "If a client genuinely needs it, allow-list that client's IP only.",
    ], {
        "PHP (mu-plugin)": "add_filter('xmlrpc_enabled', '__return_false');",
        "Nginx": "location = /xmlrpc.php { deny all; return 404; }",
        "Apache (.htaccess)": "<Files xmlrpc.php>\n    Require all denied\n</Files>",
    })


@rule(r"user enumerat|username\(s\) enumerable|user enumerated", None)
def _user_enum(f):
    return _rem("user-enumeration", "Stop anonymous user enumeration", [
        "Block unauthenticated access to the REST users endpoint and the "
        "?author=N redirect; both leak login names.",
        "Make sure display names differ from login names, and that no account "
        "is literally 'admin'.",
        "Pair this with rate limiting / 2FA on wp-login.php: enumeration only "
        "matters because it feeds password guessing.",
    ], {
        "PHP (mu-plugin)":
            "add_filter('rest_endpoints', function ($endpoints) {\n"
            "    if (!is_user_logged_in()) {\n"
            "        unset($endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\\d]+)']);\n"
            "    }\n    return $endpoints;\n});\n"
            "add_action('template_redirect', function () {\n"
            "    if (is_author() && !is_user_logged_in()) { wp_safe_redirect(home_url(), 301); exit; }\n});",
        "Nginx": "if ($args ~* \"author=\\d\") { return 403; }",
    })


@rule(r"login page reachable|wp-login")
def _login(f):
    return _rem("login-hardening", "Harden the admin login", [
        "Restrict /wp-login.php and /wp-admin to known IP ranges or a VPN "
        "where the team allows it.",
        "Enforce two-factor authentication for every Administrator and Editor.",
        "Rate-limit login attempts at the web server or WAF (fail2ban reads "
        "the auth log; most WAFs have a wp-login rule).",
        "Keep FORCE_SSL_ADMIN on so credentials never travel in clear text.",
    ], {
        "wp-config.php": "define('FORCE_SSL_ADMIN', true);",
        "Nginx (IP allow-list)":
            "location = /wp-login.php {\n    allow 203.0.113.0/24;\n    deny all;\n"
            "    include fastcgi_params; # your usual PHP handler\n}",
    })


@rule(r"readme\.html|wordpress version", None)
def _readme(f):
    return _rem("version-disclosure", "Remove version disclosure", [
        "Delete readme.html and license.txt from the web root after every core "
        "update (or deny them at the web server).",
        "Remove the generator meta tag; note this is cosmetic — keeping core "
        "updated is the real fix.",
    ], {
        "PHP (mu-plugin)": "remove_action('wp_head', 'wp_generator');",
        "Nginx": "location ~* ^/(readme\\.html|license\\.txt)$ { return 404; }",
    })


@rule(r"version disclosed|x-powered-by|server software")
def _server_disclosure(f):
    return _rem("version-disclosure", "Remove version disclosure", [
        "Stop advertising web-server and PHP versions in response headers.",
    ], {
        "Nginx": "server_tokens off;",
        "Apache": "ServerTokens Prod\nServerSignature Off\nHeader unset X-Powered-By",
        "php.ini": "expose_php = Off",
    })


@rule(r"cookie\(s\) set without")
def _cookies(f):
    return _rem("cookies", "Set Secure, HttpOnly and SameSite on cookies", [
        "WordPress auth cookies are HttpOnly by default; flags are usually "
        "missing on cookies set by plugins or by PHP sessions. Fix them at the "
        "source or rewrite Set-Cookie at the proxy.",
        "Serve the whole site over HTTPS so the Secure flag can be set everywhere.",
    ], {
        "Nginx (proxy)": "proxy_cookie_flags ~ secure httponly samesite=lax;",
        "Apache": "Header edit Set-Cookie ^(.*)$ \"$1; HttpOnly; Secure; SameSite=Lax\"",
        "php.ini": "session.cookie_secure = 1\nsession.cookie_httponly = 1\n"
                   "session.cookie_samesite = Lax",
    })


@rule(r"cors|origin")
def _cors(f):
    return _rem("cors", "Restrict cross-origin access", [
        "Never reflect the request Origin, and never combine '*' with "
        "Access-Control-Allow-Credentials: true.",
        "Allow-list the exact origins that need the REST API; everything else "
        "gets no CORS headers at all.",
        "Check plugins that add CORS headers (headless/front-end frameworks "
        "often ship a reflect-everything snippet).",
    ], {
        "PHP (mu-plugin)":
            "add_action('rest_api_init', function () {\n"
            "    remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');\n"
            "    add_filter('rest_pre_serve_request', function ($value) {\n"
            "        $allowed = ['https://app.example.com'];\n"
            "        $origin  = get_http_origin();\n"
            "        if ($origin && in_array($origin, $allowed, true)) {\n"
            "            header('Access-Control-Allow-Origin: ' . esc_url_raw($origin));\n"
            "            header('Vary: Origin');\n        }\n        return $value;\n"
            "    });\n}, 15);",
    })


@rule(r"served over http|plain http", ("tls",))
def _http_only(f):
    return _rem("tls", "Serve the site over HTTPS only", [
        "Obtain a certificate (Let's Encrypt via certbot is free and automatic).",
        "Redirect all HTTP to HTTPS with a 301, then set the WordPress home and "
        "site URLs to https:// and enable FORCE_SSL_ADMIN.",
        "Fix mixed content (http:// assets in the database) with wp search-replace.",
        "Add HSTS once everything works over HTTPS.",
    ], {
        "Nginx": "server {\n    listen 80;\n    server_name example.com www.example.com;\n"
                 "    return 301 https://$host$request_uri;\n}",
        "WP-CLI": "wp search-replace 'http://example.com' 'https://example.com' --skip-columns=guid",
        "wp-config.php": "define('FORCE_SSL_ADMIN', true);",
    })


@rule(r"legacy tls|weak tls", ("tls",))
def _legacy_tls(f):
    return _rem("tls", "Serve the site over HTTPS only", [
        "Disable TLS 1.0 and 1.1; keep 1.2 and 1.3 with a modern cipher list "
        "(Mozilla 'intermediate' profile).",
    ], {
        "Nginx": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;",
        "Apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
    }, ["https://ssl-config.mozilla.org/"])


@rule(r"certificate", ("tls",))
def _certificate(f):
    return _rem("tls", "Serve the site over HTTPS only", [
        "Renew or replace the certificate; make renewal automatic (certbot "
        "timer, or your CDN's managed certificate).",
        "Make sure the chain is complete and the name matches every hostname "
        "the site answers on (www and apex).",
    ], {"certbot": "certbot renew --dry-run"})


@rule(r"wp-cron")
def _wp_cron(f):
    return _rem("wp-cron", "Run WP-Cron from the system scheduler", [
        "Disable the visitor-triggered cron and call wp-cron.php from a real "
        "cron job every few minutes; this removes a cheap DoS lever and makes "
        "scheduled tasks reliable.",
    ], {
        "wp-config.php": "define('DISABLE_WP_CRON', true);",
        "crontab": "*/5 * * * * curl -s https://example.com/wp-cron.php?doing_wp_cron >/dev/null 2>&1",
    })


@rule(r"registration")
def _registration(f):
    return _rem("registration", "Close open user registration", [
        "Settings → General → untick 'Anyone can register' unless the site "
        "needs public accounts; if it does, set the default role to Subscriber "
        "and add CAPTCHA + email verification.",
    ], {"WP-CLI": "wp option update users_can_register 0"})


@rule(r"flagged insecure|is outdated")
def _outdated_generic(f):
    return _component_update(f) or _generic(f)


def _generic(f: dict[str, Any]) -> dict[str, Any]:
    refs = [r for r in (f.get("references") or []) if str(r).startswith("http")]
    return _rem("review", "Review the advisory and apply the vendor fix", [
        "Read the linked advisory for the affected versions and the vendor's fix.",
        "Apply the update or configuration change on staging, then production.",
        "Re-scan to confirm.",
    ], {}, refs)


def remediation_for(f: dict[str, Any]) -> dict[str, Any]:
    """Best remediation guidance for one finding (never None)."""
    if f.get("finding_kind") in ("vulnerability", "outdated") and \
            f.get("component_type") in ("plugin", "theme", "core"):
        rem = _component_update(f)
        if rem:
            return rem
    rem = _headers_rule(f)
    if rem:
        return rem
    for matches, builder in _RULES:
        if matches(f):
            return builder(f)
    return _generic(f)


def attach(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for f in findings:
        f["remediation"] = remediation_for(f)
    return findings


def action_plan(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group findings by action, worst severity first, then by how many rows
    one action closes. Each entry carries the steps/snippets of its first
    finding (rules in one group share them by construction)."""
    groups: dict[str, dict[str, Any]] = {}
    for f in findings:
        rem = f.get("remediation") or remediation_for(f)
        g = groups.get(rem["action_key"])
        if g is None:
            g = groups[rem["action_key"]] = {
                "action_key": rem["action_key"], "action": rem["action"],
                "severity": f.get("severity") or "info", "steps": rem["steps"],
                "snippets": rem["snippets"], "references": list(rem["references"]),
                "findings": [], "sites": set(),
            }
        if SEVERITY_RANK.get(f.get("severity"), 99) < SEVERITY_RANK.get(g["severity"], 99):
            g["severity"] = f["severity"]
        g["findings"].append({"id": f.get("id"), "site": f.get("site"),
                              "title": f.get("title"), "severity": f.get("severity")})
        g["sites"].add(f.get("site"))
        for r in rem["references"]:
            if r not in g["references"]:
                g["references"].append(r)
    out = list(groups.values())
    for g in out:
        g["sites"] = sorted(s for s in g["sites"] if s)
        g["count"] = len(g["findings"])
        g["references"] = g["references"][:5]
    out.sort(key=lambda g: (SEVERITY_RANK.get(g["severity"], 99), -g["count"], g["action"]))
    return out
