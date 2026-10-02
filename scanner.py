"""
scanner.py
==========
Two ways to get data into the dashboard:

  1. run_wpscan(url)      -> shell out to the real `wpscan` CLI
  2. ingest_file(path)    -> load a WPScan JSON report already on disk

Plus a small ScanManager that runs a batch of scans on background threads so the
web request that triggers them returns immediately and the UI can poll status.

Design notes / error handling:
  * WPScan writes its JSON report to stdout even when it finds vulnerabilities
    (exit code 5) or when it errors on a target. We therefore always try to
    parse stdout as JSON first, and only treat things as a hard failure when
    there is no parseable JSON at all.
  * If the `wpscan` binary is missing, that is reported clearly rather than
    crashing the whole batch.
  * A per-site timeout stops one slow/unreachable target from hanging the batch.
"""

from __future__ import annotations

import json
import os
import re
import signal
import socket
import ssl
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from typing import Any, Callable

import parser as report_parser
from db import Database

# WPScan exit codes that still yield a usable JSON report on stdout.
#   0 = clean, 5 = vulnerabilities found. 3 = no WP detected, 4 = no connection.
_PARSEABLE_EXIT_CODES = {0, 5}

# Substrings WPScan uses (in "scan_aborted", in the report's "vuln_api" block,
# or on stderr) when the API key's daily request quota is spent. WPScan's exact
# wording is "Your API limit has been reached". Matched case-insensitively.
_RATE_LIMIT_MARKERS = (
    "api limit", "plan limit", "request limit", "rate limit", "rate limit hit",
    "limit has been reached", "throttl", "429", "too many requests",
)

# WPScan's wording when a key is rejected outright: "The API token provided is
# invalid". A bad key should be dropped and the next one tried, not treated as
# a fatal scan error.
_INVALID_KEY_MARKERS = (
    "token provided is invalid", "invalid api token", "invalid token",
    "unauthorized", "401", "403",
)


class WPScanError(Exception):
    pass


class KeyProblem(WPScanError):
    """Base for errors that mean 'this key is unusable — try the next one'."""


class RateLimitError(KeyProblem):
    """The current API key's daily quota is spent."""


class InvalidKeyError(KeyProblem):
    """The current API key was rejected by the WPScan API."""


def _looks_like_rate_limit(message: str) -> bool:
    msg = (message or "").lower()
    return any(marker in msg for marker in _RATE_LIMIT_MARKERS)


def _looks_like_invalid_key(message: str) -> bool:
    msg = (message or "").lower()
    return any(marker in msg for marker in _INVALID_KEY_MARKERS)


def _api_problem_in_report(report: dict[str, Any]) -> str | None:
    """
    WPScan does not always abort when the API rejects a key: it can finish the
    scan and record the problem inside the report's "vuln_api" block, leaving a
    report that looks successful but carries no vulnerability data. Return the
    error text if the vuln API reported a problem, else None.
    """
    api = report.get("vuln_api")
    if not isinstance(api, dict):
        return None
    err = api.get("error")
    if err:
        return str(err)
    # Some builds nest the HTTP failure instead.
    http_err = api.get("http_error")
    if http_err:
        return str(http_err)
    return None


def _requests_remaining(report: dict[str, Any]) -> int | None:
    """Quota left on the key used for this scan, when WPScan reports it."""
    api = report.get("vuln_api")
    if not isinstance(api, dict):
        return None
    val = api.get("requests_remaining")
    if isinstance(val, int):
        return val
    return None


class KeyRing:
    """
    Thread-safe ring of WPScan API keys.

    The free WPScan plan allows 25 requests/key/day, so a fleet of keys extends
    daily capacity. Two things make all of your keys actually get used:

      * lease()  — hands out keys round-robin, so successive sites in a batch use
        different keys and the daily quota is spread across the whole ring
        instead of draining key #1 first.
      * report_exhausted() — marks a key spent (rate-limited or rejected) and
        returns the next usable one, so a scan can be retried immediately.

    Exhausted state is global for the life of the process (the quota is per key
    per day, not per site) and shared across concurrent scan threads.
    """

    def __init__(self, keys: list[str]):
        # De-duplicate while preserving order.
        seen: set[str] = set()
        self._keys = [k for k in keys if not (k in seen or seen.add(k))]
        self._idx = 0
        self._exhausted: set[str] = set()
        self._lock = threading.Lock()

    def __bool__(self) -> bool:
        return bool(self._keys)

    def count(self) -> int:
        return len(self._keys)

    def keys(self) -> list[str]:
        return list(self._keys)

    def active_count(self) -> int:
        with self._lock:
            return len([k for k in self._keys if k not in self._exhausted])

    def exhausted_keys(self) -> list[str]:
        with self._lock:
            return [k for k in self._keys if k in self._exhausted]

    def label(self, key: str | None) -> str:
        """
        Human label for UI messages: position in the ring plus a masked
        fingerprint, e.g. "key #2 of 3 (a1b2…f9e8)". Position matters because
        two keys can share the same first/last characters.
        """
        if not key:
            return "no key"
        with self._lock:
            try:
                pos = self._keys.index(key) + 1
            except ValueError:
                return _mask_key(key)
            total = len(self._keys)
        return f"key #{pos} of {total} ({_mask_key(key)})"

    def lease(self) -> str | None:
        """
        Claim the next usable key, round-robin. Each caller (i.e. each site scan)
        gets the following key in the ring, so a batch spreads its requests over
        every key you listed rather than hammering the first one.
        """
        with self._lock:
            if not self._keys:
                return None
            for _ in range(len(self._keys)):
                key = self._keys[self._idx]
                self._idx = (self._idx + 1) % len(self._keys)
                if key not in self._exhausted:
                    return key
            return None  # every key spent

    def current(self) -> str | None:
        """Peek at the key the ring is pointing at, without claiming it."""
        with self._lock:
            if not self._keys:
                return None
            cur = self._keys[self._idx]
            return None if cur in self._exhausted else cur

    def report_exhausted(self, key: str) -> str | None:
        """
        Mark `key` unusable and return the next usable key (None if all spent).
        Safe to call from multiple threads that hit the limit on the same key.
        """
        with self._lock:
            if key:
                self._exhausted.add(key)
            if not self._keys:
                return None
            for _ in range(len(self._keys)):
                candidate = self._keys[self._idx]
                self._idx = (self._idx + 1) % len(self._keys)
                if candidate not in self._exhausted:
                    return candidate
            return None


def read_api_keys(path: str) -> list[str]:
    """Read WPScan API keys from a text file (one per line, '#' comments allowed)."""
    if not path or not os.path.exists(path):
        return []
    keys: list[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            keys.append(line)
    return keys


def preflight_check(url: str, timeout: int = 10) -> tuple[bool, str]:
    """Quick check before spending an API key on WPScan.

    Returns (ok: bool, reason: str).
    ok=True means the site is reachable and looks like WordPress.
    ok=False means we should skip WPScan entirely — reason explains why.

    Checks (in order, each under `timeout` seconds):
      1. TCP connect to port 80/443 — is the host reachable at all?
      2. HTTP HEAD to the URL — does it return any response (even a 4xx)?
      3. WordPress fingerprint — is /wp-login.php or /wp-json/ accessible,
         or does the homepage contain WordPress signals?

    We deliberately do NOT check for 200 OK on the homepage — a site behind
    Cloudflare or with a WAF may return 403/503 to scanners but still be
    reachable and WordPress. We also do NOT follow too many redirects, because
    a site that redirects forever is itself a signal of misconfiguration.
    """
    import http.client
    import urllib.request as _req
    import urllib.error as _err

    parsed = urlparse(url if "://" in url else "https://" + url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # 1. TCP reachability — fastest gate, no HTTP overhead.
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
    except (socket.timeout, OSError) as exc:
        return False, f"Host unreachable ({host}:{port}): {exc}"

    # 2. HTTP response — any response means the web server is alive.
    headers = {"User-Agent": _UA}
    status = None
    try:
        req = _req.Request(url, method="HEAD", headers=headers)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with _req.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
    except _err.HTTPError as e:
        status = e.code  # 4xx/5xx still means the server responded
    except (_err.URLError, ssl.SSLError, socket.timeout, OSError) as exc:
        return False, f"HTTP request failed: {exc}"

    # A 301/302 to a completely different domain (e.g. parked) is worth noting
    # but we still proceed — WPScan can follow redirects itself.

    # 3. WordPress fingerprint — check two lightweight paths.
    #    /wp-login.php almost always returns 200 on a live WP site.
    #    /wp-json/ returns JSON on WP 4.4+.
    wp_found = False
    for path in ("/wp-login.php", "/wp-json/"):
        try:
            req2 = _req.Request(url.rstrip("/") + path, method="GET",
                                headers=headers)
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with _req.urlopen(req2, timeout=timeout, context=ctx2) as resp2:
                body = resp2.read(2048)
                if (b"wp-" in body or b"WordPress" in body
                        or b"rest_url" in body or resp2.status < 400):
                    wp_found = True
                    break
        except _err.HTTPError as e:
            if e.code in (200, 301, 302, 401, 403):
                wp_found = True  # WP auth gate still means WP is there
                break
        except Exception:  # noqa: BLE001
            pass

    if not wp_found:
        return False, (f"Site is reachable (HTTP {status}) but no WordPress "
                       f"fingerprint found (/wp-login.php, /wp-json/). "
                       f"May not be WordPress — skipping to save API quota.")

    return True, f"OK (HTTP {status}, WordPress detected)"


def _truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ("1", "true", "yes", "on")


def _split_args(raw: str | None) -> list[str] | None:
    """Split a WPSCAN_EXTRA_ARGS string into argv, respecting quotes."""
    if not raw:
        return None
    import shlex
    try:
        return shlex.split(raw)
    except ValueError:
        return None


def build_keyring(config: dict[str, Any]) -> KeyRing:
    """
    Assemble the key ring from config: an explicit WPSCAN_API_TOKEN (if set) is
    tried first, followed by every key in API_KEYS_FILE. Re-read each batch so
    edits to the key file take effect without a restart.
    """
    keys: list[str] = []
    env_token = config.get("WPSCAN_API_TOKEN")
    if env_token:
        keys.append(env_token)
    keys += read_api_keys(config.get("API_KEYS_FILE", "api_keys.txt"))
    return KeyRing(keys)


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _kill_group(proc: "subprocess.Popen") -> None:
    """Kill the whole process group so WPScan's ruby children die too."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except OSError:
            pass


def _emit_lines(buf: str, on_output, carry: list[str]) -> str:
    """Split accumulated text on newlines/carriage-returns, forward complete
    display-worthy lines to on_output, and return the leftover partial line.
    Carriage returns matter because progress bars rewrite the current line."""
    text = carry[0] + buf
    out = []
    line = ""
    for ch in text:
        if ch in "\n\r":
            out.append(line)
            line = ""
        else:
            line += ch
    carry[0] = line  # keep the partial last line for next time
    for ln in out:
        ln = _strip_ansi(ln).rstrip()
        if on_output and _is_displayable(ln):
            on_output(ln)
    return text


def _run_pty(cmd: list[str], timeout: int, on_output):
    """Run under a pseudo-terminal so output streams live. Returns
    (combined_output_text, returncode, timed_out)."""
    import pty

    master_fd, slave_fd = pty.openpty()
    try:
        proc = subprocess.Popen(
            cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            start_new_session=True, close_fds=True,
        )
    except FileNotFoundError:
        os.close(master_fd)
        os.close(slave_fd)
        raise
    os.close(slave_fd)  # parent only reads

    chunks: list[str] = []
    carry = [""]
    timed_out = {"v": False}

    def _kill():
        timed_out["v"] = True
        _kill_group(proc)

    timer = threading.Timer(max(1, timeout), _kill)
    timer.start()
    try:
        while True:
            try:
                data = os.read(master_fd, 4096)
            except OSError:
                break  # EIO on Linux signals the child closed the PTY (EOF)
            if not data:
                break
            text = data.decode("utf-8", "replace")
            chunks.append(text)
            _emit_lines(text, on_output, carry)
        # flush any trailing partial line
        if carry[0].strip():
            ln = _strip_ansi(carry[0]).rstrip()
            if on_output and _is_displayable(ln):
                on_output(ln)
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill()
    finally:
        timer.cancel()
        try:
            os.close(master_fd)
        except OSError:
            pass
    return "".join(chunks), proc.returncode, timed_out["v"]


def _run_pipes(cmd: list[str], timeout: int, on_output):
    """Fallback path (no PTY): plain pipes. Live output may be buffered by the
    child, but parsing and timeout handling still work. Returns
    (combined_output_text, returncode, timed_out)."""
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, start_new_session=True,
    )
    chunks: list[str] = []
    carry = [""]

    def _drain():
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                chunks.append(line)
                _emit_lines(line, on_output, carry)
        except (ValueError, OSError):
            pass

    drainer = threading.Thread(target=_drain, daemon=True)
    drainer.start()

    timed_out = {"v": False}

    def _kill():
        timed_out["v"] = True
        _kill_group(proc)

    timer = threading.Timer(max(1, timeout), _kill)
    timer.start()
    try:
        proc.wait(timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        _kill()
    finally:
        timer.cancel()
        drainer.join(timeout=3)
    return "".join(chunks), proc.returncode, timed_out["v"]


def run_wpscan(
    url: str,
    wpscan_path: str = "wpscan",
    api_token: str | None = None,
    timeout: int = 600,
    enumerate: str | None = "vp,vt,u,cb,dbe",
    plugins_detection: str | None = "aggressive",
    extra_args: list[str] | None = None,
    on_output: "Callable[[str], None] | None" = None,
    verbose: bool = True,
    fmt: str = "cli-no-colour",
) -> dict[str, Any]:
    """Run WPScan against one URL and return a structured report
    ({site, wp_version, target_ip, findings}).

    Output format matters a lot here:
      * cli-no-colour (default) streams human-readable progress live, which is
        what powers the live console. Findings are recovered from that text by
        cli_parser, preserving the structured table.
      * json runs SILENTLY (WPScan emits nothing until the end), so the console
        stays empty, but the report is natively structured. Use it only if you
        don't need the live console.

    The enumeration flags make the scan thorough rather than fast and shallow:
    vp = vulnerable plugins, vt = vulnerable themes, u = users, cb = config
    backups, dbe = db exports; plugins_detection=aggressive probes known paths.

    `on_output`, if given, receives each live progress line for the console.
    This live output is purely for display — never stored or exported.
    """
    is_json = fmt == "json"
    cmd = [wpscan_path, "--url", url, "--format", fmt, "--no-banner",
           "--random-user-agent"]
    # --verbose enriches the live progress; only meaningful for cli formats.
    if verbose and on_output and not is_json:
        cmd += ["--verbose"]
    if enumerate:
        cmd += ["--enumerate", enumerate]
    if plugins_detection:
        cmd += ["--plugins-detection", plugins_detection]
    if api_token:
        cmd += ["--api-token", api_token]
    if extra_args:
        cmd += extra_args

    if on_output:
        on_output(f"$ {_redacted_cmd(cmd)}")

    # Ruby (and therefore WPScan) fully buffers its output when stdout is a pipe,
    # so live progress never arrives until the scan ends. Running it attached to
    # a pseudo-terminal makes it behave as if in a real terminal and flush line
    # by line, which is what makes the live console work. Fall back to pipes if
    # a PTY can't be created (non-POSIX).
    use_pty = on_output is not None and hasattr(os, "openpty")
    try:
        if use_pty:
            output_text, returncode, timed_out_flag = _run_pty(
                cmd, timeout, on_output)
        else:
            output_text, returncode, timed_out_flag = _run_pipes(
                cmd, timeout, on_output)
    except FileNotFoundError as exc:
        raise WPScanError(
            f"'{wpscan_path}' not found. Install WPScan (gem install wpscan) "
            f"or ingest existing JSON reports instead."
        ) from exc

    stdout_data = output_text
    stderr_text = output_text  # combined under a PTY; used only for error detail

    if timed_out_flag:
        if on_output:
            on_output(f"!! killed after {timeout}s (timeout)")
        raise WPScanError(
            f"Scan of {url} timed out after {timeout}s. Aggressive plugin "
            f"detection probes thousands of paths and can exceed this on large "
            f"or slow sites. Raise SCAN_TIMEOUT, or set "
            f"WPSCAN_PLUGINS_DETECTION=mixed (or passive) for a faster scan."
        )

    # ---- JSON format: parse the JSON report via parser.parse_report --------
    if is_json:
        report = _first_json(stdout_data)
        if report is not None:
            if report.get("scan_aborted"):
                detail = str(report["scan_aborted"])
                if _looks_like_rate_limit(detail):
                    raise RateLimitError(f"{url}: {detail}")
                if _looks_like_invalid_key(detail):
                    raise InvalidKeyError(f"{url}: {detail}")
                raise WPScanError(f"{url}: {detail}")
            api_problem = _api_problem_in_report(report)
            if api_problem:
                if _looks_like_rate_limit(api_problem):
                    raise RateLimitError(f"{url}: {api_problem}")
                if _looks_like_invalid_key(api_problem):
                    raise InvalidKeyError(f"{url}: {api_problem}")
                raise WPScanError(f"{url}: vuln API error: {api_problem}")
            parsed_json = report_parser.parse_report(report, site_hint=url)
            rem = _requests_remaining(report)
            if rem is not None:
                parsed_json["requests_remaining"] = rem
            return parsed_json
        detail = _extract_error_detail(stderr_text) or f"exit code {returncode}"
        if _looks_like_rate_limit(detail):
            raise RateLimitError(f"{url}: {detail[:600]}")
        if _looks_like_invalid_key(detail):
            raise InvalidKeyError(f"{url}: {detail[:600]}")
        raise WPScanError(f"WPScan produced no report for {url}: {detail[:600]}")

    # ---- CLI format: detect failures in the text, else parse with cli_parser
    plain = _strip_ansi(stdout_data)
    # WPScan reports fatal problems as "Scan Aborted: ..." in cli mode.
    abort = re.search(r"Scan Aborted:\s*(.+)", plain)
    if abort:
        detail = abort.group(1).strip()
        if _looks_like_rate_limit(detail):
            raise RateLimitError(f"{url}: {detail}")
        if _looks_like_invalid_key(detail):
            raise InvalidKeyError(f"{url}: {detail}")
        raise WPScanError(f"{url}: Scan Aborted: {detail}")
    if _looks_like_rate_limit(plain) and "vulns" not in plain.lower():
        raise RateLimitError(f"{url}: {_extract_error_detail(plain)[:600]}")
    if _looks_like_invalid_key(plain):
        raise InvalidKeyError(f"{url}: {_extract_error_detail(plain)[:600]}")

    import cli_parser
    parsed = cli_parser.parse_cli(plain, site_hint=url)
    # A completely empty parse usually means the scan never really ran (host
    # down, blocked). Treat that as a failure with whatever detail we can find.
    if not parsed["findings"] and "Interesting Finding" not in plain \
            and "WordPress" not in plain:
        detail = _extract_error_detail(plain) or f"exit code {returncode}"
        raise WPScanError(f"WPScan produced no usable output for {url}: "
                          f"{detail[:600]}")
    return parsed


def _extract_error_detail(text: str) -> str:
    """From WPScan's (possibly verbose) output, pick the lines that explain a
    failure: error markers, aborts, fatals. Falls back to the last few
    non-empty lines, which usually carry the reason."""
    if not text:
        return ""
    clean = [_strip_ansi(ln).rstrip() for ln in text.splitlines()]
    clean = [ln for ln in clean if ln.strip()]
    markers = ("[!]", "error", "aborted", "fatal", "cannot", "unable",
               "failed", "refused", "timed out", "could not", "forbidden",
               "blocked", "429", "403", "connection")
    hits = [ln for ln in clean if any(m in ln.lower() for m in markers)]
    if hits:
        # De-duplicate, keep order, cap length.
        seen, picked = set(), []
        for ln in hits:
            if ln not in seen:
                seen.add(ln)
                picked.append(ln)
        return " | ".join(picked[-6:])
    return " | ".join(clean[-4:])


def _is_displayable(line: str) -> bool:
    """True if a raw output line should appear in the live console.

    Filters out the JSON report itself (which may arrive on stdout, possibly as
    one very long line or pretty-printed) so the console shows human-readable
    progress rather than a wall of JSON. Blank lines are dropped too."""
    s = line.strip()
    if not s:
        return False
    # WPScan's human progress lines start with [i] [+] [!] [e] — always keep.
    if len(s) >= 3 and s[0] == "[" and s[2] == "]":
        return True
    # Otherwise treat JSON (report body, pretty-printed or inline) as noise.
    if s[0] in "{}[" or s.startswith('"') or s.startswith("],") or s == "]":
        return False
    if len(s) > 400:
        return False
    return True


def _redacted_cmd(cmd: list[str]) -> str:
    """Render the command for display with the API token masked."""
    out = []
    redact_next = False
    for part in cmd:
        if redact_next:
            out.append(part[:4] + "…" + part[-4:] if len(part) > 8 else "****")
            redact_next = False
        elif part == "--api-token":
            out.append(part)
            redact_next = True
        else:
            out.append(part)
    return " ".join(out)


def _first_json(text: str) -> dict[str, Any] | None:
    """Extract the WPScan JSON report from stdout.

    Usually stdout is clean JSON, but with --verbose WPScan can interleave
    progress text before and/or after the report, so this finds the first
    balanced top-level {...} object and parses that, rather than assuming the
    JSON is the whole stream."""
    if not text:
        return None
    stripped = text.strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    # Walk braces to find a complete top-level object anywhere in the text.
    start = stripped.find("{")
    while start != -1:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(stripped)):
            ch = stripped[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = stripped[start:i + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        break  # not valid; try the next '{'
        start = stripped.find("{", start + 1)
    return None


def ingest_file(path: str) -> dict[str, Any]:
    """Load a WPScan JSON report from disk."""
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            raise WPScanError(f"{path} is not valid WPScan JSON: {exc}") from exc


def normalize_site(raw: str) -> str:
    """Normalize a site URL the same way for both sites.txt and single retries:
    default to https://, strip a trailing slash."""
    line = (raw or "").strip()
    if not line:
        return ""
    if not line.startswith(("http://", "https://")):
        line = "https://" + line
    return line.rstrip("/")


def read_sites(path: str) -> list[str]:
    """Read site URLs from a text file (one per line, '#' comments allowed)."""
    if not os.path.exists(path):
        return []
    sites: list[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sites.append(normalize_site(line))
    return sites


# --------------------------------------------------------------------------- #
# Background batch runner
# --------------------------------------------------------------------------- #
def _mask_key(key: str | None) -> str:
    """Identify a key in UI messages without printing the secret."""
    if not key:
        return "no key"
    if len(key) <= 8:
        return key[:2] + "…" + key[-2:]
    return f"{key[:4]}…{key[-4:]}"


class EventLog:
    """
    Small in-memory ring of scan progress events for the UI to poll.

    Scans run on background threads, so progress (key rotation, moving to the
    next target, batch completion) is invisible to the browser otherwise. Each
    event gets a monotonic id; the frontend passes the highest id it has seen
    and receives only newer ones, which keeps toasts from repeating.
    """

    def __init__(self, maxlen: int = 200):
        self._events: list[dict[str, Any]] = []
        self._next_id = 1
        self._maxlen = maxlen
        self._lock = threading.Lock()

    def emit(self, kind: str, message: str, level: str = "info") -> None:
        import time as _time
        with self._lock:
            self._events.append({
                "id": self._next_id,
                "kind": kind,          # scan_start | target_start | target_done
                                       # | key_rotated | scan_complete
                "level": level,        # info | success | warn | error
                "message": message,
                "ts": _time.time(),
            })
            self._next_id += 1
            if len(self._events) > self._maxlen:
                self._events = self._events[-self._maxlen:]

    def since(self, last_id: int) -> list[dict[str, Any]]:
        with self._lock:
            return [e for e in self._events if e["id"] > last_id]

    def latest_id(self) -> int:
        with self._lock:
            return self._next_id - 1

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class ScanLog:
    """
    In-memory ring of raw verbose scan output lines for the live console.

    This is display-only: it holds WPScan's progress stream so the UI can show
    a terminal-like view of a scan in flight. It is never persisted to the
    database and never included in exported reports — clearing it loses nothing
    that matters to the findings. Lines carry a monotonic id so the frontend can
    poll incrementally with a `since` cursor, exactly like EventLog.
    """

    def __init__(self, maxlen: int = 2000):
        self._lines: list[dict[str, Any]] = []
        self._next_id = 1
        self._maxlen = maxlen
        self._lock = threading.Lock()

    def append(self, site: str, text: str) -> None:
        with self._lock:
            self._lines.append({"id": self._next_id, "site": site, "text": text})
            self._next_id += 1
            if len(self._lines) > self._maxlen:
                self._lines = self._lines[-self._maxlen:]

    def since(self, last_id: int) -> list[dict[str, Any]]:
        with self._lock:
            return [ln for ln in self._lines if ln["id"] > last_id]

    def latest_id(self) -> int:
        with self._lock:
            return self._next_id - 1

    def clear(self) -> None:
        with self._lock:
            self._lines.clear()


class ScanManager:
    """
    Runs a batch of WPScan jobs on a thread pool. One batch at a time; the web
    layer checks `is_running()` before starting another. State lives in the DB,
    so the dashboard reflects progress by polling /api/findings. Progress events
    (target changes, key rotation, completion) go to `self.events` for the UI,
    and raw verbose scan output goes to `self.log` for the live console.
    """

    def __init__(self, db: Database, config: dict[str, Any]):
        self.db = db
        self.config = config
        self._lock = threading.Lock()
        self._running = False
        self._keyring = KeyRing([])
        self.events = EventLog()
        self.log = ScanLog()
        self._done = 0
        self._total = 0

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def progress(self) -> dict[str, int]:
        with self._lock:
            return {"done": self._done, "total": self._total}

    def start_batch(self, sites: list[str]) -> bool:
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._done = 0
            self._total = len(sites)
        thread = threading.Thread(target=self._run_batch, args=(sites,), daemon=True)
        thread.start()
        return True

    def _run_batch(self, sites: list[str]) -> None:
        import time
        started = time.time()
        try:
            # Reload keys each batch so edits to api_keys.txt take effect without
            # restarting the server. Shared across this batch's scan threads.
            self._keyring = build_keyring(self.config)
            self.log.clear()  # fresh console per batch
            keys = self._keyring.count()
            self.events.emit(
                "scan_start",
                f"Scan started — {len(sites)} target(s), "
                f"{keys if keys else 'no'} API key(s) in rotation.",
                level="info",
            )
            # Pre-create scan rows so the UI shows every site as "running".
            scan_ids = {s: self.db.create_scan(s, status="running") for s in sites}
            workers = max(1, int(self.config.get("MAX_CONCURRENT", 3)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for idx, site in enumerate(sites, 1):
                    pool.submit(self._scan_one, site, scan_ids[site], idx, len(sites))
        finally:
            with self._lock:
                self._running = False
                done = self._done
            elapsed = int(time.time() - started)
            statuses = self.db.latest_scan_status()
            ok = sum(1 for s in sites if statuses.get(s, {}).get("status") == "success")
            failed = len(sites) - ok
            total_findings = len(self.db.all_findings())
            msg = (f"Scan complete — {ok}/{len(sites)} target(s) succeeded"
                   + (f", {failed} failed" if failed else "")
                   + f". {total_findings} finding(s) in {elapsed}s.")
            self.events.emit("scan_complete", msg,
                             level="warn" if failed else "success")

    def _scan_one(self, site: str, scan_id: int, index: int = 1, total: int = 1) -> None:
        import time
        keyring = self._keyring

        # --- Pre-flight: check the site is reachable and looks like WordPress
        # before spending any API quota on WPScan. ---
        preflight_timeout = int(self.config.get("PREFLIGHT_TIMEOUT", 10))
        if _truthy(self.config.get("PREFLIGHT_CHECK", True)):
            self.log.append(site, f"[~] Pre-flight check: {site}")
            ok, reason = preflight_check(site, timeout=preflight_timeout)
            self.log.append(site, f"[{'i' if ok else '!'}] {reason}")
            if not ok:
                self.db.update_scan(scan_id, status="error",
                                    finished_at=time.time(), error=reason)
                self.events.emit(
                    "target_done",
                    f"[{index}/{total}] {site} skipped — {reason}",
                    level="warn",
                )
                self._mark_done()
                return

        # Use the current key for all sites; only rotate when a key is actually
        # rejected or rate-limited (KeyProblem). This preserves quota — burning
        # a fresh key per site wastes 25 requests just in the API handshake.
        key = keyring.current()
        self.events.emit(
            "target_start",
            f"[{index}/{total}] Scanning {site}"
            + (f" — using {keyring.label(key)}" if key else " — no API key"),
            level="info",
        )
        # At least one attempt; up to one attempt per key if keys keep failing.
        attempts = max(1, keyring.count())
        last_limit_err: Exception | None = None

        for _ in range(attempts):
            try:
                # run_wpscan returns an already-parsed report (cli_parser for
                # cli formats, parser.parse_report for json), so the findings
                # pipeline is identical regardless of format.
                parsed = run_wpscan(
                    site,
                    wpscan_path=self.config.get("WPSCAN_PATH", "wpscan"),
                    api_token=key,
                    timeout=int(self.config.get("SCAN_TIMEOUT", 600)),
                    enumerate=self.config.get("WPSCAN_ENUMERATE", "vp,vt,u,cb,dbe"),
                    plugins_detection=self.config.get(
                        "WPSCAN_PLUGINS_DETECTION", "aggressive"),
                    extra_args=_split_args(self.config.get("WPSCAN_EXTRA_ARGS")),
                    on_output=lambda line, s=site: self.log.append(s, line),
                    verbose=_truthy(self.config.get("WPSCAN_VERBOSE", True)),
                    fmt=self.config.get("WPSCAN_FORMAT", "cli-no-colour"),
                )
                wp_findings = parsed["findings"]

                # Add passive web-hygiene checks (headers, CORS, TLS, exposed
                # files, directory listing, REST user enumeration) that WPScan
                # doesn't cover. Optional and best-effort — never fail the scan.
                extra_findings: list[dict[str, Any]] = []
                if _truthy(self.config.get("EXTRA_CHECKS", True)):
                    try:
                        import checks
                        extra_findings = checks.run_passive_checks(
                            parsed["site"],
                            timeout=int(self.config.get("CHECK_TIMEOUT", 10)),
                        )
                    except Exception:  # noqa: BLE001 — hygiene checks are optional
                        extra_findings = []

                all_findings = wp_findings + extra_findings
                self.db.replace_findings(parsed["site"], scan_id, all_findings)
                self.db.update_scan(
                    scan_id, status="success", finished_at=time.time(),
                    wp_version=parsed.get("wp_version"),
                    target_ip=parsed.get("target_ip"),
                )
                n = len(all_findings)
                extra_note = (f" ({len(wp_findings)} WPScan + "
                              f"{len(extra_findings)} hygiene)"
                              if extra_findings else "")
                self.events.emit(
                    "target_done",
                    f"[{index}/{total}] {site} done — {n} finding(s){extra_note}.",
                    level="success",
                )
                self._mark_done()
                # Scan succeeded, but if that used up the key's quota, retire it
                # now so the next site doesn't waste an attempt discovering it.
                # (Only available from the JSON format; None for cli, which just
                # relies on reactive rotation when a key next rate-limits.)
                remaining = parsed.get("requests_remaining")
                if key and remaining is not None and remaining <= 0:
                    keyring.report_exhausted(key)
                    self.events.emit(
                        "key_rotated",
                        f"API {keyring.label(key)} reached its daily limit and was "
                        f"retired — {keyring.active_count()} key(s) still usable.",
                        level="warn",
                    )
                return
            except KeyProblem as exc:
                # Key is spent or rejected — retire it and retry on the next one.
                last_limit_err = exc
                if not key:
                    break  # no keys configured at all; nothing to rotate to
                spent = key
                next_key = keyring.report_exhausted(key)
                if next_key and next_key != key:
                    reason = ("rejected as invalid"
                              if isinstance(exc, InvalidKeyError)
                              else "hit its daily limit")
                    self.events.emit(
                        "key_rotated",
                        f"API {keyring.label(spent)} {reason} — rotated to "
                        f"{keyring.label(next_key)}, retrying {site}.",
                        level="warn",
                    )
                    key = next_key
                    continue
                break  # every key is now unusable
            except WPScanError as exc:
                self.db.update_scan(scan_id, status="error", finished_at=time.time(),
                                    error=str(exc))
                self.log.append(site, f"!! FAILED: {exc}")
                self.events.emit("target_done",
                                 f"[{index}/{total}] {site} failed: {exc}",
                                 level="error")
                self._mark_done()
                return
            except Exception as exc:  # noqa: BLE001 — never let one site kill the batch
                self.db.update_scan(scan_id, status="error", finished_at=time.time(),
                                    error=f"Unexpected error: {exc}")
                self.log.append(site, f"!! FAILED (unexpected): {exc}")
                self.events.emit("target_done",
                                 f"[{index}/{total}] {site} failed: {exc}",
                                 level="error")
                self._mark_done()
                return

        # Fell out of the loop: no usable key remaining.
        if keyring.count() == 0:
            msg = ("WPScan API key required for vulnerability data, but none are "
                   "configured. Add keys to api_keys.txt (one per line).")
        else:
            msg = (f"All {keyring.count()} WPScan API key(s) are exhausted or "
                   f"rejected (free plan = 25 requests/day per key). Try again "
                   f"later or add more keys. Last response: {last_limit_err}")
        self.db.update_scan(scan_id, status="error", finished_at=time.time(), error=msg)
        self.log.append(site, f"!! FAILED: {msg}")
        self.events.emit("target_done", f"[{index}/{total}] {site}: {msg}",
                         level="error")
        self._mark_done()

    def _mark_done(self) -> None:
        with self._lock:
            self._done += 1


def ingest_directory(db: Database, directory: str) -> int:
    """Load every *.json WPScan report in a directory. Returns count ingested."""
    import time
    count = 0
    if not os.path.isdir(directory):
        return 0
    for name in sorted(os.listdir(directory)):
        if not name.lower().endswith(".json"):
            continue
        path = os.path.join(directory, name)
        try:
            report = ingest_file(path)
            parsed = report_parser.parse_report(report, site_hint=name)
            scan_id = db.create_scan(parsed["site"], status="running", source="ingest")
            db.replace_findings(parsed["site"], scan_id, parsed["findings"])
            db.update_scan(scan_id, status="success", finished_at=time.time(),
                           wp_version=parsed.get("wp_version"),
                           target_ip=parsed.get("target_ip"))
            count += 1
        except WPScanError as exc:
            sid = db.create_scan(name, status="error", source="ingest")
            db.update_scan(sid, error=str(exc), finished_at=time.time())
    return count


# --------------------------------------------------------------------------- #
# Diagnostics: `python scanner.py` shows which keys were loaded
# --------------------------------------------------------------------------- #
def _mask(key: str) -> str:
    """Show enough of a key to identify it without printing the secret."""
    if len(key) <= 8:
        return key[:2] + "…" + key[-2:]
    return f"{key[:4]}…{key[-4:]} ({len(key)} chars)"


if __name__ == "__main__":
    from config import CONFIG

    path = CONFIG["API_KEYS_FILE"]
    print(f"Key file : {os.path.abspath(path)}")
    print(f"Exists   : {os.path.exists(path)}")

    file_keys = read_api_keys(path)
    print(f"Keys read from file: {len(file_keys)}")
    for i, k in enumerate(file_keys, 1):
        print(f"  {i}. {_mask(k)}")

    if CONFIG.get("WPSCAN_API_TOKEN"):
        print(f"Plus WPSCAN_API_TOKEN env var: {_mask(CONFIG['WPSCAN_API_TOKEN'])}")

    ring = build_keyring(CONFIG)
    print(f"\nUsable keys in rotation (after de-duplication): {ring.count()}")
    if ring.count() == 0:
        print("  !! No keys loaded. Check that the file exists, is in this")
        print("     directory, and has one key per line (no quotes, no commas).")
    else:
        order = [_mask(ring.lease() or "-") for _ in range(ring.count())]
        print(f"  Round-robin order across sites: {', '.join(order)}")
