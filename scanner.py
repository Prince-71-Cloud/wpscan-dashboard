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
import time as time_module
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
    "api limit", "plan limit", "request limit", "limit has been reached",
)
# Generic throttling words a *target site or WAF* can also produce; they only
# count as a key problem when the message is about the API.
_WEAK_RATE_LIMIT_MARKERS = ("rate limit", "throttl", "429", "too many requests")

# WPScan's wording when a key is rejected outright: "The API token provided is
# invalid". A bad key should be dropped and the next one tried, not treated as
# a fatal scan error. Bare status codes (401/403) are deliberately NOT markers:
# they appear in WPScan's response-code stats and progress counters, and a WAF
# 403 is not a key problem.
_INVALID_KEY_MARKERS = (
    "token provided is invalid", "invalid api token", "invalid token",
    "api token is invalid",
)


# WPScan refuses to scan a URL that redirects elsewhere (www., https, a new
# domain) unless told to follow; we re-run once against the effective URL.
_MAIN_REDIRECT_RE = re.compile(r"redirects to (\S+?)\.?(?:\s|$)")
# cURL's wording when the certificate cannot be verified; the target is up,
# WPScan just refuses the handshake. We retry once with checks disabled (the
# passive checks already report the certificate problem as a finding).
_TLS_FAILURE_RE = re.compile(r"ssl|tls|certificate", re.I)


class WPScanError(Exception):
    pass


class PartialScanError(WPScanError):
    """Raised when a scan is killed (e.g. timeout) but has partial findings.
    The `partial` attribute holds {site, wp_version, target_ip, findings}."""
    def __init__(self, message: str, partial: dict):
        super().__init__(message)
        self.partial = partial


class KeyProblem(WPScanError):
    """Base for errors that mean 'this key is unusable — try the next one'."""


class RateLimitError(KeyProblem):
    """The current API key's daily quota is spent."""


class InvalidKeyError(KeyProblem):
    """The current API key was rejected by the WPScan API."""


def _looks_like_rate_limit(message: str) -> bool:
    msg = (message or "").lower()
    if any(marker in msg for marker in _RATE_LIMIT_MARKERS):
        return True
    return "api" in msg and any(m in msg for m in _WEAK_RATE_LIMIT_MARKERS)


def _cli_error_lines(plain: str) -> str:
    """Only the lines of cli output that can report a scan/API problem:
    top-level '[!]' notices and 'Scan Aborted'. Excludes guttered vulnerability
    blocks (' | [!] Title: ...'), progress bars and stats, which contain
    numbers like 403/429 that must not be read as errors."""
    picked = []
    for ln in plain.splitlines():
        s = ln.strip()
        if "Scan Aborted" in s or (s.startswith("[!]") and "Title:" not in s):
            picked.append(s)
    return "\n".join(picked)


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

    def _seek_usable(self) -> str | None:
        """Move the pointer onto the first usable key at or after it (without
        advancing past it) and return that key; None if every key is spent.
        Caller must hold the lock."""
        n = len(self._keys)
        for step in range(n):
            pos = (self._idx + step) % n
            if self._keys[pos] not in self._exhausted:
                self._idx = pos
                return self._keys[pos]
        return None

    def current(self) -> str | None:
        """The key in use: the first usable key at or after the pointer. Skips
        exhausted keys, so it only returns None when every key is spent."""
        with self._lock:
            if not self._keys:
                return None
            return self._seek_usable()

    def report_exhausted(self, key: str) -> str | None:
        """
        Mark `key` unusable and return the next usable key (None if all spent).
        The pointer is left ON the returned key, so a following current() call
        returns the same key. Safe to call from multiple threads that hit the
        limit on the same key.
        """
        with self._lock:
            if key:
                self._exhausted.add(key)
            if not self._keys:
                return None
            return self._seek_usable()


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


def key_file_is_shared(path: str) -> bool:
    """True if the key file is readable by group/others (should be 0600)."""
    try:
        return bool(os.stat(path).st_mode & 0o077)
    except OSError:
        return False


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

    # 2. HTTP response — any response means the web server is alive. The
    #    homepage body doubles as the first WordPress fingerprint source.
    headers = {"User-Agent": _UA}
    status = None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    home_body = b""
    home_headers: dict[str, str] = {}
    try:
        req = _req.Request(url, method="GET", headers=headers)
        with _req.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            home_body = resp.read(65536)
            home_headers = {k.lower(): v for k, v in resp.headers.items()}
    except _err.HTTPError as e:
        status = e.code  # 4xx/5xx still means the server responded
        try:
            home_body = e.read(65536)
            home_headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        except Exception:  # noqa: BLE001 — body is optional here
            pass
    except (_err.URLError, ssl.SSLError, socket.timeout, OSError) as exc:
        return False, f"HTTP request failed: {exc}"

    # 3. WordPress fingerprint. A status code alone proves nothing: a WAF
    #    answers 403 to everything and a SPA answers 200 to everything, and
    #    both used to pass here and burn API quota. Require an actual
    #    WordPress marker in a body or header.
    wp_found = _wp_signal(home_body, home_headers)
    if not wp_found:
        for path in ("/wp-login.php", "/wp-json/"):
            try:
                req2 = _req.Request(url.rstrip("/") + path, method="GET",
                                    headers=headers)
                with _req.urlopen(req2, timeout=timeout, context=ctx) as resp2:
                    body = resp2.read(16384)
                    hdrs = {k.lower(): v for k, v in resp2.headers.items()}
            except _err.HTTPError as e:
                try:
                    body = e.read(16384)
                except Exception:  # noqa: BLE001
                    body = b""
                hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
            except Exception:  # noqa: BLE001
                continue
            if _wp_signal(body, hdrs):
                wp_found = True
                break

    if not wp_found:
        return False, (f"Site is reachable (HTTP {status}) but no WordPress "
                       f"fingerprint found (homepage, /wp-login.php, /wp-json/). "
                       f"May not be WordPress, or a WAF is hiding it — skipping "
                       f"to save API quota (disable the pre-flight check to "
                       f"force a scan).")

    return True, f"OK (HTTP {status}, WordPress detected)"


_WP_BODY_MARKERS = (b"wp-content/", b"wp-includes/", b"/wp-json/", b"wp-login.php",
                    b'"namespaces"', b"user_login", b"wp-emoji", b"WordPress")


def _wp_signal(body: bytes, headers: dict[str, str]) -> bool:
    """True if a response carries a WordPress marker in body or headers."""
    if any(m in body for m in _WP_BODY_MARKERS):
        return True
    link = headers.get("link", "")
    if "wp-json" in link or "api.w.org" in link:
        return True
    if "x-pingback" in headers:
        return True
    return "wordpress" in headers.get("x-generator", "").lower()


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


_key_count_cache: dict[str, Any] = {"sig": None, "count": 0}
_key_count_lock = threading.Lock()


def configured_key_count(config: dict[str, Any]) -> int:
    """Number of distinct configured API keys, for the UI. Cached on the key
    file's mtime/size (and the env token) so the dashboard's frequent polling
    doesn't re-read the file every time; edits are still picked up."""
    path = config.get("API_KEYS_FILE", "api_keys.txt")
    try:
        st = os.stat(path)
        file_sig = (st.st_mtime_ns, st.st_size)
    except OSError:
        file_sig = None
    sig = (path, file_sig, config.get("WPSCAN_API_TOKEN"))
    with _key_count_lock:
        if _key_count_cache["sig"] != sig:
            _key_count_cache["count"] = build_keyring(config).count()
            _key_count_cache["sig"] = sig
        return _key_count_cache["count"]


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
    on_finding: "Callable[[dict], None] | None" = None,
    verbose: bool = True,
    fmt: str = "cli-no-colour",
    throttle_ms: int = 0,
    max_threads: int = 0,
    disable_tls_checks: bool = False,
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

    `on_finding`, if given, is called immediately each time a complete finding is
    parsed from the live output stream, so findings can be written to the database
    and appear in the UI table *during* the scan rather than only at the end.
    If WPScan is killed by the timeout, all findings discovered up to that point
    are still available via this callback even though the scan never finished.
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
    # Load controls: production sites and their WAFs notice a 5-thread
    # aggressive plugin scan. --throttle forces single-threaded pacing.
    if throttle_ms and throttle_ms > 0:
        cmd += ["--throttle", str(int(throttle_ms))]
    elif max_threads and max_threads > 0:
        cmd += ["--max-threads", str(int(max_threads))]
    if disable_tls_checks:
        cmd += ["--disable-tls-checks"]
    if extra_args:
        cmd += extra_args

    if on_output:
        on_output(f"$ {_redacted_cmd(cmd)}")

    # For CLI formats, build a StreamingParser that's fed each line as it
    # arrives from the PTY so findings hit the DB in real time.
    _streaming_parser: dict = {}
    if not is_json:
        import cli_parser as _cli_parser_mod
        _sp = _cli_parser_mod.StreamingParser(
            site_hint=url, on_finding=on_finding)
        _streaming_parser["sp"] = _sp
        _orig_on_output = on_output

        def _combined_output(line: str) -> None:
            # Feed into the live finding parser first, then into the console log.
            _sp.feed(line)
            if _orig_on_output:
                _orig_on_output(line)

        on_output = _combined_output

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
        # Flush the streaming parser to emit any finding that was mid-parse.
        _sp2 = _streaming_parser.get("sp")
        if _sp2 is not None:
            _sp2.finish()
            partial = _sp2.result()
        else:
            partial = {"site": url, "wp_version": None, "target_ip": None,
                       "findings": []}
        # Raise a PartialScanError so _scan_one can store findings + warning.
        raise PartialScanError(
            f"Scan of {url} timed out after {timeout}s — "
            f"{len(partial['findings'])} finding(s) collected before timeout. "
            f"Aggressive plugin detection probes thousands of paths. "
            f"Raise SCAN_TIMEOUT or switch to WPSCAN_PLUGINS_DETECTION=mixed.",
            partial=partial,
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
    # "[+] WPScan DB API OK" means the key was accepted for this scan.
    if "wpscan db api ok" not in plain.lower():
        err_lines = _cli_error_lines(plain)
        if _looks_like_rate_limit(err_lines):
            raise RateLimitError(f"{url}: {err_lines[:600]}")
        if _looks_like_invalid_key(err_lines):
            raise InvalidKeyError(f"{url}: {err_lines[:600]}")

    import cli_parser
    # StreamingParser was already fed each line live during PTY output if
    # on_finding was supplied; its result() already contains all findings
    # discovered during the scan. If on_finding was not provided (or for any
    # lines that arrived after _sp was set), fall back to parsing the full text.
    _sp: "cli_parser.StreamingParser | None" = _streaming_parser.get("sp")
    if _sp is not None:
        _sp.finish()
        parsed = _sp.result()
    else:
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
    seen: set[str] = set()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            site = normalize_site(line)
            # A repeated target would be scanned twice and burn API quota.
            if site in seen:
                continue
            seen.add(site)
            sites.append(site)
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
        self._paused = False          # batch-level pause flag
        self._paused_site: str | None = None  # per-site pause (site URL or None)
        self._cancel = False          # set True to abort the whole batch
        self._keyring = KeyRing([])
        self.events = EventLog()
        self.log = ScanLog()
        self._done = 0
        self._total = 0
        self._current_site: str | None = None

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def is_paused(self) -> bool:
        with self._lock:
            return self._paused

    def paused_site(self) -> str | None:
        with self._lock:
            return self._paused_site

    def current_site(self) -> str | None:
        with self._lock:
            return self._current_site

    def progress(self) -> dict[str, int]:
        with self._lock:
            return {"done": self._done, "total": self._total}

    def pause(self) -> None:
        """Pause after the current site finishes."""
        with self._lock:
            self._paused = True

    def resume(self) -> None:
        """Resume a paused batch."""
        with self._lock:
            self._paused = False
            self._paused_site = None

    def cancel(self) -> None:
        """Cancel the batch after the current site finishes."""
        with self._lock:
            self._cancel = True
            self._paused = False  # unblock the wait loop

    def pause_site(self, site: str) -> None:
        """Pause before scanning a specific site."""
        with self._lock:
            self._paused_site = site

    def resume_site(self, site: str) -> None:
        """Resume a per-site pause."""
        with self._lock:
            if self._paused_site == site:
                self._paused_site = None

    def start_batch(self, sites: list[str]) -> bool:
        # De-duplicate (order kept) so no target is scanned twice, whatever the
        # caller passed — sites.txt or an API body.
        sites = list(dict.fromkeys(sites))
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._paused = False
            self._paused_site = None
            self._cancel = False
            self._done = 0
            self._total = len(sites)
        thread = threading.Thread(target=self._run_batch, args=(sites,), daemon=True)
        thread.start()
        return True

    def _wait_if_paused(self, site: str | None = None) -> bool:
        """Block while paused (batch-level or per-site). Returns False if cancelled."""
        while True:
            with self._lock:
                if self._cancel:
                    return False
                batch_pause = self._paused
                site_pause = (self._paused_site == site) if site else False
            if not batch_pause and not site_pause:
                return True
            time_module.sleep(0.3)

    def _run_batch(self, sites: list[str]) -> None:
        started = time_module.time()
        scan_ids: dict[str, int] = {}
        try:
            self._keyring = build_keyring(self.config)
            self.log.clear()
            keys = self._keyring.count()
            self.events.emit(
                "scan_start",
                f"Scan started — {len(sites)} target(s) sequentially, "
                f"{keys if keys else 'no'} API key(s) in rotation.",
                level="info",
            )
            key_path = self.config.get("API_KEYS_FILE", "api_keys.txt")
            if keys and key_file_is_shared(key_path):
                self.events.emit(
                    "scan_start",
                    f"{key_path} is readable by other users on this machine — "
                    f"run: chmod 600 {key_path}",
                    level="warn",
                )
            # Sites run one at a time — sequential, predictable, cheap on API quota.
            scan_ids.update({s: self.db.create_scan(s, status="queued") for s in sites})
            for idx, site in enumerate(sites, 1):
                # Honour per-site pause (set by the UI before this site starts).
                if not self._wait_if_paused(site):
                    self.events.emit("scan_complete",
                                     "Batch cancelled by user.", level="warn")
                    return
                # Mark the site as running now that we're about to scan it.
                self.db.update_scan(scan_ids[site], status="running")
                with self._lock:
                    self._current_site = site
                try:
                    self._scan_one(site, scan_ids[site], idx, len(sites))
                except Exception as exc:  # noqa: BLE001 — never strand a site in 'running'
                    self.db.update_scan(scan_ids[site], status="error",
                                        finished_at=time_module.time(),
                                        error=f"Internal error: {exc}")
                    self.log.append(site, f"!! FAILED (internal): {exc}")
                    self.events.emit("target_done",
                                     f"[{idx}/{len(sites)}] {site} failed: {exc}",
                                     level="error")
                    self._mark_done()
                with self._lock:
                    self._current_site = None
                # Honour batch-level pause between sites.
                if not self._wait_if_paused():
                    self.events.emit("scan_complete",
                                     "Batch cancelled by user.", level="warn")
                    return
        finally:
            # Sites the batch never reached (cancelled) still hold a 'queued'
            # placeholder row. Drop it so each site falls back to its last real
            # status instead of showing — and exporting — a phantom 'queued'.
            skipped = set()
            for s, sid in scan_ids.items():
                before = self.db.latest_scan_status().get(s, {})
                if before.get("id") == sid and before.get("status") == "queued":
                    skipped.add(s)
                self.db.delete_scan_if_status(sid, "queued")
            with self._lock:
                self._running = False
                self._current_site = None
                done = self._done
            elapsed = int(time_module.time() - started)
            statuses = self.db.latest_scan_status()
            st_of = {s: statuses.get(s, {}).get("status")
                     for s in sites if s not in skipped}
            ok = sum(1 for v in st_of.values() if v == "success")
            partial = sum(1 for v in st_of.values() if v == "partial")
            failed = len(st_of) - ok - partial
            total_findings = len(self.db.all_findings())
            msg = (f"Scan complete — {ok}/{len(sites)} target(s) succeeded"
                   + (f", {partial} partial (timed out)" if partial else "")
                   + (f", {failed} failed" if failed else "")
                   + (f", {len(skipped)} skipped (cancelled)" if skipped else "")
                   + f". {total_findings} finding(s) in {elapsed}s.")
            self.events.emit("scan_complete", msg,
                             level="warn" if (failed or partial) else "success")

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
        # Redirect/TLS retries do not count against the key budget.
        max_key_attempts = max(1, keyring.count())
        key_attempts = 0
        last_limit_err: Exception | None = None
        target_url = site          # may become the effective URL after a redirect
        redirect_followed = False
        tls_relaxed = False

        while True:
            try:
                # run_wpscan returns an already-parsed report (cli_parser for
                # cli formats, parser.parse_report for json), so the findings
                # pipeline is identical regardless of format.
                #
                # For CLI format, on_finding fires the instant a finding is
                # parsed from the live stream, so it appears in the table during
                # the scan. We write it straight to the DB here; replace_findings
                # at the end overwrites with the final complete set (no duplicates).
                def _live_finding(f: dict, _scan_id: int = scan_id,
                                  _site: str = site) -> None:
                    self.db.add_finding_live(_site, _scan_id, f)
                    self.events.emit(
                        "finding_live",
                        f"[{f['severity'].upper()}] {f['title'][:60]}",
                        level=("error" if f["severity"] in ("critical","high")
                               else "warn" if f["severity"] == "medium"
                               else "info"),
                    )

                parsed = run_wpscan(
                    target_url,
                    wpscan_path=self.config.get("WPSCAN_PATH", "wpscan"),
                    api_token=key,
                    timeout=int(self.config.get("SCAN_TIMEOUT", 600)),
                    enumerate=self.config.get("WPSCAN_ENUMERATE", "vp,vt,u,cb,dbe"),
                    plugins_detection=self.config.get(
                        "WPSCAN_PLUGINS_DETECTION", "aggressive"),
                    extra_args=_split_args(self.config.get("WPSCAN_EXTRA_ARGS")),
                    on_output=lambda line, s=site: self.log.append(s, line),
                    on_finding=_live_finding,
                    verbose=_truthy(self.config.get("WPSCAN_VERBOSE", True)),
                    fmt=self.config.get("WPSCAN_FORMAT", "cli-no-colour"),
                    throttle_ms=int(self.config.get("WPSCAN_THROTTLE", 0) or 0),
                    max_threads=int(self.config.get("WPSCAN_MAX_THREADS", 0) or 0),
                    disable_tls_checks=tls_relaxed,
                )
                wp_findings = parsed["findings"]

                # Findings are keyed by the operator's target (sites.txt entry),
                # even when WPScan ran against the redirected effective URL.
                effective = parsed.get("site") or target_url
                extra_findings = self._hygiene_findings(effective)
                all_findings = wp_findings + extra_findings
                self.db.replace_findings(site, scan_id, all_findings)

                # WPScan does not abort when the key's daily quota runs out
                # mid-scan: the API client silently returns no data for every
                # component checked after that point. The scan then *looks*
                # successful. Zero requests remaining therefore means the
                # vulnerability data is incomplete, which is 'partial', not
                # 'success'.
                remaining = parsed.get("requests_remaining")
                quota_hit = bool(key) and remaining is not None and remaining <= 0
                status = "partial" if quota_hit else "success"
                note = None
                if quota_hit:
                    note = (f"API {keyring.label(key)} ran out of daily requests "
                            f"during this scan; components checked after that "
                            f"point have no vulnerability data. Re-scan with a "
                            f"fresh key for full coverage.")
                self.db.update_scan(
                    scan_id, status=status, finished_at=time.time(),
                    wp_version=parsed.get("wp_version"),
                    target_ip=parsed.get("target_ip"),
                    error=note,
                )
                n = len(all_findings)
                extra_note = (f" ({len(wp_findings)} WPScan + "
                              f"{len(extra_findings)} hygiene)"
                              if extra_findings else "")
                redirect_note = (f" via {effective}" if effective.rstrip("/")
                                 != site.rstrip("/") else "")
                self.events.emit(
                    "target_done",
                    f"[{index}/{total}] {site}{redirect_note} "
                    f"{'partial (API quota exhausted)' if quota_hit else 'done'}"
                    f" — {n} finding(s){extra_note}.",
                    level="warn" if quota_hit else "success",
                )
                if quota_hit:
                    self.log.append(site, f"!! PARTIAL: {note}")
                self._mark_done()
                # Retire a spent key now so the next site doesn't waste an
                # attempt discovering it.
                if quota_hit:
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
                key_attempts += 1
                if not key or key_attempts >= max_key_attempts:
                    break  # nothing (left) to rotate to
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
            except PartialScanError as exc:
                # Timeout with partial findings — save what we have.
                partial = exc.partial
                # The host answered WPScan, so the bounded hygiene checks are
                # still worth running to make the partial result more complete.
                extra_findings = self._hygiene_findings(partial["site"] or target_url)
                partial["findings"] = partial["findings"] + extra_findings
                self.db.replace_findings(site, scan_id, partial["findings"])
                self.db.update_scan(
                    scan_id, status="partial", finished_at=time.time(),
                    wp_version=partial.get("wp_version"),
                    target_ip=partial.get("target_ip"),
                    error=str(exc),
                )
                n = len(partial["findings"])
                self.log.append(site, f"!! PARTIAL: {n} finding(s) saved before timeout")
                self.events.emit(
                    "target_done",
                    f"[{index}/{total}] {site} partial — {n} finding(s) before timeout.",
                    level="warn",
                )
                self._mark_done()
                return
            except WPScanError as exc:
                msg = str(exc)
                # "The URL supplied redirects to https://www.x/ ..." — scan the
                # effective URL once instead of failing the target.
                rm = _MAIN_REDIRECT_RE.search(msg)
                if rm and not redirect_followed:
                    redirect_followed = True
                    target_url = normalize_site(rm.group(1))
                    self.log.append(site, f"[~] Target redirects — rescanning as {target_url}")
                    self.events.emit("target_start",
                                     f"[{index}/{total}] {site} redirects to "
                                     f"{target_url}; scanning that instead.",
                                     level="info")
                    continue
                # Certificate rejected by cURL: retry with TLS checks off. The
                # passive checks still report the certificate problem itself.
                if (_TLS_FAILURE_RE.search(msg) and not tls_relaxed
                        and target_url.startswith("https://")):
                    tls_relaxed = True
                    self.log.append(site, "[~] TLS handshake rejected — retrying "
                                          "with --disable-tls-checks")
                    self.events.emit("target_start",
                                     f"[{index}/{total}] {site}: certificate "
                                     f"rejected; retrying with TLS checks disabled.",
                                     level="warn")
                    continue
                self.db.update_scan(scan_id, status="error", finished_at=time.time(),
                                    error=msg)
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

    def _hygiene_findings(self, site: str) -> list[dict[str, Any]]:
        """Passive web-hygiene checks (headers, CORS, TLS, exposed files,
        directory listing, REST user enumeration) that WPScan doesn't cover.
        Optional and best-effort — never fails the scan."""
        if not _truthy(self.config.get("EXTRA_CHECKS", True)):
            return []
        try:
            import checks
            return checks.run_passive_checks(
                site, timeout=int(self.config.get("CHECK_TIMEOUT", 10)))
        except Exception:  # noqa: BLE001 — hygiene checks are optional
            return []

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
        except Exception as exc:  # noqa: BLE001 — one bad file mustn't abort the ingest
            msg = str(exc) if isinstance(exc, WPScanError) else (
                f"Could not ingest {name}: {type(exc).__name__}: {exc}")
            sid = db.create_scan(name, status="error", source="ingest")
            db.update_scan(sid, error=msg, finished_at=time.time())
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
