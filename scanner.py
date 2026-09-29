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
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import parser as report_parser
from db import Database

# WPScan exit codes that still yield a usable JSON report on stdout.
#   0 = clean, 5 = vulnerabilities found. 3 = no WP detected, 4 = no connection.
_PARSEABLE_EXIT_CODES = {0, 5}

# Substrings WPScan uses (in its "scan_aborted" message or on stderr) when the
# API key's daily request quota is spent. Matched case-insensitively.
_RATE_LIMIT_MARKERS = (
    "api limit", "plan limit", "request limit", "rate limit", "throttl",
    "429", "too many requests", "reached your",
)


class WPScanError(Exception):
    pass


class RateLimitError(WPScanError):
    """Raised when a scan fails specifically because the API key is exhausted."""


def _looks_like_rate_limit(message: str) -> bool:
    msg = (message or "").lower()
    return any(marker in msg for marker in _RATE_LIMIT_MARKERS)


class KeyRing:
    """
    Thread-safe ring of WPScan API keys.

    The free WPScan plan allows 25 requests/key/day, so a fleet of keys extends
    daily capacity. Scans share one ring: when a key comes back rate-limited it
    is marked exhausted and the ring advances to the next usable key. Because the
    quota is per key per day (not per site), the exhausted state is global for
    the life of the process and shared across the concurrent scan threads.
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

    def active_count(self) -> int:
        with self._lock:
            return len([k for k in self._keys if k not in self._exhausted])

    def current(self) -> str | None:
        """The key a scan should use right now, or None if there are none/all spent."""
        with self._lock:
            if not self._keys:
                return None
            cur = self._keys[self._idx]
            return None if cur in self._exhausted else cur

    def report_exhausted(self, key: str) -> str | None:
        """
        Mark `key` spent and return the next usable key (or None if all are spent).
        Safe to call from multiple threads that hit the limit on the same key.
        """
        with self._lock:
            if key:
                self._exhausted.add(key)
            if not self._keys:
                return None
            # Only advance the shared pointer if it is still on the spent key;
            # another thread may already have rotated us forward.
            if self._keys[self._idx] == key:
                for _ in range(len(self._keys)):
                    self._idx = (self._idx + 1) % len(self._keys)
                    if self._keys[self._idx] not in self._exhausted:
                        return self._keys[self._idx]
                return None
            cur = self._keys[self._idx]
            return None if cur in self._exhausted else cur


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


def run_wpscan(
    url: str,
    wpscan_path: str = "wpscan",
    api_token: str | None = None,
    timeout: int = 600,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Run WPScan against one URL and return the parsed JSON report."""
    cmd = [wpscan_path, "--url", url, "--format", "json", "--no-banner",
           "--random-user-agent"]
    if api_token:
        cmd += ["--api-token", api_token]
    if extra_args:
        cmd += extra_args

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError as exc:
        raise WPScanError(
            f"'{wpscan_path}' not found. Install WPScan (gem install wpscan) "
            f"or ingest existing JSON reports instead."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise WPScanError(f"Scan of {url} timed out after {timeout}s") from exc

    # Try to parse stdout regardless of exit code.
    report = _first_json(proc.stdout)
    if report is not None:
        # WPScan puts its own errors inside "scan_aborted" when it can't proceed.
        if report.get("scan_aborted"):
            detail = str(report["scan_aborted"])
            if _looks_like_rate_limit(detail):
                raise RateLimitError(f"{url}: {detail}")
            raise WPScanError(f"{url}: {detail}")
        return report

    # No JSON -> surface the most useful error text we can find.
    stderr = (proc.stderr or "").strip()
    stdout = (proc.stdout or "").strip()
    detail = stderr or stdout or f"exit code {proc.returncode}"
    if _looks_like_rate_limit(detail):
        raise RateLimitError(f"{url}: {detail[:500]}")
    raise WPScanError(f"WPScan produced no report for {url}: {detail[:500]}")


def _first_json(text: str) -> dict[str, Any] | None:
    """WPScan is usually clean JSON, but be tolerant of leading warnings."""
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start > 0:
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            return None
    return None


def ingest_file(path: str) -> dict[str, Any]:
    """Load a WPScan JSON report from disk."""
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            raise WPScanError(f"{path} is not valid WPScan JSON: {exc}") from exc


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
            if not line.startswith(("http://", "https://")):
                line = "https://" + line
            sites.append(line.rstrip("/"))
    return sites


# --------------------------------------------------------------------------- #
# Background batch runner
# --------------------------------------------------------------------------- #
class ScanManager:
    """
    Runs a batch of WPScan jobs on a thread pool. One batch at a time; the web
    layer checks `is_running()` before starting another. State lives in the DB,
    so the dashboard reflects progress by polling /api/findings.
    """

    def __init__(self, db: Database, config: dict[str, Any]):
        self.db = db
        self.config = config
        self._lock = threading.Lock()
        self._running = False
        self._keyring = KeyRing([])

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def start_batch(self, sites: list[str]) -> bool:
        with self._lock:
            if self._running:
                return False
            self._running = True
        thread = threading.Thread(target=self._run_batch, args=(sites,), daemon=True)
        thread.start()
        return True

    def _run_batch(self, sites: list[str]) -> None:
        try:
            # Reload keys each batch so edits to api_keys.txt take effect without
            # restarting the server. Shared across this batch's scan threads.
            self._keyring = build_keyring(self.config)
            # Pre-create scan rows so the UI shows every site as "running".
            scan_ids = {s: self.db.create_scan(s, status="running") for s in sites}
            workers = max(1, int(self.config.get("MAX_CONCURRENT", 3)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for site in sites:
                    pool.submit(self._scan_one, site, scan_ids[site])
        finally:
            with self._lock:
                self._running = False

    def _scan_one(self, site: str, scan_id: int) -> None:
        import time
        keyring = self._keyring
        key = keyring.current()
        # At least one attempt; up to one attempt per key if we keep hitting limits.
        attempts = max(1, keyring.count())
        last_limit_err: Exception | None = None

        for _ in range(attempts):
            try:
                report = run_wpscan(
                    site,
                    wpscan_path=self.config.get("WPSCAN_PATH", "wpscan"),
                    api_token=key,
                    timeout=int(self.config.get("SCAN_TIMEOUT", 600)),
                )
                parsed = report_parser.parse_report(report, site_hint=site)
                self.db.replace_findings(parsed["site"], scan_id, parsed["findings"])
                self.db.update_scan(
                    scan_id, status="success", finished_at=time.time(),
                    wp_version=parsed.get("wp_version"),
                    target_ip=parsed.get("target_ip"),
                )
                return
            except RateLimitError as exc:
                # Current key is spent — mark it and rotate to the next one.
                last_limit_err = exc
                next_key = keyring.report_exhausted(key) if key else None
                if next_key and next_key != key:
                    key = next_key
                    continue
                break  # no key set, or every key exhausted
            except WPScanError as exc:
                self.db.update_scan(scan_id, status="error", finished_at=time.time(),
                                    error=str(exc))
                return
            except Exception as exc:  # noqa: BLE001 — never let one site kill the batch
                self.db.update_scan(scan_id, status="error", finished_at=time.time(),
                                    error=f"Unexpected error: {exc}")
                return

        # Fell out of the loop: rate-limited with no usable key remaining.
        if keyring.count() == 0:
            msg = ("Rate-limited and no WPScan API keys configured. Add keys to "
                   "api_keys.txt for full vulnerability data.")
        else:
            msg = (f"All {keyring.count()} WPScan API key(s) are rate-limited "
                   f"(25 requests/day each). Try again later or add more keys. "
                   f"Last response: {last_limit_err}")
        self.db.update_scan(scan_id, status="error", finished_at=time.time(), error=msg)


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
