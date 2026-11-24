"""
enrich.py
=========
Vulnerability-intelligence enrichment for findings that carry CVE ids.

WPScan's CLI output has no CVSS at all and its free JSON feed rarely does, so
the dashboard's severity would otherwise be a keyword guess. Three free,
public, target-independent sources fix that:

  * NVD (services.nvd.nist.gov)  CVSS v3.1/v3.0/v2 base score + vector.
  * FIRST EPSS (api.first.org)   probability of exploitation in the next 30 days.
  * CISA KEV (cisa.gov)          catalogue of vulnerabilities known to be
                                  exploited in the wild.

Results are cached per CVE in the `cve_cache` table (shared across sites,
refreshed after ENRICH_TTL_DAYS) and applied to findings:

  * a finding with no CVSS of its own takes the NVD score and is re-graded
    with the standard bands (severity_reason says so);
  * a KEV entry forces `critical` — CISA's catalogue is "patch now";
  * EPSS is stored and shown, it never changes the severity label.

Network calls happen on one background thread (NVD allows 5 requests per 30 s
without an API key, 50 with NVD_API_KEY), never on a request path, and never
touch the scanned targets. `apply()` is synchronous and cache-only so freshly
saved findings get graded immediately from what is already known.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from parser import SEVERITY_RANK, _cvss_to_severity

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
_UA = "wpscan-console-enrichment/1.0"
_KEV_TTL = 24 * 3600


def _http_get_json(url: str, headers: dict[str, str] | None = None,
                   timeout: int = 30) -> tuple[int, Any]:
    """GET a JSON document. Returns (status, parsed) and never raises for HTTP
    errors (status carries them). Module-level so tests can replace it."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            e.read()
        finally:
            e.close()
        return e.code, None


def _parse_nvd_item(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve") or {}
    metrics = cve.get("metrics") or {}
    out: dict[str, Any] = {"cvss": None, "vector": None, "cvss_version": None,
                           "description": None}
    for key, label in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                       ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        # Prefer NVD's own (Primary) assessment over CNA-supplied ones.
        entries = sorted(entries, key=lambda m: 0 if m.get("type") == "Primary" else 1)
        data = entries[0].get("cvssData") or {}
        try:
            out["cvss"] = float(data.get("baseScore"))
        except (TypeError, ValueError):
            continue
        out["vector"] = data.get("vectorString")
        out["cvss_version"] = label
        break
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            out["description"] = (d.get("value") or "")[:600]
            break
    return out


class Enricher:
    def __init__(self, db, config: dict[str, Any], events=None):
        self.db = db
        self.config = config
        self.events = events
        self._lock = threading.Lock()
        self._running = False
        self._last_run: float | None = None
        self._last_error: str | None = None
        self._last_count = 0
        self._pending_count: int | None = None   # computed by apply()/_run(), not per poll

    # -- configuration ----------------------------------------------------- #
    def enabled(self) -> bool:
        val = str(self.config.get("ENRICHMENT", "true")).strip().lower()
        return val in ("1", "true", "yes", "on")

    def _ttl(self) -> float:
        try:
            return float(self.config.get("ENRICH_TTL_DAYS", 7)) * 86400
        except (TypeError, ValueError):
            return 7 * 86400

    def _nvd_delay(self) -> float:
        # Public rate limit: 5 requests / 30 s without a key, 50 with one.
        return 0.7 if self.config.get("NVD_API_KEY") else 6.5

    # -- status ------------------------------------------------------------ #
    def status(self) -> dict[str, Any]:
        """Cheap enough for the 2-second poll: no DB work here."""
        with self._lock:
            return {"enabled": self.enabled(), "running": self._running,
                    "pending": self._pending_count or 0,
                    "last_run": self._last_run, "last_error": self._last_error,
                    "last_count": self._last_count}

    def _pending(self) -> list[str]:
        """CVE ids referenced by current findings that are missing from the
        cache or older than the TTL."""
        cves: set[str] = set()
        for f in self.db.findings_with_cves():
            cves.update(c for c in f["cves"] if str(c).upper().startswith("CVE-"))
        if not cves:
            return []
        cached = self.db.cve_cache_get(sorted(cves))
        cutoff = time.time() - self._ttl()
        return sorted(c for c in cves
                      if c not in cached or (cached[c].get("fetched_at") or 0) < cutoff)

    # -- apply (cache only, synchronous) ----------------------------------- #
    def apply(self, site: str | None = None) -> int:
        """Grade findings from the CVE cache. Safe to call on a request path."""
        findings = self.db.findings_with_cves()
        if site:
            site = site.rstrip("/")
            findings = [f for f in findings if f["site"] == site]
        all_cves = sorted({c for f in findings for c in f["cves"]})
        cache = self.db.cve_cache_get(all_cves)
        kev_ids = self._kev_ids(refresh=False)
        updated = 0
        for f in findings:
            rows = [cache[c] for c in f["cves"] if c in cache]
            kev = any(r.get("kev") for r in rows) or any(c in kev_ids for c in f["cves"])
            scores = [r["cvss"] for r in rows if r.get("cvss") is not None]
            epss = max((r["epss"] for r in rows if r.get("epss") is not None), default=None)
            fields: dict[str, Any] = {}
            severity = f["severity"]
            reason = f.get("severity_reason")
            if f.get("cvss") is None and scores:
                best = max(scores)
                ver = next((r.get("cvss_version") for r in rows
                            if r.get("cvss") == best), None)
                fields["cvss"] = best
                fields["cvss_source"] = "nvd"
                severity = _cvss_to_severity(best)
                reason = f"CVSS {best} (v{ver or '?'}, NVD)"
            if kev:
                severity = "critical"
                reason = ("CISA Known Exploited Vulnerability"
                          + (f"; {reason}" if reason and "NVD" in reason else ""))
            if kev != bool(f.get("kev")):
                fields["kev"] = 1 if kev else 0
            if epss is not None and epss != f.get("epss"):
                fields["epss"] = epss
            if severity != f["severity"]:
                fields["severity"] = severity
            if reason != f.get("severity_reason") and reason:
                fields["severity_reason"] = reason
            if fields:
                self.db.update_finding_fields(f["id"], **fields)
                updated += 1
        with self._lock:
            self._pending_count = len(self._pending()) if self.enabled() else 0
        return updated

    # -- background fetch -------------------------------------------------- #
    def schedule(self) -> bool:
        """Start one background fetch if enrichment is on and nothing is
        running. Returns True if a run was started."""
        if not self.enabled():
            return False
        with self._lock:
            if self._running:
                return False
            self._running = True
        threading.Thread(target=self._run, name="enrich", daemon=True).start()
        return True

    def _emit(self, kind: str, msg: str, level: str = "info") -> None:
        if self.events is not None:
            self.events.emit(kind, msg, level)

    def _run(self) -> None:
        count = 0
        try:
            self._last_error = None
            kev_ids = self._kev_ids(refresh=True)
            pending = self._pending()
            cap = int(self.config.get("ENRICH_MAX_PER_RUN", 150) or 150)
            batch = pending[:cap]
            epss = self._fetch_epss(batch) if batch else {}
            for cve in batch:
                data = self._fetch_nvd(cve)
                if data is None:
                    break  # rate-limited or offline; the rest waits for next run
                self.db.cve_cache_put(
                    cve, cvss=data["cvss"], vector=data["vector"],
                    cvss_version=data["cvss_version"], description=data["description"],
                    epss=epss.get(cve), kev=1 if cve in kev_ids else 0)
                count += 1
            # KEV membership can change for already-cached CVEs.
            for cve, row in self.db.cve_cache_get(pending[cap:]).items():
                if bool(row.get("kev")) != (cve in kev_ids):
                    self.db.cve_cache_put(cve, kev=1 if cve in kev_ids else 0,
                                          fetched_at=row.get("fetched_at"))
            updated = self.apply()
            if count or updated:
                self._emit("enrich_done",
                           f"Enriched {count} CVE(s) from NVD/EPSS/KEV; "
                           f"{updated} finding(s) re-graded.", "info")
            left = len(pending) - count
            if left > 0 and not self._last_error:
                self._emit("enrich_done", f"{left} CVE(s) still waiting for NVD "
                           f"(rate limited); they will be fetched on the next run.",
                           "warn")
        except Exception as exc:  # noqa: BLE001 — enrichment must never break a scan
            self._last_error = str(exc)
            self._emit("enrich_error", f"Enrichment failed: {exc}", "warn")
        finally:
            with self._lock:
                self._running = False
                self._last_run = time.time()
                self._last_count = count

    def _kev_ids(self, refresh: bool) -> set[str]:
        cached = self.db.kv_get("kev_ids")
        if cached and (not refresh or time.time() - cached[1] < _KEV_TTL):
            return set(cached[0])
        if not refresh:
            return set()
        status, doc = _http_get_json(KEV_URL, timeout=60)
        if status != 200 or not isinstance(doc, dict):
            self._last_error = f"KEV feed HTTP {status}"
            return set(cached[0]) if cached else set()
        ids = sorted({v.get("cveID") for v in doc.get("vulnerabilities") or []
                      if v.get("cveID")})
        self.db.kv_set("kev_ids", ids)
        return set(ids)

    def _fetch_epss(self, cves: list[str]) -> dict[str, float]:
        out: dict[str, float] = {}
        for i in range(0, len(cves), 100):
            chunk = cves[i:i + 100]
            status, doc = _http_get_json(f"{EPSS_URL}?cve={','.join(chunk)}")
            if status != 200 or not isinstance(doc, dict):
                self._last_error = f"EPSS HTTP {status}"
                continue
            for row in doc.get("data") or []:
                try:
                    out[row["cve"]] = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
        return out

    def _fetch_nvd(self, cve: str) -> dict[str, Any] | None:
        headers = {}
        if self.config.get("NVD_API_KEY"):
            headers["apiKey"] = str(self.config["NVD_API_KEY"])
        url = f"{NVD_URL}?{urllib.parse.urlencode({'cveId': cve})}"
        for attempt in (1, 2):
            status, doc = _http_get_json(url, headers=headers)
            if status == 200 and isinstance(doc, dict):
                items = doc.get("vulnerabilities") or []
                time.sleep(self._nvd_delay())
                if not items:  # unknown / rejected id: cache the miss
                    return {"cvss": None, "vector": None, "cvss_version": None,
                            "description": None}
                return _parse_nvd_item(items[0])
            if status in (403, 429, 503) and attempt == 1:
                time.sleep(30)
                continue
            self._last_error = f"NVD HTTP {status} for {cve}"
            return None
        return None
