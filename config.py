"""
config.py
=========
All configuration comes from environment variables with sensible defaults, so
the dashboard runs out of the box and can be tuned for a real deployment
without code changes.

  WPSCAN_PATH        path to the wpscan binary                 (default: wpscan)
  WPSCAN_ENUMERATE   what wpscan enumerates (vp,vt,u,cb,dbe)   (default: vp,vt,u,cb,dbe)
  WPSCAN_PLUGINS_DETECTION  plugin detection mode              (default: aggressive)
  WPSCAN_VERBOSE     stream live scan progress to console      (default: true)
  WPSCAN_EXTRA_ARGS  extra raw wpscan args (advanced)          (default: none)
  EXTRA_CHECKS       run passive web-hygiene checks too        (default: true)
  CHECK_TIMEOUT      per-request timeout for hygiene checks    (default: 10)
  WPSCAN_API_TOKEN   single token (optional; added to the key   (default: none)
                     ring alongside API_KEYS_FILE)
  API_KEYS_FILE      file of WPScan API keys, one per line,     (default: api_keys.txt)
                     rotated when a key hits its daily limit
  SITES_FILE         list of target site URLs, one per line    (default: sites.txt)
  DATABASE           SQLite file path                          (default: dashboard.db)
  SCAN_TIMEOUT       per-site scan timeout in seconds          (default: 1800)
  SAMPLE_DIR         directory of sample WPScan JSON reports    (default: sample_scans)
  HOST / PORT        bind address                              (default: 127.0.0.1:5000)
  ALLOW_REMOTE_BIND  allow HOST other than loopback (no auth!)  (default: false)
  TRUSTED_HOSTS      extra Host header values to accept, comma  (default: loopback names
                     separated (DNS-rebinding guard)             + HOST)
  AUDIT_LOG          file that records who started/stopped what (default: audit.log)
  WPSCAN_THROTTLE    ms to wait between WPScan requests          (default: 0)
  WPSCAN_MAX_THREADS WPScan --max-threads (gentler on targets)   (default: wpscan default)
  ENRICHMENT         fetch CVSS/EPSS/KEV for CVEs (NVD, FIRST,  (default: true)
                     CISA; never touches the targets)
  NVD_API_KEY        optional NVD key: 50 req/30s instead of 5  (default: none)
  ENRICH_TTL_DAYS    re-fetch CVE data after this many days      (default: 7)
"""

import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


CONFIG = {
    "WPSCAN_PATH":      os.environ.get("WPSCAN_PATH", "wpscan"),
    "WPSCAN_ENUMERATE": os.environ.get("WPSCAN_ENUMERATE", "vp,vt,u,cb,dbe"),
    "WPSCAN_PLUGINS_DETECTION": os.environ.get("WPSCAN_PLUGINS_DETECTION", "aggressive"),
    "WPSCAN_VERBOSE":   os.environ.get("WPSCAN_VERBOSE", "true"),
    "WPSCAN_FORMAT":    os.environ.get("WPSCAN_FORMAT", "cli-no-colour"),
    "WPSCAN_EXTRA_ARGS": os.environ.get("WPSCAN_EXTRA_ARGS") or None,
    "EXTRA_CHECKS":     os.environ.get("EXTRA_CHECKS", "true"),
    "CHECK_TIMEOUT":    _int("CHECK_TIMEOUT", 10),
    "WPSCAN_API_TOKEN": os.environ.get("WPSCAN_API_TOKEN") or None,
    "API_KEYS_FILE":    os.environ.get("API_KEYS_FILE", "api_keys.txt"),
    "SITES_FILE":       os.environ.get("SITES_FILE", "sites.txt"),
    "DATABASE":         os.environ.get("DATABASE", "dashboard.db"),
    "SCAN_TIMEOUT":     _int("SCAN_TIMEOUT", 1800),
    "PREFLIGHT_CHECK":  os.environ.get("PREFLIGHT_CHECK", "true"),
    "PREFLIGHT_TIMEOUT": _int("PREFLIGHT_TIMEOUT", 10),
    "SAMPLE_DIR":       os.environ.get("SAMPLE_DIR", "sample_scans"),
    "HOST":             os.environ.get("HOST", "127.0.0.1"),
    "PORT":             _int("PORT", 5000),
    "ALLOW_REMOTE_BIND": os.environ.get("ALLOW_REMOTE_BIND", "false"),
    "TRUSTED_HOSTS":    os.environ.get("TRUSTED_HOSTS", ""),
    "AUDIT_LOG":        os.environ.get("AUDIT_LOG", "audit.log"),
    "WPSCAN_THROTTLE":  _int("WPSCAN_THROTTLE", 0),
    "WPSCAN_MAX_THREADS": _int("WPSCAN_MAX_THREADS", 0),
    "ENRICHMENT":       os.environ.get("ENRICHMENT", "true"),
    "NVD_API_KEY":      os.environ.get("NVD_API_KEY") or None,
    "ENRICH_TTL_DAYS":  _int("ENRICH_TTL_DAYS", 7),
    "ENRICH_MAX_PER_RUN": _int("ENRICH_MAX_PER_RUN", 150),
}
