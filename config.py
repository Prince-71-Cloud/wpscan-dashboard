"""
config.py
=========
All configuration comes from environment variables with sensible defaults, so
the dashboard runs out of the box and can be tuned for a real deployment
without code changes.

  WPSCAN_PATH        path to the wpscan binary                 (default: wpscan)
  WPSCAN_ENUMERATE   what wpscan enumerates (vp,vt,u,cb,dbe)   (default: vp,vt,u,cb,dbe)
  WPSCAN_PLUGINS_DETECTION  plugin detection mode              (default: aggressive)
  WPSCAN_EXTRA_ARGS  extra raw wpscan args (advanced)          (default: none)
  EXTRA_CHECKS       run passive web-hygiene checks too        (default: true)
  CHECK_TIMEOUT      per-request timeout for hygiene checks    (default: 10)
  WPSCAN_API_TOKEN   single token (optional; added to the key   (default: none)
                     ring alongside API_KEYS_FILE)
  API_KEYS_FILE      file of WPScan API keys, one per line,     (default: api_keys.txt)
                     rotated when a key hits its daily limit
  SITES_FILE         list of target site URLs, one per line    (default: sites.txt)
  DATABASE           SQLite file path                          (default: dashboard.db)
  SCAN_TIMEOUT       per-site scan timeout in seconds          (default: 600)
  MAX_CONCURRENT     parallel scans per batch                  (default: 3)
  SAMPLE_DIR         directory of sample WPScan JSON reports    (default: sample_scans)
  HOST / PORT        bind address                              (default: 127.0.0.1:5000)
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
    "WPSCAN_EXTRA_ARGS": os.environ.get("WPSCAN_EXTRA_ARGS") or None,
    "EXTRA_CHECKS":     os.environ.get("EXTRA_CHECKS", "true"),
    "CHECK_TIMEOUT":    _int("CHECK_TIMEOUT", 10),
    "WPSCAN_API_TOKEN": os.environ.get("WPSCAN_API_TOKEN") or None,
    "API_KEYS_FILE":    os.environ.get("API_KEYS_FILE", "api_keys.txt"),
    "SITES_FILE":       os.environ.get("SITES_FILE", "sites.txt"),
    "DATABASE":         os.environ.get("DATABASE", "dashboard.db"),
    "SCAN_TIMEOUT":     _int("SCAN_TIMEOUT", 600),
    "MAX_CONCURRENT":   _int("MAX_CONCURRENT", 3),
    "SAMPLE_DIR":       os.environ.get("SAMPLE_DIR", "sample_scans"),
    "HOST":             os.environ.get("HOST", "127.0.0.1"),
    "PORT":             _int("PORT", 5000),
}
