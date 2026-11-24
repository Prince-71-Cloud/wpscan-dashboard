"""ScanManager end-to-end with a fake wpscan binary (no network, no quota):
quota exhaustion -> partial, main-redirect follow, TLS fallback, and crash
isolation so no site is ever left in 'running'."""
import os
import pathlib
import tempfile
import time
import unittest

import scanner
from db import Database

HERE = pathlib.Path(__file__).resolve().parent


def _config(tmp, **over):
    keys = pathlib.Path(tmp, "keys.txt")
    keys.write_text("fake-key-for-fake-wpscan-0001\n")
    cfg = {
        "WPSCAN_PATH": str(HERE / "fake_wpscan.sh"),
        "WPSCAN_ENUMERATE": "vp,vt,u,cb,dbe",
        "WPSCAN_PLUGINS_DETECTION": "passive",
        "WPSCAN_VERBOSE": "true",
        "WPSCAN_FORMAT": "cli-no-colour",
        "WPSCAN_EXTRA_ARGS": None,
        "EXTRA_CHECKS": "false",       # no network
        "PREFLIGHT_CHECK": "false",    # no network
        "PREFLIGHT_TIMEOUT": 5,
        "SCAN_TIMEOUT": 60,
        "API_KEYS_FILE": str(keys),
        "WPSCAN_API_TOKEN": None,
        "WPSCAN_THROTTLE": 0,
        "WPSCAN_MAX_THREADS": 0,
    }
    cfg.update(over)
    return cfg


def _run(db, cfg, sites, timeout=30):
    m = scanner.ScanManager(db, cfg)
    assert m.start_batch(sites)
    t0 = time.time()
    while m.is_running() and time.time() - t0 < timeout:
        time.sleep(0.1)
    assert not m.is_running(), "batch did not finish"
    return m


class FakeWpscanBatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wpscan-test-")
        self.db = Database(os.path.join(self.tmp, "t.db"))

    def test_quota_exhausted_is_partial_not_success(self):
        m = _run(self.db, _config(self.tmp), ["https://quota.example.test"])
        st = self.db.latest_scan_status()["https://quota.example.test"]
        self.assertEqual(st["status"], "partial")
        self.assertIn("ran out of daily requests", st["error"])
        self.assertTrue(any(f["site"] == "https://quota.example.test"
                            for f in self.db.all_findings()))
        self.assertEqual(m._keyring.active_count(), 0)  # key retired

    def test_redirect_followed_and_stored_under_original_site(self):
        _run(self.db, _config(self.tmp), ["https://redirect.example.test"])
        st = self.db.latest_scan_status()["https://redirect.example.test"]
        self.assertEqual(st["status"], "success", st.get("error"))
        sites = {f["site"] for f in self.db.all_findings()}
        self.assertEqual(sites, {"https://redirect.example.test"})

    def test_tls_failure_retried_with_checks_disabled(self):
        _run(self.db, _config(self.tmp), ["https://tls.example.test"])
        st = self.db.latest_scan_status()["https://tls.example.test"]
        self.assertEqual(st["status"], "success", st.get("error"))

    def test_internal_crash_does_not_strand_site_or_batch(self):
        orig = scanner.preflight_check

        def boom(url, timeout=10):
            if "crash" in url:
                raise ValueError("Timeout value out of range")
            return True, "ok"
        scanner.preflight_check = boom
        try:
            _run(self.db, _config(self.tmp, PREFLIGHT_CHECK="true"),
                 ["https://crash.example.test", "https://ok.example.test"])
        finally:
            scanner.preflight_check = orig
        st = self.db.latest_scan_status()
        self.assertEqual(st["https://crash.example.test"]["status"], "error")
        self.assertIn("Internal error", st["https://crash.example.test"]["error"])
        self.assertEqual(st["https://ok.example.test"]["status"], "success")


if __name__ == "__main__":
    unittest.main()
