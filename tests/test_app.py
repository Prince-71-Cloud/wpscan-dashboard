"""HTTP-layer guards: CSRF header, Origin/Host validation, settings bounds,
target allow-list. Runs against a scratch database."""
import os
import pathlib
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="wpscan-test-")
_SITES = pathlib.Path(_TMP, "sites.txt")
_SITES.write_text("https://blog.example.com\n")
os.environ.update({
    "DATABASE": os.path.join(_TMP, "scratch.db"),
    "SITES_FILE": str(_SITES),
    "API_KEYS_FILE": os.path.join(_TMP, "no-keys"),
    "AUDIT_LOG": os.path.join(_TMP, "audit.log"),
    "SAMPLE_DIR": str(pathlib.Path(__file__).resolve().parent.parent / "sample_scans"),
})

from app import app  # noqa: E402  (env must be set first)

XHR = {"X-Requested-With": "XMLHttpRequest"}


class Guards(unittest.TestCase):
    def setUp(self):
        self.c = app.test_client()

    def test_post_without_header_is_refused(self):
        self.assertEqual(self.c.post("/api/clear").status_code, 403)
        self.assertEqual(self.c.post("/api/clear", data="x=1",
                                     content_type="application/x-www-form-urlencoded",
                                     headers={"Origin": "https://attacker.example"}).status_code, 403)

    def test_foreign_origin_refused_even_with_header(self):
        r = self.c.post("/api/clear", headers={**XHR, "Origin": "https://attacker.example"})
        self.assertEqual(r.status_code, 403)
        r = self.c.post("/api/clear", headers={**XHR, "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(r.status_code, 403)

    def test_same_origin_allowed(self):
        r = self.c.post("/api/ingest-samples", headers={**XHR, "Origin": "http://localhost"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["ingested"], 3)
        self.assertTrue(len(self.c.get("/api/findings").get_json()["findings"]) > 0)
        self.assertEqual(self.c.post("/api/clear", headers=XHR).status_code, 200)

    def test_untrusted_host_rejected(self):
        self.assertEqual(self.c.get("/", headers={"Host": "attacker.example"}).status_code, 400)
        self.assertEqual(self.c.get("/", headers={"Host": "localhost:5000"}).status_code, 200)

    def test_security_headers_present(self):
        h = self.c.get("/").headers
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")

    def test_settings_validation(self):
        r = self.c.post("/api/settings", json={"PREFLIGHT_TIMEOUT": -5,
                                               "WPSCAN_FORMAT": "garbage",
                                               "WPSCAN_ENUMERATE": "vp;rm -rf"}, headers=XHR)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(set(r.get_json()["invalid"]),
                         {"PREFLIGHT_TIMEOUT", "WPSCAN_FORMAT", "WPSCAN_ENUMERATE"})
        r = self.c.post("/api/settings", json={"PREFLIGHT_CHECK": False,
                                               "WPSCAN_ENUMERATE": "vp,vt,u1-5,cb,dbe"}, headers=XHR)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["settings"]["PREFLIGHT_CHECK"], "false")

    def test_scan_targets_restricted_to_known_sites(self):
        r = self.c.post("/api/scan", json={"site": "http://10.0.0.1"}, headers=XHR)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["rejected"], ["http://10.0.0.1"])
        self.assertEqual(self.c.post("/api/scan", json={"sites": "x"}, headers=XHR).status_code, 400)

    def test_audit_log_written(self):
        self.c.post("/api/clear", headers=XHR)
        self.assertIn("clear from=", pathlib.Path(os.environ["AUDIT_LOG"]).read_text())


if __name__ == "__main__":
    unittest.main()
