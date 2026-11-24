"""NVD / EPSS / KEV enrichment with the HTTP layer replaced by canned
payloads: cache, re-grading, KEV override, graceful failure."""
import os
import tempfile
import unittest

import enrich
from db import Database

NVD_OK = {"vulnerabilities": [{"cve": {
    "id": "CVE-2020-35489",
    "descriptions": [{"lang": "en", "value": "Unrestricted upload"}],
    "metrics": {"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/x"}},
        {"type": "Primary", "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}},
    ]}}}]}


def _fake(url, headers=None, timeout=30):
    if url.startswith(enrich.KEV_URL):
        return 200, {"vulnerabilities": [{"cveID": "CVE-2021-0001"}]}
    if url.startswith(enrich.EPSS_URL):
        return 200, {"data": [{"cve": "CVE-2020-35489", "epss": "0.93"},
                              {"cve": "CVE-2021-0001", "epss": "0.05"}]}
    if "CVE-2020-35489" in url:
        return 200, NVD_OK
    return 200, {"vulnerabilities": []}   # unknown id


class Enrichment(unittest.TestCase):
    def setUp(self):
        self.db = Database(os.path.join(tempfile.mkdtemp(), "e.db"))
        sid = self.db.create_scan("https://a")
        self.db.replace_findings("https://a", sid, [
            {"component_type": "plugin", "component_name": "p", "title": "kw", "severity": "high",
             "cves": ["CVE-2020-35489"], "references": [], "severity_reason": "keyword"},
            {"component_type": "plugin", "component_name": "q", "title": "kev", "severity": "medium",
             "cves": ["CVE-2021-0001"], "references": []},
            {"component_type": "plugin", "component_name": "r", "title": "own", "severity": "low",
             "cvss": 3.1, "cves": ["CVE-2020-35489"], "references": []},
            {"component_type": "headers", "component_name": "h", "title": "nocve", "severity": "low",
             "cves": [], "references": []},
        ])
        self._orig = enrich._http_get_json
        enrich._http_get_json = _fake
        self.e = enrich.Enricher(self.db, {"ENRICHMENT": "true", "NVD_API_KEY": "k"})
        self.e._nvd_delay = lambda: 0

    def tearDown(self):
        enrich._http_get_json = self._orig

    def _by_title(self):
        return {f["title"]: f for f in self.db.all_findings()}

    def test_run_grades_findings(self):
        self.e._run()
        f = self._by_title()
        self.assertEqual((f["kw"]["severity"], f["kw"]["cvss"], f["kw"]["cvss_source"]),
                         ("critical", 9.8, "nvd"))          # Primary metric wins
        self.assertIn("NVD", f["kw"]["severity_reason"])
        self.assertAlmostEqual(f["kw"]["epss"], 0.93)
        self.assertEqual(f["kev"]["severity"], "critical")   # KEV forces critical
        self.assertTrue(f["kev"]["kev"])
        self.assertIn("Known Exploited", f["kev"]["severity_reason"])
        self.assertEqual((f["own"]["severity"], f["own"]["cvss"]), ("low", 3.1))  # own CVSS kept
        self.assertEqual(f["nocve"]["severity"], "low")
        self.assertEqual(self.e.status()["pending"], 0)
        self.assertIsNone(self.e.status()["last_error"])

    def test_apply_is_cache_only_and_survives_rescan(self):
        self.e._run()
        # a re-scan replaces the rows; apply() must re-grade from the cache
        sid = self.db.create_scan("https://a")
        self.db.replace_findings("https://a", sid, [
            {"component_type": "plugin", "component_name": "p", "title": "kw", "severity": "high",
             "cves": ["CVE-2020-35489"], "references": []}])
        enrich._http_get_json = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network!"))
        self.e.apply("https://a")
        self.assertEqual(self._by_title()["kw"]["severity"], "critical")

    def test_nvd_failure_is_contained(self):
        enrich._http_get_json = lambda url, headers=None, timeout=30: (503, None) \
            if url.startswith(enrich.NVD_URL) else _fake(url, headers, timeout)
        import time as _t
        real_sleep = _t.sleep
        _t.sleep = lambda s: None
        try:
            self.e._run()
        finally:
            _t.sleep = real_sleep
        self.assertIn("NVD HTTP 503", self.e.status()["last_error"] or "")
        self.assertEqual(self._by_title()["kw"]["severity"], "high")   # unchanged
        self.assertEqual(self._by_title()["kev"]["severity"], "critical")  # KEV still applied

    def test_disabled(self):
        e = enrich.Enricher(self.db, {"ENRICHMENT": "false"})
        self.assertFalse(e.schedule())


if __name__ == "__main__":
    unittest.main()
