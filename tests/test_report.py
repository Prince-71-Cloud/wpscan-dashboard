"""Target-controlled strings must not be interpreted as reportlab markup."""
import unittest

import report


class _DB:
    def __init__(self, title, error=None):
        self.title, self.error = title, error

    def all_findings(self):
        return [{"site": "https://evil.test", "finding_kind": "vulnerability",
                 "component_type": "plugin", "component_name": "<b>x</b>",
                 "component_version": "1<2", "title": self.title, "severity": "high",
                 "cvss": None, "fixed_in": "</para>", "cves": [], "references": []}]

    def latest_scan_status(self):
        return {"https://evil.test": {"status": "error" if self.error else "success",
                                      "error": self.error, "wp_version": "<6>",
                                      "started_at": 1, "finished_at": 2}}


class PdfEscaping(unittest.TestCase):
    def _pdf(self, title, error=None):
        try:
            return report.build_pdf(report.build_report(_DB(title, error)))
        except report.PdfUnavailable:
            self.skipTest("reportlab not installed")

    def test_markup_in_title_does_not_crash(self):
        self.assertTrue(self._pdf("Plugin </para><para> x <font size='40'>FAKE</font>"))

    def test_markup_in_error_does_not_crash(self):
        self.assertTrue(self._pdf("ok", error="Scan Aborted: <b>injected</b> </para>"))

    def test_plain_less_than(self):
        self.assertTrue(self._pdf("Elementor Pro < 4.2.2 - Upload & more"))


if __name__ == "__main__":
    unittest.main()
