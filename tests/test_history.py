"""Finding history: new / recurring / fixed / regressed across scans, and the
counts the scan manager records."""
import os
import tempfile
import unittest

from db import Database
from tests.test_scanner import _config, _run


def _f(title, sev="high"):
    return {"component_type": "plugin", "component_name": "x", "title": title,
            "severity": sev, "cves": [], "references": []}


class HistoryDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.tmp, "h.db"))

    def test_lifecycle(self):
        d1 = self.db.replace_findings("https://a", self.db.create_scan("https://a"), [_f("A"), _f("B")])
        self.assertEqual((sorted(d1["new"]), d1["fixed"]), (["A", "B"], []))
        d2 = self.db.replace_findings("https://a", self.db.create_scan("https://a"), [_f("B"), _f("C")])
        self.assertEqual((d2["new"], d2["fixed"], d2["recurring"]), (["C"], ["A"], 1))
        d3 = self.db.replace_findings("https://a", self.db.create_scan("https://a"), [_f("A"), _f("C")])
        self.assertEqual((d3["regressed"], d3["fixed"]), (["A"], ["B"]))
        st = {f["title"]: f["history_status"] for f in self.db.all_findings()}
        self.assertEqual(st, {"A": "regressed", "C": "recurring"})
        fixed = self.db.resolved_findings("https://a")
        self.assertEqual([r["title"] for r in fixed], ["B"])
        # first_seen survives a fix/regress cycle
        a = next(f for f in self.db.all_findings() if f["title"] == "A")
        self.assertLess(a["first_seen"], a["last_seen"])

    def test_sites_are_independent(self):
        self.db.replace_findings("https://a", self.db.create_scan("https://a"), [_f("A")])
        d = self.db.replace_findings("https://b", self.db.create_scan("https://b"), [_f("A")])
        self.assertEqual(d["new"], ["A"])

    def test_clear_wipes_history(self):
        self.db.replace_findings("https://a", self.db.create_scan("https://a"), [_f("A")])
        self.db.clear()
        self.assertEqual(self.db.resolved_findings(), [])
        d = self.db.replace_findings("https://a", self.db.create_scan("https://a"), [_f("A")])
        self.assertEqual(d["new"], ["A"])


class ScanManagerRecordsDiff(unittest.TestCase):
    def test_counts_on_scan_row(self):
        tmp = tempfile.mkdtemp()
        db = Database(os.path.join(tmp, "s.db"))
        # a previous scan with one finding that the replayed scan will not report
        db.replace_findings("https://ok.example.test", db.create_scan("https://ok.example.test"),
                            [_f("Gone plugin vuln")])
        _run(db, _config(tmp), ["https://ok.example.test"])
        st = db.latest_scan_status()["https://ok.example.test"]
        self.assertEqual(st["status"], "success")
        self.assertGreater(st["new_count"], 0)
        self.assertEqual(st["fixed_count"], 1)
        self.assertEqual([r["title"] for r in db.resolved_findings()], ["Gone plugin vuln"])


if __name__ == "__main__":
    unittest.main()
