import unittest

import parser as p


class Severity(unittest.TestCase):
    def sev(self, title, vuln=None):
        return p.classify_severity(title, vuln)[0]

    def test_cvss_wins(self):
        self.assertEqual(self.sev("Nothing", {"cvss": {"score": "9.8"}}), "critical")

    def test_preauth_is_critical(self):
        self.assertEqual(self.sev("X < 1 - Unauthenticated SQL Injection"), "critical")
        self.assertEqual(self.sev("X - Unauthenticated Arbitrary Options Update"), "critical")
        self.assertEqual(self.sev("X - Arbitrary Plugin Installation"), "critical")

    def test_admin_only_is_capped(self):
        self.assertEqual(self.sev("X - Authenticated (Admin+) SQL Injection"), "medium")
        self.assertEqual(self.sev("X - Admin+ Stored Cross-Site Scripting"), "medium")
        # lower roles keep their rating
        self.assertEqual(self.sev("X - Subscriber+ Privilege Escalation"), "high")

    def test_default(self):
        self.assertEqual(self.sev("Something unusual"), "medium")


class References(unittest.TestCase):
    def test_exploit_refs_kept_last(self):
        vuln = {"title": "t", "references": {
            "cve": ["2020-1"], "url": ["https://a/"], "wpvulndb": ["abc"],
            "exploitdb": [1234], "metasploit": ["exploit/x/y"]}}
        cves, urls = p._split_refs(vuln)
        self.assertEqual(cves, ["CVE-2020-1"])
        self.assertEqual(urls[:2], ["https://a/", "https://wpscan.com/vulnerability/abc"])
        self.assertEqual(urls[2:], ["https://www.exploit-db.com/exploits/1234",
                                    "https://www.rapid7.com/db/modules/exploit/x/y/"])
        self.assertTrue(p.has_exploit(urls))
        self.assertFalse(p.has_exploit(urls[:2]))


if __name__ == "__main__":
    unittest.main()
