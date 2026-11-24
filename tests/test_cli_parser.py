"""cli_parser must recover every finding class from WPScan's text output, in
both the 4.2 layout and the older 'count after the list' layout."""
import pathlib
import unittest

import cli_parser

FIX = pathlib.Path(__file__).parent / "fixtures"


def _by_title(findings):
    return {f["title"]: f for f in findings}


class Layout42(unittest.TestCase):
    def setUp(self):
        text = (FIX / "wpscan_cli_42.txt").read_text()
        self.r = cli_parser.parse_cli(text, site_hint="https://example.test")
        self.f = _by_title(self.r["findings"])

    def test_meta(self):
        self.assertEqual(self.r["wp_version"], "6.1")
        self.assertEqual(self.r["target_ip"], "203.0.113.5")
        self.assertEqual(self.r["requests_remaining"], 20)

    def test_main_theme_is_not_attributed_to_core(self):
        f = self.f["Astra < 4.1.6 - Reflected Cross-Site Scripting"]
        self.assertEqual(f["component_type"], "theme")
        self.assertEqual(f["component_name"], "astra")
        self.assertEqual(f["component_version"], "4.1.0")
        self.assertEqual(f["cves"], ["CVE-2023-1234"])
        self.assertFalse(any(x["component_name"] == "WordPress core"
                             for x in self.r["findings"]))

    def test_config_backup_and_db_export_are_emitted(self):
        cb = self.f["Exposed config backups: https://example.test/wp-config.php.bak"]
        self.assertEqual((cb["severity"], cb["component_type"], cb["component_name"],
                          cb["finding_kind"]), ("high", "config", "config_backups", "exposure"))
        dbe = self.f["Exposed db exports: https://example.test/backup.sql"]
        self.assertEqual(dbe["severity"], "critical")
        self.assertEqual(dbe["references"], ["https://example.test/backup.sql"])

    def test_plugin_with_exploit_refs(self):
        f = self.f["Contact Form 7 < 5.3.2 - Unrestricted File Upload"]
        self.assertEqual(f["component_type"], "plugin")
        self.assertEqual(f["fixed_in"], "5.3.2")
        # advisory first, exploit links last
        self.assertEqual(f["references"][0], "https://wpscan.com/vulnerability/def")
        self.assertIn("https://www.exploit-db.com/exploits/49000", f["references"])
        self.assertIn("https://www.rapid7.com/db/modules/exploit/multi/http/wp_cf7_upload/",
                      f["references"])

    def test_evidence_and_reason(self):
        f = self.f["Astra < 4.1.6 - Reflected Cross-Site Scripting"]
        self.assertEqual(f["evidence"]["version_confidence"], "80%")
        self.assertEqual(f["evidence"]["location"], "https://example.test/wp-content/themes/astra/")
        self.assertIn("keyword", f["severity_reason"])
        cb = self.f["Exposed config backups: https://example.test/wp-config.php.bak"]
        self.assertEqual(cb["evidence"]["url"], "https://example.test/wp-config.php.bak")

    def test_users_and_interesting(self):
        self.assertIn("User enumerated: admin", self.f)
        self.assertTrue(any(t.startswith("XML-RPC enabled") for t in self.f))


class LayoutCountAfter(unittest.TestCase):
    def test_count_line_ends_section(self):
        text = (FIX / "wpscan_cli_4x_count_after.txt").read_text()
        r = cli_parser.parse_cli(text, site_hint="https://example.test")
        f = _by_title(r["findings"])
        cf7 = f["Contact Form 7 < 5.3.2 - Unrestricted File Upload"]
        self.assertEqual(cf7["component_name"], "contact-form-7")
        self.assertEqual(r["requests_remaining"], 0)
        self.assertFalse(any(x["finding_kind"] == "exposure" for x in r["findings"]))


if __name__ == "__main__":
    unittest.main()
