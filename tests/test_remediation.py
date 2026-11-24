"""Every finding gets concrete guidance; the action plan groups by fix."""
import unittest

import remediation


def _f(**kw):
    base = {"site": "https://a.test", "finding_kind": "vulnerability", "component_type": "plugin",
            "component_name": "x", "component_version": "1.0", "title": "t", "severity": "medium",
            "cvss": None, "fixed_in": None, "cves": [], "references": []}
    base.update(kw)
    return base


class Rules(unittest.TestCase):
    def test_plugin_update_with_fix(self):
        r = remediation.remediation_for(_f(component_name="contact-form-7", fixed_in="5.3.2",
                                           component_version="5.3.1"))
        self.assertEqual(r["action_key"], "update:plugin:contact-form-7")
        self.assertIn("5.3.2", r["action"])
        self.assertIn("WP-CLI", r["snippets"])
        self.assertIn("wp plugin update contact-form-7", r["snippets"]["WP-CLI"])

    def test_plugin_without_fix_says_remove(self):
        r = remediation.remediation_for(_f(component_name="bad", severity="critical"))
        self.assertIn("Remove or replace", r["action"])
        self.assertTrue(any("compromised" in s for s in r["steps"]))

    def test_core_update(self):
        r = remediation.remediation_for(_f(component_type="core", component_name="WordPress core"))
        self.assertEqual(r["action_key"], "update:core")

    def test_hygiene_rules_have_snippets(self):
        cases = {
            "Missing security header: Strict-Transport-Security (HSTS)": "headers",
            "wp-config backup exposed (DB credentials): /wp-config.php.bak": "remove-exposed-files",
            "Exposed db exports: https://a.test/backup.sql": "remove-exposed-files",
            "Directory listing enabled: /wp-content/uploads/": "directory-listing",
            "xmlrpc.php enabled (pingback/brute-force surface): /xmlrpc.php": "xmlrpc",
            "User enumeration via REST API: /wp-json/wp/v2/users": "user-enumeration",
            "Cookie(s) set without HttpOnly flag: wordpress_test_cookie": "cookies",
            "REST API reflects arbitrary Origin in Access-Control-Allow-Origin": "cors",
            "Legacy TLS protocol accepted: TLSv1.0": "tls",
            "Server software version disclosed via Server: nginx/1.2": "version-disclosure",
        }
        for title, key in cases.items():
            r = remediation.remediation_for(_f(finding_kind="hygiene", component_type="tls" if "TLS" in title else "web", title=title))
            self.assertEqual(r["action_key"], key, title)
            self.assertTrue(r["steps"], title)
            self.assertTrue(r["snippets"], title)

    def test_generic_fallback_never_none(self):
        r = remediation.remediation_for(_f(finding_kind="info", component_type="server", title="odd"))
        self.assertEqual(r["action_key"], "review")


class ActionPlan(unittest.TestCase):
    def test_groups_and_orders(self):
        fs = [
            _f(id=1, component_name="cf7", fixed_in="2", title="A", severity="medium"),
            _f(id=2, component_name="cf7", fixed_in="2", title="B", severity="critical"),
            _f(id=3, finding_kind="hygiene", component_type="headers", title="Missing security header: Referrer-Policy", severity="info"),
            _f(id=4, finding_kind="hygiene", component_type="headers", title="Missing security header: X-Frame-Options (clickjacking)", severity="low"),
        ]
        remediation.attach(fs)
        plan = remediation.action_plan(fs)
        self.assertEqual([g["action_key"] for g in plan], ["update:plugin:cf7", "headers"])
        self.assertEqual(plan[0]["severity"], "critical")
        self.assertEqual(plan[0]["count"], 2)
        self.assertEqual(plan[1]["count"], 2)


if __name__ == "__main__":
    unittest.main()
