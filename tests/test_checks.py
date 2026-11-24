"""Passive checks against a local HTTP server: soft-404 pages must not become
critical findings, redirects are not followed, real content is flagged."""
import http.server
import threading
import unittest

import checks

ROUTES = {
    "/": (200, {"Server": "nginx/1.25.3"}, b"<html>home</html>"),
    "/wp-config.php.bak": (200, {}, b"<html><body>Not found</body></html>"),   # soft 404
    "/wp-config.php.old": (200, {}, b"<?php define('DB_PASSWORD', 'hunter2');"),
    "/.env": (200, {}, b"APP_KEY=base64:abc\nDB_PASSWORD=x\n"),
    "/wp-content/debug.log": (302, {"Location": "/"}, b""),
    "/readme.html": (200, {}, b"<html><h1>WordPress</h1></html>"),
    "/wp-login.php": (200, {"Set-Cookie": "wordpress_test_cookie=WP+Cookie+check; path=/"},
                      b'<form><input name="log" id="user_login"></form>'),
    "/wp-json/wp/v2/users": (200, {"Content-Type": "application/json"},
                             b'[{"id":1,"slug":"admin","name":"admin"}]'),
}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path == "/wp-json/":
            origin = self.headers.get("Origin")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b'{"namespaces":["wp/v2"]}')
            return
        status, hdrs, body = ROUTES.get(self.path, (404, {}, b"nope"))
        self.send_response(status)
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


class PassiveChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()
        base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        cls.findings = checks.run_passive_checks(base, timeout=5, delay=0)
        cls.titles = [f["title"] for f in cls.findings]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def has(self, fragment):
        return any(fragment in t for t in self.titles)

    def test_soft_404_is_not_a_critical_finding(self):
        self.assertFalse(self.has("/wp-config.php.bak"), self.titles)

    def test_real_content_is_flagged(self):
        self.assertTrue(self.has("/wp-config.php.old"))
        self.assertTrue(self.has("/.env"))
        self.assertTrue(self.has("readme.html"))

    def test_redirects_are_not_followed(self):
        self.assertFalse(self.has("debug.log"), self.titles)

    def test_headers_cookies_cors_users(self):
        self.assertTrue(self.has("Missing security header: Content-Security-Policy"))
        self.assertTrue(self.has("Server software version disclosed"))
        self.assertTrue(self.has("Site served over HTTP"))
        self.assertTrue(self.has("without HttpOnly flag: wordpress_test_cookie"))
        self.assertTrue(self.has("REST API reflects arbitrary Origin"))
        self.assertTrue(self.has("User enumeration via REST API"))
        self.assertTrue(self.has("Admin login page reachable"))

    def test_finding_shape(self):
        keys = {"site", "finding_kind", "component_type", "component_name",
                "component_version", "title", "severity", "cvss", "fixed_in",
                "cves", "references", "evidence", "severity_reason"}
        for f in self.findings:
            self.assertEqual(set(f), keys)
            self.assertIn(f["severity"], ("critical", "high", "medium", "low", "info"))
            if f["evidence"] is not None:
                self.assertIsInstance(f["evidence"], dict)

    def test_evidence_is_reproducible(self):
        env = next(f for f in self.findings if "/.env" in f["title"])
        self.assertEqual(env["evidence"]["status"], 200)
        self.assertTrue(env["evidence"]["request"].startswith("GET http://127.0.0.1"))
        self.assertIn("APP_KEY", env["evidence"]["sample"])


if __name__ == "__main__":
    unittest.main()
