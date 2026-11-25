"""대시보드 점검 반영 시험: 보안 헤더, 정상 브라우저 요청 제외, 조사용 사건 라벨, 외부 자원 없음."""
from __future__ import annotations

import http.cookiejar
import json
import re
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.dashboard import (  # noqa: E402
    AuthConfig, DashboardStore, _fmt_status, _is_suspect_event, make_handler, parse_user_roles,
)
from soc.incident_service import build_incidents  # noqa: E402
from soc.normalizer import normalize_log_line  # noqa: E402


def _login_incident():
    events = []
    for i in range(5):
        raw = json.dumps({
            "timestamp_utc": f"2026-11-22T03:00:0{i}Z", "source": "erp", "event_type": "login_failed",
            "outcome": "failure", "username": "alice", "client_ip": "172.28.10.11", "peer_ip": "172.28.20.5",
            "client_ip_trusted": True, "request_id": f"r{i}", "http_method": "POST", "http_path": "/api/login",
            "status_code": 401, "ingest_mode": "live",
        })
        events.append(normalize_log_line(raw, source="erp", file_path="e.jsonl", line_offset=i * 100,
                                         collection_mode="live")[1])
    return build_incidents([], events)[0]


class SuspectRuleTests(unittest.TestCase):
    def test_browser_housekeeping_requests_are_not_anomalies(self):
        self.assertFalse(_is_suspect_event("caddy", "http_request", "failure", 404, "/favicon.ico"))
        self.assertFalse(_is_suspect_event("caddy", "http_request", "failure", 401, "/api/session"))
        self.assertFalse(_is_suspect_event("caddy", "http_request", "failure", 404, "/favicon.ico?v=2"))

    def test_real_errors_stay_anomalies(self):
        self.assertTrue(_is_suspect_event("caddy", "http_request", "failure", 404, "/admin"))
        self.assertTrue(_is_suspect_event("caddy", "http_request", "failure", 401, "/api/login"))
        self.assertTrue(_is_suspect_event("caddy", "http_request", "failure", 500, "/favicon.ico"))
        self.assertTrue(_is_suspect_event("caddy", "http_request", "failure", 404))  # 경로를 모르면 기존대로 센다
        self.assertTrue(_is_suspect_event("erp", "login_failed", "failure", 401))
        self.assertTrue(_is_suspect_event("gateway", "fw_deny", "deny", None))


class StatusLabelTests(unittest.TestCase):
    def test_investigation_only_incident_is_not_asked_for_approval(self):
        self.assertIn("확인 필요", _fmt_status("open", False))
        self.assertNotIn("승인", _fmt_status("open", False))

    def test_blockable_or_unknown_incident_keeps_approval_label(self):
        self.assertIn("확인·승인 필요", _fmt_status("open", True))
        self.assertIn("확인·승인 필요", _fmt_status("open"))
        self.assertIn("차단 해제됨", _fmt_status("released", False))


class HeadersAndAssetsOverHttpTests(unittest.TestCase):
    def setUp(self):
        self.inc = _login_incident()
        self.store = DashboardStore(incidents=[self.inc])
        self.auth = AuthConfig(username="ops", password="pw", secret="sec", roles=parse_user_roles("", "ops"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.store, auth_config=self.auth))
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.op.open(urllib.request.Request(
            self.base + "/login", method="POST",
            data=urllib.parse.urlencode({"username": "admin1", "password": "pw"}).encode())).close()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_security_headers_on_login_and_authenticated_pages(self):
        for path, opener in (("/login", urllib.request.urlopen), ("/", self.op.open),
                             (f"/incidents/{self.inc.incident_id}", self.op.open), ("/api/incidents", self.op.open)):
            with opener(self.base + path) as r:
                h = r.headers
                self.assertEqual(h["X-Frame-Options"], "DENY", path)
                self.assertEqual(h["X-Content-Type-Options"], "nosniff", path)
                self.assertEqual(h["Referrer-Policy"], "same-origin", path)
                self.assertEqual(h["Cache-Control"], "no-store", path)
                self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"], path)
                self.assertIn("form-action 'self'", h["Content-Security-Policy"], path)

    def test_server_header_does_not_reveal_python_version(self):
        with urllib.request.urlopen(self.base + "/login") as r:
            server = r.headers["Server"]
        self.assertNotIn("Python", server)
        self.assertNotIn("BaseHTTP", server)

    def test_pages_load_no_external_resources(self):
        for path in ("/login", "/", f"/incidents/{self.inc.incident_id}", "/events"):
            opener = urllib.request.urlopen if path == "/login" else self.op.open
            with opener(self.base + path) as r:
                page = r.read().decode("utf-8")
            external = re.findall(r"""(?:src|href)=["']https?://[^"']+""", page)
            self.assertEqual(external, [], f"{path}: 외부 자원 {external}")
            self.assertNotIn("cdn.jsdelivr.net", page, path)

    def test_overview_shows_incident_queue_before_trend_chart(self):
        with self.op.open(self.base + "/") as r:
            page = r.read().decode("utf-8")
        queue = page.find("우선 확인할 사건")
        trend = page.find("로그인 실패 추이")
        self.assertGreater(queue, 0)
        self.assertGreater(trend, 0)
        self.assertLess(queue, trend)

    def test_font_is_served_locally_without_login_and_cached(self):
        # 로그인 화면에서도 글꼴이 필요하므로 인증 없이 받을 수 있어야 한다.
        with urllib.request.urlopen(self.base + "/static/fonts/PretendardVariable.woff2") as r:
            body = r.read()
            self.assertEqual(r.status, 200)
            self.assertEqual(r.headers["Content-Type"], "font/woff2")
            self.assertEqual(body[:4], b"wOF2")
            self.assertIn("immutable", r.headers["Cache-Control"])
            self.assertNotIn("no-store", r.headers["Cache-Control"])
            self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(int(r.headers["Content-Length"]), len(body))

    def test_only_the_font_file_is_served_as_static(self):
        for path in ("/static/fonts/../dashboard.py", "/static/fonts/other.woff2", "/static/dashboard.py",
                     "/static/fonts/PretendardVariable.woff2/../../dashboard.py"):
            try:
                with urllib.request.urlopen(self.base + path) as r:
                    status, body = r.status, r.read()
            except urllib.error.HTTPError as err:
                status, body = err.code, b""
            self.assertNotEqual(status, 200, path)
            self.assertNotIn(b"def ", body, path)

    def test_pages_declare_the_local_font_face(self):
        with urllib.request.urlopen(self.base + "/login") as r:
            page = r.read().decode("utf-8")
        self.assertIn("/static/fonts/PretendardVariable.woff2", page)
        self.assertIn("@font-face", page)

    def test_login_wording_is_consistent(self):
        with urllib.request.urlopen(self.base + "/login") as r:
            page = r.read().decode("utf-8")
        self.assertIn("담당자 아이디", page)
        self.assertNotIn("운영자 아이디", page)


if __name__ == "__main__":
    unittest.main()
