"""대시보드 아이디별 역할(분석가·승인자·관리자) 시험. 비밀번호는 모두 같고 아이디로 권한을 나눈다."""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.dashboard import (  # noqa: E402
    ROLE_PERMISSIONS, AuthConfig, DashboardStore, make_handler, parse_user_roles, role_can, role_of,
)
from soc.incident_service import build_incidents  # noqa: E402
from soc.models import NormalizedEvent  # noqa: E402
from soc.normalizer import normalize_log_line  # noqa: E402


def _live_incident():
    events: list[NormalizedEvent] = []
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


class RoleTableTests(unittest.TestCase):
    def test_default_accounts_and_operator_is_always_admin(self):
        roles = parse_user_roles("", "soc-operator")
        self.assertEqual(roles, {"soc-operator": "admin", "analyst1": "analyst", "approver1": "approver", "admin1": "admin"})

    def test_custom_spec_ignores_unknown_roles_and_keeps_operator(self):
        roles = parse_user_roles("kim:analyst, lee:approver, bad:superuser, :admin", "ops")
        self.assertEqual(roles, {"ops": "admin", "kim": "analyst", "lee": "approver"})

    def test_permissions_per_role(self):
        AuthConfig(username="ops", password="pw", roles=parse_user_roles("", "ops"))
        self.assertTrue(role_can("analyst1", "view"))
        self.assertFalse(role_can("analyst1", "approve"))
        self.assertFalse(role_can("analyst1", "release"))
        self.assertTrue(role_can("approver1", "approve") and role_can("approver1", "release"))
        self.assertFalse(role_can("approver1", "reset"))
        self.assertTrue(role_can("admin1", "reset") and role_can("ops", "reset"))
        self.assertFalse(role_can("nobody", "view"))
        self.assertFalse(role_can(None, "view"))
        self.assertEqual(role_of("approver1"), "approver")
        self.assertEqual(set(ROLE_PERMISSIONS), {"analyst", "approver", "admin"})

    def test_all_accounts_share_one_password_but_unknown_ids_fail(self):
        auth = AuthConfig(username="ops", password="shared-pw", roles=parse_user_roles("", "ops"))
        for user in ("ops", "analyst1", "approver1", "admin1"):
            self.assertTrue(auth.verify_credentials(user, "shared-pw"), user)
        self.assertFalse(auth.verify_credentials("analyst1", "wrong"))
        self.assertFalse(auth.verify_credentials("hacker", "shared-pw"))
        self.assertFalse(auth.verify_credentials("", "shared-pw"))

    def test_single_operator_keeps_working_without_a_role_table(self):
        auth = AuthConfig(username="sangjun", password="pw")
        self.assertTrue(auth.verify_credentials("sangjun", "pw"))
        self.assertTrue(role_can("sangjun", "approve") and role_can("sangjun", "reset"))
        self.assertFalse(auth.verify_credentials("analyst1", "pw"))


class RoleEnforcementOverHttpTests(unittest.TestCase):
    def setUp(self):
        self.inc = _live_incident()
        self.store = DashboardStore(incidents=[self.inc])
        self.auth = AuthConfig(username="ops", password="shared-pw", secret="sec", roles=parse_user_roles("", "ops"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.store, auth_config=self.auth))
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _login(self, user):
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        op.open(urllib.request.Request(self.base + "/login", method="POST",
                                       data=urllib.parse.urlencode({"username": user, "password": "shared-pw"}).encode())).close()
        return op

    def _csrf(self, op):
        html = op.open(f"{self.base}/incidents/{self.inc.incident_id}").read().decode("utf-8")
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1), html

    def _approve(self, op, token):
        req = urllib.request.Request(
            f"{self.base}/incidents/{self.inc.incident_id}/approve", method="POST",
            data=urllib.parse.urlencode({"duration_minutes": "10", "csrf_token": token}).encode())
        try:
            with op.open(req) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_analyst_cannot_approve_or_release_and_sees_role_label(self):
        op = self._login("analyst1")
        token, html = self._csrf(op)
        self.assertIn("분석가", html)
        self.assertNotIn('value="reset-practice-logs"', html)
        self.assertEqual(self._approve(op, token), 403)
        self.assertEqual(self.inc.approvals, [])
        rel = urllib.request.Request(f"{self.base}/incidents/{self.inc.incident_id}/release", method="POST",
                                     data=urllib.parse.urlencode({"approval_id": "x", "csrf_token": token}).encode())
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            op.open(rel)
        self.assertEqual(ctx.exception.code, 403)

    def test_approver_passes_the_role_check_and_sees_role_label(self):
        op = self._login("approver1")
        token, html = self._csrf(op)
        self.assertIn("승인자", html)
        # 역할 검사는 통과한다. 게이트웨이가 없으므로 이후 단계에서 정책 오류로 되돌아오지만 403은 아니다.
        self.assertNotEqual(self._approve(op, token), 403)

    def test_reset_button_is_visible_to_admin_only(self):
        with mock.patch.dict(os.environ, {"SOC_ENABLE_PRACTICE_RESET": "1"}):
            seen = {}
            for user in ("analyst1", "approver1", "admin1", "ops"):
                _, html = self._csrf(self._login(user))
                seen[user] = 'value="reset-practice-logs"' in html
        self.assertEqual(seen, {"analyst1": False, "approver1": False, "admin1": True, "ops": True})

    def test_login_with_unknown_id_is_rejected(self):
        req = urllib.request.Request(self.base + "/login", method="POST",
                                     data=urllib.parse.urlencode({"username": "stranger", "password": "shared-pw"}).encode())
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 401)


if __name__ == "__main__":
    unittest.main()
