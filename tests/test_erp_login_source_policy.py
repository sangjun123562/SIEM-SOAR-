"""Flask 요청과 임시 로그 파일로 ERP 로그인 출발지 정책을 확인한다."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
import uuid
from dataclasses import replace
from datetime import datetime, timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import Mock, patch
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.collector import collect_file
from soc.dashboard import AuthConfig, DashboardStore, make_handler, parse_user_roles
from soc.detector import LOGIN_SOURCE_DENIED_RULE_ID
from soc.incident_service import build_incidents
from soc.repository import SocRepository
from soc.storage import SQLiteSocStorage


@unittest.skipUnless(
    importlib.util.find_spec("flask") and importlib.util.find_spec("psycopg"),
    "ERP image dependencies Flask and psycopg are required",
)
class ErpLoginSourcePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.security import generate_password_hash

        spec = importlib.util.spec_from_file_location("erp_for_login_test", ROOT / "erp" / "app.py")
        cls.erp = importlib.util.module_from_spec(spec)
        # 초기 사용자·문서 생성과 로그인 조회에서 실제 PostgreSQL에는 연결하지 않는다.
        with patch.dict(os.environ, {"ERP_DB_DSN": "unused", "ERP_SECRET_KEY": "test-key",
                                     "TRUSTED_PROXY_IP": "172.28.20.5"}):
            with patch("psycopg.connect"), patch.object(sys, "path", [str(ROOT / "erp"), *sys.path]):
                spec.loader.exec_module(cls.erp)

        cls.user = {
            "id": 1, "username": "alice", "department": "영업", "role": "member",
            "password_hash": generate_password_hash("demo-password", method="pbkdf2:sha256:1000"),
        }

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.log_path = Path(folder.name) / "erp.jsonl"
        log_patch = patch.object(self.erp, "LOG_PATH", str(self.log_path))
        log_patch.start()
        self.addCleanup(log_patch.stop)

    def login(self, source_ip, *, peer="172.28.20.5", password="demo-password", username="alice", request_id=None, browser=None):
        headers = {"Origin": "https://localhost", "X-Request-ID": request_id or str(uuid.uuid4())}
        if source_ip is not None:
            headers["X-Client-IP"] = source_ip
        return (browser or self.erp.app.test_client()).post(
            "/api/login", base_url="https://localhost", headers=headers,
            environ_overrides={"REMOTE_ADDR": peer}, json={"username": username, "password": password},
        )

    def read_logs(self):
        return [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]

    def test_a_and_b_keep_normal_password_checks(self):
        with patch.object(self.erp, "_conn") as connect:
            connect.return_value.execute.return_value.fetchone.return_value = self.user
            self.assertEqual(self.login("172.28.10.11").status_code, 200)
            self.assertEqual(self.login("172.28.10.12").status_code, 200)
            self.assertEqual(self.login("172.28.10.12", password="wrong").status_code, 401)
            self.assertEqual(self.login("172.28.10.12", password=None).status_code, 400)

        self.assertEqual([event["event_type"] for event in self.read_logs()],
                         ["login_success", "login_success", "login_failed", "login_failed"])

    def test_x_is_denied_before_the_credentials_are_checked(self):
        with patch.object(self.erp, "LOGIN_ACCESS_TOKEN", ""), patch.object(self.erp, "_conn") as connect:
            response = self.login("172.28.10.13")
            connect.assert_not_called()

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json, {"error": "login source not allowed"})
        self.assertNotIn("Set-Cookie", response.headers)
        event, = self.read_logs()
        self.assertEqual(event["event_type"], "login_source_denied")
        self.assertEqual(event["reason"], "source_not_allowed")
        self.assertEqual(event["client_ip"], "172.28.10.13")
        self.assertEqual(event["username"], "alice")
        self.assertEqual(event["status_code"], 403)
        self.assertTrue(event["client_ip_trusted"])
        self.assertNotIn("demo-password", self.log_path.read_text(encoding="utf-8"))

    def test_request_without_a_verified_source_is_denied(self):
        with patch.object(self.erp, "_conn") as connect:
            self.assertEqual(self.login("172.28.10.11", peer="172.28.10.13").status_code, 403)
            self.assertEqual(self.login(None).status_code, 403)
            connect.assert_not_called()

        for event in self.read_logs():
            self.assertEqual(event["reason"], "untrusted_source")
            self.assertFalse(event["client_ip_trusted"])

    def test_source_denials_are_collected_without_counting_as_login_failures(self):
        with patch.object(self.erp, "LOGIN_ACCESS_TOKEN", "test-token"), patch.object(
            self.erp.login_access, "can_log_in", return_value=False,
        ), patch.object(self.erp, "_conn"):
            for _ in range(5):
                self.assertEqual(self.login("172.28.10.13").status_code, 403)

        storage = SQLiteSocStorage(":memory:")
        self.addCleanup(storage.close)
        collected = collect_file("erp", self.log_path, storage, collection_mode="live")
        self.assertEqual(collected.inserted_records, 5)
        raw_logs, events = SocRepository(storage).fetch_raw_and_events()
        self.assertEqual({event.event_type for event in events}, {"login_source_denied"})
        self.assertEqual({event.details["reason"] for event in events}, {"source_not_allowed"})
        repo = SocRepository(storage)
        incidents = build_incidents(raw_logs, events + events)
        self.assertEqual(len(incidents), 5)
        self.assertEqual({inc.alerts[0].rule_id for inc in incidents}, {LOGIN_SOURCE_DENIED_RULE_ID})
        self.assertTrue(all(inc.login_access_event and not inc.block_rule_eligible for inc in incidents))
        repo.sync_incidents(incidents)
        self.assertEqual(len(repo.load_incidents()), 5)
        self.assertTrue(all(inc.login_access_event for inc in repo.load_incidents()))
        replay = build_incidents([], [replace(events[0], ingest_mode="replay")])[0]
        self.assertIsNone(replay.login_access_event)

    def test_dashboard_uses_roles_csrf_and_saved_account(self):
        client = Mock()
        client.lookup.return_value = {"status": "pending"}
        with patch.object(self.erp, "LOGIN_ACCESS_TOKEN", "test-token"), patch.object(
            self.erp.login_access, "can_log_in", return_value=False,
        ), patch.object(self.erp, "_conn"):
            self.assertEqual(self.login("172.28.10.13").status_code, 403)
        storage = SQLiteSocStorage(":memory:")
        self.addCleanup(storage.close)
        collect_file("erp", self.log_path, storage, collection_mode="live")
        incident, = build_incidents(*SocRepository(storage).fetch_raw_and_events())
        auth = AuthConfig("ops", "pw", roles=parse_user_roles("", "ops"))
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            DashboardStore([incident]), auth, login_access_client=client,
        ))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        def call(user, suffix="", valid_csrf=True, reason="실습 확인"):
            http = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            token = auth.sign_session(user) if user else ""
            try:
                http.request("POST" if suffix else "GET", f"/incidents/{incident.incident_id}{suffix}",
                             urlencode({"csrf_token": auth.sign_csrf(token) if valid_csrf else "bad",
                                        "username": "other", "client_ip": "127.0.0.1", "reason": reason}) if suffix else None,
                             {"Cookie": f"soc_session={token}", "Content-Type": "application/x-www-form-urlencoded"})
                result = http.getresponse()
                return result.status, result.read().decode("utf-8")
            finally:
                http.close()

        self.assertIn("5분 임시 접속 승인", call("approver1")[1])
        self.assertNotIn("5분 임시 접속 승인</button>", call("analyst1")[1])
        self.assertEqual(call(None, "/grant-login")[0], 401)
        self.assertEqual(call("analyst1", "/grant-login")[0], 403)
        self.assertEqual(call("approver1", "/grant-login", valid_csrf=False)[0], 403)
        self.assertEqual(call("approver1", "/grant-login", reason="  ")[0], 303)
        client.update.assert_not_called()
        self.assertEqual(call("approver1", "/grant-login")[0], 303)
        client.update.assert_called_once_with(incident.login_access_event, incident.incident_id, "approver1", "approve", "실습 확인")
        self.assertEqual(call("approver1", "/revoke-login")[0], 303)
        self.assertEqual(client.update.call_args.args[3], "revoke")

    @unittest.skipUnless(os.environ.get("ERP_TEST_POSTGRES_DSN"), "set ERP_TEST_POSTGRES_DSN for PostgreSQL verification")
    def test_postgres_approval_expiry_and_revocation(self):
        import psycopg
        from psycopg.conninfo import make_conninfo

        schema = "erp_access_test_" + uuid.uuid4().hex
        conn = psycopg.connect(os.environ["ERP_TEST_POSTGRES_DSN"], autocommit=True)
        self.addCleanup(conn.close)
        conn.execute(f"CREATE SCHEMA {schema}")
        self.addCleanup(conn.execute, f"DROP SCHEMA {schema} CASCADE")
        conn.execute(f"SET search_path TO {schema}")
        conn.execute("CREATE TABLE users (id INT PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, department TEXT, role TEXT)")
        conn.execute("INSERT INTO users VALUES (%s, %s, %s, %s, %s)",
                     tuple(self.user[k] for k in ("id", "username", "password_hash", "department", "role")))
        conn.execute("INSERT INTO users VALUES (2, 'bob', %s, '영업', 'member')", (self.user["password_hash"],))
        self.erp.login_access.ensure_schema(conn)
        self.erp.login_access.ensure_schema(conn)
        self.erp.account_lock.ensure_schema(conn)
        dsn = make_conninfo(os.environ["ERP_TEST_POSTGRES_DSN"], options=f"-c search_path={schema}")
        test_client = self.erp.app.test_client()
        ip = "172.28.10.13"
        denial_id = str(uuid.uuid4())

        def manage(request_id, *, action=None, username="alice", peer="10.250.31.60", token="test-token"):
            path = f"/internal/login-access/{request_id}"
            options = {"headers": {"Authorization": f"Bearer {token}"}, "environ_overrides": {"REMOTE_ADDR": peer}}
            if action:
                return test_client.post(path, json={"action": action, "username": username, "client_ip": ip,
                                                    "incident_id": "INC-TEST", "operator": "ops", "reason": "확인"}, **options)
            return test_client.get(path, **options)

        def manage_lock(incident_id, *, action="lock", duration=1, peer="10.250.31.60"):
            return test_client.post(f"/internal/account-locks/{incident_id}",
                headers={"Authorization": "Bearer test-token"}, environ_overrides={"REMOTE_ADDR": peer},
                json={"action": action, "username": "alice", "operator": "ops", "reason": "확인", "duration_minutes": duration})

        with patch.object(self.erp, "DB_DSN", dsn), patch.object(self.erp, "LOGIN_ACCESS_TOKEN", "test-token"):
            self.assertEqual(self.login(ip, request_id=denial_id).status_code, 403)
            self.assertEqual(manage(denial_id).json["status"], "pending")
            self.assertEqual(manage(denial_id, action="approve", token="wrong").status_code, 404)
            self.assertEqual(manage(denial_id, action="approve", peer="172.28.20.5").status_code, 404)
            self.assertEqual(manage(denial_id, action="approve", username="bob").status_code, 409)
            approved = manage(denial_id, action="approve").json
            self.assertEqual(approved["status"], "active")
            self.assertEqual(datetime.fromisoformat(approved["expires_at"]) - datetime.fromisoformat(approved["approved_at"]),
                             timedelta(minutes=5))
            self.assertEqual(manage(denial_id, action="approve").json, approved)
            self.assertEqual(self.login(ip).status_code, 200)
            self.assertEqual(self.login(ip, password="wrong").status_code, 401)
            self.assertEqual(self.login(ip, username="bob").status_code, 403)
            self.assertEqual(self.login("172.28.10.14").status_code, 403)

            # 이미 로그인한 브라우저, X 이전 승인, 다른 계정을 같은 DB로 함께 검증한다.
            old_browser = self.erp.app.test_client()
            self.assertEqual(self.login("172.28.10.11", browser=old_browser).status_code, 200)
            lock_case = "INC-0123456789"
            for duration in (0, 31):
                self.assertEqual(manage_lock(lock_case, duration=duration).status_code, 400)
            self.assertEqual(manage_lock(lock_case, peer="172.28.20.5").status_code, 404)
            lock = manage_lock(lock_case).json
            self.assertEqual(lock["status"], "active")
            self.assertEqual(datetime.fromisoformat(lock["expires_at"]) - datetime.fromisoformat(lock["locked_at"]), timedelta(minutes=1))
            self.assertEqual(manage_lock(lock_case, duration=30).json, lock)
            self.assertEqual(manage_lock("INC-0000000001").status_code, 409)
            for source in ("172.28.10.11", "172.28.10.12", ip):
                self.assertEqual(self.login(source).json, {"error": "account temporarily locked"})
            self.assertEqual(self.login("172.28.10.12", username="bob").status_code, 200)
            # 잠긴 동안 틀린 비밀번호도 같은 안내를 받아야 비밀번호를 맞혀 볼 수 없다.
            wrong = self.login("172.28.10.11", password="wrong")
            self.assertEqual((wrong.status_code, wrong.json), (403, {"error": "account temporarily locked"}))
            blocked = [row for row in self.read_logs() if row["event_type"] == "login_blocked"]
            self.assertEqual([row["password_valid"] for row in blocked], [True, True, True, False])
            self.assertTrue(all(row["status_code"] == 403 and row["reason"] == "account_locked" for row in blocked))
            self.assertEqual(old_browser.get("/api/documents", base_url="https://localhost").status_code, 401)
            self.assertEqual(manage_lock(lock_case, action="unlock").json["status"], "unlocked")
            self.assertEqual(old_browser.get("/api/session", base_url="https://localhost").status_code, 401)
            self.assertEqual(self.login(ip).status_code, 200)
            self.assertEqual(manage_lock(lock_case).status_code, 409)

            expiring_case = "INC-0123456790"
            expiring_lock = manage_lock(expiring_case, duration=30).json
            self.assertEqual(expiring_lock["status"], "active")
            self.assertEqual(datetime.fromisoformat(expiring_lock["expires_at"]) - datetime.fromisoformat(expiring_lock["locked_at"]), timedelta(minutes=30))
            conn.execute("UPDATE account_locks SET expires_at = now() - interval '1 second' WHERE incident_id = %s", (expiring_case,))
            self.assertEqual(manage_lock(expiring_case, action="unlock").json["status"], "expired")
            self.assertEqual(self.login("172.28.10.11").status_code, 200)
            self.assertIn("login_blocked", {row["event_type"] for row in self.read_logs()})
            self.assertEqual(sum(row["event_type"] == "account_locked" for row in self.read_logs()), 2)
            self.assertEqual(sum(row["event_type"] == "account_unlocked" for row in self.read_logs()), 1)

            conn.execute("UPDATE login_access_requests SET expires_at = now() - interval '1 second' WHERE request_id = %s", (denial_id,))
            self.assertEqual(manage(denial_id).json["status"], "expired")
            self.assertEqual(manage(denial_id, action="approve").status_code, 409)
            new_id = str(uuid.uuid4())
            self.assertEqual(self.login(ip, request_id=new_id).status_code, 403)
            self.assertEqual(manage(new_id, action="approve").json["status"], "active")
            self.assertEqual(manage(new_id, action="revoke").json["revoked_by"], "ops")
            self.assertEqual(manage(new_id).json["status"], "revoked")
            self.assertEqual(self.login(ip).status_code, 403)
