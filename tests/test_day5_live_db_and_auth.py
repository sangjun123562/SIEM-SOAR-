from __future__ import annotations

import http.cookiejar
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.dashboard import AuthConfig, DbDashboardStore, make_handler
from soc.incident_service import ActionApiClient, ActionPolicyError, build_incidents, request_human_approval
from soc.live_collector import run_once
from soc.repository import SocRepository
from soc.storage import SQLiteSocStorage


def _write_live_logs(tmpdir: Path) -> dict[str, Path]:
    erp_path = tmpdir / "erp.jsonl"
    caddy_path = tmpdir / "caddy.jsonl"
    gw_path = tmpdir / "gateway.jsonl"

    erp_lines = [
        json.dumps(
            {
                "timestamp_utc": f"2026-11-18T03:00:0{i}Z",
                "source": "erp",
                "event_type": "login_failed",
                "outcome": "failure",
                "username": "alice",
                "client_ip": "172.28.10.11",
                "peer_ip": "172.28.20.5",
                "client_ip_trusted": True,
                "request_id": f"req-live-{i}",
                "http_method": "POST",
                "http_path": "/api/login",
                "status_code": 401,
                "ingest_mode": "live",
            }
        )
        for i in range(5)
    ]
    erp_path.write_bytes(("\n".join(erp_lines) + "\n").encode("utf-8"))

    caddy_line = json.dumps(
        {
            "timestamp_utc": "2026-11-18T03:00:00Z",
            "source": "caddy",
            "event_type": "http_request",
            "outcome": "failure",
            "request_id": "req-live-0",
            "client_ip": "172.28.10.11",
            "peer_ip": "172.28.10.11",
            "http_method": "POST",
            "http_path": "/api/login",
            "status_code": 401,
            "ingest_mode": "live",
        }
    )
    caddy_path.write_bytes((caddy_line + "\n").encode("utf-8"))

    gw_line = json.dumps(
        {
            "timestamp_utc": "2026-11-18T03:00:01Z",
            "source": "gateway",
            "event_type": "fw_allow",
            "outcome": "allow",
            "src_ip": "172.28.10.11",
            "src_port": 52000,
            "dst_ip": "172.28.20.5",
            "dst_port": 8443,
            "protocol": "TCP",
            "action": "allow",
            "ingest_mode": "live",
        }
    )
    gw_path.write_bytes((gw_line + "\n").encode("utf-8"))

    return {"gateway": gw_path, "caddy": caddy_path, "erp": erp_path}


class Day5LiveDbAndAuthTests(unittest.TestCase):
    def test_identifier_validation_rejects_spaces_and_long_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sources = _write_live_logs(Path(tmp))
            storage = SQLiteSocStorage(":memory:")
            try:
                run_once(storage, sources, collection_mode="live")
                inc = SocRepository(storage).load_incidents()[0]
                with self.assertRaises(ActionPolicyError):
                    request_human_approval(inc, approved_by="bad actor", duration_minutes=10)
                with self.assertRaises(ActionPolicyError):
                    request_human_approval(inc, approved_by="a" * 65, duration_minutes=10)
            finally:
                storage.close()

    def test_live_db_dashboard_requires_auth_and_persists_block_refresh_release(self) -> None:
        gateway_calls: list[tuple[str, str]] = []

        class MockGatewayHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                gateway_calls.append(("GET", self.path))
                ap_id = self.path.split("/")[-1]
                payload = {
                    "approval_id": ap_id,
                    "status": "applied",
                    "target_ip": "172.28.10.11",
                    "expires_at_utc": "2026-11-18T03:15:00Z",
                    "rule_present": True,
                }
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                gateway_calls.append(("POST", self.path))
                if self.path == "/actions/block":
                    code = HTTPStatus.CREATED
                    payload = {
                        "approval_id": body["approval_id"],
                        "status": "applied",
                        "target_ip": body["target_ip"],
                        "expires_at_utc": body["expires_at_utc"],
                        "applied_at_utc": "2026-11-18T03:01:00Z",
                        "rule_id": body["approval_id"],
                    }
                else:
                    code = HTTPStatus.OK
                    ap_id = self.path.split("/")[2]
                    payload = {
                        "approval_id": ap_id,
                        "status": "released",
                        "released_at_utc": "2026-11-18T03:02:00Z",
                    }
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        gw_server = ThreadingHTTPServer(("127.0.0.1", 0), MockGatewayHandler)
        gw_port = gw_server.server_address[1]
        threading.Thread(target=gw_server.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_file = tmp_path / "soc.sqlite3"
            sources = _write_live_logs(tmp_path)

            storage = SQLiteSocStorage(db_file)
            inserted, inc_count = run_once(storage, sources, collection_mode="live")
            self.assertEqual(inserted, 7)
            self.assertEqual(inc_count, 1)

            client = ActionApiClient(f"http://127.0.0.1:{gw_port}", bearer_token="tok-123")
            store = DbDashboardStore(storage, action_client=client)
            auth = AuthConfig(username="sangjun", password="strong-pw", secret="sess-secret")

            ui_server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store, auth_config=auth))
            ui_port = ui_server.server_address[1]
            threading.Thread(target=ui_server.serve_forever, daemon=True).start()

            try:
                inc_id = store.list_incidents()[0].incident_id

                # 1. Unauthenticated approve must fail with 401 and 0 gateway calls.
                unauth_req = urllib.request.Request(
                    f"http://127.0.0.1:{ui_port}/incidents/{inc_id}/approve",
                    data=b"duration_minutes=10",
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(unauth_req)
                self.assertEqual(ctx.exception.code, 401)
                ctx.exception.close()
                self.assertEqual(gateway_calls, [])

                # 2. Login with cookie jar.
                cj = http.cookiejar.CookieJar()
                opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
                login_req = urllib.request.Request(
                    f"http://127.0.0.1:{ui_port}/login",
                    data=urllib.parse.urlencode({"username": "sangjun", "password": "strong-pw"}).encode(),
                    method="POST",
                )
                with opener.open(login_req) as resp:
                    self.assertEqual(resp.status, 200)

                # 3. Authenticated approve -> gateway block -> persisted in DB.
                approve_req = urllib.request.Request(
                    f"http://127.0.0.1:{ui_port}/incidents/{inc_id}/approve",
                    data=b"duration_minutes=15",
                    method="POST",
                )
                with opener.open(approve_req) as resp:
                    self.assertEqual(resp.status, 200)

                # Verify persistence from a fresh SQLiteSocStorage connection.
                reader = SQLiteSocStorage(db_file)
                try:
                    loaded = SocRepository(reader).load_incidents()[0]
                    self.assertEqual(loaded.status, "blocked")
                    self.assertEqual(len(loaded.approvals), 1)
                    self.assertEqual(loaded.approvals[0].approved_by, "sangjun")
                    self.assertEqual(loaded.approvals[0].status, "applied")
                    ap_id = loaded.approvals[0].approval_id
                finally:
                    reader.close()

                # 4. Authenticated refresh -> GET /actions/{approval_id}.
                refresh_req = urllib.request.Request(
                    f"http://127.0.0.1:{ui_port}/incidents/{inc_id}/refresh",
                    data=urllib.parse.urlencode({"approval_id": ap_id}).encode(),
                    method="POST",
                )
                with opener.open(refresh_req) as resp:
                    self.assertEqual(resp.status, 200)

                # 5. Authenticated release -> POST /actions/{approval_id}/release -> persisted.
                release_req = urllib.request.Request(
                    f"http://127.0.0.1:{ui_port}/incidents/{inc_id}/release",
                    data=urllib.parse.urlencode({"approval_id": ap_id}).encode(),
                    method="POST",
                )
                with opener.open(release_req) as resp:
                    self.assertEqual(resp.status, 200)

                reader2 = SQLiteSocStorage(db_file)
                try:
                    loaded2 = SocRepository(reader2).load_incidents()[0]
                    self.assertEqual(loaded2.status, "released")
                    self.assertEqual(loaded2.approvals[0].status, "released")
                finally:
                    reader2.close()

                self.assertEqual(
                    gateway_calls,
                    [
                        ("POST", "/actions/block"),
                        ("GET", f"/actions/{ap_id}"),
                        ("POST", f"/actions/{ap_id}/release"),
                    ],
                )
            finally:
                ui_server.shutdown()
                ui_server.server_close()
                store.close()
                gw_server.shutdown()
                gw_server.server_close()


if __name__ == "__main__":
    unittest.main()
