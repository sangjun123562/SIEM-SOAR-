from __future__ import annotations

import http.cookiejar
import json
import sys
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.dashboard import AuthConfig, DbDashboardStore, make_handler
from soc.incident_service import ActionApiClient
from soc.live_collector import run_once
from soc.repository import SocRepository
from soc.storage import SQLiteSocStorage


def _erp_event(
    ts: str,
    *,
    event_type: str = "login_failed",
    outcome: str = "failure",
    username: str = "alice",
    client_ip: str = "172.28.10.11",
    trusted: bool = True,
    request_id: str = "req-1",
    ingest_mode: str = "live",
) -> str:
    return json.dumps(
        {
            "timestamp_utc": ts,
            "source": "erp",
            "event_type": event_type,
            "outcome": outcome,
            "username": username,
            "client_ip": client_ip,
            "peer_ip": "172.28.20.5",
            "client_ip_trusted": trusted,
            "request_id": request_id,
            "http_method": "POST",
            "http_path": "/api/login",
            "status_code": 401 if outcome == "failure" else 200,
            "ingest_mode": ingest_mode,
        }
    )


class Day6Day7RegressionTests(unittest.TestCase):
    def test_reprocessing_logs_keeps_alerts_and_incidents_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            erp_file = tmp_path / "erp.jsonl"
            erp_file.write_bytes(
                ("\n".join(_erp_event(f"2026-11-18T23:58:0{i}Z", request_id=f"r-{i}") for i in range(5)) + "\n").encode(
                    "utf-8"
                )
            )
            storage = SQLiteSocStorage(":memory:")
            try:
                sources = {"erp": erp_file}
                inserted1, inc1 = run_once(storage, sources, collection_mode="live")
                self.assertEqual(inserted1, 5)
                self.assertEqual(inc1, 1)

                # Second run must insert 0 new raw/events and keep incident count at 1.
                inserted2, inc2 = run_once(storage, sources, collection_mode="live")
                self.assertEqual(inserted2, 0)
                self.assertEqual(inc2, 1)
                self.assertEqual(storage.count_raw_logs("erp"), 5)
                self.assertEqual(len(SocRepository(storage).load_incidents()), 1)
            finally:
                storage.close()

    def test_replay_and_synthetic_incidents_send_zero_gateway_actions(self) -> None:
        gateway_calls: list[str] = []

        class MockGateway(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                gateway_calls.append(self.path)
                self.send_response(201)
                self.end_headers()

        gw_server = ThreadingHTTPServer(("127.0.0.1", 0), MockGateway)
        gw_port = gw_server.server_address[1]
        threading.Thread(target=gw_server.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for mode in ("replay", "synthetic"):
                gateway_calls.clear()
                erp_file = tmp_path / f"erp_{mode}.jsonl"
                erp_file.write_bytes(
                    (
                        "\n".join(
                            _erp_event(
                                f"2026-11-18T12:00:0{i}Z",
                                request_id=f"{mode}-{i}",
                                ingest_mode=mode,
                            )
                            for i in range(5)
                        )
                        + "\n"
                    ).encode("utf-8")
                )

                storage = SQLiteSocStorage(":memory:")
                run_once(storage, {"erp": erp_file}, collection_mode=mode)
                client = ActionApiClient(f"http://127.0.0.1:{gw_port}", bearer_token="tok")
                store = DbDashboardStore(storage, action_client=client)
                auth = AuthConfig(username="sangjun", password="pw", secret="sec")

                ui_server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store, auth_config=auth))
                ui_port = ui_server.server_address[1]
                threading.Thread(target=ui_server.serve_forever, daemon=True).start()

                try:
                    cj = http.cookiejar.CookieJar()
                    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
                    opener.open(
                        urllib.request.Request(
                            f"http://127.0.0.1:{ui_port}/login",
                            data=b"username=sangjun&password=pw",
                            method="POST",
                        )
                    ).close()

                    inc = store.list_incidents()[0]
                    self.assertFalse(inc.live_and_trusted_eligible)

                    import re
                    with opener.open(f"http://127.0.0.1:{ui_port}/incidents/{inc.incident_id}") as p_resp:
                        p_html = p_resp.read().decode("utf-8")
                    m_csrf = re.search(r'name="csrf_token" value="([^"]+)"', p_html)
                    self.assertIsNotNone(m_csrf)

                    with opener.open(
                        urllib.request.Request(
                            f"http://127.0.0.1:{ui_port}/incidents/{inc.incident_id}/approve",
                            data=urllib.parse.urlencode({"duration_minutes": "10", "csrf_token": m_csrf.group(1)}).encode(),
                            method="POST",
                        )
                    ) as resp:
                        self.assertIn("error=", urllib.parse.unquote(resp.geturl()))

                    self.assertEqual(gateway_calls, [])
                    self.assertEqual(store.list_incidents()[0].approvals, [])
                finally:
                    ui_server.shutdown()
                    ui_server.server_close()
                    store.close()
        gw_server.shutdown()
        gw_server.server_close()

    def test_shared_ip_different_users_and_midnight_boundary_and_unrelated_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            erp_file = tmp_path / "erp.jsonl"
            caddy_file = tmp_path / "caddy.jsonl"
            gw_file = tmp_path / "gateway.jsonl"

            # alice: 5 failures crossing UTC midnight (23:58:00Z .. 00:01:30Z)
            # bob:   5 failures on the SAME shared IP (must become a separate incident!)
            # carol: unrelated login_success + logout + access_denied
            erp_lines = [
                _erp_event("2026-11-18T23:58:00Z", username="alice", request_id="alice-0"),
                _erp_event("2026-11-18T23:58:30Z", username="alice", request_id="alice-1"),
                _erp_event("2026-11-18T23:59:00Z", username="carol", event_type="login_success", outcome="success", request_id="carol-ok"),
                _erp_event("2026-11-18T23:59:20Z", username="alice", request_id="alice-2"),
                _erp_event("2026-11-18T23:59:50Z", username="alice", request_id="alice-3"),
                _erp_event("2026-11-19T00:01:30Z", username="alice", request_id="alice-4"),
                _erp_event("2026-11-19T00:02:00Z", username="carol", event_type="logout", outcome="success", request_id="carol-out"),
            ] + [
                _erp_event(f"2026-11-19T00:03:0{i}Z", username="bob", request_id=f"bob-{i}")
                for i in range(5)
            ]
            erp_file.write_bytes(("\n".join(erp_lines) + "\n").encode("utf-8"))

            caddy_lines = [
                json.dumps(
                    {
                        "timestamp_utc": "2026-11-18T23:58:00Z",
                        "source": "caddy",
                        "event_type": "http_request",
                        "outcome": "failure",
                        "request_id": "alice-0",
                        "client_ip": "172.28.10.11",
                        "peer_ip": "172.28.10.11",
                        "http_method": "POST",
                        "http_path": "/api/login",
                        "status_code": 401,
                        "ingest_mode": "live",
                    }
                ),
                # Unrelated caddy request must NOT be correlated to alice or bob
                json.dumps(
                    {
                        "timestamp_utc": "2026-11-18T23:59:00Z",
                        "source": "caddy",
                        "event_type": "http_request",
                        "outcome": "success",
                        "request_id": "carol-ok",
                        "client_ip": "172.28.10.12",
                        "peer_ip": "172.28.10.12",
                        "http_method": "POST",
                        "http_path": "/api/login",
                        "status_code": 200,
                        "ingest_mode": "live",
                    }
                ),
            ]
            caddy_file.write_bytes(("\n".join(caddy_lines) + "\n").encode("utf-8"))

            gw_lines = [
                # Near alice-0 (within 10s) -> candidate for alice only
                json.dumps(
                    {
                        "timestamp_utc": "2026-11-18T23:58:01Z",
                        "source": "gateway",
                        "event_type": "fw_allow",
                        "outcome": "allow",
                        "src_ip": "172.28.10.11",
                        "src_port": 53001,
                        "dst_ip": "172.28.20.5",
                        "dst_port": 8443,
                        "protocol": "TCP",
                        "action": "allow",
                        "ingest_mode": "live",
                    }
                ),
                # Far event (1 hour earlier) -> must NOT be linked and must NOT remove near candidate
                json.dumps(
                    {
                        "timestamp_utc": "2026-11-18T22:00:00Z",
                        "source": "gateway",
                        "event_type": "fw_allow",
                        "outcome": "allow",
                        "src_ip": "172.28.10.11",
                        "src_port": 53000,
                        "dst_ip": "172.28.20.5",
                        "dst_port": 8443,
                        "protocol": "TCP",
                        "action": "allow",
                        "ingest_mode": "live",
                    }
                ),
            ]
            gw_file.write_bytes(("\n".join(gw_lines) + "\n").encode("utf-8"))

            storage = SQLiteSocStorage(":memory:")
            try:
                _, inc_cnt = run_once(
                    storage,
                    {"erp": erp_file, "caddy": caddy_file, "gateway": gw_file},
                    collection_mode="live",
                )
                self.assertEqual(inc_cnt, 2)
                incidents = {inc.username: inc for inc in SocRepository(storage).load_incidents()}
                self.assertEqual(set(incidents.keys()), {"alice", "bob"})

                alice_inc = incidents["alice"]
                self.assertEqual(len(alice_inc.evidence_events), 5)
                self.assertTrue(all(ev.username == "alice" for ev in alice_inc.evidence_events))

                exact_corrs = [c for c in alice_inc.correlations if c.link_type == "request_id_exact"]
                gw_corrs = [c for c in alice_inc.correlations if c.link_type == "gateway_candidate"]
                self.assertEqual(len(exact_corrs), 1)
                self.assertIn("alice-0", exact_corrs[0].reason)
                self.assertEqual(len(gw_corrs), 1)
            finally:
                storage.close()


if __name__ == "__main__":
    unittest.main()
