from __future__ import annotations

import json
import sys
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

from soc.dashboard import DashboardStore, make_handler
from soc.incident_service import (
    ActionApiClient,
    ActionPolicyError,
    build_incidents,
    request_human_approval,
)
from soc.models import NormalizedEvent, RawLogRecord
from soc.normalizer import normalize_log_line


def _build_fixture(
    *,
    ingest_mode: str = "live",
    trusted: bool = True,
) -> tuple[list[RawLogRecord], list[NormalizedEvent]]:
    raws: list[RawLogRecord] = []
    events: list[NormalizedEvent] = []

    for i in range(5):
        erp_line = json.dumps(
            {
                "timestamp_utc": f"2026-11-18T01:00:0{i}Z",
                "source": "erp",
                "event_type": "login_failed",
                "outcome": "failure",
                "username": "alice",
                "client_ip": "172.28.10.11",
                "peer_ip": "172.28.20.5",
                "client_ip_trusted": trusted,
                "request_id": f"req-{i}",
                "http_method": "POST",
                "http_path": "/api/login",
                "status_code": 401,
                "ingest_mode": ingest_mode,
            }
        )
        r, e = normalize_log_line(
            erp_line,
            source="erp",
            file_path="erp.jsonl",
            line_offset=i * 200,
            collection_mode=ingest_mode,
        )
        raws.append(r)
        events.append(e)

    # Matching Caddy log for req-0
    caddy_line = json.dumps(
        {
            "timestamp_utc": "2026-11-18T01:00:00Z",
            "source": "caddy",
            "event_type": "http_request",
            "outcome": "failure",
            "request_id": "req-0",
            "client_ip": "172.28.10.11",
            "peer_ip": "172.28.10.11",
            "http_method": "POST",
            "http_path": "/api/login",
            "status_code": 401,
            "ingest_mode": ingest_mode,
        }
    )
    r_c, e_c = normalize_log_line(
        caddy_line,
        source="caddy",
        file_path="caddy.jsonl",
        line_offset=0,
        collection_mode=ingest_mode,
    )
    raws.append(r_c)
    events.append(e_c)

    # Candidate gateway log within 10s
    gw_line = json.dumps(
        {
            "timestamp_utc": "2026-11-18T01:00:01Z",
            "source": "gateway",
            "event_type": "fw_allow",
            "outcome": "allow",
            "src_ip": "172.28.10.11",
            "src_port": 51000,
            "dst_ip": "172.28.20.5",
            "dst_port": 8443,
            "protocol": "TCP",
            "action": "allow",
            "ingest_mode": ingest_mode,
        }
    )
    r_g, e_g = normalize_log_line(
        gw_line,
        source="gateway",
        file_path="gateway.jsonl",
        line_offset=0,
        collection_mode=ingest_mode,
    )
    raws.append(r_g)
    events.append(e_g)

    return raws, events


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class DashboardAndActionsTests(unittest.TestCase):
    def test_incident_correlation_separates_exact_request_id_and_gateway_candidate(self) -> None:
        raws, events = _build_fixture(ingest_mode="live", trusted=True)
        incidents = build_incidents(raws, events)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(len(inc.evidence_events), 5)
        self.assertEqual(len(inc.raw_logs_by_id), 7)
        link_types = {c.link_type for c in inc.correlations}
        self.assertEqual(link_types, {"request_id_exact", "gateway_candidate"})

    def test_synthetic_or_replay_or_untrusted_blocks_enforcement(self) -> None:
        for mode in ("synthetic", "replay"):
            raws, events = _build_fixture(ingest_mode=mode, trusted=True)
            inc = build_incidents(raws, events)[0]
            self.assertFalse(inc.live_and_trusted_eligible)
            with self.assertRaises(ActionPolicyError):
                request_human_approval(inc, approved_by="operator", duration_minutes=10)

        raws_u, events_u = _build_fixture(ingest_mode="live", trusted=False)
        self.assertEqual(build_incidents(raws_u, events_u), [])

    def test_dashboard_ui_and_live_approval_calls_gateway_api(self) -> None:
        captured_calls: list[tuple[str, str, str, dict[str, Any]]] = []

        class MockGatewayHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                auth = self.headers.get("Authorization", "")
                captured_calls.append(("POST", self.path, auth, body))

                if self.path == "/actions/block":
                    resp = {
                        "approval_id": body["approval_id"],
                        "status": "applied",
                        "target_ip": body["target_ip"],
                        "expires_at_utc": body["expires_at_utc"],
                        "applied_at_utc": "2026-11-18T01:01:00Z",
                        "rule_id": body["approval_id"],
                    }
                    code = HTTPStatus.CREATED
                elif self.path.endswith("/release"):
                    ap_id = self.path.split("/")[2]
                    resp = {
                        "approval_id": ap_id,
                        "status": "released",
                        "released_at_utc": "2026-11-18T01:02:00Z",
                    }
                    code = HTTPStatus.OK
                else:
                    resp = {"error": "not_found"}
                    code = HTTPStatus.NOT_FOUND

                raw = json.dumps(resp).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        gw_server = ThreadingHTTPServer(("127.0.0.1", 0), MockGatewayHandler)
        gw_port = gw_server.server_address[1]
        gw_thread = threading.Thread(target=gw_server.serve_forever, daemon=True)
        gw_thread.start()

        raws, events = _build_fixture(ingest_mode="live", trusted=True)
        incidents = build_incidents(raws, events)
        inc_id = incidents[0].incident_id
        client = ActionApiClient(f"http://127.0.0.1:{gw_port}", bearer_token="test-secret-token")
        store = DashboardStore(incidents=incidents, action_client=client)

        ui_server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store))
        ui_port = ui_server.server_address[1]
        ui_thread = threading.Thread(target=ui_server.serve_forever, daemon=True)
        ui_thread.start()

        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{ui_port}/") as resp:
                self.assertEqual(resp.status, 200)
                list_html = resp.read().decode("utf-8")
                self.assertIn(inc_id, list_html)

            with urllib.request.urlopen(f"http://127.0.0.1:{ui_port}/incidents/{inc_id}") as resp:
                self.assertEqual(resp.status, 200)
                detail_html = resp.read().decode("utf-8")
                self.assertIn("req-0", detail_html)
                self.assertIn(incidents[0].evidence_events[0].raw_id, detail_html)

            opener = urllib.request.build_opener(_NoRedirect)
            approve_req = urllib.request.Request(
                f"http://127.0.0.1:{ui_port}/incidents/{inc_id}/approve",
                data=urllib.parse.urlencode({"approved_by": "sangjun", "duration_minutes": "15"}).encode("utf-8"),
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as approve_ctx:
                opener.open(approve_req)
            self.assertEqual(approve_ctx.exception.code, 303)
            approve_ctx.exception.close()

            self.assertEqual(incidents[0].status, "blocked")
            self.assertEqual(len(captured_calls), 1)
            self.assertEqual(captured_calls[0][1], "/actions/block")
            self.assertEqual(captured_calls[0][2], "Bearer test-secret-token")
            self.assertEqual(captured_calls[0][3]["target_ip"], "172.28.10.11")

            ap_id = incidents[0].approvals[0].approval_id
            release_req = urllib.request.Request(
                f"http://127.0.0.1:{ui_port}/incidents/{inc_id}/release",
                data=urllib.parse.urlencode({"approval_id": ap_id}).encode("utf-8"),
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as release_ctx:
                opener.open(release_req)
            self.assertEqual(release_ctx.exception.code, 303)
            release_ctx.exception.close()

            self.assertEqual(incidents[0].status, "released")
            self.assertEqual(len(captured_calls), 2)
            self.assertEqual(captured_calls[1][1], f"/actions/{ap_id}/release")
        finally:
            ui_server.shutdown()
            ui_server.server_close()
            gw_server.shutdown()
            gw_server.server_close()


if __name__ == "__main__":
    unittest.main()
