"""16가지 안정성·보안·일관성 개선 항목에 대한 Role B 단위/통합 회귀 테스트."""

from __future__ import annotations

import http.cookiejar
import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc.collector import collect_file
from soc.dashboard import AuthConfig, DashboardStore, DbDashboardStore, make_handler
from soc.incident_service import (
    ActionApiClient,
    ActionPolicyError,
    ApprovalRecord,
    build_incidents,
    refresh_approval_status,
    request_human_approval,
)
from soc.live_collector import run_once
from soc.normalizer import normalize_log_line
from soc.repository import SocRepository
from soc.storage import SQLiteSocStorage


def _erp_line(ts: str, *, req_id: str, username: str = "bob", ip: str = "172.28.10.11") -> str:
    return json.dumps(
        {
            "timestamp_utc": ts,
            "source": "erp",
            "event_type": "login_failed",
            "outcome": "failure",
            "username": username,
            "client_ip": ip,
            "peer_ip": "172.28.20.5",
            "client_ip_trusted": True,
            "request_id": req_id,
            "http_method": "POST",
            "http_path": "/api/login",
            "status_code": 401,
            "ingest_mode": "live",
        }
    )


class HardeningFixesTests(unittest.TestCase):
    def test_01_log_rotation_and_truncation_uses_new_generation_without_missing_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "erp.jsonl"
            rotated_path = Path(tmp) / "erp.jsonl.1"
            log_path.write_text(
                _erp_line("2026-11-20T01:00:00Z", req_id="r-1a") + "\n"
                + _erp_line("2026-11-20T01:00:01Z", req_id="r-1b") + "\n",
                encoding="utf-8",
            )

            storage = SQLiteSocStorage(":memory:")
            try:
                res1 = collect_file("erp", log_path, storage, collection_mode="live")
                self.assertEqual(res1.inserted_records, 2)

                # Simulate copytruncate / size shrink rotation (#1)
                log_path.write_text(_erp_line("2026-11-20T01:01:00Z", req_id="r-2") + "\n", encoding="utf-8")
                res2 = collect_file("erp", log_path, storage, collection_mode="live")
                self.assertEqual(res2.inserted_records, 1)
                self.assertEqual(storage.count_raw_logs("erp"), 3)

                # Simulate inode swap rotation where .1 still has an unread tail line
                with log_path.open("a", encoding="utf-8") as f:
                    f.write(_erp_line("2026-11-20T01:01:30Z", req_id="r-3-tail") + "\n")
                log_path.rename(rotated_path)
                log_path.write_text(_erp_line("2026-11-20T01:02:00Z", req_id="r-4-new") + "\n", encoding="utf-8")
                res3 = collect_file("erp", log_path, storage, collection_mode="live")
                self.assertGreaterEqual(res3.inserted_records, 1)
                self.assertGreaterEqual(storage.count_raw_logs("erp"), 4)
            finally:
                storage.close()

    def test_06_corrupt_line_isolated_and_other_sources_continue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            erp_path = Path(tmp) / "erp.jsonl"
            gw_path = Path(tmp) / "gateway.jsonl"
            erp_path.write_bytes(
                (_erp_line("2026-11-20T01:00:00Z", req_id="ok-1") + "\n").encode("utf-8")
                + b"{bad-json-line\n"
                + b"\xff\xfe\xfd\n"
                + (_erp_line("2026-11-20T01:00:05Z", req_id="ok-2") + "\n").encode("utf-8")
            )
            gw_path.write_text(
                json.dumps(
                    {
                        "timestamp_utc": "2026-11-20T01:00:01Z",
                        "source": "gateway",
                        "event_type": "fw_allow",
                        "outcome": "allow",
                        "src_ip": "172.28.10.11",
                        "src_port": 51000,
                        "dst_ip": "172.28.20.5",
                        "dst_port": 8443,
                        "protocol": "tcp",
                        "ingest_mode": "live",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            storage = SQLiteSocStorage(":memory:")
            try:
                inserted, _ = run_once(
                    storage,
                    {"erp": erp_path, "gateway": gw_path, "caddy": Path(tmp) / "missing.jsonl"},
                    collection_mode="live",
                )
                self.assertEqual(inserted, 3)
                self.assertEqual(storage.count_raw_logs("erp"), 2)
                self.assertEqual(storage.count_raw_logs("gateway"), 1)
            finally:
                storage.close()

    def test_03_04_05_approval_presave_unknown_recovery_dedup_and_rule_present(self) -> None:
        raws, events = [], []
        for i in range(5):
            r, e = normalize_log_line(
                _erp_line(f"2026-11-20T01:00:0{i}Z", req_id=f"req-{i}"),
                source="erp",
                file_path="erp.jsonl",
                line_offset=i * 100,
                collection_mode="live",
            )
            raws.append(r)
            events.append(e)
        inc = build_incidents(raws, events)[0]

        pre_saved: list[str] = []

        class _TimeoutClient(ActionApiClient):
            def block(self, **kwargs: str) -> dict[str, object]:
                raise TimeoutError("gateway timed out")

            def get_status(self, approval_id: str) -> dict[str, object]:
                return {"approval_id": approval_id, "status": "applied", "rule_present": False}

        client = _TimeoutClient("http://127.0.0.1:9999", "tok")
        ap = request_human_approval(
            inc,
            approved_by="sangjun",
            duration_minutes=10,
            action_client=client,
            on_before_call=lambda rec: pre_saved.append(rec.status),
        )
        # #3: Pre-saved as pending before network call, then marked unknown on timeout
        self.assertEqual(pre_saved, ["pending"])
        self.assertEqual(ap.status, "unknown")

        # #4: Duplicate approval on same incident returns existing record idempotently
        ap_dup = request_human_approval(inc, approved_by="sangjun", duration_minutes=10, action_client=client)
        self.assertEqual(ap_dup.approval_id, ap.approval_id)
        self.assertEqual(len(inc.approvals), 1)

        # #4: Cross-incident duplicate block for same target_ip is rejected
        inc2 = build_incidents(raws, events)[0]
        inc2.incident_id = "INC-OTHER99999"
        with self.assertRaises(ActionPolicyError):
            request_human_approval(
                inc2,
                approved_by="sangjun",
                duration_minutes=10,
                action_client=client,
                existing_incidents=[inc],
            )

        # #5: rule_present=False desync transitions applied -> expired / released
        refreshed = refresh_approval_status(inc, approval_id=ap.approval_id, action_client=client)
        self.assertIsNotNone(refreshed)
        self.assertEqual(refreshed.status, "expired")
        self.assertEqual(inc.status, "released")

    def test_15_gateway_candidate_excludes_unrelated_ports_and_udp(self) -> None:
        raws, events = [], []
        for i in range(5):
            r, e = normalize_log_line(
                _erp_line(f"2026-11-20T01:00:0{i}Z", req_id=f"req-{i}"),
                source="erp",
                file_path="erp.jsonl",
                line_offset=i * 100,
                collection_mode="live",
            )
            raws.append(r)
            events.append(e)

        # Unrelated UDP DNS traffic from same client IP at exact same second
        r_dns, e_dns = normalize_log_line(
            json.dumps(
                {
                    "timestamp_utc": "2026-11-20T01:00:02Z",
                    "source": "gateway",
                    "event_type": "fw_allow",
                    "outcome": "allow",
                    "src_ip": "172.28.10.11",
                    "src_port": 44444,
                    "dst_ip": "8.8.8.8",
                    "dst_port": 53,
                    "protocol": "udp",
                    "ingest_mode": "live",
                }
            ),
            source="gateway",
            file_path="gw.jsonl",
            line_offset=0,
            collection_mode="live",
        )
        # Valid Caddy TLS port 8443 TCP traffic
        r_web, e_web = normalize_log_line(
            json.dumps(
                {
                    "timestamp_utc": "2026-11-20T01:00:02Z",
                    "source": "gateway",
                    "event_type": "fw_allow",
                    "outcome": "allow",
                    "src_ip": "172.28.10.11",
                    "src_port": 55555,
                    "dst_ip": "172.28.20.5",
                    "dst_port": 8443,
                    "protocol": "tcp",
                    "ingest_mode": "live",
                }
            ),
            source="gateway",
            file_path="gw.jsonl",
            line_offset=200,
            collection_mode="live",
        )
        raws.extend([r_dns, r_web])
        events.extend([e_dns, e_web])

        inc = build_incidents(raws, events)[0]
        corr_event_ids = {c.event_id for c in inc.correlations}
        self.assertIn(e_web.event_id, corr_event_ids)
        self.assertNotIn(e_dns.event_id, corr_event_ids)

    def test_08_09_10_11_auth_unicode_ratelimit_csrf_and_contrast(self) -> None:
        auth = AuthConfig(username="sangjun", password="pw", secret="sec", max_login_failures=3, lockout_seconds=30)
        # #9: Unicode Korean username never raises TypeError
        self.assertFalse(auth.verify_credentials("한글아이디", "한글비번"))

        store = DashboardStore()
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store, auth_config=auth))
        port = srv.server_address[1]
        import threading
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            # #9 + #10: 3 bad Korean login attempts -> 401, 4th -> 429 Too Many Requests
            for attempt in range(4):
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/login",
                    data=urllib.parse.urlencode({"username": "한글아이디", "password": "wrong"}).encode(),
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req)
                expected_code = 429 if attempt == 3 else 401
                self.assertEqual(ctx.exception.code, expected_code)
                ctx.exception.close()

            # #11: Authenticated POST without csrf_token -> 403 Forbidden
            cj = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
            opener.open(
                urllib.request.Request(
                    f"http://127.0.0.1:{port}/login",
                    data=b"username=sangjun&password=pw",
                    method="POST",
                )
            ).close()
            with self.assertRaises(urllib.error.HTTPError) as csrf_ctx:
                opener.open(
                    urllib.request.Request(
                        f"http://127.0.0.1:{port}/incidents/INC-NONE/approve",
                        data=b"duration_minutes=5",
                        method="POST",
                    )
                )
            self.assertEqual(csrf_ctx.exception.code, 403)
            csrf_ctx.exception.close()

            # #8: Timestamp contrast color improved on dark navy background
            with opener.open(f"http://127.0.0.1:{port}/") as home_resp:
                home_html = home_resp.read().decode("utf-8")
                self.assertIn("Security Operations Center", home_html)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_16_unique_blocked_ip_deduplication_in_dashboard_kpi(self) -> None:
        raws, events = [], []
        for i in range(5):
            r, e = normalize_log_line(
                _erp_line(f"2026-11-20T01:00:0{i}Z", req_id=f"req-{i}"),
                source="erp",
                file_path="erp.jsonl",
                line_offset=i * 100,
                collection_mode="live",
            )
            raws.append(r)
            events.append(e)
        inc1 = build_incidents(raws, events)[0]
        inc2 = build_incidents(raws, events)[0]
        inc2.incident_id = "INC-SECOND01"
        for inc_item, ap_id in ((inc1, "APR-1"), (inc2, "APR-2")):
            inc_item.status = "blocked"
            inc_item.approvals.append(
                ApprovalRecord(
                    approval_id=ap_id,
                    incident_id=inc_item.incident_id,
                    target_ip="172.28.10.11",
                    action_type="block",
                    approved_by="sangjun",
                    approved_at_utc="2026-11-20T01:01:00Z",
                    expires_at_utc="2099-11-20T01:11:00Z",
                    status="applied",
                )
            )
        from soc.dashboard import render_incident_list

        html_out = render_incident_list(DashboardStore([inc1, inc2])).decode("utf-8")
        # 2 approvals for 1 unique IP -> KPI shows 1 unique blocked IP and 2 active approvals
        self.assertIn("활성 승인 2건", html_out)
        self.assertIn("1대 IP", html_out)


if __name__ == "__main__":
    unittest.main()
