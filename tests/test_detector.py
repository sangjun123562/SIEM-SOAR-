from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.dashboard import DashboardStore, render_incident_detail, render_incident_list
from soc.detector import (
    MULTI_ACCOUNT_RULE_ID, MULTI_SOURCE_RULE_ID, detect_login_failures,
    detect_multi_account_failures, detect_multi_source_failures,
)
from soc.incident_service import ActionPolicyError, build_incidents, request_human_approval
from soc.models import NormalizedEvent, RawLogRecord
from soc.normalizer import normalize_log_line
from soc.repository import SocRepository
from soc.storage import SQLiteSocStorage


def _make_login_failure(
    idx: int,
    ts_utc: str,
    *,
    username: str = "alice",
    client_ip: str = "172.28.10.11",
    trusted: bool = True,
    ingest_mode: str = "synthetic",
) -> NormalizedEvent:
    raw_line = json.dumps(
        {
            "timestamp_utc": ts_utc,
            "source": "erp",
            "event_type": "login_failed",
            "outcome": "failure",
            "username": username,
            "client_ip": client_ip,
            "peer_ip": "172.28.20.5",
            "client_ip_trusted": trusted,
            "request_id": f"req-{idx}",
            "http_method": "POST",
            "http_path": "/api/login",
            "status_code": 401,
            "ingest_mode": ingest_mode,
        }
    )
    _, norm = normalize_log_line(raw_line, source="erp", file_path="erp.jsonl", line_offset=idx * 100)
    return norm


class LoginFailureDetectorTests(unittest.TestCase):
    def test_n_minus_1_has_no_alert_and_n_triggers_first_alert(self) -> None:
        events = [
            _make_login_failure(i, f"2026-11-17T02:00:0{i}Z")
            for i in range(4)
        ]
        self.assertEqual(detect_login_failures(events, threshold=5, window_seconds=300), [])

        events.append(_make_login_failure(4, "2026-11-17T02:00:04Z"))
        alerts = detect_login_failures(events, threshold=5, window_seconds=300)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].failure_count, 5)
        self.assertEqual(len(alerts[0].evidence_event_ids), 5)
        self.assertEqual(len(alerts[0].evidence_raw_ids), 5)

    def test_untrusted_client_ip_never_triggers_alert(self) -> None:
        events = [
            _make_login_failure(i, f"2026-11-17T02:00:0{i}Z", trusted=False)
            for i in range(6)
        ]
        self.assertEqual(detect_login_failures(events, threshold=5, window_seconds=300), [])

    def test_separates_two_clients_and_shared_ip_different_users(self) -> None:
        # 3 failures from client .11, 3 from client .12 -> neither hits 5
        events = [
            _make_login_failure(i, f"2026-11-17T02:00:0{i}Z", client_ip="172.28.10.11")
            for i in range(3)
        ] + [
            _make_login_failure(10 + i, f"2026-11-17T02:00:0{i}Z", client_ip="172.28.10.12")
            for i in range(3)
        ]
        self.assertEqual(detect_login_failures(events, threshold=5, window_seconds=300), [])

        # Shared IP, different users (3 for alice, 3 for bob) -> neither hits 5
        shared_ip_events = [
            _make_login_failure(20 + i, f"2026-11-17T02:01:0{i}Z", username="alice", client_ip="172.28.10.11")
            for i in range(3)
        ] + [
            _make_login_failure(30 + i, f"2026-11-17T02:01:0{i}Z", username="bob", client_ip="172.28.10.11")
            for i in range(3)
        ]
        self.assertEqual(detect_login_failures(shared_ip_events, threshold=5, window_seconds=300), [])

    def test_midnight_utc_boundary_and_deduplication(self) -> None:
        sample_path = ROOT / "samples" / "erp_login_failures.jsonl"
        events: list[NormalizedEvent] = []
        offset = 0
        for line in sample_path.read_bytes().splitlines(keepends=True):
            _, norm = normalize_log_line(
                line.decode("utf-8"), source="erp", file_path="erp_login_failures.jsonl", line_offset=offset
            )
            offset += len(line)
            events.append(norm)

        alerts = detect_login_failures(events, threshold=5, window_seconds=300)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].username, "alice")
        self.assertEqual(alerts[0].client_ip, "172.28.10.11")
        self.assertEqual(alerts[0].window_start_utc, "2026-11-17T23:58:10.000000Z")
        self.assertEqual(alerts[0].window_end_utc, "2026-11-18T00:00:20.000000Z")

        # Re-running with existing dedup_keys produces 0 duplicate alerts.
        existing = {a.dedup_key for a in alerts}
        self.assertEqual(
            detect_login_failures(events, threshold=5, window_seconds=300, existing_dedup_keys=existing),
            [],
        )


class MultiAccountDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = [
            replace(_make_login_failure(i, ts, username=name), ingest_mode="live")
            for i, (name, ts) in enumerate([
                ("alice", "2026-11-17T23:59:00Z"),
                ("bob", "2026-11-18T00:00:00Z"),
                ("charlie", "2026-11-18T00:04:00Z"),
            ])
        ]

    def test_needs_three_distinct_names_from_one_trusted_ip_and_valid_erp_failures(self) -> None:
        first, second, third = self.events
        for ineligible in (
            replace(third, username="alice"),
            replace(third, client_ip="172.28.10.12"),
            replace(third, client_ip_trusted=False),
            replace(third, status_code=400),
            replace(third, source="caddy"),
            replace(third, event_ts_utc="2026-11-18T00:04:01Z"),
        ):
            with self.subTest(event=ineligible):
                self.assertEqual(detect_multi_account_failures([first, second, ineligible]), [])

        alerts = detect_multi_account_failures([third, first, second, third])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, MULTI_ACCOUNT_RULE_ID)
        self.assertEqual(alerts[0].evidence_event_ids, tuple(ev.event_id for ev in self.events))
        self.assertEqual(alerts, detect_multi_account_failures(self.events))
        self.assertEqual(detect_login_failures(self.events), [])

    def test_persisted_live_incident_is_visible_but_cannot_request_block(self) -> None:
        self.assert_persisted_investigation(self.events, "3개 계정명 실패", "charlie")

    def test_multiple_sources_need_the_same_account_and_distinct_trusted_ips(self) -> None:
        first, second, third = [
            replace(event, username="alice", client_ip=f"192.0.2.{i}")
            for i, event in enumerate(self.events, start=1)
        ]
        for ineligible in (
            replace(third, client_ip=first.client_ip),
            replace(third, username="bob"),
            replace(third, client_ip_trusted=False),
            replace(third, status_code=400),
            replace(third, event_ts_utc="2026-11-18T00:04:01Z"),
        ):
            with self.subTest(event=ineligible):
                self.assertEqual(detect_multi_source_failures([first, second, ineligible]), [])

        alerts = detect_multi_source_failures([third, first, second, third])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, MULTI_SOURCE_RULE_ID)
        self.assertEqual(alerts[0].username, "alice")
        self.assertEqual(alerts[0].client_ip, "")
        self.assertEqual(alerts[0].evidence_event_ids, (first.event_id, second.event_id, third.event_id))
        self.assertEqual(alerts, detect_multi_source_failures([first, second, third]))
        self.assert_persisted_investigation([first, second, third], "3개 출발지 실패", "192.0.2.3")

    def assert_persisted_investigation(
        self, events: list[NormalizedEvent], summary: str, evidence_text: str,
    ) -> None:
        storage = SQLiteSocStorage()
        self.addCleanup(storage.close)
        raws = [
            RawLogRecord(ev.raw_id, "erp", "erp.jsonl", i, "{}", "live")
            for i, ev in enumerate(events)
        ]
        storage.save_batch_and_advance_offset("erp", "erp.jsonl", list(zip(raws, events)), len(events))
        repo = SocRepository(storage)
        for _ in range(2):
            repo.sync_incidents(build_incidents(*repo.fetch_raw_and_events()))

        incident, = repo.load_incidents()
        self.assertTrue(incident.live_and_trusted_eligible)
        self.assertFalse(incident.block_rule_eligible)
        self.assertEqual(set(incident.raw_logs_by_id), {ev.raw_id for ev in events})
        page = render_incident_detail(incident, current_user="operator", auth_enabled=True).decode()
        self.assertIn(summary, page)
        self.assertIn(evidence_text, page)
        self.assertIn("조사용 사건입니다", page)
        disabled_approve = r'<button type="submit" disabled[^>]*>(?:<svg[^>]*>.*?</svg>\s*)?시험 단말 차단 승인'
        self.assertRegex(page, disabled_approve)

        overview = render_incident_list(
            DashboardStore([incident]), current_user="operator", auth_enabled=True,
        ).decode()
        self.assertIn("조사용 · 차단 불가", overview)
        self.assertIn(evidence_text, overview)
        self.assertNotIn("T1110.001", overview)
        self.assertRegex(overview, disabled_approve)
        self.assertNotIn("10분 즉시 차단 승인", overview)

        action_client = Mock()
        with self.assertRaisesRegex(ActionPolicyError, "조사용"):
            request_human_approval(incident, approved_by="operator", action_client=action_client)
        action_client.block.assert_not_called()


if __name__ == "__main__":
    unittest.main()
