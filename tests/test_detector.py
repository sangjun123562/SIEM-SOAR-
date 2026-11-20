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
    LOGIN_FAILURE_RULE_ID, LOGIN_SOURCE_CHANGE_RULE_ID, LOGIN_SUCCESS_REVIEW_RULE_ID,
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
    def test_input_format_errors_do_not_count_as_credential_failures(self) -> None:
        failures = [_make_login_failure(i, f"2026-11-17T02:00:0{i}Z") for i in range(5)]
        malformed = replace(failures[-1], status_code=400)
        self.assertEqual(detect_login_failures(failures[:-1] + [malformed]), [])
        self.assertEqual(len(detect_login_failures(failures)), 1)

    def test_verified_success_separates_failure_groups_below_threshold(self) -> None:
        failures = [_make_login_failure(i, f"2026-11-17T02:00:0{i * 2}Z") for i in range(5)]
        success = replace(
            _make_login_failure(8, "2026-11-17T02:00:03Z"),
            event_type="login_success", status_code=200, outcome="success",
        )
        self.assertEqual(detect_login_failures(failures + [success]), [])
        self.assertEqual(build_incidents([], failures + [success]), [])
        self.assertEqual(len(build_incidents([], failures)), 1)
        for unrelated_success in (
            replace(success, username="bob"),
            replace(success, client_ip="172.28.10.12"),
            replace(success, client_ip_trusted=False),
            replace(success, ingest_mode="replay"),
            replace(success, status_code=401),
        ):
            with self.subTest(success=unrelated_success):
                self.assertEqual(len(detect_login_failures(failures + [unrelated_success])), 1)

    def test_success_at_or_after_alert_threshold_does_not_remove_alert(self) -> None:
        failures = [_make_login_failure(i, f"2026-11-17T02:00:0{i}Z") for i in range(5)]
        expected = detect_login_failures(failures)
        for timestamp in ("2026-11-17T02:00:04Z", "2026-11-17T02:00:05Z"):
            with self.subTest(timestamp=timestamp):
                success = replace(
                    _make_login_failure(8, timestamp),
                    event_type="login_success", status_code=200, outcome="success",
                )
                self.assertEqual(detect_login_failures(failures + [success]), expected)

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


class InvestigationDetectorTests(unittest.TestCase):
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

    def test_success_after_three_or_four_failures_creates_one_review(self) -> None:
        failures = [
            replace(_make_login_failure(i, f"2026-11-17T02:00:0{i}Z"), ingest_mode="live")
            for i in range(8)
        ]
        success = replace(
            _make_login_failure(9, "2026-11-17T02:05:00Z"),
            event_type="login_success", status_code=200, outcome="success", ingest_mode="live",
        )
        self.assertEqual(build_incidents([], failures[:2] + [success]), [])
        self.assertEqual(build_incidents([], failures[:4]), [])

        for count in (3, 4):
            with self.subTest(count=count):
                events = failures[:count] + [success]
                incident, = build_incidents([], list(reversed(events)) + [success])
                alert, = incident.alerts
                self.assertEqual(alert.rule_id, LOGIN_SUCCESS_REVIEW_RULE_ID)
                self.assertEqual(alert.failure_count, count)
                self.assertEqual(alert.evidence_event_ids, tuple(event.event_id for event in events))
                self.assert_persisted_investigation(events, f"{count}회 실패 뒤 성공", success.raw_id)

        # 8회 실패에서 첫 5회로 이미 경보가 난 경우에도 남은 3회로 주의 사건을 또 만들지 않는다.
        for count in (5, 8):
            with self.subTest(count=count):
                incident, = build_incidents([], failures[:count] + [success])
                self.assertEqual(incident.alerts[0].rule_id, LOGIN_FAILURE_RULE_ID)

    def test_success_review_respects_account_ip_time_and_ingest_mode(self) -> None:
        failures = [_make_login_failure(i, f"2026-11-17T02:00:0{i}Z") for i in range(3)]
        success = replace(
            _make_login_failure(9, "2026-11-17T02:00:10Z"),
            event_type="login_success", status_code=200, outcome="success",
        )
        for mismatched_success in (
            replace(success, username="bob"),
            replace(success, client_ip_trusted=False),
            replace(success, ingest_mode="replay"),
            replace(success, event_ts_utc="2026-11-17T02:05:01Z"),
            replace(success, event_ts_utc="2026-11-17T02:00:02Z"),
        ):
            with self.subTest(success=mismatched_success):
                self.assertEqual(build_incidents([], failures + [mismatched_success]), [])

    def test_success_from_different_ip_tracks_both_sources_without_adding_a_block(self) -> None:
        failures = [
            replace(_make_login_failure(i, f"2026-11-17T02:00:0{i}Z"), ingest_mode="live")
            for i in range(5)
        ]
        success = replace(
            _make_login_failure(9, "2026-11-17T02:05:00Z", client_ip="192.0.2.2"),
            event_type="login_success", status_code=200, outcome="success", ingest_mode="live",
        )
        for count in (3, 4):
            with self.subTest(count=count):
                events = failures[:count] + [success]
                incident, = build_incidents([], list(reversed(events)) + [success])
                alert, = incident.alerts
                self.assertEqual(alert.rule_id, LOGIN_SOURCE_CHANGE_RULE_ID)
                self.assertEqual(alert.failure_count, count)
                self.assertEqual(alert.evidence_event_ids, tuple(event.event_id for event in events))
                self.assertEqual(incident.target_ip, "")
                self.assert_persisted_investigation(events, f"{count}회 실패 뒤 다른 IP에서 성공", "192.0.2.2")

        incident, = build_incidents([], failures + [success])
        self.assertEqual(incident.alerts[0].rule_id, LOGIN_FAILURE_RULE_ID)

    def test_different_ip_review_keeps_unrelated_events_out(self) -> None:
        failures = [_make_login_failure(i, f"2026-11-17T02:00:0{i}Z") for i in range(3)]
        success = replace(
            _make_login_failure(9, "2026-11-17T02:00:10Z", client_ip="192.0.2.2"),
            event_type="login_success", status_code=200, outcome="success",
        )
        self.assertEqual(build_incidents([], failures[:2] + [success]), [])
        self.assertEqual(build_incidents([], failures), [])
        for unrelated in (
            replace(success, username="bob"),
            replace(success, client_ip_trusted=False),
            replace(success, ingest_mode="replay"),
            replace(success, event_ts_utc="2026-11-17T02:05:01Z"),
            replace(success, event_ts_utc="2026-11-17T02:00:02Z"),
        ):
            with self.subTest(success=unrelated):
                self.assertEqual(build_incidents([], failures + [unrelated]), [])

        same_ip = replace(success, client_ip=failures[0].client_ip)
        incident, = build_incidents([], failures + [same_ip])
        self.assertEqual(incident.alerts[0].rule_id, LOGIN_SUCCESS_REVIEW_RULE_ID)

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
        if incident.alerts[0].rule_id == LOGIN_SUCCESS_REVIEW_RULE_ID:
            self.assertIn("주의 · 인증 성공 확인 필요", overview)
            self.assertIn("주의 · 반복 실패 후 로그인 성공", page)
            self.assertIn("로그인 성공", page)
        elif incident.alerts[0].rule_id == LOGIN_SOURCE_CHANGE_RULE_ID:
            self.assertIn("주의 · 실패와 성공의 출발지가 다름", overview)
            self.assertIn("주의 · 반복 실패 후 다른 출발지에서 로그인 성공", page)
            self.assertIn("172.28.10.11", page)
            self.assertIn("로그인 성공", page)
        else:
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
