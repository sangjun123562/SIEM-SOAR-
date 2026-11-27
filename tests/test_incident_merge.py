"""같은 공격의 '의심' 경보를 차단 후보 사건에 합쳐 한 건으로 보이는지 확인한다(팀 합의 2026-11-26)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_detector import _make_login_failure as make  # noqa: E402
from soc.incident_service import build_incidents, group_login_incidents  # noqa: E402

A, B = "172.28.10.11", "172.28.10.12"


def run(spec):
    events = [make(i, f"2026-11-26T01:00:{sec:02d}Z", username=user, client_ip=ip, ingest_mode="live")
              for i, (sec, user, ip) in enumerate(spec)]
    return group_login_incidents(build_incidents([], events))


def rules(incident):
    return {alert.rule_id.replace("RULE-ERP-LOGIN-", "") for alert in incident.alerts}


class IncidentMergeTests(unittest.TestCase):
    def test_three_failures_alone_is_investigation_only(self):
        incidents = run([(i, "alice", A) for i in range(3)])
        self.assertEqual(len(incidents), 1)
        self.assertFalse(incidents[0].block_rule_eligible)

    def test_five_failures_same_account_is_one_blockable_incident(self):
        incidents = run([(i, "alice", A) for i in range(5)])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(rules(incidents[0]), {"BRUTE-001", "THREE-FAILURES-001"})
        self.assertTrue(incidents[0].block_rule_eligible)
        self.assertEqual(incidents[0].alerts[0].rule_id, "RULE-ERP-LOGIN-BRUTE-001")

    def test_mixed_accounts_one_ip_is_one_incident(self):
        spec = [(0, "alice", A), (1, "alice", A), (2, "bob", A), (3, "bob", A), (4, "bob", A)]
        incidents = run(spec)
        self.assertEqual(len(incidents), 1)
        self.assertTrue(incidents[0].block_rule_eligible)

    def test_three_accounts_one_ip_merges_multi_account_alert(self):
        spec = [(0, "alice", A), (1, "bob", A), (2, "carol", A), (3, "alice", A), (4, "bob", A)]
        incidents = run(spec)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(rules(incidents[0]), {"IP-TOTAL-001", "MULTI-ACCOUNT-001"})
        self.assertTrue(incidents[0].block_rule_eligible)

    def test_evidence_is_not_widened_by_merge(self):
        incidents = run([(i, "alice", A) for i in range(5)])
        self.assertEqual(len(incidents[0].evidence_events), 5)

    def test_grouping_twice_does_not_duplicate_alerts_and_keeps_object(self):
        events = [make(i, f"2026-11-26T01:00:{i:02d}Z", username="alice", client_ip=A, ingest_mode="live") for i in range(5)]
        incidents = build_incidents([], events)
        first = group_login_incidents(incidents)
        second = group_login_incidents(incidents)
        self.assertEqual(len(first[0].alerts), 2)
        self.assertEqual(len(second[0].alerts), 2)
        self.assertIn(first[0], incidents)  # 상태 변경이 원래 객체에 남도록 복사본이 아니어야 한다

    def test_replay_and_live_are_not_merged(self):
        live = [make(i, f"2026-11-26T01:00:{i:02d}Z", username="alice", client_ip=A, ingest_mode="live") for i in range(5)]
        replay = [make(10 + i, f"2026-11-26T02:00:{i:02d}Z", username="bob", client_ip=B, ingest_mode="synthetic") for i in range(3)]
        incidents = group_login_incidents(build_incidents([], live + replay))
        self.assertEqual(len(incidents), 2)
        self.assertEqual(sum(1 for item in incidents if item.block_rule_eligible), 1)


class LoginGraphCountTests(unittest.TestCase):
    """5번째 실패는 ERP가 잠금(login_blocked)으로 기록한다. 그래프도 사건처럼 5회로 세야 한다."""

    def _store_with(self, events):
        from soc.dashboard import DashboardStore
        incidents = build_incidents([], events)
        return DashboardStore(incidents=incidents)

    def test_lock_denied_attempt_counts_as_login_failure_in_graph_and_summary(self):
        import json
        from datetime import datetime, timedelta, timezone
        from soc.normalizer import normalize_log_line
        events = [make(i, f"2026-11-26T01:00:{i:02d}Z", username="alice", client_ip=A, ingest_mode="live") for i in range(4)]
        blocked = json.dumps({
            "timestamp_utc": "2026-11-26T01:00:04Z", "source": "erp", "event_type": "login_blocked", "outcome": "failure",
            "username": "alice", "client_ip": A, "peer_ip": "172.28.20.5", "client_ip_trusted": True,
            "request_id": "req-4", "http_method": "POST", "http_path": "/api/login", "status_code": 403,
            "reason": "account_locked", "password_valid": False, "ingest_mode": "live"})
        events.append(normalize_log_line(blocked, source="erp", file_path="erp.jsonl", line_offset=900)[1])
        store = self._store_with(events)
        since = datetime(2026, 11, 26, 0, 0, tzinfo=timezone.utc)
        fails = [e for e in store.get_login_events(since) if e[1] == "login_failed"]
        self.assertEqual(len(fails), 5)

    def test_lock_denied_with_correct_password_is_not_counted(self):
        from soc.repository import is_lock_denied_failure
        self.assertTrue(is_lock_denied_failure("login_blocked", 403, {"reason": "account_locked", "password_valid": False}))
        self.assertFalse(is_lock_denied_failure("login_blocked", 403, {"reason": "account_locked", "password_valid": True}))
        self.assertFalse(is_lock_denied_failure("login_failed", 401, {}))


if __name__ == "__main__":
    unittest.main()
