from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.detector import detect_login_failures
from soc.models import NormalizedEvent
from soc.normalizer import normalize_log_line


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


if __name__ == "__main__":
    unittest.main()
