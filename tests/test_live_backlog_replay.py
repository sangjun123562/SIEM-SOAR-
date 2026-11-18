"""수집기 시작 전에 이미 있던 로그는 replay, 시작 후 추가된 줄만 live로 저장되는지 확인한다."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.live_collector import run_live, run_once  # noqa: E402
from soc.repository import SocRepository  # noqa: E402
from soc.storage import SQLiteSocStorage  # noqa: E402


def _fail(i: int) -> str:
    return json.dumps({
        "timestamp_utc": f"2026-11-18T04:00:{i:02d}Z", "source": "erp", "event_type": "login_failed",
        "outcome": "failure", "username": "alice", "client_ip": "172.28.10.11", "peer_ip": "172.28.20.5",
        "client_ip_trusted": True, "request_id": f"req-backlog-{i}", "http_method": "POST",
        "http_path": "/api/login", "status_code": 401, "ingest_mode": "live",
    })


class LiveBacklogReplayTests(unittest.TestCase):
    def test_existing_lines_are_replay_and_not_eligible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            erp.write_text("".join(_fail(i) + "\n" for i in range(5)), encoding="utf-8")
            storage = SQLiteSocStorage(":memory:")
            try:
                run_live(storage, {"erp": erp}, interval=0, max_passes=1)
                modes = {e["ingest_mode"] for e in storage.list_events()}
                self.assertEqual(modes, {"replay"})
                for inc in SocRepository(storage).load_incidents():
                    self.assertFalse(inc.live_and_trusted_eligible)
            finally:
                storage.close()

    def test_lines_appended_after_start_are_live(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            erp.write_text(_fail(0) + "\n", encoding="utf-8")
            storage = SQLiteSocStorage(":memory:")
            try:
                run_live(storage, {"erp": erp}, interval=0, max_passes=1)
                with erp.open("a", encoding="utf-8") as f:
                    f.write("".join(_fail(i) + "\n" for i in range(10, 15)))
                run_once(storage, {"erp": erp}, collection_mode="live")
                modes = [e["ingest_mode"] for e in storage.list_events()]
                self.assertEqual(modes.count("replay"), 1)
                self.assertEqual(modes.count("live"), 5)
            finally:
                storage.close()


if __name__ == "__main__":
    unittest.main()
