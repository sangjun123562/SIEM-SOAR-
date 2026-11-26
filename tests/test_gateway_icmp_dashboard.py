"""ICMP broadcast denials retain raw evidence and chart only live events."""

import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.dashboard import DbDashboardStore, _icmp_denial_panel  # noqa: E402
from soc.normalizer import normalize_log_line  # noqa: E402
from soc.storage import SQLiteSocStorage  # noqa: E402


class IcmpDashboardTests(unittest.TestCase):
    def test_hourly_counts_exclude_replay_and_keep_raw_id(self):
        storage = SQLiteSocStorage(":memory:")
        try:
            records = []
            for index, (hour, mode, protocol) in enumerate(((2, "live", "ICMP"), (3, "live", "ICMP"),
                                                             (3, "replay", "ICMP"), (3, "live", "TCP"))):
                record = {
                    "timestamp_utc": f"2026-11-26T{hour:02d}:00:00Z", "source": "gateway",
                    "event_type": "fw_deny", "outcome": "deny", "ingest_mode": mode,
                    "src_ip": "172.28.10.11", "dst_ip": "172.28.20.255", "protocol": protocol,
                    "rule_id": "POLICY-ICMP-BROADCAST",
                }
                records.append(normalize_log_line(json.dumps(record), source="gateway", file_path="gw.jsonl",
                                                  line_offset=index * 200, collection_mode=mode))
            storage.save_batch_and_advance_offset("gateway", "gw.jsonl", records, 800)
            store = DbDashboardStore(storage)
            since = datetime(2026, 11, 26, 0, tzinfo=timezone.utc)
            until = datetime(2026, 11, 26, 5, tzinfo=timezone.utc)
            self.assertEqual(store.get_icmp_denial_hours(since, until),
                             [("2026-11-26T02", 1), ("2026-11-26T03", 1)])
            recent = store.get_recent_icmp_denials()
            self.assertEqual(len(recent), 2)
            self.assertEqual(recent[0]["raw_id"], records[1][0].raw_id)
            panel = _icmp_denial_panel(store, now_utc=until)
            self.assertIn("ICMP 거부 추이", panel)
            self.assertIn(records[1][0].raw_id[:8], panel)
        finally:
            storage.close()


if __name__ == "__main__":
    unittest.main()
