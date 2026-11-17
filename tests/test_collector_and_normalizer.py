from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.collector import collect_file
from soc.normalizer import NormalizationError, normalize_log_line
from soc.storage import PostgresSocStorage, SQLiteSocStorage


class NormalizerAndCollectorTests(unittest.TestCase):
    def test_sample_gateway_logs_normalize_and_deduplicate_on_restart(self) -> None:
        sample_path = ROOT / "samples" / "gateway.jsonl"
        storage = SQLiteSocStorage(":memory:")
        try:
            first = collect_file("gateway", sample_path, storage)
            self.assertEqual(first.processed_lines, 4)
            self.assertEqual(first.inserted_records, 4)
            self.assertEqual(storage.count_raw_logs("gateway"), 4)
            self.assertEqual(storage.count_normalized_events("gateway"), 4)

            # Re-running collector (simulating restart) must insert 0 duplicates.
            second = collect_file("gateway", sample_path, storage)
            self.assertEqual(second.processed_lines, 0)
            self.assertEqual(second.inserted_records, 0)
            self.assertEqual(second.new_offset, first.new_offset)
            self.assertEqual(storage.count_raw_logs("gateway"), 4)
            self.assertEqual(storage.count_normalized_events("gateway"), 4)
        finally:
            storage.close()

    def test_incomplete_line_waits_for_newline_and_offset_stays_unchanged(self) -> None:
        storage = SQLiteSocStorage(":memory:")
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                log_file = Path(tmpdir) / "gateway.jsonl"
                line1 = json.dumps(
                    {
                        "timestamp_utc": "2026-11-17T02:00:01Z",
                        "source": "gateway",
                        "event_type": "fw_allow",
                        "action": "allow",
                        "src_ip": "172.28.0.10",
                        "dst_port": 80,
                    }
                )
                partial_line2 = '{"timestamp_utc":"2026-11-17T02:00:02Z","source":"gateway"'

                log_file.write_bytes((line1 + "\n" + partial_line2).encode("utf-8"))

                res1 = collect_file("gateway", log_file, storage)
                self.assertEqual(res1.processed_lines, 1)
                self.assertEqual(storage.count_raw_logs("gateway"), 1)
                self.assertEqual(storage.get_offset("gateway", "gateway.jsonl"), len((line1 + "\n").encode("utf-8")))

                # Complete line 2 with trailing newline.
                rest_line2 = ',"event_type":"fw_deny","action":"deny","src_ip":"172.28.0.10","dst_port":80}\n'
                with log_file.open("ab") as handle:
                    handle.write(rest_line2.encode("utf-8"))

                res2 = collect_file("gateway", log_file, storage)
                self.assertEqual(res2.processed_lines, 1)
                self.assertEqual(res2.inserted_records, 1)
                self.assertEqual(storage.count_raw_logs("gateway"), 2)
                self.assertEqual(storage.count_normalized_events("gateway"), 2)
        finally:
            storage.close()

    def test_sensitive_fields_stripped_and_naive_timestamp_rejected(self) -> None:
        raw_line = json.dumps(
            {
                "timestamp_utc": "2026-11-17T02:05:00+00:00",
                "source": "erp",
                "event_type": "login_failed",
                "outcome": "failure",
                "username": "alice",
                "client_ip": "172.28.0.10",
                "peer_ip": "172.28.2.5",
                "client_ip_trusted": True,
                "request_id": "req-123",
                "password": "should-never-be-stored",
                "token": "secret-jwt",
                "cookie": "session=abc",
            }
        )
        raw_rec, norm_evt = normalize_log_line(
            raw_line, source="erp", file_path="erp.jsonl", line_offset=0
        )
        self.assertEqual(norm_evt.event_ts_utc, "2026-11-17T02:05:00.000000Z")
        self.assertTrue(norm_evt.client_ip_trusted)
        self.assertNotIn("password", raw_rec.raw_payload)
        self.assertNotIn("token", raw_rec.raw_payload)
        self.assertNotIn("cookie", raw_rec.raw_payload)

        naive_line = json.dumps(
            {
                "timestamp_utc": "2026-11-17T02:05:00",
                "source": "erp",
                "event_type": "login_failed",
                "outcome": "failure",
            }
        )
        with self.assertRaises(NormalizationError):
            normalize_log_line(naive_line, source="erp", file_path="erp.jsonl", line_offset=0)

    def test_postgres_storage_connects_with_autocommit_true(self) -> None:
        fake_psycopg = MagicMock()
        with patch.dict(sys.modules, {"psycopg": fake_psycopg}):
            storage = PostgresSocStorage("postgresql://user:pass@host/db")
            fake_psycopg.connect.assert_called_once_with(
                "postgresql://user:pass@host/db", autocommit=True
            )
            storage.close()

    @unittest.skipUnless(
        os.environ.get("SOC_TEST_POSTGRES_DSN"),
        "SOC_TEST_POSTGRES_DSN not set; skipping live PostgreSQL integration test",
    )
    def test_postgres_integration_persists_across_connections(self) -> None:
        import psycopg

        dsn = os.environ["SOC_TEST_POSTGRES_DSN"]
        sample_path = ROOT / "samples" / "gateway.jsonl"

        writer = PostgresSocStorage(dsn)
        try:
            first = collect_file("gateway", sample_path, writer)
            self.assertEqual(first.processed_lines, 4)
            self.assertEqual(first.inserted_records, 4)
        finally:
            writer.close()

        # Verify from a completely separate connection that rows were committed.
        with psycopg.connect(dsn) as reader_conn:
            with reader_conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM raw_logs WHERE source = 'gateway'")
                self.assertEqual(cur.fetchone()[0], 4)
                cur.execute("SELECT outcome, COUNT(*) FROM normalized_events WHERE source = 'gateway' GROUP BY outcome ORDER BY outcome")
                self.assertEqual(cur.fetchall(), [("allow", 3), ("deny", 1)])
                cur.execute("SELECT byte_offset FROM collector_offsets WHERE source = 'gateway' AND file_path = 'gateway.jsonl'")
                self.assertGreater(cur.fetchone()[0], 0)

        # Re-running collector must insert 0 duplicates.
        writer2 = PostgresSocStorage(dsn)
        try:
            second = collect_file("gateway", sample_path, writer2)
            self.assertEqual(second.processed_lines, 0)
            self.assertEqual(second.inserted_records, 0)
        finally:
            writer2.close()


if __name__ == "__main__":
    unittest.main()
