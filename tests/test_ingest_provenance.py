from __future__ import annotations

import json
import runpy
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from soc.collector import collect_file
from soc.models import NormalizedEvent, RawLogRecord
from soc.normalizer import NormalizationError, normalize_log_line
from soc.storage import SQLiteSocStorage


def record(**overrides):
    payload = {
        "timestamp_utc": "2026-11-17T08:00:00Z", "source": "erp",
        "event_type": "login_failed", "outcome": "failure",
        "username": "alice", "client_ip": "172.28.10.11",
        "client_ip_trusted": True, "ingest_mode": "live",
    }
    payload.update(overrides)
    return payload


def normalized(payload, **options):
    return normalize_log_line(json.dumps(payload), source="erp",
                              file_path="erp.jsonl", line_offset=0, **options)


class IngestProvenanceTests(unittest.TestCase):
    def test_payload_live_cannot_promote_default_import(self):
        raw, event = normalized(record())
        self.assertEqual((raw.ingest_mode, event.ingest_mode), ("replay", "replay"))
        self.assertEqual(json.loads(raw.raw_payload)["ingest_mode"], "replay")
        self.assertEqual(event.details["reported_ingest_mode"], "live")

    def test_missing_mode_stays_replay_even_on_live_collector(self):
        payload = record()
        del payload["ingest_mode"]
        for configured in ("replay", "live"):
            with self.subTest(configured=configured):
                raw, event = normalized(payload, collection_mode=configured)
                self.assertEqual((raw.ingest_mode, event.ingest_mode), ("replay", "replay"))

    def test_collection_and_payload_modes_can_only_downgrade(self):
        for configured in ("live", "replay", "synthetic"):
            for reported in ("live", "replay", "synthetic"):
                with self.subTest(configured=configured, reported=reported):
                    expected = ("synthetic" if "synthetic" in (configured, reported)
                                else "live" if configured == reported == "live" else "replay")
                    raw, event = normalized(record(ingest_mode=reported), collection_mode=configured)
                    self.assertEqual((raw.ingest_mode, event.ingest_mode), (expected, expected))

    def test_trusted_ip_requires_actual_json_boolean(self):
        for value in ("false", "true", 0, 1, None, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(NormalizationError):
                    normalized(record(client_ip_trusted=value))
        for value in (False, True):
            _, event = normalized(record(client_ip_trusted=value))
            self.assertIs(event.client_ip_trusted, value)
        payload = record()
        del payload["client_ip_trusted"]
        self.assertIs(normalized(payload)[1].client_ip_trusted, False)

    def test_invalid_modes_are_controlled_errors(self):
        for value in ("unknown", None, [], {}, True):
            with self.subTest(value=value):
                with self.assertRaises(NormalizationError):
                    normalized(record(ingest_mode=value))
                with self.assertRaises(NormalizationError):
                    normalized(record(), collection_mode=value)

    def test_copy_of_live_file_is_persisted_as_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "erp.jsonl"
            path.write_text(json.dumps(record()) + "\n", encoding="utf-8")
            for configured in (None, "replay", "synthetic", "live"):
                with self.subTest(configured=configured):
                    store = SQLiteSocStorage(":memory:")
                    try:
                        options = {} if configured is None else {"collection_mode": configured}
                        collect_file("erp", path, store, **options)
                        self.assertEqual(store.list_events()[0]["ingest_mode"], configured or "replay")
                        self.assertEqual(collect_file("erp", path, store, **options).inserted_records, 0)
                    finally:
                        store.close()

    def test_invalid_boolean_does_not_store_or_advance_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "erp.jsonl"
            path.write_text(json.dumps(record(client_ip_trusted="false")) + "\n", encoding="utf-8")
            store = SQLiteSocStorage(":memory:")
            try:
                with self.assertRaises(NormalizationError):
                    collect_file("erp", path, store)
                self.assertEqual(store.get_offset("erp", path.name), 0)
                self.assertEqual(store.count_raw_logs(), 0)
                self.assertEqual(store.count_normalized_events(), 0)
            finally:
                store.close()

    def test_raw_log_guard_accepts_sanitized_record(self):
        check = runpy.run_path(str(ROOT / "testbed/scripts/check_caddy_raw_log.py"))["check_record"]
        self.assertEqual(check({"request": {"uri": "/echo", "remote_ip": "172.28.10.11"}}), [])

    def test_raw_log_guard_rejects_original_query_and_headers(self):
        check = runpy.run_path(str(ROOT / "testbed/scripts/check_caddy_raw_log.py"))["check_record"]
        errors = check({"request": {"uri": "/echo?password=TEST_ONLY",
                                   "headers": {"Cookie": ["TEST_ONLY"]}},
                        "resp_headers": {"Set-Cookie": ["TEST_ONLY"]}})
        self.assertIn("query retained", errors)
        self.assertIn("headers retained", errors)
        self.assertNotIn("TEST_ONLY", str(errors))

    def test_direct_model_defaults_are_not_live(self):
        raw = RawLogRecord("raw", "erp", "erp.jsonl", 0, "{}")
        event = NormalizedEvent("evt", "raw", "erp", "2026-11-17T08:00:00Z", "login_failed", "failure")
        self.assertEqual((raw.ingest_mode, event.ingest_mode), ("replay", "replay"))


if __name__ == "__main__":
    unittest.main()
