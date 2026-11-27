"""내보내기 보완: 기간 없는 로그 내려받기는 최근 7일만, CSV 수식 방지는 탭·줄바꿈까지."""
from __future__ import annotations

import csv
import io
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.exports import DEFAULT_EXPORT_DAYS, _csv, build_export  # noqa: E402


class StubStore:
    def __init__(self):
        self.calls = []

    def list_recent_events(self, limit=50, *, offset=0, since_utc=None, until_utc=None, **_):
        self.calls.append((since_utc, until_utc))
        return []


class ExportHardeningTests(unittest.TestCase):
    def test_events_without_period_default_to_last_seven_days(self):
        store = StubStore()
        _name, _mime, body = build_export(store, {"kind": "events"})
        since, until = store.calls[0]
        self.assertIsNotNone(since)
        self.assertAlmostEqual((until - since).total_seconds(), timedelta(days=DEFAULT_EXPORT_DAYS).total_seconds(), delta=5)
        self.assertIn("최근 7일".encode(), body)

    def test_explicit_period_is_not_overridden(self):
        store = StubStore()
        build_export(store, {"kind": "events", "from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z"})
        since, until = store.calls[0]
        self.assertEqual(since, datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(until, datetime(2026, 1, 2, tzinfo=timezone.utc))

    def test_flow_lookup_keeps_old_records_reachable(self):
        store = StubStore()
        build_export(store, {"kind": "flow", "request_id": "req-1"})
        self.assertIsNone(store.calls[0][0])

    def test_csv_blocks_formula_tab_and_line_break_prefixes(self):
        rows = [{"a": "\tfoo", "b": "\rbar", "c": "\nbaz", "d": "=1+1", "e": " @x", "f": "+1", "g": "-1", "h": "normal"}]
        text = _csv(rows, {}).decode("utf-8-sig")
        record = next(csv.DictReader(io.StringIO(text, newline="")))
        for key in "abcdefg":
            self.assertTrue(record[key].startswith("'"), key)
        self.assertEqual(record["h"], "normal")


if __name__ == "__main__":
    unittest.main()
