"""보고서 '수집 공백' 집계(snapshot["ingest"]) 테스트. PostgreSQL 없이 SQLite로 돈다."""
import json
import sys
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from soc.dashboard import DbDashboardStore, _ingest_source, _report_snapshot
from soc.normalizer import normalize_log_line
from soc.storage import SQLiteSocStorage

HOUR = timedelta(hours=1)
# 보고 기간: 2026-11-23(월) 00:00 KST = 2026-11-22T15:00Z 부터 7일(168시간).
START = datetime(2026, 11, 22, 15, tzinfo=timezone.utc)
END = START + timedelta(days=7)
AFTER_END = END + timedelta(days=1)


def hk(i):
    """기간 i번째 시간 칸의 키(저장소가 돌려주는 'YYYY-MM-DDTHH' UTC 형태)."""
    return (START + i * HOUR).strftime("%Y-%m-%dT%H")


def hours(indexes):
    return [(hk(i), 1) for i in indexes]


def source(hour_counts, first_event, now, bucket_hours=1, start=START, end=END):
    return _ingest_source("erp", "ERP", hour_counts, first_event, start, end, now, bucket_hours)


class IngestSourceTests(unittest.TestCase):
    def test_longest_gap_in_the_middle_is_exact(self):
        silent = set(range(10, 13)) | set(range(50, 60)) | {100, 101}
        s = source(hours(i for i in range(168) if i not in silent), START.isoformat(), AFTER_END)
        self.assertEqual(s["max_gap_hours"], 10)
        self.assertEqual(s["gap_start_kst"], "2026-11-25T02:00:00+09:00")
        self.assertEqual(s["gap_end_kst"], "2026-11-25T12:00:00+09:00")
        self.assertEqual(s["state"], "gap")
        self.assertEqual(s["total"], 168 - len(silent))
        self.assertEqual(len(s["buckets"]), 168)
        self.assertEqual(s["buckets"][50], 0)
        self.assertEqual(s["buckets"][49], 1)
        self.assertFalse(s["gap_ongoing"])  # 기간이 끝난 보고서는 '진행 중' 공백이 없다

    def test_short_silence_is_not_flagged(self):
        s = source(hours(i for i in range(168) if i not in (30, 31)), START.isoformat(), AFTER_END)
        self.assertEqual(s["max_gap_hours"], 2)
        self.assertEqual(s["state"], "ok")

    def test_unfinished_period_does_not_count_future_buckets(self):
        now = START + 50 * HOUR + timedelta(minutes=30)  # 50번째 칸 한가운데
        s = source(hours(i for i in range(50) if i not in (20, 21, 22)), START.isoformat(), now)
        self.assertEqual(s["max_gap_hours"], 3)  # 남은 118칸이 공백으로 잡히면 118이 나온다
        self.assertEqual(s["gap_start_kst"], "2026-11-23T20:00:00+09:00")
        self.assertEqual(s["buckets"][20], 0)
        self.assertTrue(all(b is None for b in s["buckets"][50:]))  # 덜 찬 현재 칸과 미래 칸은 평가 안 함
        self.assertEqual(s["evaluated_hours"], 50)
        self.assertFalse(s["gap_ongoing"])

    def test_silence_up_to_now_is_reported_as_ongoing(self):
        now = START + 50 * HOUR + timedelta(minutes=30)
        s = source(hours(range(45)), START.isoformat(), now)
        self.assertEqual(s["max_gap_hours"], 5)  # 45~49번 칸
        self.assertTrue(s["gap_ongoing"])
        self.assertEqual(s["state"], "gap")

    def test_collection_started_mid_period_is_out_of_range_not_gap(self):
        first = START + 100 * HOUR + timedelta(minutes=20)
        s = source(hours(range(100, 168)), first.isoformat(), AFTER_END)
        self.assertTrue(all(b is None for b in s["buckets"][:100]))  # 수집 시작 전은 범위 밖
        self.assertEqual(s["max_gap_hours"], 0)
        self.assertEqual(s["state"], "ok")
        self.assertFalse(s["had_prior_data"])
        self.assertEqual(s["observed_from_kst"], "2026-11-27T04:00:00+09:00")

    def test_events_before_period_make_leading_silence_a_real_gap(self):
        s = source(hours(range(40, 168)), (START - 5 * HOUR).isoformat(), AFTER_END)
        self.assertTrue(s["had_prior_data"])
        self.assertEqual(s["max_gap_hours"], 40)
        self.assertEqual(s["gap_start_kst"], "2026-11-23T00:00:00+09:00")

    def test_source_without_any_event_is_no_data_not_gap(self):
        s = source([], None, AFTER_END)
        self.assertEqual(s["state"], "no_data")
        self.assertEqual(s["total"], 0)
        self.assertIsNone(s["max_gap_hours"])
        self.assertIsNone(s["gap_start_kst"])
        self.assertIsNone(s["gap_end_kst"])
        self.assertFalse(s["had_prior_data"])
        self.assertTrue(all(b is None for b in s["buckets"]))

    def test_silent_period_with_earlier_history_is_still_no_data_but_flagged(self):
        s = source([], (START - 3 * HOUR).isoformat(), AFTER_END)
        self.assertEqual(s["state"], "no_data")
        self.assertTrue(s["had_prior_data"])
        self.assertIsNone(s["max_gap_hours"])

    def test_naturally_quiet_source_is_sparse(self):
        s = source(hours([10, 90]), (START - HOUR).isoformat(), AFTER_END)
        self.assertEqual(s["state"], "sparse")
        self.assertGreater(s["max_gap_hours"], 3)  # 수치는 그대로 주되 공백 의심으로 올리지 않는다

    def test_gap_length_stays_hourly_even_with_six_hour_buckets(self):
        start = datetime(2026, 10, 31, 15, tzinfo=timezone.utc)  # 11월 1일 00:00 KST
        end = start + timedelta(days=30)
        counts = [((start + i * HOUR).strftime("%Y-%m-%dT%H"), 1) for i in range(720) if not 7 <= i < 12]
        s = _ingest_source("erp", "ERP", counts, start.isoformat(), start, end, end + HOUR, 6)
        self.assertEqual(len(s["buckets"]), 120)
        self.assertEqual(s["max_gap_hours"], 5)
        self.assertEqual(s["buckets"][1], 1)  # 6~11번 칸 중 6번만 수신
        self.assertEqual(s["gap_start_kst"], "2026-11-01T07:00:00+09:00")


class IngestSnapshotTests(unittest.TestCase):
    def _event(self, kind, i, event_type, minute=5):
        ts = (START + i * HOUR + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return json.dumps({"timestamp_utc": ts, "source": kind, "event_type": event_type,
                           "outcome": "success", "ingest_mode": "live"})

    def _save(self, storage, kind, rows):
        pairs = [normalize_log_line(self._event(kind, i, et), source=kind, file_path=f"{kind}.jsonl",
                                    line_offset=n, collection_mode="live")
                 for n, (i, et) in enumerate(rows)]
        storage.save_batch_and_advance_offset(kind, f"{kind}.jsonl", pairs, 1000)

    def test_snapshot_splits_waf_and_marks_unfinished_period(self):
        storage = SQLiteSocStorage()
        try:
            now = START + 72 * HOUR + timedelta(minutes=10)
            self._save(storage, "erp", [(i, "login_success") for i in range(72) if not 20 <= i < 26])
            self._save(storage, "caddy",
                       [(i, "http_request") for i in range(72)] + [(5, "waf_blocked"), (6, "waf_detected")])
            snap = _report_snapshot(DbDashboardStore(storage), date(2026, 11, 23), "weekly", now=now)
        finally:
            storage.close()
        ing = snap["ingest"]
        self.assertEqual(ing["bucket_hours"], 1)
        self.assertTrue(ing["period_open"])
        self.assertEqual([s["key"] for s in ing["sources"]], ["erp", "gateway", "caddy", "waf"])
        erp, gw, caddy, waf = ing["sources"]
        self.assertEqual((erp["max_gap_hours"], erp["state"]), (6, "gap"))
        self.assertEqual(erp["gap_start_kst"], "2026-11-23T20:00:00+09:00")
        self.assertEqual(len(erp["buckets"]), 168)
        self.assertIsNone(erp["buckets"][100])  # 아직 오지 않은 시간
        self.assertEqual(gw["state"], "no_data")  # 이벤트 0건 출처는 공백으로 단정하지 않는다
        # 웹 프록시에서 WAF를 분리했고, 합계는 기존 snapshot["sources"] 건수와 같다.
        self.assertEqual(caddy["total"], 72)
        self.assertEqual(waf["total"], 2)
        for item, label in zip(ing["sources"], ("ERP", "게이트웨이", "웹 프록시(WAF 제외)", "WAF 판정")):
            self.assertEqual(item["total"], snap["sources"][label])
        json.dumps(snap)  # 확정본에 JSON으로 저장되므로 직렬화돼야 한다

    def test_store_without_hourly_queries_leaves_key_absent(self):
        class OldStore:
            def list_incidents(self):
                return []

            def count_recent_events(self, **kwargs):
                return 0

        snap = _report_snapshot(OldStore(), date(2026, 11, 23), "weekly")
        self.assertNotIn("ingest", snap)


class IngestRenderTests(unittest.TestCase):
    def _ingest(self, state, buckets):
        return {"bucket_hours": 1, "min_gap_hours": 3, "period_open": False, "observed_to_kst": "2026-11-30T00:00:00+09:00",
                "sources": [{"key": "erp", "label": "ERP", "total": 5, "buckets": buckets, "max_gap_hours": 4,
                             "gap_start_kst": "2026-11-24T01:00:00+09:00", "gap_end_kst": "2026-11-24T05:00:00+09:00",
                             "gap_ongoing": False, "state": state, "evaluated_hours": 3, "active_hours": 1}]}

    def test_none_is_not_painted_as_gap(self):
        from soc.reports import render_ingest
        html_out = render_ingest(self._ingest("gap", [3, 0, None]), "/events")
        self.assertEqual(html_out.count('<span class="n"></span>'), 1)      # 평가 안 함(None)은 공백이 아니다
        self.assertEqual(html_out.count('<span class="z"></span>'), 1)      # 0건만 0건 표시
        self.assertEqual(html_out.count('<span class="h" '), 1)             # 기록 있는 칸은 막대
        self.assertIn("공백 의심", html_out)

    def test_old_snapshot_says_not_stored(self):
        from soc.reports import ingest_summary, render_ingest
        self.assertIn("저장되어 있지 않아", render_ingest(None, "/events"))
        self.assertEqual(ingest_summary(None), "수집 공백 집계 저장 안 됨")

    def test_summary_distinguishes_states(self):
        from soc.reports import ingest_summary
        self.assertIn("공백 의심", ingest_summary(self._ingest("gap", [0])))
        prior = self._ingest("no_data", [0])
        prior["sources"][0]["had_prior_data"] = True
        self.assertIn("구분 불가", ingest_summary(prior))                 # 이전엔 받던 출처가 0건
        self.assertEqual(ingest_summary(self._ingest("no_data", [0])), "수집 공백 의심 없음")  # 원래 없던 출처는 경고 아님
        self.assertEqual(ingest_summary(self._ingest("sparse", [0])), "수집 공백 의심 없음")   # 뜸한 출처는 경고 아님
        self.assertEqual(ingest_summary(self._ingest("ok", [1])), "수집 공백 의심 없음")


class SparseStallTests(unittest.TestCase):
    def _run(self, counts_by_hour, now_hour):
        start = datetime(2026, 11, 23, tzinfo=timezone.utc)
        end = start + timedelta(days=7)
        hours = [((start + timedelta(hours=i)).strftime("%Y-%m-%dT%H"), c) for i, c in counts_by_hour]
        first = (start + timedelta(hours=counts_by_hour[0][0])).isoformat().replace("+00:00", "Z")
        return _ingest_source("erp", "ERP", hours, first, start, end, start + timedelta(hours=now_hour), 1)

    def test_sparse_source_silent_for_a_day_at_the_end_is_flagged(self):
        quiet = self._run([(0, 1), (40, 1)], now_hour=100)      # 마지막 수신 뒤 59시간 조용
        self.assertEqual(quiet["state"], "gap")
        self.assertEqual(quiet["tail_silent_hours"], 100 - 1 - 40)
        self.assertEqual(quiet["last_active_kst"][:13], "2026-11-25T01")  # 40시간째 UTC(11-24 16시) → KST 11-25 01시

    def test_sparse_source_that_just_spoke_stays_sparse(self):
        recent = self._run([(0, 1), (90, 1)], now_hour=100)     # 9시간 전에 수신
        self.assertEqual(recent["state"], "sparse")
        self.assertEqual(recent["tail_silent_hours"], 9)

    def test_finished_period_is_not_flagged_by_tail(self):
        done = self._run([(0, 1), (40, 1)], now_hour=24 * 7 + 5)  # 기간이 끝난 뒤
        self.assertEqual(done["state"], "sparse")


if __name__ == "__main__":
    unittest.main()
