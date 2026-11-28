import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc.reports import compare_periods, render_compare, render_extra, render_trend


def snap(new, state="ok"):
    return {"metrics": {"신규 사건": new, "IP 차단 요청": 1, "ERP 계정 자동 잠금": 0},
            "ingest": {"sources": [{"label": "ERP", "state": state}]}}


class ExtraMetricsTests(unittest.TestCase):
    def test_compare_requires_both_final_and_no_gap(self):
        rows, why = compare_periods(snap(5), snap(3), current_final=False)
        self.assertIsNone(rows)
        self.assertIn("확정본끼리", why)
        rows, why = compare_periods(snap(5), None, current_final=True)
        self.assertIn("직전 기간", why)
        rows, why = compare_periods(snap(5), snap(3, "gap"), current_final=True)
        self.assertIsNone(rows)
        self.assertIn("수집 공백 의심", why)
        old = {"metrics": {"신규 사건": 3}}
        self.assertIn("저장되어 있지 않아", compare_periods(snap(5), old, True)[1])
        rows, why = compare_periods(snap(5), snap(3), current_final=True)
        self.assertIsNone(why)
        out = render_compare(rows, why, "weekly")
        self.assertIn("+2", out)
        self.assertIn("비교하지 않음", render_compare(None, "이유", "weekly"))

    def test_trend_needs_three_finalized_reports(self):
        self.assertIn("3개 이상", render_trend([("2026-11-02", 1), ("2026-11-09", 2)]))
        out = render_trend([("2026-11-02", 1), ("2026-11-09", 4), ("2026-11-16", 2)])
        self.assertIn("<polyline", out)
        self.assertIn("2026-11-09 4건", out)   # 그림이 아니라 글자로도 값을 적는다

    def test_extra_distinguishes_zero_unknown_and_missing(self):
        self.assertIn("저장되어 있지 않아", render_extra(None, "/events"))
        extra = {"waf": {"state": "ok", "total": 0, "detected": 0, "blocked": 0, "families": {}},
                 "doc_read": {"state": "unknown", "total": 100000, "ok": 0, "unauth": 0, "forbidden": 0, "missing": 0, "other": 0},
                 "recur": {"state": "ok", "failed_total": 4, "ips": 1, "accounts": 2}}
        out = render_extra(extra, "/events")
        self.assertIn("관측했고 해당 기록은 없습니다", out)
        self.assertIn("집계 불가", out)
        self.assertIn("재발 계정", out)

    def test_403_and_404_are_listed_separately(self):
        extra = {"waf": {"state": "ok", "total": 1, "detected": 1, "blocked": 0, "families": {"XSS 유형(941)": 1}},
                 "doc_read": {"state": "ok", "total": 4, "ok": 1, "unauth": 0, "forbidden": 2, "missing": 1, "other": 0},
                 "recur": {"state": "ok", "failed_total": 0, "ips": 0, "accounts": 0}}
        out = render_extra(extra, "/events")
        self.assertIn("권한 없음 거부(403)", out)
        self.assertIn("없는 문서(404)", out)
        self.assertIn("XSS 유형(941)", out)


if __name__ == "__main__":
    unittest.main()
