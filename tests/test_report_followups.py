import sys
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc.reports import (ReportRepository, carry_count, followup_freeze, followup_summary, is_overdue,
                         render_followups, validate_followup_change, validate_followup_new)
from soc.storage import SQLiteSocStorage


class FollowupLedgerTests(unittest.TestCase):
    def setUp(self):
        self.repo = ReportRepository(SQLiteSocStorage())

    def test_open_items_carry_into_later_periods_automatically(self):
        old = self.repo.add_followup("weekly", "2026-11-02", "게이트웨이 적용 확인", "김", "2026-11-09", "eldi")
        done = self.repo.add_followup("weekly", "2026-11-02", "끝난 일", "", "", "eldi")
        self.repo.update_followup(done, "done", "확인함", "eldi")
        rows = self.repo.visible_followups("weekly", "2026-11-23")
        self.assertEqual([r["id"] for r in rows], [old])            # 끝난 옛 항목은 이월하지 않는다
        self.assertEqual(self.repo.visible_followups("monthly", "2026-11-01"), [])  # 유형이 다르면 섞이지 않는다
        self.assertEqual(len(self.repo.visible_followups("weekly", "2026-11-02")), 2)  # 만든 기간엔 전부 보인다

    def test_carry_count_and_flag_text_without_owner_ranking(self):
        self.assertEqual(carry_count("2026-11-02", "2026-11-23", "weekly"), 3)
        self.assertEqual(carry_count("monthly:2026-08-01", "monthly:2026-11-01", "monthly"), 3)
        row = {"id": "a", "text": "x", "owner": "김", "due": "", "status": "open", "closing_note": "",
               "period_key": "2026-11-02", "created_by": "eldi"}
        html_out = render_followups([row], frozen=None, kind="weekly", key="2026-11-23", week="2026-11-23", csrf="t",
                                    editable=False, finalized=False, today=date(2026, 11, 28))
        self.assertIn("3기간 연속 이월", html_out)

    def test_overdue_is_computed_not_stored(self):
        base = {"due": "2026-11-20", "status": "open"}
        self.assertTrue(is_overdue(base, date(2026, 11, 28)))
        self.assertFalse(is_overdue(dict(base, status="waiting"), date(2026, 11, 28)))
        self.assertFalse(is_overdue(dict(base, status="done"), date(2026, 11, 28)))

    def test_done_and_dropped_require_a_note(self):
        self.assertIn("완료 근거", validate_followup_change("done", " "))
        self.assertIn("미채택 사유", validate_followup_change("dropped", ""))
        self.assertIsNone(validate_followup_change("done", "게이트웨이 로그 확인"))
        self.assertIsNone(validate_followup_change("waiting", ""))
        self.assertIsNotNone(validate_followup_change("bogus", "x"))
        self.assertIsNotNone(validate_followup_new("", "", ""))
        self.assertIsNotNone(validate_followup_new("내용", "", "2026-13-40"))

    def test_finalized_view_shows_frozen_and_current_side_by_side(self):
        fid = self.repo.add_followup("weekly", "2026-11-23", "차단 적용 확인", "", "", "eldi")
        frozen = followup_freeze(self.repo.visible_followups("weekly", "2026-11-23"))
        self.repo.update_followup(fid, "done", "확인", "eldi")
        rows = self.repo.followups_by_ids([fid])
        out = render_followups(rows, frozen=frozen, kind="weekly", key="2026-11-23", week="2026-11-23", csrf="t",
                               editable=True, finalized=True, today=date(2026, 11, 28))
        self.assertIn("확정 당시", out)
        self.assertIn("열림", out)       # 확정 당시 상태
        self.assertIn("완료", out)       # 현재 상태
        self.assertIn("/reports/followups", out)   # 확정본에서도 상태 변경 폼은 산다
        self.assertNotIn('name="intent" value="add"', out)  # 새 항목 등록은 막힌다

    def test_old_finalized_report_without_ledger_says_not_stored(self):
        out = render_followups([], frozen=None, kind="weekly", key="2026-11-02", week="2026-11-02", csrf="",
                               editable=False, finalized=True, today=date(2026, 11, 28), legacy_text="옛 서술")
        self.assertIn("저장되어 있지 않습니다", out)
        self.assertIn("옛 서술", out)
        self.assertEqual(followup_summary(None, date(2026, 11, 28)), "후속 조치 장부 저장 안 됨")
        self.assertEqual(followup_summary([], date(2026, 11, 28)), "미결 후속 조치 0건")


if __name__ == "__main__":
    unittest.main()
