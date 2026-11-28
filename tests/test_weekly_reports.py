import sys
import unittest
from datetime import date, datetime, timedelta, timezone
import http.cookiejar
import re
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc.dashboard import AuthConfig, DbDashboardStore, _parse_utc, make_handler, parse_user_roles
from soc.reports import AGING_BUCKETS, ReportRepository, report_body, report_key, report_period, week_start, weekly_snapshot
from soc.storage import SQLiteSocStorage


class WeeklyReportTests(unittest.TestCase):
    def test_daily_chart_uses_kst_boundaries_and_keeps_exact_values(self):
        week = week_start("2026-11-23")
        incidents = [
            SimpleNamespace(incident_id=str(i), title=f"Case {i}", created_at_utc=stamp, alerts=[], approvals=[])
            for i, stamp in enumerate(("2026-11-22T14:59:59Z", "2026-11-22T15:00:00Z", "2026-11-29T15:00:00Z"))
        ]
        snapshot = weekly_snapshot(incidents, week, _parse_utc, "auto")
        self.assertEqual(snapshot["metrics"]["신규 사건"], 1)
        self.assertEqual([day["cases"] for day in snapshot["daily"]], [1, 0, 0, 0, 0, 0, 0])
        page = report_body(week, None, snapshot, [], "", False)
        self.assertIn("일별 수치 표 보기", page)
        self.assertIn('<th scope="row">2026-11-23</th><td>1</td>', page)

    def test_http_workflow_and_read_only_role(self):
        storage = SQLiteSocStorage()
        self.addCleanup(storage.close)
        auth = AuthConfig(username="ops", password="test", roles=parse_user_roles("", "ops"))
        handler = make_handler(DbDashboardStore(storage), auth_config=auth)
        with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            url = base + "/reports?week=2026-11-23"

            def login(username):
                client = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
                client.open(base + "/login", urlencode({"username": username, "password": "test"}).encode()).close()
                return client

            try:
                editor = login("approver1")
                with editor.open(url) as response:
                    page = response.read().decode()
                token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
                form = {"week": "2026-11-23", "csrf_token": token, "intent": "draft", "summary": "weekly summary"}
                with editor.open(url, urlencode(form).encode()) as response:
                    self.assertIn("초안을 저장했습니다.", response.read().decode())
                form["intent"] = "final"
                with editor.open(url, urlencode(form).encode()) as response:
                    self.assertIn("보고서를 확정했습니다.", response.read().decode())
                form.update(kind="monthly", summary="monthly summary")
                with editor.open(url, urlencode(form).encode()) as response:
                    monthly = response.read().decode()
                self.assertIn("월간 관제 보고서", monthly)
                self.assertIn("monthly summary", monthly)
                self.assertIn("인쇄 / PDF 저장", monthly)
                with editor.open(url) as response:
                    self.assertIn("weekly summary", response.read().decode())
                repo = ReportRepository(storage)
                month = report_period("2026-11-23", "monthly")
                self.assertEqual(len(repo.get(report_key(month, "monthly"))["snapshot"]["daily"]), 30)
                viewer = login("analyst1")
                with viewer.open(url) as response:
                    self.assertIn("weekly summary", response.read().decode())
                with self.assertRaises(HTTPError) as error:
                    viewer.open(url, urlencode(form).encode())
                self.assertEqual(error.exception.code, 403)
                error.exception.close()
            finally:
                server.shutdown()
                thread.join()

    def test_final_report_cannot_be_replaced_and_escapes_notes(self):
        storage = SQLiteSocStorage()
        self.addCleanup(storage.close)
        repo = ReportRepository(storage)
        week = week_start("2026-11-26")
        self.assertEqual(str(week), "2026-11-23")
        snapshot = weekly_snapshot([], week, _parse_utc, "auto")
        self.assertEqual(snapshot["metrics"]["신규 사건"], 0)
        self.assertTrue(repo.save(week, "operator", False, {"notes": {"summary": "draft"}, "snapshot": snapshot}))
        self.assertTrue(repo.save(week, "operator", True, {"notes": {"summary": "<script>"}, "snapshot": snapshot}))
        self.assertFalse(repo.save(week, "other", False, {"notes": {"summary": "replacement"}}))
        final = ReportRepository(storage).get(week)
        self.assertTrue(final["finalized"])
        self.assertEqual(final["snapshot"], snapshot)
        page = report_body(week, final, snapshot, repo.list(), "", True)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn('name="intent"', page)


KST = timezone(timedelta(hours=9))
# 월간 기간 2026-11 / 기준 시각 12-02 00:00 KST. 11월 안에서 모든 경계를 만들 수 있다.
AGING_NOW = datetime(2026, 12, 2, tzinfo=KST)


def aging_incident(name, age, *, eligible=False, status="open", **extra):
    created = (AGING_NOW - age).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return SimpleNamespace(incident_id=name, title=f"Case {name}", created_at_utc=created, alerts=[], approvals=[],
                           block_rule_eligible=eligible, status=status, **extra)


def aging_snapshot(incidents):
    return weekly_snapshot(incidents, date(2026, 11, 1), _parse_utc, "auto", kind="monthly", now=AGING_NOW)


def aging_page(snapshot):
    return report_body(date(2026, 11, 1), None, snapshot, [], "", False, kind="monthly")


class AgingAndRawEvidenceTests(unittest.TestCase):
    def test_bucket_boundaries_split_action_and_review(self):
        near = timedelta(seconds=-1)  # 경계 직전은 한 단계 아래 버킷이다.
        incidents = [
            aging_incident("a1", timedelta(days=2) + near, eligible=True),       # 1일 23:59:59 -> 0~1일
            aging_incident("a2", timedelta(days=2)),                             # 2일 -> 2~3일
            aging_incident("a3", timedelta(days=4) + near, eligible=True),       # 3일 23:59:59 -> 2~3일
            aging_incident("a4", timedelta(days=4)),                             # 4일 -> 4~7일
            aging_incident("a5", timedelta(days=8) + near),                      # 7일 23:59:59 -> 4~7일
            aging_incident("a6", timedelta(days=8), eligible=True),              # 8일 -> 8일 이상
            aging_incident("a7", timedelta(days=9)),                             # 8일 이상, 판단 대기
            aging_incident("done", timedelta(days=9), status="closed"),          # 닫힌 사건은 세지 않는다
        ]
        snapshot = aging_snapshot(incidents)
        self.assertEqual([(row["action"], row["review"]) for row in snapshot["open"]["aging"]],
                         [(1, 0), (1, 1), (0, 2), (1, 1)])
        self.assertEqual(len(AGING_BUCKETS), len(snapshot["open"]["aging"]))
        open_counts = snapshot["open"]
        self.assertEqual(sum(row["action"] + row["review"] for row in open_counts["aging"]),
                         open_counts["action"] + open_counts["review"])
        self.assertEqual(open_counts["oldest_days"], 9)

    def test_chart_keeps_zero_rows_and_states_counts_in_text(self):
        snapshot = aging_snapshot([aging_incident("x", timedelta(days=9)), aging_incident("y", timedelta(days=9)),
                                   aging_incident("z", timedelta(days=9))])
        page = aging_page(snapshot)
        self.assertIn('id="rp-aging"', page)
        self.assertLess(page.index('id="rp-now"'), page.index('id="rp-aging"'))
        self.assertLess(page.index('id="rp-aging"'), page.index('id="rp-detect"'))
        self.assertEqual(page.count('class="rp-age-row"'), 4)       # 0건 행도 그대로 남는다
        rows = re.findall(r'<a class="rp-age-row" href="/incidents"([^>]*)>', page)
        self.assertEqual([" data-zero" in attrs for attrs in rows], [True, True, True, False])
        self.assertEqual([" data-old" in attrs for attrs in rows], [False, False, False, True])
        self.assertIn("경과일별 미결 사건 — 8일 넘은 조사용 사건 3건이 가장 오래 남아 있습니다", page)
        self.assertIn("<b>3건</b><small>조치 0 · 판단 3</small>", page)
        self.assertIn("<b>0건</b><small>조치 0 · 판단 0</small>", page)
        self.assertIn('<a href="#rp-aging">', page)
        # 일별 추이 차트의 스크립트는 첫 .rp-chart 만 잡는다. 새 차트가 그 클래스를 가져가면 안 된다.
        self.assertEqual(page.count('class="rp-chart"'), 1)

    def test_no_open_incident_says_checked_and_none(self):
        page = aging_page(aging_snapshot([aging_incident("done", timedelta(days=3), status="closed")]))
        self.assertIn("미결은 0건입니다", page)
        self.assertNotIn('class="rp-age-list"', page)
        self.assertNotIn("경과일별 미결 사건 —", page)

    def test_old_finalized_snapshot_without_new_keys_still_renders(self):
        old = {"metrics": {"신규 사건": 1}, "open": {"action": 1, "review": 0, "oldest_days": 2},
               "cases": [{"id": "INC-1", "title": "옛 사건", "new": True, "locks": 0, "ip": ["applied"]}], "daily": []}
        page = aging_page(old)
        self.assertIn("경과일별 미결 집계가 저장되어 있지 않아", page)
        self.assertNotIn('class="rp-age-list"', page)
        self.assertIn("저장 안 됨", page)                      # 심각도 등은 없다고 적는다
        self.assertIn("승인 ID와 승인 시각이 저장되어 있지 않습니다", page)
        self.assertIn("적용", page)
        bare = report_body(date(2026, 11, 1), None, {"metrics": {}}, [], "", False, kind="monthly")
        self.assertIn('id="rp-raw"', bare)

    def test_raw_evidence_lists_cases_and_approvals_in_kst(self):
        approval = SimpleNamespace(approval_id="APR-7", target_ip="203.0.113.9", action_type="block",
                                   approved_at_utc="2026-11-30T00:00:01Z", status="applied")
        incident = aging_incident("INC-9", timedelta(days=5), severity="high", target_ip="203.0.113.9",
                                  username="kim<script>")
        incident.approvals = [approval]
        page = aging_page(aging_snapshot([incident]))
        self.assertIn('id="rp-raw"', page)
        self.assertIn("<details><summary>감사용 전체 근거 열기 — 사건 1건 · 차단 승인 1건</summary>", page)
        self.assertLess(page.index('id="rp-evidence"'), page.index('id="rp-raw"'))
        self.assertLess(page.index('id="rp-raw"'), page.index('id="rp-writing"'))
        self.assertIn('<a href="/incidents/INC-9">INC-9</a>', page)
        self.assertIn("<td>APR-7</td>", page)
        self.assertIn("2026-11-30 09:00:01", page)             # UTC 00:00:01 -> KST 09:00:01
        self.assertIn("kim&lt;script&gt;", page)
        self.assertNotIn("kim<script>", page)
        self.assertIn("적용", page)

    def test_print_rules_unfold_details_and_order_new_sections(self):
        from soc.reports import REPORT_STYLE
        self.assertIn("details:not([open])::details-content", REPORT_STYLE)   # 최신 크로미움용
        self.assertIn("#rp-aging {order:4}", REPORT_STYLE)
        self.assertIn("#rp-raw {order:9}", REPORT_STYLE)
