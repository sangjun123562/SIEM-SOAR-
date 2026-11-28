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
                self.assertIn("인쇄 / PDF</button>", monthly)
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

    def test_saved_draft_can_be_printed_downloaded_and_mailed(self):
        storage = SQLiteSocStorage()
        self.addCleanup(storage.close)
        auth = AuthConfig(username="ops", password="test", roles=parse_user_roles("", "ops"))
        handler = make_handler(DbDashboardStore(storage), auth_config=auth)
        with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            url = base + "/reports?week=2026-11-23"
            client = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
            client.open(base + "/login", urlencode({"username": "approver1", "password": "test"}).encode()).close()
            try:
                with client.open(url) as response:
                    page = response.read().decode()
                self.assertIn("초안을 저장하면 인쇄·내려받기·메일 보내기가 열립니다", page)   # 저장 전에는 안내만
                with self.assertRaises(HTTPError) as missing:
                    client.open(url + "&export=1")
                self.assertEqual(missing.exception.code, 404)
                missing.exception.close()
                token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
                form = {"week": "2026-11-23", "csrf_token": token, "intent": "draft", "summary": "초안 핵심 판단"}
                with client.open(url, urlencode(form).encode()) as response:
                    saved = response.read().decode()
                self.assertIn("인쇄 / PDF</button>", saved)                  # 초안도 바로 출력할 수 있다
                self.assertIn("파일 저장</a>", saved)
                self.assertIn("mailto:?subject=", saved)
                self.assertIn("초안 — 확정 전 보고서입니다", saved)
                with client.open(url + "&export=1") as response:
                    disposition = response.headers["Content-Disposition"]
                    exported = response.read().decode()
                self.assertIn("sentinel-report-weekly-2026-11-23-draft.html", disposition)
                self.assertTrue(exported.startswith("<!doctype html>"))
                self.assertIn("초안 핵심 판단", exported)
                self.assertIn("초안 — 확정 전 보고서입니다", exported)
                self.assertNotIn("<details>", exported)                  # 접힌 부분도 파일에서는 모두 펼쳐 둔다
                self.assertNotIn('name="csrf_token"', exported)          # 내려받은 파일에는 입력 폼도 토큰도 없다
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

    def test_queue_states_counts_oldest_first_and_zero_buckets_in_text(self):
        snapshot = aging_snapshot([aging_incident("x", timedelta(days=9)), aging_incident("y", timedelta(days=9)),
                                   aging_incident("z", timedelta(days=2) - timedelta(seconds=1), eligible=True)])
        page = aging_page(snapshot)
        self.assertIn('id="rp-aging"', page)
        self.assertLess(page.index('id="rp-now"'), page.index('id="rp-aging"'))
        self.assertLess(page.index('id="rp-aging"'), page.index('id="rp-detect"'))
        self.assertEqual(page.count('class="rp-q"'), 2)             # 조치 대기 / 판단 대기 두 칸
        self.assertIn("8일 넘은 조사용 사건 2건이 가장 오래 남아 있습니다", page)
        self.assertIn("4일 넘은 건 <b>2건</b>", page)               # 판단 대기: 오래된 건수를 글자로
        self.assertIn("4일 넘은 건 없음", page)                     # 조치 대기: 0도 글자로 말한다
        self.assertIn("8일 이상 <b>2</b>", page)
        self.assertIn("0~1일 <b>0</b>", page)                        # 0건 구간도 범례에 남는다
        self.assertIn('<b>9일</b>', page)                            # 오래된 순 목록에 경과일
        self.assertIn('<a href="#rp-aging">', page)
        # 일별 추이 차트의 스크립트는 첫 .rp-chart 만 잡는다. 새 차트가 그 클래스를 가져가면 안 된다.
        self.assertEqual(page.count('class="rp-chart"'), 1)

    def test_summary_layer_comes_before_appendix(self):
        page = report_body(date(2026, 11, 23), None, aging_snapshot([]), [], "tok", True)
        order = [page.index(f'id="{name}"') for name in ("rp-now", "rp-writing", "rp-todo", "rp-followups")]
        self.assertEqual(order, sorted(order))
        appendix = page.index('class="rp-appx-head"')
        self.assertLess(order[-1], appendix)                       # 1층 네 칸이 모두 부록 머리말보다 앞
        for name in ("rp-aging", "rp-evidence", "rp-detect", "rp-extra", "rp-ingest", "rp-facts", "rp-raw", "rp-footnotes"):
            self.assertGreater(page.index(f'id="{name}"'), appendix)
        self.assertIn('data-scope="summary"', page)                # 출력은 요약이 기본
        self.assertIn('form="report-form"', page)                  # 헤더의 초안 저장은 아래 입력 폼을 제출한다
        saved = {"author": "eldi", "saved_at": "2026-11-28T10:00:00+09:00", "finalized": False, "notes": {}}
        page = report_body(date(2026, 11, 23), saved, aging_snapshot([]), [], "tok", True)
        self.assertIn('value="full"', page)                        # 저장한 뒤에는 전체(부록 포함)도 고를 수 있다

    def test_todo_lists_actionable_items_and_says_when_none(self):
        empty = aging_page(aging_snapshot([]))
        self.assertIn("지금 이 보고서에서 바로 처리할 항목이 없습니다", empty)
        page = aging_page(aging_snapshot([aging_incident("a", timedelta(days=2) - timedelta(seconds=1), eligible=True)]))
        self.assertIn("차단 승인 대기", page)
        self.assertIn("차단 승인 대기 <b>1건</b>", page)

    def test_non_live_only_incidents_are_excluded_but_counted(self):
        replay = aging_incident("old", timedelta(days=3))
        replay.alerts = [SimpleNamespace(ingest_modes=("replay",), window_end_utc="2026-11-24T00:00:00Z", rule_id="r", alert_id="a1")]
        live = aging_incident("now", timedelta(days=3))
        live.alerts = [SimpleNamespace(ingest_modes=("live",), window_end_utc="2026-11-24T00:00:00Z", rule_id="r", alert_id="a2")]
        snapshot = aging_snapshot([replay, live])
        self.assertEqual(snapshot["excluded"], {"incidents": 1})
        self.assertEqual([c["id"] for c in snapshot["cases"]], ["now"])
        self.assertIn("재생·합성 근거 사건 <b>1건</b> 제외", aging_page(snapshot))

    def test_draft_save_is_not_blocked_by_browser_validation(self):
        # 핵심 판단이 비어도 초안은 저장할 수 있어야 한다. required 가 있으면 브라우저가 '초안 저장'까지 막는다.
        page = report_body(date(2026, 11, 23), None, aging_snapshot([]), [], "tok", True)
        summary = page[page.index('id="report-summary"'):]
        summary = summary[:summary.index("</textarea>")]
        self.assertNotIn(" required", summary)
        self.assertIn('aria-required="true"', summary)
        self.assertIn('name="intent" value="draft"', page)

    def test_action_cell_oldest_is_not_polluted_by_review_cases(self):
        # 조치 대기 칸에 조사용 사건의 경과일(합산 최댓값)이 붙던 오류의 회귀 방지
        page = aging_page(aging_snapshot([
            aging_incident("old-review", timedelta(days=9)),
            aging_incident("new-action", timedelta(days=2) - timedelta(seconds=1), eligible=True)]))
        self.assertIn("IP 차단 승인 경로가 있는 사건 · 가장 오래된 건 1일 경과", page)
        self.assertIn("종결 경로가 없는 사건 · 가장 오래된 건 9일 경과", page)

    def test_snapshot_keeps_oldest_open_cases_per_group(self):
        incidents = [aging_incident(f"r{i}", timedelta(days=i + 1)) for i in range(14)]
        snapshot = aging_snapshot(incidents)
        review = snapshot["open_cases"]["review"]
        self.assertEqual(len(review), 10)                           # 저장은 10건까지
        self.assertEqual(review[0]["id"], "r13")                    # 가장 오래된 것이 먼저
        self.assertGreaterEqual(review[0]["age_hours"], review[-1]["age_hours"])
        self.assertEqual(snapshot["open_cases"]["action"], [])
        self.assertIn("우선순위 순 5건만 표시", aging_page(snapshot))

    def test_no_open_incident_says_checked_and_none(self):
        page = aging_page(aging_snapshot([aging_incident("done", timedelta(days=3), status="closed")]))
        self.assertIn("미결은 0건입니다", page)
        self.assertNotIn('class="rp-q"', page)

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
        self.assertLess(page.index('id="rp-writing"'), page.index('id="rp-raw"'))     # 판단은 1층, 감사용 근거는 부록
        self.assertIn('<a href="/incidents/INC-9">INC-9</a>', page)
        self.assertIn("<td>APR-7</td>", page)
        self.assertIn("2026-11-30 09:00:01", page)             # UTC 00:00:01 -> KST 09:00:01
        self.assertIn("kim&lt;script&gt;", page)
        self.assertNotIn("kim<script>", page)
        self.assertIn("적용", page)

    def test_print_rules_unfold_details_and_order_new_sections(self):
        from soc.reports import REPORT_STYLE
        self.assertIn("details:not([open])::details-content", REPORT_STYLE)   # 최신 크로미움용
        self.assertIn("#rp-aging {order:6}", REPORT_STYLE)
        self.assertIn("#rp-raw {order:12}", REPORT_STYLE)
