import sys
import unittest
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
from soc.reports import ReportRepository, report_body, report_key, report_period, week_start, weekly_snapshot
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
