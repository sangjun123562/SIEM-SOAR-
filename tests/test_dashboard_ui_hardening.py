"""대시보드 점검 반영 시험: 보안 헤더, 정상 브라우저 요청 제외, 조사용 사건 라벨, 외부 자원 없음."""
from __future__ import annotations

import http.cookiejar
import html
import json
import re
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.dashboard import (  # noqa: E402
    AuthConfig, DashboardStore, _approval_row, _bk_area_chart, _block_effects, _fmt_status, _fmt_user_badge, _incident_queue_content, _page_shell,
    _ip_block_minutes, _is_suspect_event, _login_failure_panel, _render_incidents_control_panels, make_handler, parse_user_roles,
    render_incident_detail, render_incident_list, render_permissions_page, render_recent_events, render_source_logs,
)
from soc.incident_service import ApprovalRecord, build_incidents, release_approval  # noqa: E402
from soc.normalizer import normalize_log_line  # noqa: E402


def _login_incident():
    events = []
    for i in range(5):
        raw = json.dumps({
            "timestamp_utc": f"2026-11-22T03:00:0{i}Z", "source": "erp", "event_type": "login_failed",
            "outcome": "failure", "username": "alice", "client_ip": "172.28.10.11", "peer_ip": "172.28.20.5",
            "client_ip_trusted": True, "request_id": f"r{i}", "http_method": "POST", "http_path": "/api/login",
            "status_code": 401, "ingest_mode": "live",
        })
        events.append(normalize_log_line(raw, source="erp", file_path="e.jsonl", line_offset=i * 100,
                                         collection_mode="live")[1])
    return build_incidents([], events)[0]


class BlockEffectTests(unittest.TestCase):
    def test_ip_block_duration_in_selected_units(self):
        for value, unit, expected in [
            ("1", "minutes", 1), ("43200", "minutes", 43200),
            ("2", "hours", 120), ("720", "hours", 43200),
        ]:
            with self.subTest(value=value, unit=unit):
                self.assertEqual(_ip_block_minutes({"block_unit": [unit], "block_duration": [value]}), expected)
        self.assertEqual(_ip_block_minutes({"duration_minutes": ["90"]}), 90)
        for value, unit in [("721", "hours"), ("43201", "minutes"), ("0", "minutes"),
                            ("1.5", "hours"), ("", "hours"), ("1", "days")]:
            with self.subTest(value=value, unit=unit), self.assertRaises(ValueError):
                _ip_block_minutes({"block_unit": [unit], "block_duration": [value]})

    def test_effect_counts_all_pages_for_the_rule_and_excludes_rejected(self):
        approval = SimpleNamespace(
            approval_id="APR-test", action_type="block", status="applied",
            target_ip="172.28.10.11", approved_at_utc="2025-01-01T00:00:00Z",
            expires_at_utc="2025-01-01T00:10:00Z", gateway_response={}, approved_by="operator",
        )

        class Store:
            def list_recent_events(self, *, offset, limit, source, event_types, since_utc, until_utc):
                assert since_utc < until_utc
                if source == "erp":
                    return []
                assert event_types == ("fw_deny",)
                return [
                    {"event_type": "fw_deny", "rule_id": "APR-test", "src_port": i}
                    for i in range(offset, min(501, offset + limit))
                ]

        effect = _block_effects(Store(), [approval])["APR-test"]
        self.assertEqual(effect["attempts"], 501)
        approval.status = "rejected"
        self.assertEqual(_block_effects(Store(), [approval]), {})
        row = _approval_row(approval, effect=effect)
        self.assertIn("차단 미적용", row)
        self.assertNotIn("차단 중 막은 접속 시도", row)


class LoginFailureChartTests(unittest.TestCase):
    def test_waf_log_shows_attack_type_above_crs_rule_ids(self):
        class WafStore(DashboardStore):
            def list_recent_events(self, *args, **kwargs):
                return [{
                    "event_type": "waf_blocked", "event_ts_utc": "2026-11-26T03:00:00Z",
                    "client_ip": "172.28.10.11", "rule_id": "941110, 941160, 942100",
                    "request_id": "11111111-1111-1111-1111-111111111111", "raw_id": "raw-waf-1",
                }]

        page = render_source_logs(WafStore(), "waf").decode("utf-8")
        self.assertIn("<th>공격 유형</th>", page)
        self.assertIn('<span class="waf-type">SQL 인젝션 · XSS 의심</span>', page)
        self.assertIn('OWASP CRS 규칙 941110, 941160, 942100', page)
        self.assertLess(page.index('SQL 인젝션 · XSS 의심'), page.index('OWASP CRS 규칙 941110'))

    def test_all_log_source_tabs_share_the_same_row_height_rule(self):
        store = DashboardStore(incidents=[])
        shell = _page_shell("t", "", current_user=None, auth_enabled=False, active_path="/", csrf_token="")
        shell = shell.decode("utf-8") if isinstance(shell, bytes) else shell
        # 기준(방화벽 탭의 자연 높이)은 전역 변수 하나이고, 네 탭이 같은 표 클래스로 그 값을 쓴다.
        self.assertIn("--log-row-h: 54px", shell)
        self.assertIn(".log-source-tbl tbody tr { height: var(--log-row-h); }", shell)
        for kind in ("erp", "gateway", "caddy", "waf"):
            page = render_source_logs(store, kind).decode("utf-8")
            self.assertIn('<table class="log-tbl log-source-tbl">', page, kind)
        # ERP의 추적 ID 칩 두 개는 위아래 그대로 두고 높이만 줄인다(옆으로 옮기지 않는다).
        self.assertIn(".log-source-tbl .idstack button.id-copy-chip { padding-block: 0; line-height: 18px; }", shell)
        self.assertIn("flex-direction: column", shell[shell.index(".idstack {"):shell.index(".idstack {") + 120])

    def test_icmp_denial_table_rows_follow_the_log_row_height_without_dropping_lines(self):
        shell = _page_shell("t", "", current_user=None, auth_enabled=False, active_path="/", csrf_token="")
        shell = shell.decode("utf-8") if isinstance(shell, bytes) else shell
        # 아래 로그 표와 같은 전역 줄 높이 변수를 쓰고, 세 줄(이름·설명·규칙 코드)은 줄 간격만 줄인다.
        self.assertIn(".icmp-trace tbody tr { height: var(--log-row-h); }", shell)
        self.assertRegex(shell, r"\.icmp-trace td \{ padding-top: 4px; padding-bottom: 4px; line-height: 15px; \}")
        self.assertIn(".icmp-trace .ev-act { display: flex;", shell)
        self.assertIn(".icmp-trace .cell-sub { margin: 0;", shell)
        self.assertIn(".icmp-trace .waf-rule-id { margin: 0;", shell)
        # 표의 열과 칸 내용은 그대로다(시각 · 출발지→목적지 · 거부 규칙 · 원본 raw_id).
        from soc.dashboard import _icmp_denial_panel

        class Store(DashboardStore):
            def get_icmp_denial_hours(self, since_utc, until_utc):
                return []

            def get_recent_icmp_denials(self, limit=10):
                return [{"event_ts_utc": "2026-11-26T08:09:02Z", "src_ip": "172.28.10.11", "dst_ip": "172.28.20.5",
                         "rule_id": "POLICY-CLIENT-CADDY-ONLY", "raw_id": "28d18c95aaaa", "file_path": "gateway.jsonl", "line_offset": 182405}]

        panel = _icmp_denial_panel(Store(incidents=[]))
        for text in ("<th>시각</th>", "<th>출발지 → 목적지</th>", "<th>거부 규칙</th>", "<th>원본 raw_id</th>",
                     "172.28.10.11", "172.28.20.5", "POLICY-CLIENT-CADDY-ONLY", "gateway.jsonl · 위치 182405"):
            self.assertIn(text, panel)

    def test_priority_incident_row_opens_detail_from_any_cell(self):
        incident = _login_incident()
        page = _incident_queue_content([incident], overview=True)
        self.assertIn(f"data-incident-href='/incidents/{incident.incident_id}'", page)
        self.assertIn("data-overview-incident", page)

    def test_released_incident_gets_green_bar_but_keeps_its_severity(self):
        incident = _login_incident()
        released = replace(incident, incident_id="INC-RELEASED", status="released")
        still_open = replace(incident, incident_id="INC-OPEN", status="open")
        page = _incident_queue_content([released, still_open])
        row = {inc.incident_id: next(r for r in page.split("<tr ") if f"/incidents/{inc.incident_id}'" in r)
               for inc in (released, still_open)}
        self.assertIn("sev-resolved", row["INC-RELEASED"].split(">", 1)[0])
        self.assertIn("차단 해제됨", row["INC-RELEASED"])
        # 심각도 글자는 그대로이고, 아직 열린 사건은 기존 심각도 색을 유지한다.
        self.assertIn("class='sev sev-high'", row["INC-RELEASED"])
        self.assertNotIn("sev-resolved", row["INC-OPEN"].split(">", 1)[0])
        shell = _page_shell("t", "", current_user=None, auth_enabled=False, active_path="/incidents", csrf_token="")
        shell = shell.decode("utf-8") if isinstance(shell, bytes) else shell
        self.assertIn("tr.sev-row.sev-resolved { --sev-c: var(--ok); }", shell)

    def test_incident_filter_controls_share_the_button_height(self):
        shell = _page_shell("t", "", current_user=None, auth_enabled=False, active_path="/incidents", csrf_token="")
        shell = shell.decode("utf-8") if isinstance(shell, bytes) else shell
        # 선택 상자와 적용·초기화 버튼(.btn-ghost, 34px)의 높이가 같아야 한 줄이 들쭉날쭉해 보이지 않는다.
        self.assertRegex(shell, r"\.incident-filters select \{[^}]*height:34px")
        self.assertRegex(shell, r"\.btn-ghost \{[^}]*min-height: 34px")
        self.assertRegex(shell, r"\.incident-filters label \{[^}]*margin-right:12px")

    def test_overview_incident_cards_have_fixed_list_limits(self):
        incident = _login_incident()
        pending = [replace(incident, incident_id=f"INC-P{i}", status="open") for i in range(4)]
        recent = [replace(incident, incident_id=f"INC-R{i}", status="closed") for i in range(6)]
        page = _incident_queue_content(pending + recent, overview=True)
        self.assertIn("미처리 4건 · 3건 표시", page)
        self.assertEqual(page.count("data-overview-incident"), 3)
        self.assertEqual(page.count("class='pq-item'"), 5)

    def test_event_chart_separates_waf_from_caddy_without_double_count(self):
        now = datetime(2026, 11, 26, 3, 30, tzinfo=timezone.utc)

        class TrendStore(DashboardStore):
            def get_trend_events(self, since_utc):
                stamp = now - timedelta(minutes=5)
                return [(stamp, "caddy", "waf_blocked", "blocked", 403, "/api/login"),
                        (stamp, "caddy", "http_request", "success", 200, "/")]

        chart, subtitle = _bk_area_chart(TrendStore(), "hourly", now_utc=now)
        payload = json.loads(html.unescape(re.search(r'data-chart="([^"]+)"', chart).group(1)))
        self.assertEqual(sum(row["waf"] for row in payload["rows"]), 1)
        self.assertEqual(sum(row["caddy"] for row in payload["rows"]), 1)
        self.assertIn("2건", subtitle)
        self.assertIn("WAF", [series["label"] for series in payload["series"]])

    def test_waf_detection_appears_in_suspect_trend(self):
        now = datetime(2026, 11, 26, 3, 30, tzinfo=timezone.utc)

        class TrendStore(DashboardStore):
            def get_trend_events(self, since_utc):
                return [(now - timedelta(minutes=5), "caddy", "waf_detected", "detected", 200, "/")]

        chart, _ = _bk_area_chart(TrendStore(), "suspect", now_utc=now)
        payload = json.loads(html.unescape(re.search(r'data-chart="([^"]+)"', chart).group(1)))
        self.assertEqual(sum(row["waf"] for row in payload["rows"]), 1)

    def test_overview_includes_waf_collection_card_and_consistent_status_markers(self):
        page = render_incident_list(DashboardStore()).decode("utf-8")
        self.assertIn('class="hitem wait" href="/logs/waf"', page)
        self.assertIn("판정 기록 없음", page)
        self.assertIn(".b-closed::before", page)
        self.assertIn(".pq-dot.is-released", page)

    def test_event_popup_states_recent_limit_and_full_list_link(self):
        page = render_incident_list(DashboardStore()).decode("utf-8")
        self.assertIn("전체 수집 이벤트 <b>0건</b> 중 최신 <b>0건</b>", page)
        self.assertIn('<a class="btn-ghost" href="/events">전체 이벤트 보기', page)
        self.assertIn(".ev-act.good::before { background: var(--ok); }", page)
        self.assertIn(".b-ok::before, .b-released::before { background: var(--ok) !important; }", page)

    def test_login_trend_shares_row_with_existing_ranking(self):
        page = render_incident_list(DashboardStore()).decode("utf-8")
        login_grid = page.index('class="overview-login-grid"')
        chart = page.index('id="login-failures"', login_grid)
        ranking = page.index('id="login-failure-ranking"', chart)
        active = page.index('id="active-blocks-overview"', ranking)
        self.assertLess(login_grid, chart)
        self.assertLess(chart, ranking)
        self.assertLess(ranking, active)
        self.assertEqual(page.count('id="login-failure-ranking"'), 1)
        self.assertIn('viewBox="0 0 560 150"', page)
        self.assertIn(".overview-login-grid { grid-template-columns: 1fr; }", page)

    def test_overview_counts_waf_events_from_caddy(self):
        now = datetime.now(timezone.utc).isoformat()

        class WafStore(DashboardStore):
            def list_recent_events(self, limit=50, *, source=None, event_types=None, **kwargs):
                if source == "caddy" and event_types == ("waf_detected", "waf_blocked"):
                    return [{"event_ts_utc": now, "received_at_utc": now, "event_type": "waf_blocked"}]
                return []

            def count_recent_events(self, *, source=None, event_types=None, **kwargs):
                return 1 if source == "caddy" and event_types == ("waf_detected", "waf_blocked") else 0

        page = render_incident_list(WafStore()).decode("utf-8")
        self.assertIn('class="hitem ok" href="/logs/waf"', page)
        self.assertIn("판정 기록 있음", page)
        self.assertIn("1건 · 마지막 수신", page)

    def test_incident_explains_attack_and_links_to_evidence(self):
        page = render_incident_detail(_login_incident()).decode("utf-8")
        self.assertIn("의심 공격: 비밀번호 추측 (T1110.001)", page)
        self.assertIn("로그인 실패 5회가 기록되어 탐지했습니다", page)
        self.assertIn('href="#incident-evidence"', page)
        self.assertIn('id="incident-evidence"', page)
        self.assertIn('href="#incident-raw-logs"', page)
        self.assertIn('id="incident-raw-logs"', page)

    def test_ip_panel_explains_remaining_approval(self):
        incident = _login_incident()
        incident.status = "blocked"
        incident.approvals = [
            ApprovalRecord(
                approval_id=f"APR-20261122030000-{suffix}",
                incident_id=incident.incident_id,
                target_ip=incident.target_ip,
                action_type="block",
                approved_by="ops",
                approved_at_utc="2026-11-22T03:00:00Z",
                expires_at_utc="2026-11-22T03:10:00Z",
                status="applied",
            )
            for suffix in ("abc123", "def456")
        ]
        page = _render_incidents_control_panels([incident])
        self.assertIn("활성 승인 2건(현재 승인만 해제)", page)

        class Gateway:
            def release(self, approval_id):
                return {"approval_id": approval_id, "status": "released", "released_at_utc": "2026-11-22T03:01:00Z"}

        release_approval(incident, approval_id=incident.approvals[1].approval_id, action_client=Gateway())
        self.assertEqual(incident.status, "blocked")
        page = _render_incidents_control_panels([incident])
        self.assertIn("활성 승인 1건", page)

    def test_chart_shows_incident_window_count_across_hour_boundary(self):
        incident = _login_incident()
        boundaries = [
            datetime(2026, 11, 22, hour, tzinfo=timezone.utc)
            for hour in (2, 3, 4)
        ]
        events = [
            (datetime(2026, 11, 22, 2, 59, second, tzinfo=timezone.utc), "login_failed", "172.28.10.11", "alice")
            for second in (58, 59)
        ] + [
            (datetime(2026, 11, 22, 3, 0, second, tzinfo=timezone.utc), "login_failed", "172.28.10.11", "alice")
            for second in (0, 1, 2)
        ]
        page = _login_failure_panel(DashboardStore(), "hourly", events, boundaries=boundaries, incidents=[incident])
        self.assertIn('data-fail="2"', page)
        self.assertIn('data-fail="3"', page)
        self.assertIn('<b>5회</b>', page)


def _x_denial_incident(username, second):
    raw = json.dumps({
        "timestamp_utc": f"2026-11-25T03:00:{second:02d}Z", "source": "erp", "event_type": "login_source_denied",
        "outcome": "failure", "username": username, "client_ip": "172.28.10.13",
        "peer_ip": "172.28.20.5", "client_ip_trusted": True,
        "request_id": str(uuid.UUID(int=second + 1)),
        "http_method": "POST", "http_path": "/api/login", "status_code": 403, "ingest_mode": "live",
        "reason": "source_not_allowed", "access_requested": True,
    })
    event = normalize_log_line(raw, source="erp", file_path="e.jsonl", line_offset=second * 100, collection_mode="live")[1]
    return build_incidents([], [event])[0]


class SuspectRuleTests(unittest.TestCase):
    def test_browser_housekeeping_requests_are_not_anomalies(self):
        self.assertFalse(_is_suspect_event("caddy", "http_request", "failure", 404, "/favicon.ico"))
        self.assertFalse(_is_suspect_event("caddy", "http_request", "failure", 401, "/api/session"))
        self.assertFalse(_is_suspect_event("caddy", "http_request", "failure", 404, "/favicon.ico?v=2"))

    def test_real_errors_stay_anomalies(self):
        self.assertTrue(_is_suspect_event("caddy", "http_request", "failure", 404, "/admin"))
        self.assertTrue(_is_suspect_event("caddy", "http_request", "failure", 401, "/api/login"))
        self.assertTrue(_is_suspect_event("caddy", "http_request", "failure", 500, "/favicon.ico"))
        self.assertTrue(_is_suspect_event("caddy", "http_request", "failure", 404))  # 경로를 모르면 기존대로 센다
        self.assertTrue(_is_suspect_event("erp", "login_failed", "failure", 401))
        self.assertTrue(_is_suspect_event("gateway", "fw_deny", "deny", None))


class StatusLabelTests(unittest.TestCase):
    def test_investigation_only_incident_is_not_asked_for_approval(self):
        self.assertIn("확인 필요", _fmt_status("open", False))
        self.assertNotIn("승인", _fmt_status("open", False))

    def test_blockable_or_unknown_incident_keeps_approval_label(self):
        self.assertIn("확인·승인 필요", _fmt_status("open", True))
        self.assertIn("확인·승인 필요", _fmt_status("open"))
        self.assertIn("차단 해제됨", _fmt_status("released", False))


class PermissionStatusOverHttpTests(unittest.TestCase):
    """권한 현황의 보기·상세가 주소로 전달되고, 권한 회수 뒤에도 보던 화면으로 돌아오는지 실제 요청으로 확인한다."""

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    def setUp(self):
        from unittest.mock import Mock
        self.client = Mock()
        self.client.fetch_permissions.return_value = {
            "status": "ok",
            "users": [{"username": "alice", "department": "영업", "role": "member", "account_status": "active"}],
            "documents": [{"id": "d-sec", "title": "인사 평가 기준", "department": "인사", "level": "secret"}],
            "grants": [{
                "id": 1, "username": "alice", "department": "영업", "role": "member", "document_id": "d-sec", "document_title": "인사 평가 기준",
                "doc_department": "인사", "doc_level": "secret", "granted_by": "soc-operator", "reason": "타 부서 업무 협조 지원",
                "expires_at": "2099-01-01T00:00:00+00:00", "status": "active",
            }],
        }
        self.auth = AuthConfig(username="ops", password="pw", secret="sec", roles=parse_user_roles("", "ops"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            DashboardStore(incidents=[]), auth_config=self.auth, login_access_client=self.client))
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.op.open(urllib.request.Request(
            self.base + "/login", method="POST", data=urllib.parse.urlencode({"username": "admin1", "password": "pw"}).encode())).close()
        self.csrf = self.auth.sign_csrf(next(iter(self.jar)).value)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _post_revoke(self, **extra):
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), self._NoRedirect)
        data = {"action": "revoke_doc", "username": "alice", "document_id": "d-sec", "reason": "종료", "csrf_token": self.csrf, **extra}
        try:
            opener.open(urllib.request.Request(self.base + "/permissions/action", data=urllib.parse.urlencode(data).encode()))
        except urllib.error.HTTPError as exc:
            return exc.code, urllib.parse.urlsplit(exc.headers["Location"])
        self.fail("리다이렉트가 와야 한다")

    def test_view_and_selection_come_from_the_address(self):
        with self.op.open(self.base + "/permissions?view=account&acct=alice") as r:
            page = r.read().decode("utf-8")
        self.assertIn('id="perm-detail"', page)
        self.assertIn("name='acct' value='alice'", page)
        with self.op.open(self.base + "/permissions?view=doc&doc=d-sec&gp=zzz") as r:
            page = r.read().decode("utf-8")
        self.assertIn('class="tbl-perm-doc"', page)
        self.assertIn("name='doc' value='d-sec'", page)

    def test_revoke_returns_to_the_same_view_and_open_detail(self):
        code, loc = self._post_revoke(view="account", acct="alice", gp="1")
        self.assertIn(code, (302, 303))
        query = urllib.parse.parse_qs(loc.query)
        self.assertEqual((loc.path, query["view"], query["acct"], query["gp"]), ("/permissions", ["account"], ["alice"], ["1"]))
        self.assertIn("notice", query)
        self.client.update_permission.assert_called_once()
        self.assertEqual(self.client.update_permission.call_args.kwargs["action"], "revoke_doc")
        _, loc = self._post_revoke(view="doc", doc="d-sec")
        self.assertEqual(urllib.parse.parse_qs(loc.query)["doc"], ["d-sec"])

    def test_revoke_drops_unexpected_view_values_instead_of_echoing_them(self):
        _, loc = self._post_revoke(view="<script>", acct="a b", doc="x" * 80)
        query = urllib.parse.parse_qs(loc.query)
        for key in ("view", "acct", "doc"):
            self.assertNotIn(key, query)


class HeadersAndAssetsOverHttpTests(unittest.TestCase):
    def setUp(self):
        self.inc = _login_incident()
        self.store = DashboardStore(incidents=[self.inc])
        self.auth = AuthConfig(username="ops", password="pw", secret="sec", roles=parse_user_roles("", "ops"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.store, auth_config=self.auth))
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.op.open(urllib.request.Request(
            self.base + "/login", method="POST",
            data=urllib.parse.urlencode({"username": "admin1", "password": "pw"}).encode())).close()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_security_headers_on_login_and_authenticated_pages(self):
        for path, opener in (("/login", urllib.request.urlopen), ("/", self.op.open),
                             (f"/incidents/{self.inc.incident_id}", self.op.open), ("/api/incidents", self.op.open)):
            with opener(self.base + path) as r:
                h = r.headers
                self.assertEqual(h["X-Frame-Options"], "DENY", path)
                self.assertEqual(h["X-Content-Type-Options"], "nosniff", path)
                self.assertEqual(h["Referrer-Policy"], "same-origin", path)
                self.assertEqual(h["Cache-Control"], "no-store", path)
                self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"], path)
                self.assertIn("form-action 'self'", h["Content-Security-Policy"], path)

    def test_server_header_does_not_reveal_python_version(self):
        with urllib.request.urlopen(self.base + "/login") as r:
            server = r.headers["Server"]
        self.assertNotIn("Python", server)
        self.assertNotIn("BaseHTTP", server)

    def test_pages_load_no_external_resources(self):
        for path in ("/login", "/", f"/incidents/{self.inc.incident_id}", "/events"):
            opener = urllib.request.urlopen if path == "/login" else self.op.open
            with opener(self.base + path) as r:
                page = r.read().decode("utf-8")
            external = re.findall(r"""(?:src|href)=["']https?://[^"']+""", page)
            self.assertEqual(external, [], f"{path}: 외부 자원 {external}")
            self.assertNotIn("cdn.jsdelivr.net", page, path)

    def test_overview_shows_incident_queue_before_trend_chart(self):
        with self.op.open(self.base + "/") as r:
            page = r.read().decode("utf-8")
        queue = page.find("우선 확인할 사건")
        trend = page.find("로그인 실패 추이")
        self.assertGreater(queue, 0)
        self.assertGreater(trend, 0)
        self.assertLess(queue, trend)

    def test_font_is_served_locally_without_login_and_cached(self):
        # 로그인 화면에서도 글꼴이 필요하므로 인증 없이 받을 수 있어야 한다.
        with urllib.request.urlopen(self.base + "/static/fonts/PretendardVariable.woff2") as r:
            body = r.read()
            self.assertEqual(r.status, 200)
            self.assertEqual(r.headers["Content-Type"], "font/woff2")
            self.assertEqual(body[:4], b"wOF2")
            self.assertIn("immutable", r.headers["Cache-Control"])
            self.assertNotIn("no-store", r.headers["Cache-Control"])
            self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(int(r.headers["Content-Length"]), len(body))

    def test_only_the_font_file_is_served_as_static(self):
        for path in ("/static/fonts/../dashboard.py", "/static/fonts/other.woff2", "/static/dashboard.py",
                     "/static/fonts/PretendardVariable.woff2/../../dashboard.py"):
            try:
                with urllib.request.urlopen(self.base + path) as r:
                    status, body = r.status, r.read()
            except urllib.error.HTTPError as err:
                status, body = err.code, b""
            self.assertNotEqual(status, 200, path)
            self.assertNotIn(b"def ", body, path)

    def test_pages_declare_the_local_font_face(self):
        with urllib.request.urlopen(self.base + "/login") as r:
            page = r.read().decode("utf-8")
        self.assertIn("/static/fonts/PretendardVariable.woff2", page)
        self.assertIn("@font-face", page)

    def test_login_wording_is_consistent(self):
        with urllib.request.urlopen(self.base + "/login") as r:
            page = r.read().decode("utf-8")
        self.assertIn("담당자 아이디", page)
        self.assertNotIn("운영자 아이디", page)

    def test_department_display_maps_sales_to_admin_support(self):
        for badge in (
            _fmt_user_badge("alice"),
            _fmt_user_badge("bob"),
            _fmt_user_badge("alice", "영업", "member"),
        ):
            self.assertIn("행정", badge)
            self.assertNotIn("영업", badge)

    def test_incidents_control_panels_allow_custom_ip_duration_and_prominent_account(self):
        raw = json.dumps({
            "timestamp_utc": "2026-11-22T04:00:00Z", "source": "erp", "event_type": "account_locked",
            "outcome": "success", "username": "alice", "client_ip": "172.28.10.12",
            "peer_ip": "172.28.20.5", "client_ip_trusted": True,
            "request_id": "11111111-1111-1111-1111-111111111111",
            "http_method": "POST", "http_path": "/api/login", "status_code": 403, "ingest_mode": "live",
            "reason": "automatic_login_failure_limit",
        })
        ev = normalize_log_line(raw, source="erp", file_path="e.jsonl", line_offset=1000, collection_mode="live")[1]
        account_inc = build_incidents([], [ev])[0]
        panel_html = _render_incidents_control_panels(
            [_login_incident(), account_inc],
            current_user="ops",
            auth_enabled=False,
        )
        from unittest.mock import Mock

        self.assertIn('name="block_duration" type="number" value="10" min="1" max="43200"', panel_html)
        self.assertIn('<option value="minutes" data-max="43200">분</option>', panel_html)
        self.assertIn('<option value="hours" data-max="720">시간</option>', panel_html)
        self.assertNotIn('list="blockDurationPresets"', panel_html)
        self.assertIn("IP 차단</button>", panel_html)
        lock_client = Mock()
        lock_client.lookup_account_lock.return_value = {"status": "available"}
        lock_panel_html = _render_incidents_control_panels(
            [account_inc],
            current_user="ops",
            auth_enabled=False,
            csrf_token="tok",
            login_access_client=lock_client,
        )
        self.assertIn('name="duration" type="number" value="10" min="1" max="43200"', lock_panel_html)
        self.assertIn("width:68px;", lock_panel_html)
        self.assertIn("width:76px;", lock_panel_html)
        self.assertIn("분 잠금</button>", lock_panel_html)
        self.assertIn("행정 · 사원", panel_html)
        self.assertNotIn("영업", panel_html)
        self.assertIn("font-size:15px", panel_html)
        self.assertIn("class='cell-sub'", panel_html)
        self.assertIn('class="grid-2col-half"', panel_html)
        self.assertIn('class="tbl-control"', panel_html)
        self.assertIn("class='ctrl-primary'", panel_html)

    def test_incidents_queue_and_detail_presets_match_unified_typography(self):
        queue_html = _incident_queue_content([_login_incident()], overview=False)
        self.assertIn('class="tbl-incidents tbl-incidents-queue"', queue_html)
        detail_html = render_incident_detail(_login_incident()).decode("utf-8")
        self.assertNotIn('list="blockDurationPresets"', detail_html)
        self.assertIn('class="duration-presets"', detail_html)
        self.assertIn("30일(최대)", detail_html)

    def test_permissions_category_renders_individual_doc_grant_and_retirement_panels(self):
        from unittest.mock import Mock

        page_html = render_permissions_page(current_user="ops", auth_enabled=False).decode("utf-8")
        self.assertIn('href="/permissions"', page_html)
        self.assertIn("자료실 문서 특별 권한 부여 · 회수", page_html)
        self.assertIn("퇴사 · 계정 전체 권한 회수", page_html)
        self.assertIn("계정별 자료실 문서 열람 권한 현황", page_html)
        self.assertIn('id="permDocSelect"', page_html)
        self.assertIn('id="permDurationSelect"', page_html)
        self.assertIn("1시간 후 자동 회수", page_html)
        self.assertIn("인사 업무 절차 안내 (인사 · 부서)", page_html)
        self.assertIn("퇴사 · 전면 회수</button>", page_html)

        client = Mock()
        client.fetch_permissions.return_value = {
            "status": "ok",
            "users": [{"username": "alice", "department": "영업", "role": "member", "account_status": "active"}],
            "documents": [{"id": "82942466-9254-5654-8155-96182c788a25", "title": "인사 평가 기준", "department": "인사", "level": "secret"}],
            "grants": [{
                "id": 1, "username": "alice", "department": "영업", "role": "member",
                "document_id": "82942466-9254-5654-8155-96182c788a25", "document_title": "인사 평가 기준",
                "doc_department": "인사", "doc_level": "secret", "granted_by": "soc-operator",
                "reason": "타 부서 업무 협조 지원", "expires_at": "2099-01-01T00:00:00+00:00", "status": "active",
            }],
        }
        grant_html = render_permissions_page(
            current_user="ops", auth_enabled=True, csrf_token="tok", login_access_client=client,
        ).decode("utf-8")
        self.assertIn("자동 회수까지", grant_html)
        self.assertIn("관리 대상 계정", grant_html)
        self.assertIn("활성 특별 권한", grant_html)
        self.assertIn('class="perm-form-row1"', grant_html)
        self.assertIn('class="perm-form-row2"', grant_html)
        # 제출 버튼은 확인 정보와 같은 맨 아래 줄(perm-form-foot)에 있고, 입력 줄에는 없다.
        form = grant_html[grant_html.index('class="perm-form-card"'):grant_html.index("</form>", grant_html.index('class="perm-form-card"'))]
        self.assertGreater(form.index("권한 부여</button>"), form.index('class="perm-form-foot"'))
        self.assertGreater(form.index('id="permUserScopeHint"'), form.index('class="perm-form-foot"'))
        self.assertIn("grid-2col-half perm-split", grant_html)
        self.assertIn('class="tbl-perm-acct"', grant_html)  # 기본 보기는 계정 기준 요약 표
        self.assertIn("perm-matrix-filters", grant_html)
        self.assertNotIn("&lt;span", grant_html)

    def test_special_grant_list_is_paged_so_it_never_grows_without_limit(self):
        from unittest.mock import Mock

        doc = {"id": "82942466-9254-5654-8155-96182c788a25", "title": "인사 평가 기준", "department": "인사", "level": "secret"}

        def page_for(count, page=1):
            client = Mock()
            client.fetch_permissions.return_value = {
                "status": "ok",
                "users": [{"username": "alice", "department": "영업", "role": "member", "account_status": "active"}],
                "documents": [doc],
                "grants": [{
                    "id": i, "username": f"user{i:03d}", "department": "영업", "role": "member",
                    "document_id": doc["id"], "document_title": f"문서{i:03d}", "doc_department": "인사", "doc_level": "secret",
                    "granted_by": "soc-operator", "reason": "타 부서 업무 협조 지원",
                    "expires_at": "2099-01-01T00:00:00+00:00", "status": "active",
                } for i in range(count)],
            }
            return render_permissions_page(
                current_user="ops", auth_enabled=True, csrf_token="tok", login_access_client=client, grant_page=page,
            ).decode("utf-8")

        rows = lambda html_: re.findall(r"<tr data-source='grant (user\d{3})'", html_)
        # 8건 이하: 지금과 같은 화면이고 쪽 이동 줄이 없다.
        self.assertEqual(len(rows(page_for(8))), 8)
        self.assertNotIn('class="perm-grant-pager"', page_for(8))  # (스타일 규칙 이름은 CSS에 항상 있으므로 태그로 확인)
        self.assertIn('class="perm-grant-pager"', page_for(9))
        # 100건: 한 쪽에 8건, 13쪽. 쪽마다 겹치지 않고 모두 다 나온다.
        first, second, last = page_for(100, 1), page_for(100, 2), page_for(100, 13)
        self.assertEqual(rows(first), [f"user{i:03d}" for i in range(0, 8)])
        self.assertEqual(rows(second), [f"user{i:03d}" for i in range(8, 16)])
        self.assertEqual(rows(last), [f"user{i:03d}" for i in range(96, 100)])
        self.assertIn("총 <b>100</b>건 · 1–8건", first)
        self.assertIn('href="/permissions?gp=2"', first)
        self.assertIn('aria-label="특별 권한 부여 목록 페이지"', first)
        self.assertIn("활성 100건", first)  # 머리말의 전체 건수는 쪽과 상관없이 그대로
        # 범위를 벗어난 쪽 번호는 마지막 쪽으로 맞추고, 회수 버튼은 보던 쪽 번호를 들고 간다.
        self.assertEqual(rows(page_for(100, 99)), rows(last))
        self.assertIn("name='gp' value='13'", last)
        self.assertEqual(rows(page_for(100, 0)), rows(first))

    def test_permission_grid_shows_one_symbol_per_account_and_document(self):
        from unittest.mock import Mock

        docs = [
            {"id": "d-sec", "title": "인사 평가 기준", "department": "인사", "level": "secret"},
            {"id": "d-pub1", "title": "포털 이용 안내", "department": "", "level": "public"},
            {"id": "d-hr", "title": "인사 업무 절차 안내", "department": "인사", "level": "dept"},
            {"id": "d-pub2", "title": "정보 보호 기본 수칙", "department": "", "level": "public"},
        ]
        client = Mock()
        client.fetch_permissions.return_value = {
            "status": "ok",
            "users": [
                {"username": "alice", "department": "영업", "role": "member", "account_status": "active"},
                {"username": "dave", "department": "인사", "role": "manager", "account_status": "active"},
                {"username": "frank", "department": "보안", "role": "manager", "account_status": "revoked"},
            ],
            "documents": docs,
            "grants": [{
                "id": 1, "username": "alice", "department": "영업", "role": "member", "document_id": "d-sec",
                "document_title": "인사 평가 기준", "doc_department": "인사", "doc_level": "secret", "granted_by": "soc-operator",
                "reason": "타 부서 업무 협조 지원", "expires_at": "2099-01-01T00:00:00+00:00", "status": "active",
            }],
        }
        page = render_permissions_page(current_user="ops", auth_enabled=False, login_access_client=client, view="grid").decode("utf-8")
        start = page.index('<table class="tbl-perm-grid">')
        grid = page[start:page.index("</table>", start)]
        head, body = grid.split("<tbody>", 1)
        # 열 = 문서. 부서별로 묶고(공통 먼저) 묶음 안에서는 일반 -> 부서 -> 기밀 순서.
        titles = re.findall(r'<th class="pm-doc[^"]*" scope="col" title="[^"]*">([^<]+)', head)
        self.assertEqual(titles, ["포털 이용 안내", "정보 보호 기본 수칙", "인사 업무 절차 안내", "인사 평가 기준"])
        self.assertIn('colspan="2" scope="colgroup">공통</th>', head)
        self.assertIn('colspan="2" scope="colgroup">인사</th>', head)
        # 기밀 여부는 문서 제목 아래에 한 번만, 부서는 묶음 제목에 한 번만 나온다(칸마다 되풀이하지 않는다).
        self.assertEqual(head.count('<span class="pm-secret">기밀</span>'), 1)
        self.assertNotIn("★", grid)
        visible_body = re.sub(r'title="[^"]*"', "", body)
        self.assertNotIn("·기밀", visible_body)
        self.assertNotIn("인사 평가 기준", visible_body)
        # 한 계정 = 한 행, 칸마다 기호 하나.
        rows = {name: next(r for r in body.split("<tr") if f"matrix {name} " in r) for name in ("alice", "dave", "frank")}
        marks = {name: re.findall(r'class="pm-mark (pm-\w+)"', row) for name, row in rows.items()}
        self.assertEqual(marks["alice"], ["pm-default", "pm-default", "pm-none", "pm-special"])
        self.assertEqual(marks["dave"], ["pm-default"] * 4)
        self.assertEqual(marks["frank"], ["pm-blocked"] * 4)
        # 특별 부여 칸은 남은 시간을 보여 주고, 마우스를 올리면 문서·사유·승인자를 볼 수 있다.
        special = re.search(r'<span class="pm-mark pm-special" title="([^"]*)">([^<]+)</span>', rows["alice"])
        self.assertIn("인사 평가 기준 · 인사 · 기밀 — 특별 부여", special.group(1))
        self.assertIn("사유: 타 부서 업무 협조 지원", special.group(1))
        self.assertIn("승인자: soc-operator", special.group(1))
        self.assertNotIn("남음", special.group(2))
        # 계정 칸의 상태 문구와 필터용 행 표시는 그대로다.
        self.assertIn("재직 · 특별 권한 1건", rows["alice"])
        self.assertIn("재직 · 기본 권한", rows["dave"])
        self.assertIn("퇴사 · 로그인·열람 불가", rows["frank"])
        self.assertRegex(rows["alice"], r"data-perm-tags='all \S+ active granted secret soon\b|data-perm-tags='all \S+ active granted secret'")
        self.assertRegex(rows["frank"], r"data-perm-tags='all \S+ revoked'")
        self.assertIn("row-locked", rows["frank"])
        # 기호 설명이 표 위에 있다.
        self.assertIn('class="pm-legend"', page)
        # '특별 권한 보유' 필터 숫자는 그 필터로 남는 행 수와 같다.
        granted_rows = len(re.findall(r"data-perm-tags='[^']*\bgranted\b", body))
        self.assertIn(f'특별 권한 보유 <span class="chip-cnt">{granted_rows}</span>', page)
        self.assertEqual(granted_rows, 1)

    def _status_fixture(self):
        from unittest.mock import Mock

        docs = [
            {"id": "d-pub", "title": "포털 이용 안내", "department": "", "level": "public"},
            {"id": "d-hr", "title": "인사 업무 절차 안내", "department": "인사", "level": "dept"},
            {"id": "d-sec", "title": "인사 평가 기준", "department": "인사", "level": "secret"},
            {"id": "d-ops", "title": "영업 업무 절차 안내", "department": "영업", "level": "dept"},
        ]
        grant = lambda i, user, doc_id, title, dept, level, mins: {
            "id": i, "username": user, "department": "영업", "role": "member", "document_id": doc_id, "document_title": title,
            "doc_department": dept, "doc_level": level, "granted_by": "soc-operator", "reason": f"사유-{user}",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=mins)).isoformat(), "status": "active",
        }
        client = Mock()
        client.fetch_permissions.return_value = {
            "status": "ok",
            "users": [
                {"username": "alice", "department": "영업", "role": "member", "account_status": "active"},
                {"username": "bob", "department": "영업", "role": "manager", "account_status": "active"},
                {"username": "dave", "department": "인사", "role": "manager", "account_status": "active"},
                {"username": "frank", "department": "보안", "role": "manager", "account_status": "revoked"},
            ],
            "documents": docs,
            "grants": [grant(1, "alice", "d-sec", "인사 평가 기준", "인사", "secret", 30),
                       grant(2, "alice", "d-hr", "인사 업무 절차 안내", "인사", "dept", 300),
                       grant(3, "bob", "d-hr", "인사 업무 절차 안내", "인사", "dept", 600)],
        }
        return client

    def _status_page(self, **kw):
        return render_permissions_page(current_user="ops", auth_enabled=True, csrf_token="tok",
                                       login_access_client=self._status_fixture(), **kw).decode("utf-8")

    def test_permission_status_default_view_is_one_line_per_account_with_exceptions_first(self):
        page = self._status_page()
        start = page.index('<table class="tbl-perm-acct">')
        table = page[start:page.index("</table>", start)]
        rows = {n: next(r for r in table.split("<tr") if f"matrix {n} " in r) for n in ("alice", "bob", "dave", "frank")}
        self.assertEqual(table.count("data-source='matrix "), 4)  # 계정 한 줄씩
        # 기밀 예외가 있는 계정이 가장 위, 그다음 특별 부여가 많은 계정.
        order = re.findall(r"data-source='matrix (\w+) ", table)
        self.assertEqual(order[:2], ["alice", "bob"])
        # 문서 이름·부서·등급 꼬리표·별표를 목록에 늘어놓지 않고 건수만 둔다.
        for text in ("인사 평가 기준", "인사 업무 절차 안내", "포털 이용 안내", "★", "doc-chip"):
            self.assertNotIn(text, table)
        self.assertIn("2건", rows["alice"]); self.assertIn("기밀 1", rows["alice"])
        self.assertIn("1건", rows["bob"]); self.assertNotIn("기밀", rows["bob"])
        self.assertIn("퇴사 · 차단", rows["frank"]); self.assertIn("row-locked", rows["frank"])
        self.assertIn('class="perm-soon"', rows["alice"])  # 30분 뒤 만료는 1시간 이내
        self.assertNotIn('class="perm-soon"', rows["bob"])
        # 상세는 처음엔 닫혀 있고, 열기 링크는 보기와 계정을 주소에 담는다.
        self.assertNotIn('id="perm-detail"', page)
        self.assertIn("view=account&amp;acct=alice#perm-selection", rows["alice"])
        self.assertIn('aria-expanded="false"', rows["alice"])
        self.assertIn('data-perm-detail="alice"', rows["alice"])

    def test_permission_status_summary_chips_count_exactly_the_rows_they_keep(self):
        page = self._status_page()
        tags = re.findall(r"data-perm-tags='([^']*)'", page)
        count = lambda tag: sum(tag in t.split() for t in tags)
        for mode, label in (("granted", "특별 권한 보유"), ("secret", "기밀 예외"), ("soon", "1시간 내 만료"), ("revoked", "퇴사 · 차단")):
            self.assertIn(f'{label} <span class="chip-cnt">{count(mode)}</span>', page, mode)
        self.assertEqual((count("granted"), count("secret"), count("soon"), count("revoked")), (2, 1, 1, 1))

    def test_permission_status_detail_opens_per_account_and_keeps_revoke_working(self):
        page = self._status_page(acct="alice")
        selected, detail, next_row = re.search(
            r'(<tr[^>]*id="perm-selection"[^>]*>.*?)</tr>'
            r'(<tr class="perm-detail-row">.*?)</tr>(<tr[^>]*>)', page, re.S,
        ).groups()
        self.assertIn("data-source='matrix alice ", selected)
        self.assertIn('aria-expanded="true" aria-controls="perm-detail"', selected)
        self.assertIn('data-perm-detail="alice"', selected)
        self.assertIn('href="/permissions?view=account#perm-status"', selected)
        self.assertIn('<td colspan="7"><div class="perm-detail" id="perm-detail" role="region" aria-label="alice 문서 열람 상세">', detail)
        self.assertEqual((selected + detail).count(">닫기</a>"), 1)
        self.assertIn("data-source='matrix bob ", next_row)
        self.assertEqual(page.count('id="perm-detail"'), 1)
        self.assertIn("인사 평가 기준", detail)
        self.assertIn("인사 · 기밀", detail)         # 부서·등급은 상세 안에서 한 번만, 문서 이름 옆에
        self.assertIn("사유: 사유-alice", detail)
        self.assertIn("승인자: soc-operator", detail)
        self.assertIn("name='document_id' value='d-sec'", detail)
        self.assertIn("name='acct' value='alice'", detail)  # 회수 뒤에도 같은 계정 상세로 돌아오도록
        self.assertIn("name='view' value='account'", detail)
        self.assertIn("포털 이용 안내", detail)       # 기본 열람 목록도 상세에서는 볼 수 있다
        self.assertIn("영업 업무 절차 안내", detail)

    def test_permission_status_document_view_shows_one_line_per_document(self):
        page = self._status_page(view="doc")
        start = page.index('<table class="tbl-perm-doc">')
        table = page[start:page.index("</table>", start)]
        self.assertEqual(table.count("data-source='doc "), 4)
        order = re.findall(r"data-source='doc ([^']+)'", table)
        self.assertEqual(order[0], "인사 업무 절차 안내")  # 특별 부여가 가장 많은 문서가 위
        self.assertIn("2명", next(r for r in table.split("<tr") if "인사 업무 절차 안내" in r))
        self.assertNotIn("perm-matrix-filters", page.split('id="perm-status"')[1])  # 문서 기준 보기에는 계정 필터가 없다
        self.assertIn("view=doc&amp;doc=d-hr#perm-selection", table)
        detail_page = self._status_page(view="doc", doc="d-hr")
        selected, detail = re.search(
            r'(<tr[^>]*id="perm-selection"[^>]*>.*?)</tr>(<tr class="perm-detail-row">.*?)</tr>',
            detail_page, re.S,
        ).groups()
        self.assertIn("data-source='doc 인사 업무 절차 안내'", selected)
        self.assertIn('data-perm-detail="d-hr"', selected)
        self.assertIn('<td colspan="7"><div class="perm-detail" id="perm-detail" role="region" aria-label="인사 업무 절차 안내 열람 가능 계정 상세">', detail)
        self.assertEqual((selected + detail).count(">닫기</a>"), 1)
        self.assertIn("사유-alice", detail); self.assertIn("사유-bob", detail)
        self.assertIn("name='doc' value='d-hr'", detail)

    def test_permission_status_ignores_unknown_view_account_and_document(self):
        for kw in ({"view": "<script>"}, {"acct": "nobody"}, {"view": "doc", "doc": "nope"}, {"acct": "<b>"}):
            page = self._status_page(**kw)
            self.assertNotIn('id="perm-detail"', page, kw)
            self.assertNotIn("<script>alert", page)
            self.assertTrue('class="tbl-perm-acct"' in page or 'class="tbl-perm-doc"' in page, kw)

    def test_permission_status_view_tabs_mark_the_current_view(self):
        for view, label in (("account", "계정 기준"), ("doc", "문서 기준"), ("grid", "격자 비교")):
            page = self._status_page(view=view)
            self.assertRegex(page, rf'<a href="[^"]*view={view}[^"]*" aria-current="page">{label}</a>')

    def test_event_pager_default_links_are_unchanged(self):
        from soc.dashboard import _event_pagination
        pager = _event_pagination(2, 5)
        self.assertIn('href="/events?page=1"', pager)
        self.assertIn('href="/events?page=3"', pager)
        self.assertIn('aria-label="이벤트 페이지"', pager)

    def test_events_category_renders_4col_health_metrics_and_request_context(self):
        inc = _login_incident()
        store = DashboardStore(incidents=[inc])
        page_html = render_recent_events(store, current_user="ops", auth_enabled=False).decode("utf-8")
        self.assertIn('href="/logs/waf"', page_html)
        self.assertIn("표시 요청 묶음", page_html)
        self.assertIn("다계층 상관 흐름", page_html)
        self.assertIn("이상 · 차단 징후", page_html)
        self.assertIn('data-filter="waf"', page_html)
        self.assertIn("모두 펼치기", page_html)
        self.assertIn('class="request-summary-ctx"', page_html)
        self.assertIn("POST /api/login", page_html)
        self.assertIn("HTTP 401", page_html)
        self.assertIn('class="request-stages-head"', page_html)

    def test_x_terminal_source_denial_shows_auto_blocked_in_ip_panel_and_queue(self):
        from unittest.mock import Mock

        x_inc = _x_denial_incident("alice", 0)
        client = Mock()
        client.lookup_account_access.return_value = {"status": "pending", "username": "alice", "client_ip": "172.28.10.13"}
        panel_html = _render_incidents_control_panels(
            [x_inc], current_user="ops", auth_enabled=True, csrf_token="tok", login_access_client=client,
        )
        self.assertIn("172.28.10.13", panel_html)
        self.assertIn("(단말 X)", panel_html)
        self.assertIn("승인 대기", panel_html)
        self.assertIn("5분 임시 승인", panel_html)
        queue_html = _incident_queue_content([x_inc])
        self.assertIn("자동 차단 중", queue_html)
        self.assertIn("비인가 IP 자동 차단 · 보안팀 임시 해제 가능", queue_html)

    def test_x_panel_keeps_older_active_grant_visible_beside_another_account_pending(self):
        from unittest.mock import Mock, call

        approved = _x_denial_incident("alice", 0)
        alice_later = [_x_denial_incident("alice", second) for second in range(1, 7)]
        bob_pending = _x_denial_incident("bob", 7)
        client = Mock()
        client.lookup_account_access.side_effect = lambda event: (
            {"status": "active", "incident_id": approved.incident_id, "expires_at": "2099-01-01T00:00:00Z"}
            if event.username == "alice" else {"status": "pending"}
        )
        panel_html = _render_incidents_control_panels(
            [approved, *alice_later, bob_pending], current_user="ops", auth_enabled=True, csrf_token="tok",
            login_access_client=client,
        )

        self.assertEqual(panel_html.count("(단말 X)"), 2)
        self.assertIn("1개 IP", panel_html)
        rows = panel_html.split("</tr>")
        self.assertTrue(any("임시 허용 중" in row and f"/incidents/{approved.incident_id}/revoke-login" in row for row in rows))
        self.assertTrue(any("승인 대기" in row and f"/incidents/{bob_pending.incident_id}/grant-login" in row for row in rows))
        self.assertNotIn(f"/incidents/{alice_later[-1].incident_id}/grant-login", panel_html)
        self.assertEqual(client.lookup_account_access.call_args_list, [
            call(bob_pending.login_access_event), call(alice_later[-1].login_access_event),
        ])

    def test_account_unlock_panel_targets_the_incident_that_started_the_lock(self):
        from unittest.mock import Mock

        events = _login_incident().evidence_events[:4]
        events[-1] = replace(events[-1], event_type="login_success", outcome="success", status_code=200)
        older, newer = sorted(build_incidents([], events), key=lambda incident: incident.created_at_utc)
        client = Mock()
        client.lookup_account_lock.return_value = {
            "status": "active", "username": "alice", "incident_id": older.incident_id,
        }

        html = _render_incidents_control_panels(
            [older, newer], current_user="ops", auth_enabled=True, csrf_token="tok", login_access_client=client,
        )

        client.lookup_account_lock.assert_called_once_with(newer.incident_id, "alice")
        self.assertIn(f"href='/incidents/{older.incident_id}'", html)
        self.assertIn(f'action="/incidents/{older.incident_id}/unlock-account"', html)
        self.assertNotIn(f'action="/incidents/{newer.incident_id}/unlock-account"', html)

        # ERP에 잠금은 남아 있어도 관제에 그 사건이 없으면 다른 사건으로 해제를 보내지 않는다.
        html = _render_incidents_control_panels(
            [newer], current_user="ops", auth_enabled=True, csrf_token="tok", login_access_client=client,
        )
        self.assertIn("계정 잠금 중", html)
        self.assertIn("잠금을 시작한 사건을 확인할 수 없습니다.", html)
        self.assertNotIn("/unlock-account", html)

    def test_account_lock_panel_hides_expired_or_unlocked_accounts_and_shows_green_allow_badge(self):
        from unittest.mock import Mock

        raw = json.dumps({
            "timestamp_utc": "2026-11-25T03:10:00Z", "source": "erp", "event_type": "account_locked",
            "outcome": "success", "username": "alice", "client_ip": "172.28.10.11",
            "peer_ip": "172.28.20.5", "client_ip_trusted": True,
            "request_id": "33333333-3333-3333-3333-333333333333",
            "http_method": "POST", "http_path": "/api/login", "status_code": 403, "ingest_mode": "live",
            "reason": "automatic_login_failure_limit",
        })
        ev = normalize_log_line(raw, source="erp", file_path="e.jsonl", line_offset=3000, collection_mode="live")[1]
        acc_inc = build_incidents([], [ev])[0]
        client = Mock()
        client.lookup_account_lock.return_value = {"status": "expired", "username": "alice"}
        expired_html = _render_incidents_control_panels(
            [_login_incident(), acc_inc], current_user="ops", auth_enabled=True, csrf_token="tok",
            login_access_client=client,
        )
        self.assertIn('class="badge b-allow">허용 중</span>', expired_html)
        self.assertIn("0개 계정", expired_html)
        self.assertNotIn("잠금 만료", expired_html)

        client.lookup_account_lock.return_value = {"status": "available", "username": "alice"}
        avail_html = _render_incidents_control_panels(
            [_login_incident(), acc_inc], current_user="ops", auth_enabled=True, csrf_token="tok",
            login_access_client=client,
        )
        self.assertIn("1개 계정", avail_html)
        self.assertIn('class="badge b-suspect">의심 · 조치 필요</span>', avail_html)
        self.assertIn("class='row-suspect'", avail_html)


if __name__ == "__main__":
    unittest.main()
