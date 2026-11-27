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
    AuthConfig, DashboardStore, _approval_row, _bk_area_chart, _block_effects, _fmt_status, _fmt_user_badge, _incident_queue_content,
    _is_suspect_event, _login_failure_panel, _render_incidents_control_panels, make_handler, parse_user_roles,
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

    def test_priority_incident_row_opens_detail_from_any_cell(self):
        incident = _login_incident()
        page = _incident_queue_content([incident], overview=True)
        self.assertIn(f"data-incident-href='/incidents/{incident.incident_id}'", page)
        self.assertIn("data-overview-incident", page)

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

        self.assertIn('name="duration_minutes" type="number" value="10" min="1" max="43200"', panel_html)
        self.assertNotIn('list="blockDurationPresets"', panel_html)
        self.assertIn("width:78px;", panel_html)
        self.assertIn("분 차단</button>", panel_html)
        lock_client = Mock()
        lock_client.lookup_account_lock.return_value = {"status": "available"}
        lock_panel_html = _render_incidents_control_panels(
            [account_inc],
            current_user="ops",
            auth_enabled=False,
            csrf_token="tok",
            login_access_client=lock_client,
        )
        self.assertIn('name="duration" type="number" value="10" min="1" max="1440"', lock_panel_html)
        self.assertIn('onsubmit="return confirmLongBlock(this)"', panel_html)
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
        self.assertIn("class='doc-chip is-granted'", grant_html)
        self.assertIn("perm-matrix-filters", grant_html)
        self.assertNotIn("&lt;span", grant_html)

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
