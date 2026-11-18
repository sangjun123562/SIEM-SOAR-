from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
import urllib.parse
from dataclasses import asdict
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .incident_service import (
    ActionApiClient,
    ActionPolicyError,
    IncidentView,
    build_incidents,
    refresh_approval_status,
    release_approval,
    request_human_approval,
)
from .models import NormalizedEvent, RawLogRecord
from .normalizer import normalize_log_line
from .repository import SocRepository
from .storage import PostgresSocStorage, SocStorage


class AuthConfig:
    """Operator session authentication configuration."""

    def __init__(
        self,
        username: str,
        password: str,
        secret: str | None = None,
        ttl_seconds: int = 3600,
    ) -> None:
        self.username = username
        self.password = password
        self.secret = (secret or secrets.token_hex(32)).encode("utf-8")
        self.ttl_seconds = ttl_seconds

    def verify_credentials(self, username: str, password: str) -> bool:
        if not self.password:
            return False
        user_ok = hmac.compare_digest(username, self.username)
        pass_ok = hmac.compare_digest(password, self.password)
        return user_ok and pass_ok

    def sign_session(self, username: str) -> str:
        exp = int(time.time()) + self.ttl_seconds
        payload = f"{username}|{exp}"
        sig = hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        token = f"{payload}|{sig}"
        return base64.urlsafe_b64encode(token.encode("utf-8")).decode("ascii")

    def verify_session(self, cookie_val: str | None) -> str | None:
        if not cookie_val:
            return None
        try:
            decoded = base64.urlsafe_b64decode(cookie_val.encode("ascii")).decode("utf-8")
            username, exp_str, sig = decoded.split("|", 2)
            exp = int(exp_str)
        except Exception:
            return None
        if exp < int(time.time()):
            return None
        expected_sig = hmac.new(
            self.secret, f"{username}|{exp_str}".encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        return username


class DashboardStore:
    """In-memory store holding incidents and optional gateway action client."""

    def __init__(
        self,
        incidents: list[IncidentView] | None = None,
        action_client: ActionApiClient | None = None,
    ) -> None:
        self.incidents: dict[str, IncidentView] = {
            inc.incident_id: inc for inc in (incidents or [])
        }
        self.action_client = action_client

    def list_incidents(self) -> list[IncidentView]:
        return sorted(
            self.incidents.values(),
            key=lambda item: item.created_at_utc,
            reverse=True,
        )

    def get_incident(self, incident_id: str) -> IncidentView | None:
        return self.incidents.get(incident_id)

    def persist_approval(self, inc: IncidentView, approval: Any) -> None:
        return

    def close(self) -> None:
        return


class DbDashboardStore:
    """Database-backed store reading incidents, evidence, raw_id, and approvals from SocStorage."""

    def __init__(self, storage: SocStorage, action_client: ActionApiClient | None = None) -> None:
        self.storage = storage
        self.repo = SocRepository(storage)
        self.action_client = action_client

    def list_incidents(self) -> list[IncidentView]:
        return self.repo.load_incidents()

    def get_incident(self, incident_id: str) -> IncidentView | None:
        for inc in self.repo.load_incidents():
            if inc.incident_id == incident_id:
                return inc
        return None

    def persist_approval(self, inc: IncidentView, approval: Any) -> None:
        self.repo.save_approval(approval, inc.status, inc.updated_at_utc)

    def close(self) -> None:
        close_fn = getattr(self.storage, "close", None)
        if callable(close_fn):
            close_fn()


def _page_shell(title: str, body_html: str, current_user: str | None = None, auth_enabled: bool = False) -> bytes:
    auth_nav = ""
    if auth_enabled:
        if current_user:
            auth_nav = (
                f' &nbsp;|&nbsp; 담당자: <strong>{html.escape(current_user)}</strong> '
                f'<form method="post" action="/logout" style="display:inline;">'
                f'<button type="submit" class="secondary" style="padding:3px 8px;font-size:12px;">로그아웃</button></form>'
            )
        else:
            auth_nav = ' &nbsp;|&nbsp; <a href="/login">로그인</a>'

    doc = f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }}
    header {{ background: #1e293b; border-bottom: 1px solid #334155; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }}
    header h1 {{ margin: 0; font-size: 18px; color: #f8fafc; }}
    main {{ max-width: 1120px; margin: 24px auto; padding: 0 20px; }}
    a {{ color: #38bdf8; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 14px 16px; }}
    .card .label {{ font-size: 12px; color: #94a3b8; }}
    .card .val {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
    .panel {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 18px; margin-bottom: 18px; }}
    .panel h2 {{ margin: 0 0 12px 0; font-size: 16px; color: #f8fafc; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid #334155; vertical-align: top; }}
    th {{ color: #94a3b8; font-weight: 600; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }}
    .b-open {{ background: #7c2d12; color: #fdba74; }}
    .b-approved {{ background: #1e3a8a; color: #93c5fd; }}
    .b-blocked, .b-applied, .b-rejected {{ background: #7f1d1d; color: #fca5a5; }}
    .b-released, .b-expired {{ background: #14532d; color: #86efac; }}
    .b-ok {{ background: #14532d; color: #86efac; }}
    .b-warn {{ background: #78350f; color: #fcd34d; }}
    code, pre {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 2px 6px; font-size: 12px; color: #cbd5e1; }}
    pre {{ padding: 10px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
    button {{ background: #ef4444; color: #fff; border: 0; border-radius: 6px; padding: 8px 14px; font-weight: 600; cursor: pointer; }}
    button.secondary {{ background: #0284c7; }}
    button:disabled {{ background: #475569; cursor: not-allowed; }}
    input, select {{ background: #0f172a; color: #e2e8f0; border: 1px solid #475569; border-radius: 6px; padding: 7px 10px; }}
    .notice {{ background: #451a03; border: 1px solid #b45309; color: #fde68a; padding: 10px 12px; border-radius: 8px; font-size: 13px; margin-bottom: 12px; }}
  </style>
</head>
<body>
  <header>
    <h1>SIEM·SOAR 관제 대시보드 (B)</h1>
    <div><a href="/">사건 목록</a> &nbsp;|&nbsp; <a href="/api/incidents">JSON API</a>{auth_nav}</div>
  </header>
  <main>{body_html}</main>
</body>
</html>"""
    return doc.encode("utf-8")


def render_login_page(error_msg: str | None = None) -> bytes:
    err_html = f'<div class="notice">{html.escape(error_msg)}</div>' if error_msg else ""
    body = f"""
    <div class="panel" style="max-width:420px; margin:40px auto;">
      <h2>관제 담당자 로그인</h2>
      {err_html}
      <form method="post" action="/login">
        <p><label>아이디<br /><input type="text" name="username" required style="width:100%;box-sizing:border-box;" /></label></p>
        <p><label>비밀번호<br /><input type="password" name="password" required style="width:100%;box-sizing:border-box;" /></label></p>
        <p><button type="submit" class="secondary">로그인</button></p>
      </form>
    </div>
    """
    return _page_shell("관제 대시보드 · 로그인", body, auth_enabled=True)


def render_incident_list(
    store: DashboardStore | DbDashboardStore,
    current_user: str | None = None,
    auth_enabled: bool = False,
) -> bytes:
    incidents = store.list_incidents()
    open_cnt = sum(1 for i in incidents if i.status == "open")
    blocked_cnt = sum(1 for i in incidents if i.status == "blocked")
    released_cnt = sum(1 for i in incidents if i.status == "released")

    rows = []
    for inc in incidents:
        esc = html.escape
        badge_cls = f"b-{esc(inc.status)}"
        live_badge = (
            '<span class="badge b-ok">live + trusted</span>'
            if inc.live_and_trusted_eligible
            else '<span class="badge b-warn">차단 불가(비라이브/미신뢰)</span>'
        )
        rows.append(
            f"<tr>"
            f"<td><a href='/incidents/{esc(inc.incident_id)}'><code>{esc(inc.incident_id)}</code></a></td>"
            f"<td>{esc(inc.title)}</td>"
            f"<td><span class='badge {badge_cls}'>{esc(inc.status)}</span></td>"
            f"<td><code>{esc(inc.target_ip)}</code></td>"
            f"<td>{esc(inc.username)}</td>"
            f"<td>{live_badge}</td>"
            f"<td><code>{esc(inc.created_at_utc)}</code></td>"
            f"</tr>"
        )

    table_body = "".join(rows) if rows else "<tr><td colspan='7'>탐지된 사건이 없습니다.</td></tr>"
    body = f"""
    <div class="cards">
      <div class="card"><div class="label">전체 사건</div><div class="val">{len(incidents)}</div></div>
      <div class="card"><div class="label">미처리(open)</div><div class="val">{open_cnt}</div></div>
      <div class="card"><div class="label">차단 적용(blocked)</div><div class="val">{blocked_cnt}</div></div>
      <div class="card"><div class="label">해제 복구(released)</div><div class="val">{released_cnt}</div></div>
    </div>
    <div class="panel">
      <h2>탐지된 보안 사건 목록</h2>
      <table>
        <thead><tr><th>사건 ID</th><th>제목</th><th>상태</th><th>대상 IP</th><th>계정</th><th>조치 자격</th><th>발생 시각(UTC)</th></tr></thead>
        <tbody>{table_body}</tbody>
      </table>
    </div>
    """
    return _page_shell("관제 대시보드 · 사건 목록", body, current_user=current_user, auth_enabled=auth_enabled)


def render_incident_detail(
    inc: IncidentView,
    error_msg: str | None = None,
    current_user: str | None = None,
    auth_enabled: bool = False,
) -> bytes:
    esc = html.escape
    err_html = f'<div class="notice">{esc(error_msg)}</div>' if error_msg else ""

    alert_rows = "".join(
        f"<tr><td><code>{esc(a.alert_id)}</code></td><td><code>{esc(a.rule_id)}</code></td>"
        f"<td>{esc(a.rule_name)}</td><td>{a.failure_count}건</td>"
        f"<td><code>{esc(a.window_start_utc)}</code> ~ <code>{esc(a.window_end_utc)}</code></td></tr>"
        for a in inc.alerts
    )

    ev_rows = "".join(
        f"<tr>"
        f"<td><code>{esc(ev.event_id[:12])}</code></td>"
        f"<td><code>{esc(ev.source)}</code></td>"
        f"<td><code>{esc(ev.event_ts_utc)}</code></td>"
        f"<td><code>{esc(ev.request_id or '-')}</code></td>"
        f"<td><code>{esc(ev.client_ip or '-')}</code> (trusted={ev.client_ip_trusted})</td>"
        f"<td><code>{esc(ev.ingest_mode)}</code></td>"
        f"<td><a href='#raw-{esc(ev.raw_id)}'><code>{esc(ev.raw_id[:16])}...</code></a></td>"
        f"</tr>"
        for ev in inc.evidence_events
    )

    corr_rows = "".join(
        f"<tr><td><code>{esc(c.link_type)}</code></td><td><code>{esc(c.event_id[:12])}</code></td>"
        f"<td>{esc(c.reason)}</td><td><a href='#raw-{esc(c.raw_id)}'><code>{esc(c.raw_id[:16])}...</code></a></td></tr>"
        for c in inc.correlations
    ) or "<tr><td colspan='4'>연결된 Caddy/게이트웨이 상관 이벤트가 없습니다.</td></tr>"

    raw_blocks = "".join(
        f"<div id='raw-{esc(rid)}' style='margin-bottom:10px;'>"
        f"<div><strong>raw_id:</strong> <code>{esc(rid)}</code> "
        f"(source=<code>{esc(rec.source)}</code>, mode=<code>{esc(rec.ingest_mode)}</code>, offset=<code>{rec.line_offset}</code>)</div>"
        f"<pre>{esc(rec.raw_payload)}</pre></div>"
        for rid, rec in inc.raw_logs_by_id.items()
    )

    approval_rows = "".join(
        f"<tr><td><code>{esc(ap.approval_id)}</code></td><td>{esc(ap.action_type)}</td>"
        f"<td><span class='badge b-{esc(ap.status)}'>{esc(ap.status)}</span></td>"
        f"<td><code>{esc(ap.target_ip)}</code></td><td>{esc(ap.approved_by)}</td>"
        f"<td><code>{esc(ap.expires_at_utc)}</code></td>"
        f"<td><code>{esc(json.dumps(ap.gateway_response, ensure_ascii=False))}</code></td></tr>"
        for ap in inc.approvals
    ) or "<tr><td colspan='7'>아직 승인·조치 이력이 없습니다.</td></tr>"

    auth_ok = (not auth_enabled) or bool(current_user)
    can_approve = auth_ok and inc.live_and_trusted_eligible and inc.status in {"open", "released"}
    disabled_attr = "" if can_approve else "disabled"

    notices: list[str] = []
    if auth_enabled and not current_user:
        notices.append('<div class="notice">조치 승인 및 해제를 실행하려면 먼저 <a href="/login">로그인</a>해야 합니다.</div>')
    if not inc.live_and_trusted_eligible:
        notices.append('<div class="notice">합성(synthetic)·재생(replay) 또는 미신뢰 IP(client_ip_trusted=false) 근거에서는 실제 차단을 승인할 수 없습니다.</div>')
    gate_msg = "".join(notices)

    actor_input = (
        f'<span>승인자: <strong>{esc(current_user)}</strong></span>'
        if auth_enabled and current_user
        else f'<label>승인자: <input type="text" name="approved_by" value="soc-operator" required {disabled_attr} /></label>'
    )

    latest_applied = next((ap for ap in reversed(inc.approvals) if ap.status == "applied"), None)
    release_html = ""
    if latest_applied is not None:
        rel_disabled = "" if auth_ok else "disabled"
        release_html = f"""
        <form method="post" action="/incidents/{esc(inc.incident_id)}/release" style="display:inline-block; margin-left:10px;">
          <input type="hidden" name="approval_id" value="{esc(latest_applied.approval_id)}" />
          <button type="submit" class="secondary" {rel_disabled}>차단 해제 요청 ({esc(latest_applied.approval_id)})</button>
        </form>
        <form method="post" action="/incidents/{esc(inc.incident_id)}/refresh" style="display:inline-block; margin-left:8px;">
          <input type="hidden" name="approval_id" value="{esc(latest_applied.approval_id)}" />
          <button type="submit" class="secondary">상태 조회</button>
        </form>
        """

    body = f"""
    <p><a href="/">← 사건 목록으로</a></p>
    {err_html}
    <div class="panel">
      <h2>사건 상세: <code>{esc(inc.incident_id)}</code></h2>
      <p><strong>제목:</strong> {esc(inc.title)} &nbsp;|&nbsp;
         <strong>상태:</strong> <span class="badge b-{esc(inc.status)}">{esc(inc.status)}</span> &nbsp;|&nbsp;
         <strong>대상 IP:</strong> <code>{esc(inc.target_ip)}</code> &nbsp;|&nbsp;
         <strong>계정:</strong> {esc(inc.username)}</p>
    </div>

    <div class="panel">
      <h2>1. 경보 (Alerts)</h2>
      <table>
        <thead><tr><th>경보 ID</th><th>규칙 ID</th><th>규칙명</th><th>실패 횟수</th><th>시간창(UTC)</th></tr></thead>
        <tbody>{alert_rows}</tbody>
      </table>
    </div>

    <div class="panel">
      <h2>2. 근거 이벤트 (Evidence Events → raw_id)</h2>
      <table>
        <thead><tr><th>event_id</th><th>출처</th><th>시각(UTC)</th><th>request_id</th><th>client_ip</th><th>mode</th><th>원본 raw_id</th></tr></thead>
        <tbody>{ev_rows}</tbody>
      </table>
    </div>

    <div class="panel">
      <h2>3. 상관분석 연결 (Caddy request_id / 게이트웨이 후보)</h2>
      <table>
        <thead><tr><th>연결 유형</th><th>event_id</th><th>근거 설명</th><th>원본 raw_id</th></tr></thead>
        <tbody>{corr_rows}</tbody>
      </table>
    </div>

    <div class="panel">
      <h2>4. 사람 승인 및 방화벽 조치</h2>
      {gate_msg}
      <form method="post" action="/incidents/{esc(inc.incident_id)}/approve" style="display:inline-block;">
        {actor_input}
        <label style="margin-left:8px;">차단 시간(분, 최대 30): <input type="number" name="duration_minutes" value="10" min="1" max="30" required {disabled_attr} /></label>
        <button type="submit" {disabled_attr} style="margin-left:8px;">시험 단말 차단 승인</button>
      </form>
      {release_html}
      <h3 style="font-size:14px; margin-top:16px;">승인·조치 이력</h3>
      <table>
        <thead><tr><th>승인 ID</th><th>유형</th><th>상태</th><th>대상 IP</th><th>승인자</th><th>만료(UTC)</th><th>게이트웨이 응답</th></tr></thead>
        <tbody>{approval_rows}</tbody>
      </table>
    </div>

    <div class="panel">
      <h2>5. 원본 로그 추적 (raw_logs)</h2>
      {raw_blocks}
    </div>
    """
    return _page_shell(f"사건 {inc.incident_id}", body, current_user=current_user, auth_enabled=auth_enabled)


def make_handler(
    store: DashboardStore | DbDashboardStore,
    auth_config: AuthConfig | None = None,
) -> type[BaseHTTPRequestHandler]:
    auth_enabled = auth_config is not None

    class SocDashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _current_user(self) -> str | None:
            if auth_config is None:
                return None
            cookie_header = self.headers.get("Cookie", "")
            cookie: SimpleCookie[str] = SimpleCookie()
            cookie.load(cookie_header)
            morsel = cookie.get("soc_session")
            return auth_config.verify_session(morsel.value if morsel else None)

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _redirect(self, location: str, set_cookie: str | None = None) -> None:
            self.send_response(HTTPStatus.SEE_OTHER)
            if set_cookie:
                self.send_header("Set-Cookie", set_cookie)
            self.send_header("Location", location)
            self.end_headers()

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            user = self._current_user()

            if path == "/login" and auth_enabled:
                qs = urllib.parse.parse_qs(parsed.query)
                self._send(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    render_login_page(qs.get("error", [None])[0]),
                )
                return

            if path == "/":
                self._send(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    render_incident_list(store, current_user=user, auth_enabled=auth_enabled),
                )
                return

            if path == "/api/incidents":
                payload = [asdict(inc) for inc in store.list_incidents()]
                self._send(
                    HTTPStatus.OK,
                    "application/json; charset=utf-8",
                    json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                )
                return

            if path.startswith("/incidents/"):
                inc_id = urllib.parse.unquote(path[len("/incidents/") :])
                inc = store.get_incident(inc_id)
                if inc is None:
                    self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"Incident not found")
                    return
                qs = urllib.parse.parse_qs(parsed.query)
                err = qs.get("error", [None])[0]
                self._send(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    render_incident_detail(inc, err, current_user=user, auth_enabled=auth_enabled),
                )
                return

            self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"Not found")

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
            form = urllib.parse.parse_qs(raw_body)

            if path == "/login" and auth_config is not None:
                uname = form.get("username", [""])[0]
                pw = form.get("password", [""])[0]
                if not auth_config.verify_credentials(uname, pw):
                    self._send(
                        HTTPStatus.UNAUTHORIZED,
                        "text/html; charset=utf-8",
                        render_login_page("아이디 또는 비밀번호가 올바르지 않습니다."),
                    )
                    return
                token = auth_config.sign_session(uname)
                self._redirect("/", set_cookie=f"soc_session={token}; Path=/; HttpOnly; SameSite=Lax")
                return

            if path == "/logout" and auth_enabled:
                self._redirect("/login", set_cookie="soc_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
                return

            if path.startswith("/incidents/") and (
                path.endswith("/approve") or path.endswith("/release") or path.endswith("/refresh")
            ):
                user = self._current_user()
                if auth_enabled and not user:
                    self._send(HTTPStatus.UNAUTHORIZED, "text/plain; charset=utf-8", b"Authentication required")
                    return

                action_suffix = "/" + path.rsplit("/", 1)[-1]
                inc_id = urllib.parse.unquote(path[len("/incidents/") : -len(action_suffix)])
                inc = store.get_incident(inc_id)
                if inc is None:
                    self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"Incident not found")
                    return

                if action_suffix == "/approve":
                    approved_by = user if (auth_enabled and user) else form.get("approved_by", [""])[0]
                    try:
                        duration = int(form.get("duration_minutes", ["10"])[0])
                        ap = request_human_approval(
                            inc,
                            approved_by=approved_by,
                            duration_minutes=duration,
                            action_client=store.action_client,
                        )
                        store.persist_approval(inc, ap)
                    except (ValueError, ActionPolicyError) as exc:
                        q = urllib.parse.urlencode({"error": str(exc)})
                        self._redirect(f"/incidents/{urllib.parse.quote(inc_id)}?{q}")
                        return
                elif action_suffix == "/release":
                    approval_id = form.get("approval_id", [""])[0]
                    ap = release_approval(inc, approval_id=approval_id, action_client=store.action_client)
                    if ap is not None:
                        store.persist_approval(inc, ap)
                elif action_suffix == "/refresh":
                    approval_id = form.get("approval_id", [""])[0]
                    ap = refresh_approval_status(inc, approval_id=approval_id, action_client=store.action_client)
                    if ap is not None:
                        store.persist_approval(inc, ap)

                self._redirect(f"/incidents/{urllib.parse.quote(inc_id)}")
                return

            self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"Not found")

    return SocDashboardHandler


def load_sample_store() -> DashboardStore:
    """Load sample ERP login-failure events for local UI preview."""
    root = Path(__file__).resolve().parents[2]
    sample_file = root / "samples" / "erp_login_failures.jsonl"
    raws: list[RawLogRecord] = []
    events: list[NormalizedEvent] = []
    if sample_file.exists():
        offset = 0
        for line in sample_file.read_bytes().splitlines(keepends=True):
            raw_rec, norm_evt = normalize_log_line(
                line.decode("utf-8"),
                source="erp",
                file_path="erp_login_failures.jsonl",
                line_offset=offset,
                collection_mode="synthetic",
            )
            offset += len(line)
            raws.append(raw_rec)
            events.append(norm_evt)
    incidents = build_incidents(raws, events)
    return DashboardStore(incidents=incidents)


def run_server(
    host: str = "127.0.0.1",
    port: int = 8050,
    store: DashboardStore | DbDashboardStore | None = None,
    auth_config: AuthConfig | None = None,
) -> None:
    allow_container = os.environ.get("SOC_ALLOW_CONTAINER_BIND") == "1"
    if host != "127.0.0.1" and not (allow_container and host == "0.0.0.0"):
        raise ValueError("Dashboard must bind only to 127.0.0.1 (or 0.0.0.0 inside container)")

    active_store = store or load_sample_store()
    server = ThreadingHTTPServer((host, port), make_handler(active_store, auth_config=auth_config))
    print(f"SOC Dashboard listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        active_store.close()


if __name__ == "__main__":
    port_env = int(os.environ.get("SOC_DASHBOARD_PORT", "8050"))
    bind_host = os.environ.get("SOC_DASHBOARD_BIND", "127.0.0.1")
    db_dsn = os.environ.get("SOC_DB_DSN", "").strip()

    if db_dsn:
        action_url = os.environ.get("SOC_ACTION_API_URL", "").strip()
        action_token = os.environ.get("SOC_ACTION_API_TOKEN", "").strip()
        client = ActionApiClient(action_url, action_token) if (action_url and action_token) else None
        pg_storage = PostgresSocStorage(db_dsn)
        db_store: DbDashboardStore | DashboardStore = DbDashboardStore(pg_storage, action_client=client)
        op_user = os.environ.get("SOC_OPERATOR_USER", "soc-operator")
        op_pass = os.environ.get("SOC_OPERATOR_PASSWORD", "")
        sess_secret = os.environ.get("SOC_SESSION_SECRET", "")
        auth = AuthConfig(username=op_user, password=op_pass, secret=sess_secret or None)
        run_server(host=bind_host, port=port_env, store=db_store, auth_config=auth)
    else:
        run_server(host=bind_host, port=port_env)
