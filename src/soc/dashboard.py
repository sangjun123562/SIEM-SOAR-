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

from .detector import MULTI_ACCOUNT_RULE_ID, MULTI_SOURCE_RULE_ID
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

    def list_recent_events(
        self,
        limit: int = 50,
        *,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
    ) -> list[dict[str, Any]]:
        seen: set[str] = set()
        rows: list[dict[str, Any]] = []
        for inc in self.incidents.values():
            for ev in list(inc.evidence_events):
                if ev.event_id in seen:
                    continue
                if source is not None and ev.source != source:
                    continue
                if event_types and ev.event_type not in event_types:
                    continue
                seen.add(ev.event_id)
                rows.append(
                    {
                        "event_ts_utc": ev.event_ts_utc,
                        "received_at_utc": ev.event_ts_utc,
                        "source": ev.source,
                        "event_type": ev.event_type,
                        "outcome": ev.outcome,
                        "username": ev.username,
                        "client_ip": ev.client_ip,
                        "src_ip": ev.src_ip,
                        "src_port": ev.src_port,
                        "dst_ip": ev.dst_ip,
                        "dst_port": ev.dst_port,
                        "device_ip": ev.client_ip or ev.src_ip or "-",
                        "client_ip_trusted": ev.client_ip_trusted,
                        "request_id": ev.request_id,
                        "http_method": ev.http_method,
                        "http_path": ev.http_path,
                        "status_code": ev.status_code,
                        "ingest_mode": ev.ingest_mode,
                        "raw_id": ev.raw_id,
                        "rule_id": ev.details.get("rule_id"),
                    }
                )
        rows.sort(key=lambda r: r["event_ts_utc"], reverse=True)
        return rows[:limit]

    def get_hourly_summary(self) -> dict[str, int]:
        return {
            "erp_login_success": 0,
            "erp_login_failed": len(self.list_recent_events(limit=500, source="erp", event_types=("login_failed",))),
            "fw_allow": 0,
            "fw_deny": 0,
            "caddy_requests": 0,
            "caddy_errors": 0,
        }

    def list_source_stats(self) -> list[dict[str, Any]]:
        by_source: dict[str, dict[str, Any]] = {}
        for ev in self.list_recent_events(limit=500):
            src = ev["source"]
            entry = by_source.setdefault(src, {"source": src, "count": 0, "last_received_utc": ev["received_at_utc"]})
            entry["count"] += 1
            if ev["received_at_utc"] > entry["last_received_utc"]:
                entry["last_received_utc"] = ev["received_at_utc"]
        return [by_source[k] for k in sorted(by_source)]

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

    def list_recent_events(
        self,
        limit: int = 50,
        *,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
    ) -> list[dict[str, Any]]:
        return self.repo.fetch_recent_events(limit=limit, source=source, event_types=event_types)

    def get_hourly_summary(self) -> dict[str, int]:
        return self.repo.fetch_hourly_summary()

    def list_source_stats(self) -> list[dict[str, Any]]:
        return self.repo.fetch_source_stats()

    def persist_approval(self, inc: IncidentView, approval: Any) -> None:
        self.repo.save_approval(approval, inc.status, inc.updated_at_utc)

    def close(self) -> None:
        close_fn = getattr(self.storage, "close", None)
        if callable(close_fn):
            close_fn()


def _page_shell(
    title: str,
    body_html: str,
    current_user: str | None = None,
    auth_enabled: bool = False,
    refresh_seconds: int | None = None,
    active_path: str = "/",
) -> bytes:
    auth_box = ""
    if auth_enabled:
        if current_user:
            auth_box = (
                f'<div class="side-user">담당자: <strong>{html.escape(current_user)}</strong>'
                f'<form method="post" action="/logout" style="margin-top:8px;">'
                f'<button type="submit" class="secondary" style="width:100%;padding:6px 10px;font-size:12px;">로그아웃</button></form></div>'
            )
        else:
            auth_box = '<div class="side-user"><a href="/login">담당자 로그인 →</a></div>'

    nav_items = [
        ("/", "📊 현황 요약 · 사건 목록"),
        ("/logs/erp", "🔐 ERP 로그인 기록"),
        ("/logs/gateway", "🛡️ 방화벽(게이트웨이) 기록"),
        ("/logs/caddy", "🌐 웹(Caddy) 기록"),
        ("/events", "📋 전체 최근 이벤트"),
    ]
    nav_html = "".join(
        f'<a class="nav-link{" active" if active_path == href else ""}" href="{href}">{label}</a>'
        for href, label in nav_items
    )

    logo_svg = (
        '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
        '<path d="M12 2L4 5.5V11.5C4 16.8 7.4 21.6 12 23C16.6 21.6 20 16.8 20 11.5V5.5L12 2Z" '
        'fill="#0284c7" fill-opacity="0.22" stroke="#38bdf8" stroke-width="1.8"/>'
        '<circle cx="12" cy="12" r="3" fill="#38bdf8"/>'
        '<path d="M12 6.5V9M12 15V17.5M6.5 12H9M15 12H17.5" stroke="#7dd3fc" stroke-width="1.5" stroke-linecap="round"/>'
        "</svg>"
    )

    refresh_meta = f'<meta http-equiv="refresh" content="{int(refresh_seconds)}" />' if refresh_seconds else ""

    doc = f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  {refresh_meta}
  <title>{html.escape(title)}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #0b1120; color: #e2e8f0; }}
    .layout {{ display: flex; min-height: 100vh; }}
    aside.sidebar {{ width: 252px; flex-shrink: 0; background: #111c33; border-right: 1px solid #23324d; padding: 20px 14px; display: flex; flex-direction: column; justify-content: space-between; }}
    .brand {{ display: flex; align-items: center; gap: 10px; padding: 4px 6px 16px; border-bottom: 1px solid #23324d; margin-bottom: 14px; }}
    .brand-title {{ font-size: 15px; font-weight: 700; color: #f8fafc; line-height: 1.2; }}
    .brand-sub {{ font-size: 11px; color: #64748b; margin-top: 2px; }}
    .nav-section {{ font-size: 11px; color: #64748b; text-transform: uppercase; margin: 14px 8px 6px; letter-spacing: 0.05em; font-weight: 600; }}
    .nav-link {{ display: block; padding: 9px 12px; border-radius: 8px; color: #cbd5e1; font-size: 13px; margin-bottom: 4px; text-decoration: none; transition: background 0.15s, color 0.15s; }}
    .nav-link:hover {{ background: #1e293b; color: #f8fafc; text-decoration: none; }}
    .nav-link.active {{ background: linear-gradient(90deg, #0284c7, #0369a1); color: #ffffff; font-weight: 600; box-shadow: 0 2px 8px rgba(2,132,199,0.28); }}
    .side-user {{ border-top: 1px solid #23324d; padding-top: 12px; margin-top: 16px; font-size: 12px; color: #94a3b8; }}
    main.content {{ flex: 1; min-width: 0; padding: 26px 30px; max-width: 1240px; }}
    a {{ color: #38bdf8; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin-bottom: 20px; }}
    .card {{ background: #162238; border: 1px solid #263654; border-top: 3px solid #0284c7; border-radius: 10px; padding: 14px 16px; transition: border-color 0.15s; }}
    .card:hover {{ border-color: #38bdf8; }}
    .card .label {{ font-size: 12px; color: #94a3b8; }}
    .card .val {{ font-size: 23px; font-weight: 700; margin-top: 5px; color: #f8fafc; }}
    .panel {{ background: #162238; border: 1px solid #263654; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 14px rgba(0,0,0,0.18); }}
    .panel h2 {{ margin: 0 0 14px 0; font-size: 16px; color: #f8fafc; }}
    .chain {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 14px; font-size: 12px; }}
    .chain-step {{ background: #0b1120; border: 1px solid #2c3f63; border-radius: 8px; padding: 7px 11px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #23324d; vertical-align: top; }}
    th {{ color: #94a3b8; font-weight: 600; background: #111c33; }}
    tbody tr:hover {{ background: rgba(56, 189, 248, 0.05); }}
    .badge {{ display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; }}
    .b-open {{ background: #7c2d12; color: #fdba74; }}
    .b-approved {{ background: #1e3a8a; color: #93c5fd; }}
    .b-blocked, .b-applied, .b-rejected {{ background: #7f1d1d; color: #fca5a5; }}
    .b-released, .b-expired {{ background: #14532d; color: #86efac; }}
    .b-ok {{ background: #14532d; color: #86efac; }}
    .b-warn {{ background: #78350f; color: #fcd34d; }}
    code, pre {{ background: #0b1120; border: 1px solid #263654; border-radius: 6px; padding: 2px 6px; font-size: 12px; color: #cbd5e1; }}
    pre {{ padding: 10px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
    button {{ background: #ef4444; color: #fff; border: 0; border-radius: 7px; padding: 8px 14px; font-weight: 600; cursor: pointer; transition: opacity 0.15s; }}
    button:hover:not(:disabled) {{ opacity: 0.9; }}
    button.secondary {{ background: #0284c7; }}
    button:disabled {{ background: #475569; cursor: not-allowed; }}
    input, select {{ background: #0b1120; color: #e2e8f0; border: 1px solid #334155; border-radius: 6px; padding: 7px 10px; }}
    .notice {{ background: #451a03; border: 1px solid #b45309; color: #fde68a; padding: 10px 12px; border-radius: 8px; font-size: 13px; margin-bottom: 12px; }}
  </style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <div>
        <div class="brand">
          {logo_svg}
          <div>
            <div class="brand-title">SIEM·SOAR 관제</div>
            <div class="brand-sub">Capstone SOC · B</div>
          </div>
        </div>
        <div class="nav-section">관제 메뉴</div>
        {nav_html}
        <div class="nav-section">데이터 API</div>
        <a class="nav-link" href="/api/incidents">사건 JSON API</a>
        <a class="nav-link" href="/api/events">이벤트 JSON API</a>
      </div>
      {auth_box}
    </aside>
    <main class="content">{body_html}</main>
  </div>
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


def _fmt_ts(ts_val: str | None) -> str:
    """ISO-8601 UTC 시각 문자열을 한국 시간(KST) + UTC 병기 형태로 읽기 쉽게 변환한다."""
    if not ts_val or ts_val == "수집 대기":
        return '<span style="color:#94a3b8;">수집 대기 중</span>'
    raw = str(ts_val).strip()
    try:
        iso_str = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_utc = dt.astimezone(timezone.utc)
        from datetime import timedelta
        dt_kst = dt_utc.astimezone(timezone(timedelta(hours=9)))
        kst_str = dt_kst.strftime("%Y-%m-%d %H:%M:%S")
        utc_hm = dt_utc.strftime("%H:%M:%S")
        return (
            f'<span title="{html.escape(raw)}" style="white-space:nowrap;">'
            f'<strong style="color:#0f172a;">{kst_str}</strong> '
            f'<span style="color:#64748b;font-size:11px;">KST ({utc_hm} UTC)</span>'
            f"</span>"
        )
    except Exception:
        return f"<code>{html.escape(raw)}</code>"


def _fmt_status(status: str) -> str:
    labels = {
        "open": ("b-open", "🚨 미조치 (open)"),
        "blocked": ("b-blocked", "🛑 차단 중 (blocked)"),
        "applied": ("b-applied", "🛑 차단 적용 중 (applied)"),
        "released": ("b-released", "✅ 차단 해제 (released)"),
        "approved": ("b-approved", "✔️ 승인됨 (approved)"),
        "expired": ("b-expired", "⏱️ 만료됨 (expired)"),
        "pending": ("b-warn", "⏳ 대기 중 (pending)"),
        "rejected": ("b-blocked", "❌ 거부됨 (rejected)"),
        "closed": ("b-released", "📁 종료 (closed)"),
    }
    cls, text = labels.get(status, (f"b-{html.escape(status)}", html.escape(status)))
    return f'<span class="badge {cls}">{text}</span>'


def _fmt_event_type(ev_type: str, outcome: str | None = None) -> str:
    esc = html.escape
    if ev_type == "login_success":
        return '<span class="badge b-ok">✅ 로그인 성공 <small>(login_success)</small></span>'
    if ev_type == "login_failed":
        return '<span class="badge b-blocked">🚨 로그인 실패 <small>(login_failed)</small></span>'
    if ev_type == "logout":
        return '<span class="badge b-approved">🚪 로그아웃 <small>(logout)</small></span>'
    if ev_type == "fw_allow":
        return '<span class="badge b-ok">🟢 통과·허용 <small>(fw_allow)</small></span>'
    if ev_type == "fw_deny":
        return '<span class="badge b-blocked">🛑 방화벽 차단 <small>(fw_deny)</small></span>'
    if ev_type == "http_request":
        cls = "b-blocked" if outcome == "failure" else "b-approved"
        return f'<span class="badge {cls}">🌐 웹 요청 <small>(http_request)</small></span>'
    return f'<span class="badge b-approved">{esc(ev_type)}</span>'


def _fmt_ingest_mode(mode: str) -> str:
    if mode == "live":
        return '<span class="badge b-ok">🟢 실시간 (live)</span>'
    if mode == "replay":
        return '<span class="badge b-warn">🟡 재현 (replay)</span>'
    if mode == "synthetic":
        return '<span class="badge b-warn">🟣 가상 (synthetic)</span>'
    return f'<span class="badge b-warn">{html.escape(mode)}</span>'


def _fmt_source_badge(source: str) -> str:
    labels = {
        "erp": ("#eff6ff", "#1d4ed8", "🏢 ERP"),
        "gateway": ("#fef3c7", "#b45309", "🛡️ 방화벽(Gateway)"),
        "caddy": ("#f0fdf4", "#15803d", "🌐 웹(Caddy)"),
    }
    bg, fg, label = labels.get(source, ("#f1f5f9", "#334155", html.escape(source)))
    return (
        f'<span class="badge" style="background:{bg};color:{fg};" title="{html.escape(source)}">'
        f"{label}</span>"
    )


def _summarize_event_ko(ev: dict[str, Any]) -> str:
    esc = html.escape
    src = ev.get("source")
    et = ev.get("event_type")
    user = esc(str(ev.get("username") or "-"))
    cip = esc(str(ev.get("client_ip") or ev.get("device_ip") or "-"))
    if src == "erp":
        if et == "login_failed":
            return f"계정 <strong>{user}</strong> 로그인 실패 (단말 IP: <code>{cip}</code>)"
        if et == "login_success":
            return f"계정 <strong>{user}</strong> 정상 로그인 (단말 IP: <code>{cip}</code>)"
        if et == "logout":
            return f"계정 <strong>{user}</strong> 로그아웃 (단말 IP: <code>{cip}</code>)"
        return f"ERP 이벤트 (<code>{esc(str(et))}</code> · 계정: <strong>{user}</strong>)"
    if src == "gateway":
        sip = esc(str(ev.get("src_ip") or "-"))
        sport = esc(str(ev.get("src_port") or "-"))
        dip = esc(str(ev.get("dst_ip") or "-"))
        dport = esc(str(ev.get("dst_port") or "-"))
        rule_id = esc(str(ev.get("rule_id") or "-"))
        if et == "fw_allow":
            return f"단말 <code>{sip}:{sport}</code> → <code>{dip}:{dport}</code> 통신 허용"
        return f"단말 <code>{sip}:{sport}</code> → <code>{dip}:{dport}</code> 차단됨 (규칙: <code>{rule_id}</code>)"
    if src == "caddy":
        method = esc(str(ev.get("http_method") or "-"))
        path = esc(str(ev.get("http_path") or "-"))
        sc = ev.get("status_code")
        sc_str = str(sc) if sc is not None else "-"
        status_note = "오류/실패" if (sc is not None and int(sc) >= 400) else "정상 응답"
        return f"단말 <code>{cip}</code> → <code>{method} {path}</code> 요청 ({status_note}: <strong>{esc(sc_str)}</strong>)"
    return f"<code>{esc(str(et))}</code> ({esc(str(ev.get('outcome') or '-'))})"


def _ratio_bar(ok_cnt: int, bad_cnt: int, ok_label: str, bad_label: str) -> str:
    total = ok_cnt + bad_cnt
    ok_pct = int(round((ok_cnt / total) * 100)) if total > 0 else 50
    bad_pct = 100 - ok_pct if total > 0 else 50
    bar_bg = (
        f'<div style="display:flex;height:8px;border-radius:999px;overflow:hidden;background:#e2e8f0;margin-top:8px;">'
        f'<div style="width:{ok_pct}%;background:#22c55e;"></div>'
        f'<div style="width:{bad_pct}%;background:#ef4444;"></div>'
        f"</div>"
        if total > 0
        else '<div style="height:8px;border-radius:999px;background:#e2e8f0;margin-top:8px;"></div>'
    )
    return (
        f'<div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px;font-size:14px;">'
        f'<span style="color:#15803d;font-weight:700;">🟢 {ok_label} {ok_cnt}건</span>'
        f'<span style="color:#b91c1c;font-weight:700;">🔴 {bad_label} {bad_cnt}건</span>'
        f"</div>"
        f"{bar_bg}"
        f'<div class="label" style="margin-top:4px;">최근 1시간 총 {total}건</div>'
    )


def render_incident_list(
    store: DashboardStore | DbDashboardStore,
    current_user: str | None = None,
    auth_enabled: bool = False,
) -> bytes:
    esc = html.escape
    incidents = store.list_incidents()
    open_cnt = sum(1 for i in incidents if i.status == "open")
    blocked_cnt = sum(1 for i in incidents if i.status == "blocked")
    released_cnt = sum(1 for i in incidents if i.status == "released")
    hourly = store.get_hourly_summary()
    stats_map = {s["source"]: s for s in store.list_source_stats()}

    def _src_card(src_key: str, label: str) -> str:
        st = stats_map.get(src_key)
        last_ts = st["last_received_utc"] if st else "수집 대기"
        cnt = int(st["count"]) if st else 0
        state_badge = (
            '<span class="badge b-ok" style="float:right;">● 수집 정상</span>'
            if st and cnt > 0
            else '<span class="badge b-warn" style="float:right;">○ 대기 중</span>'
        )
        return (
            f'<div class="card">'
            f'<div class="label">{esc(label)} 수집 현황 {state_badge}</div>'
            f'<div class="val" style="font-size:20px;margin:6px 0;">누적 {cnt:,}건</div>'
            f'<div class="label">마지막 수집: {_fmt_ts(last_ts)}</div>'
            f"</div>"
        )

    rows = []
    for inc in incidents:
        live_badge = (
            '<span class="badge b-ok" title="live + trusted">✅ 즉시 차단 가능 (실시간·신뢰 IP)</span>'
            if inc.live_and_trusted_eligible
            else '<span class="badge b-warn">⚠️ 차단 불가 (비라이브/미신뢰)</span>'
        )
        if not inc.block_rule_eligible:
            live_badge = '<span class="badge b-warn">조사용 · 차단 불가</span>'
        rows.append(
            f"<tr>"
            f"<td><a href='/incidents/{esc(inc.incident_id)}'><strong><code>{esc(inc.incident_id)}</code></strong></a></td>"
            f"<td><strong>{esc(inc.title)}</strong></td>"
            f"<td>{_fmt_status(inc.status)}</td>"
            f"<td><code style='font-size:13px;font-weight:700;color:#b91c1c;'>{esc(inc.target_ip or '여러 출발지')}</code></td>"
            f"<td><strong>{esc(inc.username or '여러 계정')}</strong></td>"
            f"<td>{live_badge}</td>"
            f"<td>{_fmt_ts(inc.created_at_utc)}</td>"
            f"<td><a href='/incidents/{esc(inc.incident_id)}'><button type='button' class='secondary' style='padding:4px 10px;font-size:12px;'>상세 · 조치 →</button></a></td>"
            f"</tr>"
        )

    table_body = "".join(rows) if rows else "<tr><td colspan='8'>탐지된 보안 사건이 없습니다.</td></tr>"
    body = f"""
    <div class="cards">
      {_src_card("erp", "🏢 ERP 인증 로그")}
      {_src_card("caddy", "🌐 Caddy(웹 프록시)")}
      {_src_card("gateway", "🛡️ 게이트웨이(방화벽)")}
      <div class="card">
        <div class="label">보안 사건 · 차단 요약</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
          <span class="badge b-open" style="font-size:13px;">🚨 미조치 사건 {open_cnt}건</span>
          <span class="badge b-blocked" style="font-size:13px;">🛑 차단 적용 중 {blocked_cnt}건</span>
          <span class="badge b-released" style="font-size:13px;">✅ 해제·복구 {released_cnt}건</span>
        </div>
        <div class="label" style="margin-top:8px;">전체 누적 사건: {len(incidents)}건</div>
      </div>
    </div>
    <div class="cards">
      <div class="card">
        <div class="label">최근 1시간 ERP 로그인 현황</div>
        {_ratio_bar(hourly["erp_login_success"], hourly["erp_login_failed"], "성공", "실패")}
      </div>
      <div class="card">
        <div class="label">최근 1시간 방화벽 트래픽 현황</div>
        {_ratio_bar(hourly["fw_allow"], hourly["fw_deny"], "허용", "차단")}
      </div>
      <div class="card">
        <div class="label">최근 1시간 웹(Caddy) 응답 현황</div>
        {_ratio_bar(max(0, hourly["caddy_requests"] - hourly["caddy_errors"]), hourly["caddy_errors"], "정상", "오류")}
      </div>
    </div>
    <div class="panel">
      <h2>🚨 탐지된 보안 사건 목록 (5분 내 로그인 실패 5회 이상)</h2>
      <table>
        <thead><tr><th>사건 ID</th><th>사건 내용</th><th>현재 상태</th><th>공격 의심 IP</th><th>대상 계정</th><th>조치 가능 여부</th><th>발생 시각</th><th>상세 / 조치</th></tr></thead>
        <tbody>{table_body}</tbody>
      </table>
    </div>
    """
    return _page_shell("관제 대시보드 · 현황 및 사건 목록", body, current_user=current_user, auth_enabled=auth_enabled)


def render_source_logs(
    store: DashboardStore | DbDashboardStore,
    log_kind: str,
    current_user: str | None = None,
    auth_enabled: bool = False,
) -> bytes:
    esc = html.escape
    if log_kind == "erp":
        title = "🏢 ERP 로그인·로그아웃 기록 (최신 50건 · 5초 자동 새로고침)"
        events = store.list_recent_events(
            limit=50, source="erp", event_types=("login_success", "login_failed", "logout")
        )
        headers = "<tr><th>발생 시각</th><th>구분</th><th>로그 내용 요약</th><th>계정</th><th>단말 IP</th><th>IP 신뢰 여부</th><th>수집 방식</th><th>추적 ID (request_id / raw_id)</th></tr>"
        rows = "".join(
            f"<tr>"
            f"<td>{_fmt_ts(ev['event_ts_utc'])}</td>"
            f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
            f"<td>{_summarize_event_ko(ev)}</td>"
            f"<td><strong>{esc(ev.get('username') or '-')}</strong></td>"
            f"<td><code>{esc(ev.get('client_ip') or '-')}</code></td>"
            f"<td>{'<span class=\"badge b-ok\">✅ 신뢰됨</span>' if ev['client_ip_trusted'] else '<span class=\"badge b-warn\">⚠️ 미신뢰</span>'}</td>"
            f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
            f"<td><div style='font-size:11px;color:#475569;'>요청: <code>{esc(ev.get('request_id') or '-')}</code><br/>원본: <code>{esc(ev['raw_id'][:14])}...</code></div></td>"
            f"</tr>"
            for ev in events
        )
        colspan = 8
    elif log_kind == "gateway":
        title = "🛡️ 방화벽(게이트웨이) 허용·차단 기록 (최신 50건 · 5초 자동 새로고침)"
        events = store.list_recent_events(limit=50, source="gateway")
        headers = "<tr><th>발생 시각</th><th>동작</th><th>로그 내용 요약</th><th>출발지 → 목적지:포트</th><th>적용 규칙 구분</th><th>수집 방식</th><th>원본 raw_id</th></tr>"
        row_list = []
        for ev in events:
            rule_id = ev.get("rule_id") or "-"
            if rule_id == "POLICY-CLIENT-CADDY-ONLY":
                rule_html = f'<span class="badge b-warn">⚠️ 정책 차단 ({esc(rule_id)})</span>'
            elif isinstance(rule_id, str) and rule_id.startswith("APR-"):
                rule_html = f'<span class="badge b-blocked">🛑 관제 승인 차단 ({esc(rule_id)})</span>'
            else:
                rule_html = f"<code>{esc(str(rule_id))}</code>"
            src_ep = f"{ev.get('src_ip') or '-'}:{ev.get('src_port') or '-'}"
            dst_ep = f"{ev.get('dst_ip') or '-'}:{ev.get('dst_port') or '-'}"
            row_list.append(
                f"<tr>"
                f"<td>{_fmt_ts(ev['event_ts_utc'])}</td>"
                f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
                f"<td>{_summarize_event_ko(ev)}</td>"
                f"<td><code>{esc(src_ep)}</code> → <code>{esc(dst_ep)}</code></td>"
                f"<td>{rule_html}</td>"
                f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
                f"<td><code>{esc(ev['raw_id'][:14])}...</code></td>"
                f"</tr>"
            )
        rows = "".join(row_list)
        colspan = 7
    else:
        title = "🌐 웹(Caddy HTTPS) 요청 기록 (최신 50건 · 5초 자동 새로고침)"
        events = store.list_recent_events(limit=50, source="caddy")
        headers = "<tr><th>발생 시각</th><th>응답 상태</th><th>로그 내용 요약</th><th>HTTP 요청</th><th>단말 IP</th><th>추적 request_id</th><th>수집 방식</th></tr>"
        row_list = []
        for ev in events:
            sc = ev.get("status_code")
            is_err = sc is not None and int(sc) >= 400
            sc_html = (
                f'<span class="badge b-blocked">⚠️ {int(sc)} 오류</span>'
                if is_err
                else f'<span class="badge b-ok">✅ {sc if sc is not None else "-"} 정상</span>'
            )
            req_str = f"{ev.get('http_method') or '-'} {ev.get('http_path') or '-'}"
            row_list.append(
                f"<tr>"
                f"<td>{_fmt_ts(ev['event_ts_utc'])}</td>"
                f"<td>{sc_html}</td>"
                f"<td>{_summarize_event_ko(ev)}</td>"
                f"<td><code>{esc(req_str)}</code></td>"
                f"<td><code>{esc(ev.get('client_ip') or '-')}</code></td>"
                f"<td><code>{esc(ev.get('request_id') or '-')}</code></td>"
                f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
                f"</tr>"
            )
        rows = "".join(row_list)
        colspan = 7

    table_body = rows or f"<tr><td colspan='{colspan}'>수집된 로그가 없습니다.</td></tr>"
    body = f"""
    <div class="panel">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <h2 style="margin:0;">{esc(title)}</h2>
        <a href="/logs/{esc(log_kind)}"><button type="button" class="secondary">지금 새로고침</button></a>
      </div>
      <table><thead>{headers}</thead><tbody>{table_body}</tbody></table>
    </div>
    """
    return _page_shell(
        f"관제 대시보드 · {log_kind.upper()}",
        body,
        current_user=current_user,
        auth_enabled=auth_enabled,
        refresh_seconds=5,
        active_path=f"/logs/{log_kind}",
    )


def render_recent_events(
    store: DashboardStore | DbDashboardStore,
    current_user: str | None = None,
    auth_enabled: bool = False,
) -> bytes:
    esc = html.escape
    stats = store.list_source_stats()
    events = store.list_recent_events(limit=50)

    stat_cards = "".join(
        f'<div class="card"><div class="label">{_fmt_source_badge(s["source"])} 수집 현황</div>'
        f'<div class="val" style="font-size:18px;margin:6px 0;">누적 {int(s["count"]):,}건</div>'
        f'<div class="label">마지막 수집: {_fmt_ts(s["last_received_utc"])}</div></div>'
        for s in stats
    ) or '<div class="card"><div class="label">수집 상태</div><div class="val" style="font-size:16px;">아직 수집된 로그 없음</div></div>'

    rows = "".join(
        f"<tr>"
        f"<td>{_fmt_ts(ev['event_ts_utc'])}</td>"
        f"<td>{_fmt_source_badge(ev['source'])}</td>"
        f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
        f"<td>{_summarize_event_ko(ev)}</td>"
        f"<td><strong>{esc(ev.get('username') or '-')}</strong></td>"
        f"<td><code>{esc(ev.get('device_ip') or '-')}</code></td>"
        f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
        f"<td><code title='{esc(ev['raw_id'])}'>{esc(ev['raw_id'][:14])}...</code></td>"
        f"</tr>"
        for ev in events
    ) or "<tr><td colspan='8'>수집된 이벤트가 없습니다.</td></tr>"

    body = f"""
    <div class="cards">{stat_cards}</div>
    <div class="panel">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <h2 style="margin:0;">📋 통합 최근 이벤트 (최신 50건 · 5초마다 자동 새로고침)</h2>
        <a href="/events"><button type="button" class="secondary">지금 새로고침</button></a>
      </div>
      <table>
        <thead><tr><th>발생 시각</th><th>출처</th><th>이벤트 종류</th><th>로그 내용 요약</th><th>계정</th><th>단말 IP</th><th>수집 방식</th><th>원본 raw_id</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    """
    return _page_shell(
        "관제 대시보드 · 최근 이벤트",
        body,
        current_user=current_user,
        auth_enabled=auth_enabled,
        refresh_seconds=5,
        active_path="/events",
    )


def _pretty_json_payload(raw_payload: str) -> str:
    try:
        parsed = json.loads(raw_payload)
        return json.dumps(parsed, ensure_ascii=False, indent=2)
    except Exception:
        return raw_payload


def render_incident_detail(
    inc: IncidentView,
    error_msg: str | None = None,
    current_user: str | None = None,
    auth_enabled: bool = False,
) -> bytes:
    esc = html.escape
    err_html = f'<div class="notice">{esc(error_msg)}</div>' if error_msg else ""
    failure_labels = {
        MULTI_ACCOUNT_RULE_ID: "개 계정명 실패",
        MULTI_SOURCE_RULE_ID: "개 출발지 실패",
    }

    alert_rows = "".join(
        f"<tr><td><code>{esc(a.alert_id)}</code></td><td><code>{esc(a.rule_id)}</code></td>"
        f"<td><strong>{esc(a.rule_name)}</strong></td>"
        f"<td>{a.failure_count}{failure_labels.get(a.rule_id, '회 연속 실패')}</td>"
        f"<td>{_fmt_ts(a.window_start_utc)} ~ {_fmt_ts(a.window_end_utc)}</td></tr>"
        for a in inc.alerts
    )

    ev_rows = "".join(
        f"<tr>"
        f"<td><code>{esc(ev.event_id[:12])}</code></td>"
        f"<td>{_fmt_source_badge(ev.source)}</td>"
        f"<td>{_fmt_ts(ev.event_ts_utc)}</td>"
        f"<td><code>{esc(ev.request_id or '-')}</code></td>"
        f"<td>{esc(ev.username or '-')}</td>"
        f"<td><code>{esc(ev.client_ip or '-')}</code> ({'✅ 신뢰 IP' if ev.client_ip_trusted else '⚠️ 미신뢰'})</td>"
        f"<td>{_fmt_ingest_mode(ev.ingest_mode)}</td>"
        f"<td><a href='#raw-{esc(ev.raw_id)}'><code>{esc(ev.raw_id[:16])}...</code></a></td>"
        f"</tr>"
        for ev in inc.evidence_events
    )

    corr_rows = "".join(
        f"<tr>"
        f"<td>{'<span class=\"badge b-ok\">🔗 request_id 정확 일치</span>' if c.link_type == 'request_id_exact' else '<span class=\"badge b-warn\">🔍 게이트웨이 근접 후보</span>'} <small>(<code>{esc(c.link_type)}</code>)</small></td>"
        f"<td><code>{esc(c.event_id[:12])}</code></td>"
        f"<td>{esc(c.reason)}</td>"
        f"<td><a href='#raw-{esc(c.raw_id)}'><code>{esc(c.raw_id[:16])}...</code></a></td></tr>"
        for c in inc.correlations
    ) or "<tr><td colspan='4'>연결된 Caddy/게이트웨이 상관 이벤트가 없습니다.</td></tr>"

    raw_blocks = "".join(
        f"<div id='raw-{esc(rid)}' style='margin-bottom:12px;padding:10px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;'>"
        f"<div style='margin-bottom:6px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;'>"
        f"{_fmt_source_badge(rec.source)} {_fmt_ingest_mode(rec.ingest_mode)} "
        f"<span><strong>원본 ID:</strong> <code>{esc(rid)}</code></span> "
        f"<span style='color:#64748b;font-size:12px;'>(파일 오프셋: <code>{rec.line_offset}</code>)</span></div>"
        f"<pre style='margin:0;'>{esc(_pretty_json_payload(rec.raw_payload))}</pre></div>"
        for rid, rec in inc.raw_logs_by_id.items()
    )

    approval_rows = "".join(
        f"<tr><td><code>{esc(ap.approval_id)}</code></td>"
        f"<td>{'🛑 IP 차단 (block)' if ap.action_type == 'block' else '✅ 차단 해제 (unblock)'}</td>"
        f"<td>{_fmt_status(ap.status)}</td>"
        f"<td><code>{esc(ap.target_ip)}</code></td><td><strong>{esc(ap.approved_by)}</strong></td>"
        f"<td>{_fmt_ts(ap.expires_at_utc)}</td>"
        f"<td><code>{esc(json.dumps(ap.gateway_response, ensure_ascii=False))}</code></td></tr>"
        for ap in inc.approvals
    ) or "<tr><td colspan='7'>아직 승인·조치 이력이 없습니다.</td></tr>"

    auth_ok = (not auth_enabled) or bool(current_user)
    can_approve = (
        auth_ok and inc.block_rule_eligible and inc.live_and_trusted_eligible
        and inc.status in {"open", "released"}
    )
    disabled_attr = "" if can_approve else "disabled"

    notices: list[str] = []
    if auth_enabled and not current_user:
        notices.append('<div class="notice">조치 승인 및 해제를 실행하려면 먼저 <a href="/login">로그인</a>해야 합니다.</div>')
    if not inc.block_rule_eligible:
        notices.append('<div class="notice">조사용 사건입니다. 방화벽 차단을 승인할 수 없습니다.</div>')
    elif not inc.live_and_trusted_eligible:
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
         <strong>대상 IP:</strong> <code>{esc(inc.target_ip or '여러 출발지')}</code> &nbsp;|&nbsp;
         <strong>계정:</strong> {esc(inc.username or '여러 계정')}</p>
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
        <thead><tr><th>event_id</th><th>출처</th><th>시각(UTC)</th><th>request_id</th><th>계정명</th><th>client_ip</th><th>mode</th><th>원본 raw_id</th></tr></thead>
        <tbody>{ev_rows}</tbody>
      </table>
    </div>

    <div class="panel">
      <h2>3. 연결 보기 (통합 관제 추적)</h2>
      <div class="chain">
        <span class="chain-step"><strong>1. ERP 로그인 실패</strong> ({len(inc.evidence_events)}건)</span>
        <span>──(<code>request_id</code> 정확 일치)──▶</span>
        <span class="chain-step"><strong>2. Caddy 웹 요청</strong> ({sum(1 for c in inc.correlations if c.link_type == "request_id_exact")}건)</span>
        <span>──(IP·포트·시각 근접 후보)──▶</span>
        <span class="chain-step"><strong>3. 게이트웨이 접속</strong> ({sum(1 for c in inc.correlations if c.link_type == "gateway_candidate")}건 · 단정 금지)</span>
      </div>
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
                if auth_enabled and not user:
                    self._redirect("/login")
                    return
                self._send(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    render_incident_list(store, current_user=user, auth_enabled=auth_enabled),
                )
                return

            if path in {"/logs/erp", "/logs/gateway", "/logs/caddy"}:
                if auth_enabled and not user:
                    self._redirect("/login")
                    return
                kind = path.rsplit("/", 1)[-1]
                self._send(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    render_source_logs(store, kind, current_user=user, auth_enabled=auth_enabled),
                )
                return

            if path == "/events":
                if auth_enabled and not user:
                    self._redirect("/login")
                    return
                self._send(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    render_recent_events(store, current_user=user, auth_enabled=auth_enabled),
                )
                return

            if path == "/api/events":
                if auth_enabled and not user:
                    self._send(HTTPStatus.UNAUTHORIZED, "text/plain; charset=utf-8", b"Authentication required")
                    return
                payload = {
                    "sources": store.list_source_stats(),
                    "events": store.list_recent_events(limit=50),
                }
                self._send(
                    HTTPStatus.OK,
                    "application/json; charset=utf-8",
                    json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                )
                return

            if path == "/api/incidents":
                if auth_enabled and not user:
                    self._send(HTTPStatus.UNAUTHORIZED, "text/plain; charset=utf-8", b"Authentication required")
                    return
                payload = [asdict(inc) for inc in store.list_incidents()]
                self._send(
                    HTTPStatus.OK,
                    "application/json; charset=utf-8",
                    json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                )
                return

            if path.startswith("/incidents/"):
                if auth_enabled and not user:
                    self._redirect("/login")
                    return
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
