from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import threading
import time
import urllib.parse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
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
from .repository import FOLLOWUP_LOGIN_MINUTES, FollowupLoginSuccess, SocRepository
from .storage import PostgresSocStorage, SocStorage


class LoginRateLimiter:
    """Thread-safe per-(client_ip, username) failed-login rate limiter."""

    def __init__(
        self,
        max_failures: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 60,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._lock = threading.Lock()
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    def check_lockout(self, key: str, now: float | None = None) -> int:
        ts = time.monotonic() if now is None else now
        with self._lock:
            until = self._locked_until.get(key, 0.0)
            if until > ts:
                return max(1, int(until - ts))
            self._locked_until.pop(key, None)
            return 0

    def record_failure(self, key: str, now: float | None = None) -> int:
        ts = time.monotonic() if now is None else now
        cutoff = ts - self.window_seconds
        with self._lock:
            hist = [t for t in self._failures.get(key, []) if t >= cutoff]
            hist.append(ts)
            self._failures[key] = hist
            if len(hist) >= self.max_failures:
                self._locked_until[key] = ts + self.lockout_seconds
                return self.lockout_seconds
            return 0

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)


class AuthConfig:
    """Operator session authentication, CSRF token, and rate-limit configuration."""

    def __init__(
        self,
        username: str,
        password: str,
        secret: str | None = None,
        ttl_seconds: int = 3600,
        max_login_failures: int = 5,
        lockout_seconds: int = 60,
    ) -> None:
        self.username = username
        self.password = password
        self.secret = (secret or secrets.token_hex(32)).encode("utf-8")
        self.ttl_seconds = ttl_seconds
        self.rate_limiter = LoginRateLimiter(
            max_failures=max_login_failures,
            lockout_seconds=lockout_seconds,
        )

    def verify_credentials(self, username: str, password: str) -> bool:
        if not self.password:
            return False
        user_ok = hmac.compare_digest(username.encode("utf-8"), self.username.encode("utf-8"))
        pass_ok = hmac.compare_digest(password.encode("utf-8"), self.password.encode("utf-8"))
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

    def sign_csrf(self, session_token: str) -> str:
        return hmac.new(self.secret, f"csrf|{session_token}".encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_csrf(self, session_token: str | None, csrf_token: str | None) -> bool:
        if not session_token or not csrf_token:
            return False
        expected = self.sign_csrf(session_token)
        return hmac.compare_digest(csrf_token.encode("utf-8"), expected.encode("utf-8"))


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
        self._last_gw_sync: float = 0.0
        self._sync_lock = threading.Lock()

    def practice_reset_in_progress(self) -> bool:
        return self.storage.get_offset("__practice_reset", "maintenance") > int(time.time())

    def _sync_active_or_expired(self, incidents: list[IncidentView]) -> list[IncidentView]:
        if self.practice_reset_in_progress():
            return incidents
        now_mono = time.monotonic()
        now_utc = datetime.now(timezone.utc)
        with self._sync_lock:
            should_poll_gw = self.action_client is not None and (now_mono - self._last_gw_sync) >= 5.0
            if should_poll_gw:
                self._last_gw_sync = now_mono
        for inc in incidents:
            for ap in reversed(inc.approvals):
                if ap.status not in {"applied", "unknown", "pending"}:
                    continue
                is_past_exp = False
                try:
                    raw_exp = ap.expires_at_utc.strip()
                    if raw_exp.endswith("Z"):
                        raw_exp = raw_exp[:-1] + "+00:00"
                    is_past_exp = datetime.fromisoformat(raw_exp).astimezone(timezone.utc) <= now_utc
                except Exception:
                    is_past_exp = False
                if self.action_client is not None and (should_poll_gw or is_past_exp):
                    prev_status = ap.status
                    prev_inc_status = inc.status
                    refresh_approval_status(inc, approval_id=ap.approval_id, action_client=self.action_client, now_utc=now_utc)
                    if ap.status != prev_status or inc.status != prev_inc_status:
                        self.persist_approval(inc, ap)
                elif self.action_client is None and ap.status == "applied" and is_past_exp:
                    ap.status = "expired"
                    inc.status = "released"
                    inc.updated_at_utc = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
                    self.persist_approval(inc, ap)
        return incidents

    def list_incidents(self) -> list[IncidentView]:
        return self._sync_active_or_expired(self.repo.load_incidents())

    def get_incident(self, incident_id: str) -> IncidentView | None:
        for inc in self.list_incidents():
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
        if self.practice_reset_in_progress():
            raise ActionPolicyError("관제 기록 초기화 중에는 조치할 수 없습니다.")
        self.repo.save_approval(approval, inc.status, inc.updated_at_utc)

    def close(self) -> None:
        close_fn = getattr(self.storage, "close", None)
        if callable(close_fn):
            close_fn()


def _svg_icon(name: str, color: str = "currentColor", size: int = 14) -> str:
    """Return a crisp monochrome/neon inline SVG line icon matching the cyber-hologram palette."""
    s = int(size)
    paths = {
        "dashboard": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
        "lock": '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/><circle cx="12" cy="16" r="1.2" fill="currentColor"/>',
        "shield": '<path d="M12 2.5L4.5 5.8v5.7c0 5 3.2 9.4 7.5 10.8 4.3-1.4 7.5-5.8 7.5-10.8V5.8L12 2.5z"/><path d="M9.5 12.2l1.8 1.8 3.5-3.6"/>',
        "shield_off": '<path d="M12 2.5L4.5 5.8v5.7c0 5 3.2 9.4 7.5 10.8 4.3-1.4 7.5-5.8 7.5-10.8V5.8L12 2.5z"/><path d="M12 8.5v4M12 16h.01"/>',
        "globe": '<circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3a13.5 13.5 0 0 1 0 18M12 3a13.5 13.5 0 0 0 0 18"/>',
        "list": '<path d="M4 6h16M4 12h16M4 18h11"/><circle cx="19" cy="18" r="1.5" fill="currentColor"/>',
        "server": '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><circle cx="7" cy="7" r="1" fill="currentColor"/><circle cx="7" cy="17" r="1" fill="currentColor"/>',
        "database": '<ellipse cx="12" cy="5.5" rx="8" ry="3"/><path d="M4 5.5v6.5c0 1.66 3.58 3 8 3s8-1.34 8-3V5.5"/><path d="M4 12v6.5c0 1.66 3.58 3 8 3s8-1.34 8-3V12"/>',
        "alert": '<path d="M10.3 3.9L2.6 17.5A2 2 0 0 0 4.3 20.5h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4.2M12 16.8h.01"/>',
        "trend": '<path d="M3 17l6-6 4 4 8-8"/><path d="M16 7h5v5"/>',
        "donut": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.8"/><path d="M12 3v5.2M15.8 12H21"/>',
        "bolt": '<path d="M13 2L4.5 13.5h6.5L9.8 22 19.5 10.5H13L13 2z"/>',
        "radar": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5" fill="currentColor"/><path d="M12 12l6.2-6.2"/>',
        "refresh": '<path d="M20 11a8.1 8.1 0 0 0-15.5-2M4 5v4h4"/><path d="M4 13a8.1 8.1 0 0 0 15.5 2M20 19v-4h-4"/>',
        "search": '<circle cx="11" cy="11" r="7"/><path d="M16.5 16.5L21 21"/>',
        "check": '<circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.3 2.3 4.8-5"/>',
        "warn": '<circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16.5h.01"/>',
        "stop": '<polygon points="7.9 3 16.1 3 21 7.9 21 16.1 16.1 21 7.9 21 3 16.1 3 7.9"/><path d="M9 9l6 6M15 9l-6 6"/>',
        "link": '<path d="M10 13a5 5 0 0 0 7.5.5l2.5-2.5a5 5 0 0 0-7.1-7.1L11.5 5.3"/><path d="M14 11a5 5 0 0 0-7.5-.5L4 13a5 5 0 0 0 7.1 7.1l1.4-1.4"/>',
        "unlock": '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.7-1.5"/>',
        "terminal": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3.5 3L7 15M12.5 15h4.5"/>',
        "copy": '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
        "arrow_right": '<path d="M4 12h16"/><path d="M14 6l6 6-6 6"/>',
    }
    body = paths.get(name, paths["radar"])
    return (
        f'<svg width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{html.escape(color)}" '
        f'stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" '
        f'style="display:inline-block;vertical-align:-2px;flex-shrink:0;" aria-hidden="true">{body}</svg>'
    )


def _page_shell(
    title: str,
    body_html: str,
    current_user: str | None = None,
    auth_enabled: bool = False,
    refresh_seconds: int | None = None,
    active_path: str = "/",
    csrf_token: str = "",
) -> bytes:
    practice_reset_form = ""
    if auth_enabled and current_user and csrf_token and os.environ.get("SOC_ENABLE_PRACTICE_RESET") == "1":
        practice_reset_form = (
            '<form method="post" onsubmit="return beginPracticeReset(event,this)" style="margin-top:14px;">'
            f'<input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}" />'
            '<input type="hidden" name="confirm" value="reset-practice-logs" />'
            '<button type="submit" class="btn-ghost" style="width:100%;justify-content:center;color:#fda4af;border:1px solid #713547;">관제 기록 초기화</button>'
            '<div role="status" class="practice-reset-status" style="font-size:11px;color:#94a3b8;margin-top:6px;">백업 없이 삭제 · 활성 차단 시 불가</div></form>'
        )
    auth_box = ""
    if auth_enabled:
        if current_user:
            initial = html.escape(current_user[:1].upper() or "S")
            csrf_field = f'<input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}" />' if csrf_token else ""
            auth_box = (
                f'<div class="side-user">'
                f'<div style="display:flex;align-items:center;gap:10px;">'
                f'<div class="user-avatar">{initial}</div>'
                f'<div style="min-width:0;flex:1;">'
                f'<div style="font-size:13px;font-weight:700;color:#f8fafc;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{html.escape(current_user)}</div>'
                f'<div style="font-size:11px;color:#05f3ad;">● 보안관제 운영자</div>'
                f"</div></div>"
                f"{practice_reset_form}"
                f'<form method="post" action="/logout" style="margin-top:10px;">'
                f"{csrf_field}"
                f'<button type="submit" class="btn-ghost" style="width:100%;justify-content:center;padding:6px 10px;font-size:12px;">세션 로그아웃</button></form></div>'
            )
        else:
            auth_box = '<div class="side-user"><a href="/login" class="btn-ghost" style="display:flex;justify-content:center;">담당자 로그인 →</a></div>'

    nav_items = [
        ("/", "현황 요약 · 전광판", _svg_icon("dashboard", "currentColor", 16)),
        ("/logs/erp", "ERP 인증 관제", _svg_icon("lock", "currentColor", 16)),
        ("/logs/gateway", "방화벽(Gateway) 관제", _svg_icon("shield", "currentColor", 16)),
        ("/logs/caddy", "웹(Caddy) 프록시 관제", _svg_icon("globe", "currentColor", 16)),
        ("/events", "통합 이벤트 스트림", _svg_icon("list", "currentColor", 16)),
    ]
    nav_html = "".join(
        f'<a class="nav-link{" active" if active_path == href else ""}" href="{href}">'
        f'<span class="nav-icon">{icon_svg}</span><span>{label}</span></a>'
        for href, label, icon_svg in nav_items
    )

    logo_svg = (
        '<svg width="38" height="38" viewBox="0 0 36 36" fill="none" aria-hidden="true" class="holo-shield-svg">'
        '<defs>'
        '<linearGradient id="holoShieldGrad" x1="0" y1="0" x2="36" y2="36" gradientUnits="userSpaceOnUse">'
        '<stop offset="0%" stop-color="#00f0ff"/>'
        '<stop offset="55%" stop-color="#2979ff"/>'
        '<stop offset="100%" stop-color="#05f3ad"/>'
        "</linearGradient>"
        '<filter id="holoGlow" x="-25%" y="-25%" width="150%" height="150%">'
        '<feGaussianBlur stdDeviation="2" result="blur"/>'
        '<feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>'
        "</filter>"
        "</defs>"
        '<polygon points="18,1.5 32.5,9.5 32.5,26.5 18,34.5 3.5,26.5 3.5,9.5" stroke="rgba(0,240,255,0.35)" stroke-width="1" stroke-dasharray="3 2" fill="none"/>'
        '<path d="M18 4.5L6.5 9.2V17.8C6.5 25.2 11.4 31.6 18 33.6C24.6 31.6 29.5 25.2 29.5 17.8V9.2L18 4.5Z" '
        'fill="url(#holoShieldGrad)" fill-opacity="0.2" stroke="url(#holoShieldGrad)" stroke-width="1.9" filter="url(#holoGlow)"/>'
        '<path d="M18 8L10 11.4V17.5C10 22.8 13.4 27.3 18 28.9C22.6 27.3 26 22.8 26 17.5V11.4L18 8Z" '
        'fill="none" stroke="#00f0ff" stroke-opacity="0.5" stroke-width="1"/>'
        '<circle cx="18" cy="18" r="3.5" fill="#00f0ff" filter="url(#holoGlow)"/>'
        '<path d="M18 10.5V13.5M18 22.5V25.5M10.5 18H13.5M22.5 18H25.5" stroke="#05f3ad" stroke-width="1.6" stroke-linecap="round"/>'
        "</svg>"
    )

    refresh_ms = int(refresh_seconds) * 1000 if refresh_seconds else 0
    refresh_meta = f'<noscript><meta http-equiv="refresh" content="{int(refresh_seconds)}" /></noscript>' if refresh_seconds else ""
    sync_pill = (
        f'<span id="socSyncPill" class="live-pill"><span class="pulse-dot"></span>{int(refresh_seconds)}초 자동 동기화</span>'
        if refresh_seconds
        else '<span id="socSyncPill" class="live-pill"><span class="pulse-dot"></span>REALTIME SOC LINKED</span>'
    )
    globe_opacity = "0.55" if active_path == "/" else "0.52"
    subpage_cls = (
        " subpage-glass"
        if active_path in {"/logs/erp", "/logs/gateway", "/logs/caddy", "/events", "/logs/events"}
        else ""
    )

    doc = f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  {refresh_meta}
  <title>{html.escape(title)}</title>
  <style>
    * {{ box-sizing: border-box; }}
    @keyframes holoPulse {{
      0%, 100% {{ filter: drop-shadow(0 0 6px rgba(0, 240, 255, 0.55)); transform: scale(1); }}
      50% {{ filter: drop-shadow(0 0 15px rgba(5, 243, 173, 0.92)); transform: scale(1.04); }}
    }}
    @keyframes scanlineMove {{
      0% {{ transform: translateY(-100%); }}
      100% {{ transform: translateY(450%); }}
    }}
    body {{
      font-family: "Pretendard", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      margin: 0;
      background-color: #03060d;
      background-image:
        radial-gradient(circle at 50% 42%, rgba(0, 240, 255, 0.10), transparent 58%),
        radial-gradient(circle at 18% 12%, rgba(41, 121, 255, 0.08), transparent 40%),
        linear-gradient(rgba(0, 240, 255, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 240, 255, 0.03) 1px, transparent 1px);
      background-size: 100% 100%, 100% 100%, 36px 36px, 36px 36px;
      color: #e2f1ff;
      line-height: 1.45;
    }}
    .holo-shield-svg {{ animation: holoPulse 3.2s infinite ease-in-out; }}
    .layout {{ display: flex; min-height: 100vh; }}
    aside.sidebar {{
      width: 246px;
      flex-shrink: 0;
      background: rgba(5, 9, 19, 0.86);
      backdrop-filter: blur(10px);
      border-right: 1px solid rgba(0, 240, 255, 0.22);
      box-shadow: 4px 0 28px rgba(0, 0, 0, 0.65);
      padding: 20px 14px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      position: sticky;
      top: 0;
      height: 100vh;
      z-index: 20;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 11px;
      padding: 6px 8px 18px;
      border-bottom: 1px solid rgba(0, 240, 255, 0.18);
      margin-bottom: 14px;
      cursor: pointer;
      transition: transform 0.15s ease;
    }}
    .brand:hover {{ transform: translateX(2px); }}
    .brand-title {{
      font-size: 16px;
      font-weight: 900;
      color: #ffffff;
      letter-spacing: 0.08em;
      text-shadow: 0 0 12px rgba(0, 240, 255, 0.6);
    }}
    .brand-sub {{ font-size: 10.5px; color: #00f0ff; margin-top: 2px; font-weight: 700; letter-spacing: 0.05em; opacity: 0.88; }}
    .nav-section {{
      font-size: 10px;
      color: #5b799e;
      text-transform: uppercase;
      margin: 16px 10px 7px;
      letter-spacing: 0.1em;
      font-weight: 800;
    }}
    .nav-link {{
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 9px;
      color: #93b4d8;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 5px;
      text-decoration: none;
      border: 1px solid transparent;
      transition: all 0.18s ease;
    }}
    .nav-icon {{ display: inline-flex; align-items: center; opacity: 0.92; }}
    .nav-link:hover {{
      background: rgba(0, 240, 255, 0.09);
      color: #ffffff;
      border-color: rgba(0, 240, 255, 0.3);
      box-shadow: 0 0 14px rgba(0, 240, 255, 0.12);
      text-decoration: none;
    }}
    .nav-link.active {{
      background: linear-gradient(90deg, rgba(0, 240, 255, 0.2), rgba(41, 121, 255, 0.05));
      color: #00f0ff;
      font-weight: 800;
      border-color: rgba(0, 240, 255, 0.45);
      box-shadow: inset 3px 0 0 #00f0ff, 0 0 18px rgba(0, 240, 255, 0.18);
      text-shadow: 0 0 8px rgba(0, 240, 255, 0.4);
    }}
    .side-user {{
      border-top: 1px solid rgba(0, 240, 255, 0.18);
      padding-top: 14px;
      margin-top: 16px;
      font-size: 12px;
      color: #93b4d8;
    }}
    .user-avatar {{
      width: 34px;
      height: 34px;
      border-radius: 50%;
      background: linear-gradient(135deg, #00f0ff, #2979ff);
      color: #03060d;
      font-weight: 900;
      font-size: 14px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      box-shadow: 0 0 12px rgba(0, 240, 255, 0.5);
    }}
    main.content {{ flex: 1; min-width: 0; padding: 18px 26px 36px; max-width: 1540px; margin: 0 auto; }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      padding-bottom: 14px;
      margin-bottom: 16px;
      border-bottom: 1px solid rgba(0, 240, 255, 0.18);
    }}
    .breadcrumb {{ font-size: 12px; color: #6c8db5; display: flex; align-items: center; gap: 8px; }}
    .breadcrumb strong {{ color: #00f0ff; font-weight: 700; text-shadow: 0 0 8px rgba(0, 240, 255, 0.35); }}
    .topbar-right {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
    .search-box-wrap {{
      position: relative;
      display: inline-flex;
      align-items: center;
    }}
    .search-box-wrap svg {{
      position: absolute;
      left: 10px;
      pointer-events: none;
      color: #00f0ff;
    }}
    .search-box {{
      background: rgba(6, 12, 26, 0.72);
      border: 1px solid rgba(0, 240, 255, 0.28);
      border-radius: 8px;
      padding: 6px 12px 6px 30px;
      color: #e2f1ff;
      font-size: 12px;
      width: 245px;
      outline: none;
      transition: all 0.15s;
    }}
    .search-box:focus {{ border-color: #00f0ff; box-shadow: 0 0 12px rgba(0, 240, 255, 0.3); }}
    .live-pill {{
      display: inline-flex;
      align-items: center;
      gap: 7px;
      background: rgba(5, 243, 173, 0.1);
      border: 1px solid rgba(5, 243, 173, 0.42);
      color: #05f3ad;
      padding: 5px 12px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.04em;
      box-shadow: 0 0 12px rgba(5, 243, 173, 0.16);
    }}
    .pulse-dot {{
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #05f3ad;
      box-shadow: 0 0 10px #05f3ad;
      display: inline-block;
    }}
    a {{ color: #00f0ff; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(215px, 1fr)); gap: 14px; margin-bottom: 16px; }}
    .card {{
      background: rgba(6, 13, 28, 0.54);
      border: 1px solid rgba(0, 240, 255, 0.38);
      border-radius: 12px;
      padding: 14px 17px;
      position: relative;
      overflow: hidden;
      box-shadow: 0 8px 26px rgba(0, 0, 0, 0.52), 0 0 16px rgba(0, 240, 255, 0.11), inset 0 1px 0 rgba(0, 240, 255, 0.28), inset 0 0 14px rgba(0, 240, 255, 0.04);
      transition: transform 0.2s cubic-bezier(0.2, 0.8, 0.2, 1), border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
    }}
    .card.clickable {{ cursor: pointer; }}
    .card.clickable::after {{
      content: "";
      position: absolute;
      inset: 0;
      background: radial-gradient(circle at 88% 14%, rgba(0, 240, 255, 0.16), transparent 55%);
      opacity: 0;
      transition: opacity 0.2s ease;
      pointer-events: none;
    }}
    .card.clickable:hover {{
      background: rgba(8, 20, 42, 0.72);
      border-color: #00f0ff;
      box-shadow: 0 12px 34px rgba(0, 0, 0, 0.7), 0 0 26px rgba(0, 240, 255, 0.28), inset 0 0 14px rgba(0, 240, 255, 0.14);
      transform: translateY(-3px) scale(1.012);
    }}
    .card.clickable:hover::after {{ opacity: 1; }}
    .card-expand-icon {{
      width: 24px;
      height: 24px;
      border-radius: 6px;
      border: 1px solid rgba(0, 240, 255, 0.28);
      background: rgba(0, 240, 255, 0.08);
      color: #8ab0d8;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      transition: all 0.2s ease;
    }}
    .card.clickable:hover .card-expand-icon {{
      color: #03060d;
      background: #00f0ff;
      border-color: #00f0ff;
      box-shadow: 0 0 12px #00f0ff;
      transform: translate(1px, -1px);
    }}
    .card .label {{ font-size: 12px; color: #9ec2e6; font-weight: 600; letter-spacing: 0.02em; text-shadow: 0 1px 3px rgba(0,0,0,0.9); }}
    .card .val {{
      font-size: 28px;
      font-weight: 900;
      margin-top: 6px;
      color: #ffffff;
      letter-spacing: -0.02em;
      font-variant-numeric: tabular-nums;
      text-shadow: 0 0 14px rgba(0, 240, 255, 0.4), 0 2px 4px rgba(0,0,0,0.95);
    }}
    /* 3단 사이버 홀로그램 히어로 무대 (중앙 지구본 오픈 쇼케이스) */
    .hero-stage-3col {{
      display: grid;
      grid-template-columns: 330px 1fr 340px;
      gap: 16px;
      margin-bottom: 18px;
      align-items: stretch;
    }}
    .hero-col-stack {{
      display: flex;
      flex-direction: column;
      gap: 14px;
    }}
    .hero-center-window {{
      display: flex;
      flex-direction: column;
      justify-content: flex-end;
      min-height: 440px;
      position: relative;
    }}
    .grid-2col {{ display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr); gap: 16px; margin-bottom: 18px; }}
    .grid-2col-eq {{ display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: 16px; margin-bottom: 18px; }}
    @media (max-width: 1220px) {{
      .hero-stage-3col {{ grid-template-columns: 1fr; }}
      .hero-center-window {{ min-height: 220px; }}
    }}
    @media (max-width: 1120px) {{
      .grid-2col, .grid-2col-eq {{ grid-template-columns: 1fr; }}
    }}
    .panel {{
      min-width: 0;
      background: rgba(6, 13, 28, 0.54);
      border: 1px solid rgba(0, 240, 255, 0.36);
      border-radius: 14px;
      padding: 16px 18px;
      margin-bottom: 16px;
      position: relative;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.56), 0 0 18px rgba(0, 240, 255, 0.10), inset 0 1px 0 rgba(0, 240, 255, 0.25), inset 0 0 16px rgba(0, 240, 255, 0.04);
    }}
    .panel-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }}
    .panel h2 {{
      margin: 0;
      font-size: 14.5px;
      font-weight: 800;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 8px;
      letter-spacing: 0.02em;
      text-shadow: 0 0 10px rgba(0, 240, 255, 0.3), 0 1px 3px rgba(0,0,0,0.95);
    }}
    .panel-sub {{ font-size: 11.5px; color: #8ab0d8; margin-top: 3px; text-shadow: 0 1px 2px rgba(0,0,0,0.9); }}
    .chain {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 14px; font-size: 12px; }}
    .chain-step {{
      background: rgba(4, 9, 20, 0.72);
      border: 1px solid rgba(0, 240, 255, 0.34);
      box-shadow: inset 0 0 10px rgba(0, 240, 255, 0.05);
      border-radius: 9px;
      padding: 8px 13px;
      color: #e2f1ff;
    }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; font-size: 12.5px; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid rgba(0, 240, 255, 0.13); vertical-align: middle; }}
    th {{
      color: #8ab0d8;
      font-weight: 800;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      background: rgba(4, 9, 20, 0.8);
      border-top: 1px solid rgba(0, 240, 255, 0.24);
    }}
    th:first-child {{ border-top-left-radius: 8px; }}
    th:last-child {{ border-top-right-radius: 8px; }}
    tbody tr {{ transition: background 0.14s ease; }}
    tbody tr.clickable-row {{ cursor: pointer; }}
    tbody tr:hover {{ background: rgba(0, 240, 255, 0.11); }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3.5px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.02em;
      border: 1px solid transparent;
      white-space: nowrap;
    }}
    .b-open {{ background: rgba(255, 26, 83, 0.18); color: #ff4d79; border-color: rgba(255, 26, 83, 0.52); box-shadow: 0 0 10px rgba(255, 26, 83, 0.22); }}
    .b-approved {{ background: rgba(41, 121, 255, 0.2); color: #6ea8ff; border-color: rgba(41, 121, 255, 0.48); }}
    .b-blocked, .b-applied, .b-rejected {{ background: rgba(255, 26, 83, 0.2); color: #ff4d79; border-color: rgba(255, 26, 83, 0.52); }}
    .b-released, .b-expired, .b-ok {{ background: rgba(5, 243, 173, 0.16); color: #05f3ad; border-color: rgba(5, 243, 173, 0.45); }}
    .b-warn {{ background: rgba(255, 171, 0, 0.16); color: #ffd740; border-color: rgba(255, 171, 0, 0.45); }}
    code, pre {{
      font-family: "JetBrains Mono", "Fira Code", Consolas, monospace;
      background: rgba(4, 8, 18, 0.84);
      border: 1px solid rgba(0, 240, 255, 0.24);
      border-radius: 6px;
      padding: 2px 7px;
      font-size: 11.5px;
      color: #c8e6ff;
    }}
    pre {{ padding: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; line-height: 1.5; color: #00f0ff; }}
    button {{
      background: linear-gradient(135deg, #ff1a53, #d50032);
      color: #fff;
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 8px;
      padding: 8px 14px;
      font-weight: 800;
      font-size: 12.5px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.16s ease;
      box-shadow: 0 0 14px rgba(255, 26, 83, 0.35);
    }}
    button:hover:not(:disabled) {{ filter: brightness(1.15); transform: translateY(-1px); }}
    button.secondary {{
      background: linear-gradient(135deg, #2979ff, #00b0ff);
      box-shadow: 0 0 14px rgba(41, 121, 255, 0.35);
    }}
    button.btn-emerald {{
      background: linear-gradient(135deg, #05f3ad, #00bfa5);
      color: #03060d;
      box-shadow: 0 0 14px rgba(5, 243, 173, 0.35);
    }}
    .btn-ghost {{
      background: rgba(6, 15, 34, 0.72);
      color: #b8dcff;
      border: 1px solid rgba(0, 240, 255, 0.3);
      border-radius: 8px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 700;
      box-shadow: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }}
    .btn-ghost:hover {{
      background: rgba(0, 240, 255, 0.16);
      color: #00f0ff;
      border-color: #00f0ff;
      box-shadow: 0 0 14px rgba(0, 240, 255, 0.25);
      text-decoration: none;
    }}
    button:disabled {{ background: #162238; color: #475569; border-color: #26354f; box-shadow: none; cursor: not-allowed; }}
    input, select {{
      background: rgba(4, 8, 18, 0.85);
      color: #ffffff;
      border: 1px solid rgba(0, 240, 255, 0.28);
      border-radius: 7px;
      padding: 8px 11px;
      font-size: 13px;
    }}
    input:focus {{ outline: none; border-color: #00f0ff; box-shadow: 0 0 10px rgba(0, 240, 255, 0.25); }}
    .notice {{
      background: rgba(255, 26, 83, 0.14);
      border: 1px solid rgba(255, 26, 83, 0.45);
      color: #ff99b3;
      padding: 11px 14px;
      border-radius: 9px;
      font-size: 12.5px;
      margin-bottom: 14px;
    }}
    .swimlane-row {{
      display: grid;
      grid-template-columns: 140px 1fr;
      align-items: center;
      gap: 10px;
      padding: 7px 0;
      border-bottom: 1px solid rgba(0, 240, 255, 0.1);
    }}
    .swimlane-row:last-child {{ border-bottom: none; }}
    .swimlane-track {{
      position: relative;
      height: 24px;
      background: rgba(4, 8, 18, 0.68);
      border: 1px solid rgba(0, 240, 255, 0.30);
      box-shadow: inset 0 0 8px rgba(0, 240, 255, 0.05);
      border-radius: 999px;
      display: flex;
      align-items: center;
      padding: 0 12px;
      overflow: hidden;
    }}
    /* 배경 대형 3D 홀로그램 지구본 */
    .bg-globe-wrap {{
      position: fixed;
      top: 0;
      left: 246px;
      right: 0;
      bottom: 0;
      pointer-events: none;
      z-index: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }}
    @media (max-width: 900px) {{
      .bg-globe-wrap {{ left: 0; }}
    }}
    /* 대형 반투명 홀로그램 상세 창 */
    .holo-modal-backdrop {{
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(2, 6, 15, 0.56);
      backdrop-filter: blur(5px);
      z-index: 9999;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }}
    .holo-modal-backdrop.open {{ display: flex; }}
    .holo-modal {{
      width: 100%;
      max-width: 1120px;
      max-height: 86vh;
      display: flex;
      flex-direction: column;
      background: linear-gradient(180deg, rgba(6, 15, 32, 0.76) 0%, rgba(4, 9, 20, 0.82) 100%);
      backdrop-filter: blur(12px);
      border: 1.5px solid rgba(0, 240, 255, 0.65);
      border-radius: 18px;
      box-shadow: 0 0 60px rgba(0, 240, 255, 0.3), inset 0 0 32px rgba(0, 240, 255, 0.1);
      padding: 24px 28px;
      position: relative;
      overflow: hidden;
      color: #f0f7ff;
    }}
    .holo-modal-body {{
      overflow-y: auto;
      padding-right: 4px;
      font-size: 13px;
      line-height: 1.55;
    }}
    .holo-modal::before {{
      content: "";
      position: absolute;
      left: 0;
      right: 0;
      height: 60px;
      background: linear-gradient(180deg, transparent, rgba(0, 240, 255, 0.08), transparent);
      animation: scanlineMove 5s linear infinite;
      pointer-events: none;
    }}
    /* 세부 관제 페이지 (/logs/*, /events) 투명 유리감 & 배경 지구본 은은하게 투과 */
    .subpage-glass .card,
    .subpage-glass .panel {{
      background: rgba(6, 13, 28, 0.56);
      backdrop-filter: none;
      -webkit-backdrop-filter: none;
      border: 1px solid rgba(0, 240, 255, 0.34);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.56), 0 0 18px rgba(0, 240, 255, 0.09), inset 0 1px 0 rgba(0, 240, 255, 0.24);
    }}
    .subpage-glass th {{ background: rgba(4, 9, 20, 0.68); }}
    .subpage-glass td {{ text-shadow: 0 1px 3px rgba(2, 6, 15, 0.94); }}
    /* 추적 식별자 축약 & 클릭 복사 칩 */
    button.id-copy-chip {{
      display: inline-flex;
      align-items: center;
      gap: 5px;
      background: rgba(4, 10, 24, 0.9);
      color: #b8dcff;
      border: 1px solid rgba(0, 240, 255, 0.28);
      border-radius: 6px;
      padding: 2px 7px;
      font-family: "JetBrains Mono", "Fira Code", Consolas, monospace;
      font-size: 11px;
      font-weight: 600;
      box-shadow: none;
      cursor: pointer;
      white-space: nowrap;
    }}
    button.id-copy-chip:hover:not(:disabled) {{
      background: rgba(0, 240, 255, 0.14);
      color: #00f0ff;
      border-color: #00f0ff;
      box-shadow: 0 0 10px rgba(0, 240, 255, 0.24);
      transform: translateY(-1px);
    }}
    button.id-copy-chip.copied {{
      background: rgba(5, 243, 173, 0.2);
      color: #05f3ad;
      border-color: #05f3ad;
    }}
    .holo-copy-toast {{
      position: fixed;
      right: 24px;
      bottom: 24px;
      z-index: 10000;
      padding: 10px 16px;
      border-radius: 10px;
      background: rgba(5, 14, 30, 0.94);
      backdrop-filter: blur(10px);
      border: 1px solid #05f3ad;
      color: #05f3ad;
      font-size: 12.5px;
      font-weight: 700;
      box-shadow: 0 0 24px rgba(5, 243, 173, 0.32);
      opacity: 0;
      transform: translateY(8px);
      pointer-events: none;
      transition: opacity 0.18s ease, transform 0.18s ease;
    }}
    .holo-copy-toast.show {{ opacity: 1; transform: translateY(0); }}
    /* ERP login_failed 행 좌측 3px 레드 인디케이터 & 배경 강조 */
    tr.row-erp-failed td {{ background: rgba(239, 68, 68, 0.08); }}
    tr.row-erp-failed td:first-child {{ box-shadow: inset 3px 0 0 #ff1a53; }}
    tr.row-erp-failed:hover td {{ background: rgba(239, 68, 68, 0.16); }}
    /* 통합 이벤트 스트림 계층별 좌측 컬러 바 & 연결 흐름 카드 */
    tr.tier-row-gateway td:first-child {{ box-shadow: inset 3px 0 0 #05f3ad; }}
    tr.tier-row-caddy td:first-child {{ box-shadow: inset 3px 0 0 #00f0ff; }}
    tr.tier-row-erp td:first-child {{ box-shadow: inset 3px 0 0 #c084fc; }}
    .tier-flow-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 34px minmax(0, 1fr) 34px minmax(0, 1fr);
      gap: 8px;
      align-items: stretch;
      margin-bottom: 16px;
    }}
    .tier-flow-arrow {{
      display: flex;
      align-items: center;
      justify-content: center;
      color: #00f0ff;
      filter: drop-shadow(0 0 8px rgba(0, 240, 255, 0.72));
      animation: holoPulse 2.4s infinite ease-in-out;
    }}
    @media (max-width: 1020px) {{
      .tier-flow-grid {{ grid-template-columns: 1fr; }}
      .tier-flow-arrow {{ transform: rotate(90deg); justify-self: center; padding: 2px 0; }}
    }}
    .filter-chip-bar {{
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(0, 240, 255, 0.16);
    }}
    button.filter-chip {{
      background: rgba(4, 10, 24, 0.85);
      color: #9ec2e6;
      border: 1px solid rgba(0, 240, 255, 0.24);
      border-radius: 999px;
      padding: 5px 13px;
      font-size: 12px;
      font-weight: 700;
      box-shadow: none;
      cursor: pointer;
    }}
    button.filter-chip:hover:not(:disabled) {{
      background: rgba(0, 240, 255, 0.12);
      color: #ffffff;
      border-color: rgba(0, 240, 255, 0.55);
      transform: none;
    }}
    button.filter-chip.active {{
      background: rgba(0, 240, 255, 0.22);
      color: #00f0ff;
      border-color: #00f0ff;
      box-shadow: 0 0 14px rgba(0, 240, 255, 0.28);
    }}
    button.filter-chip[data-filter="gateway"].active {{
      background: rgba(5, 243, 173, 0.2);
      color: #05f3ad;
      border-color: #05f3ad;
      box-shadow: 0 0 14px rgba(5, 243, 173, 0.28);
    }}
    button.filter-chip[data-filter="erp"].active {{
      background: rgba(192, 132, 252, 0.2);
      color: #c084fc;
      border-color: #c084fc;
      box-shadow: 0 0 14px rgba(192, 132, 252, 0.28);
    }}
    button.filter-chip[data-filter="anomaly"].active {{
      background: rgba(255, 26, 83, 0.22);
      color: #ff4d79;
      border-color: #ff1a53;
      box-shadow: 0 0 14px rgba(255, 26, 83, 0.32);
    }}
  </style>
  <script>
  function beginPracticeReset(event, form) {{
    event.preventDefault();
    if (!confirm("관제 로그·사건·승인 이력을 백업 없이 초기화할까요? 원본 로그 파일과 ERP 계정은 유지됩니다.")) return false;
    var button = form.querySelector("button");
    var status = form.querySelector(".practice-reset-status");
    button.disabled = true;
    button.textContent = "초기화 중…";
    status.textContent = "원본 로그를 유지하며 관제 기록을 정리하고 있습니다.";
    fetch("http://" + location.hostname + ":18888/practice-reset", {{
      method: "POST", credentials: "include",
      body: new URLSearchParams(new FormData(form)), signal: AbortSignal.timeout(120000)
    }}).then(async function(response) {{
      var text = await response.text();
      var result = new DOMParser().parseFromString(text, "text/html").querySelector("h1");
      if (!response.ok) throw new Error(result ? result.textContent : "초기화 실패. 현재 상태를 확인하세요.");
      status.textContent = "초기화 완료. 최신 상태를 불러옵니다.";
      location.href = "/";
    }}).catch(function(error) {{
      status.textContent = error.message;
      button.disabled = false; button.textContent = "관제 기록 초기화";
    }});
    return false;
  }}
    var activeEventChip = "all";
    var searchTermSoc = "";
    var autoRefreshMs = {refresh_ms};
    var autoRefreshLabel = "{int(refresh_seconds) if refresh_seconds else 0}초 자동 동기화";
    function isAutoRefreshPaused() {{
      var sb = document.getElementById("socSearchBox");
      var modal = document.getElementById("holoModalBackdrop");
      var searching = sb && (document.activeElement === sb || (sb.value || "").trim().length > 0);
      var modalOpen = modal && modal.classList.contains("open");
      return Boolean(searching || modalOpen);
    }}
    function updateAutoRefreshState() {{
      if (!autoRefreshMs) return;
      var pill = document.getElementById("socSyncPill");
      if (!pill) return;
      if (isAutoRefreshPaused()) {{
        pill.innerHTML = '<span class="pulse-dot" style="background:#ffd740;box-shadow:0 0 8px #ffd740;"></span>검색 중 · 일시정지';
      }} else {{
        pill.innerHTML = '<span class="pulse-dot"></span>' + autoRefreshLabel;
      }}
    }}
    function applySocTableFilters() {{
      var rows = document.querySelectorAll("table tbody tr");
      var shown = 0;
      var total = 0;
      for (var i = 0; i < rows.length; i++) {{
        var r = rows[i];
        var src = r.getAttribute("data-source");
        if (src) total++;
        var okChip = true;
        if (activeEventChip && activeEventChip !== "all" && src) {{
          if (activeEventChip === "anomaly") {{
            okChip = r.getAttribute("data-anomaly") === "1";
          }} else {{
            okChip = src === activeEventChip;
          }}
        }}
        var txt = (r.innerText || "").toLowerCase();
        var okSearch = (!searchTermSoc || txt.indexOf(searchTermSoc) !== -1);
        var visible = okChip && okSearch;
        r.style.display = visible ? "" : "none";
        if (visible && src) shown++;
      }}
      var cntEl = document.getElementById("eventsFilterCount");
      if (cntEl && total > 0) {{
        cntEl.innerText = "표시: " + shown + " / " + total + "건";
      }}
    }}
    function filterSocTables(q) {{
      var rawQ = q || "";
      try {{ sessionStorage.setItem("sentinel_search_" + window.location.pathname, rawQ); }} catch (e) {{}}
      searchTermSoc = rawQ.toLowerCase();
      applySocTableFilters();
      updateAutoRefreshState();
    }}
    function setEventFilterChip(mode, skipSave) {{
      activeEventChip = mode || "all";
      if (!skipSave) {{
        try {{ sessionStorage.setItem("sentinel_events_filter", activeEventChip); }} catch (e) {{}}
      }}
      var btns = document.querySelectorAll("button.filter-chip");
      for (var i = 0; i < btns.length; i++) {{
        var b = btns[i];
        if (b.getAttribute("data-filter") === activeEventChip) {{
          b.classList.add("active");
        }} else {{
          b.classList.remove("active");
        }}
      }}
      applySocTableFilters();
    }}
    function showCopyToast(msg) {{
      var t = document.getElementById("holoCopyToast");
      if (!t) return;
      t.innerText = msg;
      t.classList.add("show");
      clearTimeout(t._timer);
      t._timer = setTimeout(function() {{ t.classList.remove("show"); }}, 1600);
    }}
    function fallbackCopy(val) {{
      var ta = document.createElement("textarea");
      ta.value = val;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      try {{ document.execCommand("copy"); }} catch (e) {{}}
      document.body.removeChild(ta);
    }}
    function copyIdChip(btn, ev) {{
      if (ev) ev.stopPropagation();
      var val = btn.getAttribute("data-copy") || "";
      if (!val) return;
      var done = function() {{
        btn.classList.add("copied");
        showCopyToast("전체 ID 복사 완료: " + (val.length > 22 ? val.slice(0, 22) + "..." : val));
        clearTimeout(btn._cpTimer);
        btn._cpTimer = setTimeout(function() {{ btn.classList.remove("copied"); }}, 1200);
      }};
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(val).then(done, function() {{
          fallbackCopy(val);
          done();
        }});
      }} else {{
        fallbackCopy(val);
        done();
      }}
    }}
    window.addEventListener("DOMContentLoaded", function() {{
      var sb = document.getElementById("socSearchBox");
      if (sb) {{
        var savedQ = "";
        try {{ savedQ = sessionStorage.getItem("sentinel_search_" + window.location.pathname) || ""; }} catch (e) {{}}
        if (savedQ) {{
          sb.value = savedQ;
          searchTermSoc = savedQ.toLowerCase();
        }}
      }}
      if (document.querySelector(".filter-chip-bar")) {{
        var saved = "all";
        try {{ saved = sessionStorage.getItem("sentinel_events_filter") || "all"; }} catch (e) {{}}
        setEventFilterChip(saved, true);
      }} else if (searchTermSoc) {{
        applySocTableFilters();
      }}
      updateAutoRefreshState();
      if (autoRefreshMs > 0) {{
        setInterval(function() {{
          if (!isAutoRefreshPaused()) {{
            window.location.reload();
          }}
        }}, autoRefreshMs);
      }}
    }});
    function openHoloModal(title, badgeText, bodyHtml) {{
      var bd = document.getElementById("holoModalBackdrop");
      if (!bd) return;
      document.getElementById("holoModalTitle").innerText = title || "HOLOGRAM INSPECTOR";
      document.getElementById("holoModalBadge").innerText = badgeText || "SENTINEL HOLO-CORE";
      document.getElementById("holoModalBody").innerHTML = bodyHtml || "";
      bd.classList.add("open");
    }}
    function openHoloTemplate(tplId, title, badgeText) {{
      var tpl = document.getElementById(tplId);
      if (!tpl) return;
      openHoloModal(title, badgeText, tpl.innerHTML);
    }}
    function closeHoloModal() {{
      var bd = document.getElementById("holoModalBackdrop");
      if (bd) bd.classList.remove("open");
    }}
    window.addEventListener("keydown", function(e) {{
      if (e.key === "Escape") closeHoloModal();
    }});
    function openShieldBriefing() {{
      openHoloModal(
        "SENTINEL 3계층 홀로그램 방어 아키텍처",
        "HOLO-SHIELD CORE · SIEM·SOAR",
        "<div style='display:grid;grid-template-columns:repeat(3,1fr);gap:14px;'>" +
        "<div style='padding:16px;background:rgba(0,240,255,0.08);border:1px solid rgba(0,240,255,0.35);border-radius:12px;'>" +
        "<div style='font-size:13px;color:#00f0ff;font-weight:800;'>1. Gateway (방화벽 계층)</div>" +
        "<div style='font-size:12.5px;margin-top:6px;color:#dbeafe;'>외부 단말의 직접 우회 접근(<code>POLICY-CLIENT-CADDY-ONLY</code>)을 차단하고, SOAR 승인 시 <code>APR-*</code> DROP 규칙을 즉시 집행합니다.</div></div>" +
        "<div style='padding:16px;background:rgba(5,243,173,0.08);border:1px solid rgba(5,243,173,0.35);border-radius:12px;'>" +
        "<div style='font-size:13px;color:#05f3ad;font-weight:800;'>2. Caddy (TLS 프록시 계층)</div>" +
        "<div style='font-size:12.5px;margin-top:6px;color:#dbeafe;'>HTTPS 종단 및 고유 <code>request_id</code>를 부여해 ERP 인증 이벤트와 웹 요청을 1:1로 정확히 상관 분석합니다.</div></div>" +
        "<div style='padding:16px;background:rgba(41,121,255,0.1);border:1px solid rgba(41,121,255,0.4);border-radius:12px;'>" +
        "<div style='font-size:13px;color:#6ea8ff;font-weight:800;'>3. ERP &amp; SOAR 탐지 엔진</div>" +
        "<div style='font-size:12.5px;margin-top:6px;color:#dbeafe;'><code>RULE-ERP-LOGIN-BRUTE-001</code>(5분 내 5회 실패) 및 신뢰 IP·실시간(<code>live</code>) 검증 통과 시 담당자 승인으로 차단합니다.</div></div>" +
        "</div>"
      );
    }}
  </script>
</head>
<body>
  <!-- 배경 대형 3D 홀로그램 지구본 (실제 대륙 윤곽 + 회전 홀로그램 궤도 링) -->
  <div class="bg-globe-wrap" aria-hidden="true">
    <canvas id="bgGlobeCanvas" width="960" height="960" style="width:min(76vw, 820px);height:min(76vw, 820px);opacity:{globe_opacity};transform:translateY(-4%);"></canvas>
  </div>

  <!-- 대형 반투명 홀로그램 상세 모달 창 -->
  <div id="holoModalBackdrop" class="holo-modal-backdrop" onclick="if(event.target===this)closeHoloModal()">
    <div class="holo-modal">
      <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(0,240,255,0.3);padding-bottom:14px;margin-bottom:16px;flex-shrink:0;">
        <div>
          <span id="holoModalBadge" class="badge" style="background:rgba(0,240,255,0.16);color:#00f0ff;border-color:rgba(0,240,255,0.5);margin-bottom:6px;">HOLO-CORE</span>
          <h3 id="holoModalTitle" style="margin:0;font-size:19px;font-weight:900;color:#ffffff;text-shadow:0 0 14px rgba(0,240,255,0.45);">홀로그램 상세 정보</h3>
        </div>
        <button type="button" class="btn-ghost" onclick="closeHoloModal()" style="padding:7px 14px;font-size:13px;">✕ 닫기 (ESC)</button>
      </div>
      <div id="holoModalBody" class="holo-modal-body"></div>
    </div>
  </div>

  <div id="holoCopyToast" class="holo-copy-toast" role="status" aria-live="polite"></div>

  <div class="layout" style="position:relative;z-index:2;">
    <aside class="sidebar">
      <div>
        <div class="brand" onclick="openShieldBriefing()" title="SENTINEL 홀로그램 브리핑">
          {logo_svg}
          <div>
            <div class="brand-title">SENTINEL</div>
            <div class="brand-sub">HOLO SIEM · SOAR</div>
          </div>
        </div>
        <div class="nav-section">SECURITY OPERATIONS</div>
        {nav_html}
        <div class="nav-section">TELEMETRY FEEDS</div>
        <a class="nav-link" href="/api/incidents"><span class="nav-icon">{_svg_icon("bolt", "#00f0ff", 15)}</span><span>사건 JSON API</span></a>
        <a class="nav-link" href="/api/events"><span class="nav-icon">{_svg_icon("radar", "#05f3ad", 15)}</span><span>이벤트 JSON API</span></a>
      </div>
      {auth_box}
    </aside>
    <main class="content{subpage_cls}">
      <div class="topbar">
        <div class="breadcrumb">
          <span>Workspace</span> <span>/</span> <span>Holo-SOC</span> <span>/</span> <strong>{html.escape(title)}</strong>
        </div>
        <div class="topbar-right">
          <div class="search-box-wrap">
            {_svg_icon("search", "#00f0ff", 13)}
            <input id="socSearchBox" type="search" class="search-box" placeholder="로그, 사건, IP, 계정 즉시 필터..." oninput="filterSocTables(this.value)" onfocus="updateAutoRefreshState()" onblur="updateAutoRefreshState()" />
          </div>
          {sync_pill}
          <a href="{html.escape(active_path)}" class="btn-ghost" title="새로고침">{_svg_icon("refresh", "#00f0ff", 13)} 새로고침</a>
        </div>
      </div>
      {body_html}
    </main>
  </div>
  <script>
  (function() {{
    var c = document.getElementById("bgGlobeCanvas");
    if (!c || !c.getContext) return;
    var ctx = c.getContext("2d");
    var rotY = -2.25;
    var rotX = 0.24;
    var targetRotX = 0.24;

    window.addEventListener("mousemove", function(e) {{
      var nx = (e.clientX / Math.max(window.innerWidth, 1)) - 0.5;
      var ny = (e.clientY / Math.max(window.innerHeight, 1)) - 0.5;
      targetRotX = 0.24 + ny * 0.16;
      rotY += nx * 0.0006;
    }});

    /* 실제 대륙 윤곽선 폴리곤 [lat, lon] */
    var continents = [
      [[68,-165],[70,-140],[62,-125],[60,-95],[52,-78],[47,-53],[42,-70],[30,-81],[25,-81],[28,-97],[18,-95],[15,-84],[19,-104],[32,-117],[48,-125],[60,-148]], /* 북미 */
      [[82,-55],[81,-22],[70,-22],[60,-44],[68,-53]], /* 그린란드 */
      [[11,-74],[10,-62],[2,-50],[-6,-35],[-16,-39],[-23,-43],[-38,-57],[-54,-68],[-46,-74],[-18,-71],[-2,-81]], /* 남미 */
      [[70,28],[68,15],[59,5],[51,2],[43,-9],[36,-5],[38,15],[42,29],[47,39],[58,28],[66,24]], /* 유럽 */
      [[36,-6],[35,10],[31,32],[12,44],[10,51],[-2,41],[-18,36],[-34,26],[-34,18],[-15,12],[4,9],[5,-8],[15,-17],[28,-12]], /* 아프리카 */
      [[71,40],[74,95],[70,145],[65,175],[55,160],[44,142],[38,129],[35,126],[31,122],[21,107],[10,104],[1,104],[16,96],[22,90],[8,77],[23,68],[26,56],[13,45],[31,34],[42,41],[55,48]], /* 아시아 + 한반도 */
      [[44,145],[35,140],[31,131],[36,136]], /* 일본 */
      [[-12,131],[-12,142],[-25,153],[-38,148],[-35,137],[-33,115],[-21,114]] /* 호주 */
    ];

    function ptInPoly(lat, lon, poly) {{
      var inside = false;
      for (var i = 0, j = poly.length - 1; i < poly.length; j = i++) {{
        var yi = poly[i][0], xi = poly[i][1];
        var yj = poly[j][0], xj = poly[j][1];
        var intersect = ((yi > lat) !== (yj > lat)) &&
          (lon < (xj - xi) * (lat - yi) / ((yj - yi) || 1e-6) + xi);
        if (intersect) inside = !inside;
      }}
      return inside;
    }}

    var landDots = [];
    for (var la = -58; la <= 78; la += 2.6) {{
      var stepLon = 2.6 / Math.max(0.28, Math.cos(la * Math.PI / 180));
      for (var lo = -175; lo <= 178; lo += stepLon) {{
        var insideAny = false;
        for (var p = 0; p < continents.length; p++) {{
          if (ptInPoly(la, lo, continents[p])) {{ insideAny = true; break; }}
        }}
        if (insideAny) {{
          var s = Math.sin(la * 12.9898 + lo * 78.233) * 43758.5453;
          var frac = s - Math.floor(s);
          landDots.push({{
            lat: la * Math.PI / 180,
            lon: lo * Math.PI / 180,
            flare: frac > 0.87
          }});
        }}
      }}
    }}

    /* 해안선 강조 엣지 점 */
    var coastDots = [];
    for (var cp = 0; cp < continents.length; cp++) {{
      var poly = continents[cp];
      for (var vi = 0; vi < poly.length; vi++) {{
        var a1 = poly[vi], a2 = poly[(vi + 1) % poly.length];
        for (var sub = 0; sub < 5; sub++) {{
          var t = sub / 5;
          coastDots.push({{
            lat: (a1[0] + (a2[0] - a1[0]) * t) * Math.PI / 180,
            lon: (a1[1] + (a2[1] - a1[1]) * t) * Math.PI / 180
          }});
        }}
      }}
    }}

    /* 외곽 홀로그램 위성 정점 */
    var cageNodes = [];
    for (var ci = 0; ci < 22; ci++) {{
      var phi = Math.acos(-1 + (2 * ci) / 22);
      var theta = Math.sqrt(22 * Math.PI) * phi;
      cageNodes.push({{ lat: phi - Math.PI / 2, lon: theta }});
    }}

    function proj(lat, lon, radius, cx, cy) {{
      var x = radius * Math.cos(lat) * Math.sin(lon + rotY);
      var y0 = radius * Math.sin(lat);
      var z0 = radius * Math.cos(lat) * Math.cos(lon + rotY);
      var y = y0 * Math.cos(rotX) - z0 * Math.sin(rotX);
      var z = y0 * Math.sin(rotX) + z0 * Math.cos(rotX);
      return {{ x: cx + x, y: cy - y, z: z }};
    }}

    var orbitT = 0;
    function renderBgGlobe() {{
      var W = c.width, H = c.height;
      var cx = W * 0.5, cy = H * 0.5;
      var R = W * 0.36;
      ctx.clearRect(0, 0, W, H);

      rotY += 0.0026;
      orbitT = (orbitT + 0.008) % (Math.PI * 2);
      rotX += (targetRotX - rotX) * 0.05;

      /* 1) 은은한 외곽 홀로그램 대기권 림 글로우 */
      var outerAura = ctx.createRadialGradient(cx, cy, R * 0.78, cx, cy, R * 1.40);
      outerAura.addColorStop(0, "rgba(0, 240, 255, 0.26)");
      outerAura.addColorStop(0.35, "rgba(41, 121, 255, 0.15)");
      outerAura.addColorStop(0.75, "rgba(0, 180, 255, 0.04)");
      outerAura.addColorStop(1, "rgba(3, 6, 13, 0)");
      ctx.fillStyle = outerAura;
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.40, 0, Math.PI * 2);
      ctx.fill();

      /* 2) 구체 베이스 & 네온 프레넬 림 테두리 */
      var sg = ctx.createRadialGradient(cx - R * 0.25, cy - R * 0.25, R * 0.05, cx, cy, R);
      sg.addColorStop(0, "rgba(10, 44, 82, 0.72)");
      sg.addColorStop(0.65, "rgba(4, 20, 46, 0.84)");
      sg.addColorStop(0.92, "rgba(0, 140, 200, 0.52)");
      sg.addColorStop(1, "rgba(0, 240, 255, 0.85)");
      ctx.fillStyle = sg;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.fill();

      ctx.save();
      ctx.shadowColor = "#00f0ff";
      ctx.shadowBlur = 22;
      ctx.strokeStyle = "rgba(0, 240, 255, 0.82)";
      ctx.lineWidth = 2.0;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();

      /* 3) 위도·경도 와이어프레임 */
      ctx.strokeStyle = "rgba(0, 240, 255, 0.14)";
      ctx.lineWidth = 0.85;
      for (var lo = -180; lo < 180; lo += 30) {{
        ctx.beginPath();
        var st = false;
        for (var la = -80; la <= 80; la += 8) {{
          var p = proj(la * Math.PI / 180, lo * Math.PI / 180, R, cx, cy);
          if (p.z > 0) {{
            if (!st) {{ ctx.moveTo(p.x, p.y); st = true; }}
            else ctx.lineTo(p.x, p.y);
          }} else st = false;
        }}
        ctx.stroke();
      }}
      for (var la2 = -60; la2 <= 60; la2 += 30) {{
        ctx.beginPath();
        var st2 = false;
        for (var lo2 = -180; lo2 <= 180; lo2 += 8) {{
          var p2 = proj(la2 * Math.PI / 180, lo2 * Math.PI / 180, R, cx, cy);
          if (p2.z > 0) {{
            if (!st2) {{ ctx.moveTo(p2.x, p2.y); st2 = true; }}
            else ctx.lineTo(p2.x, p2.y);
          }} else st2 = false;
        }}
        ctx.stroke();
      }}

      /* 4) 실제 대륙 도트 클라우드 + 밝은 해안선 */
      for (var i = 0; i < landDots.length; i++) {{
        var d = landDots[i];
        var dp = proj(d.lat, d.lon, R, cx, cy);
        if (dp.z > 0) {{
          var al = Math.min(1, (dp.z / R) * 0.95 + 0.18);
          if (d.flare) {{
            ctx.fillStyle = "rgba(5, 243, 173, " + al.toFixed(2) + ")";
            ctx.fillRect(dp.x - 1.8, dp.y - 1.8, 3.6, 3.6);
          }} else {{
            ctx.fillStyle = "rgba(0, 240, 255, " + (al * 0.86).toFixed(2) + ")";
            ctx.fillRect(dp.x - 1.2, dp.y - 1.2, 2.4, 2.4);
          }}
        }}
      }}
      for (var j = 0; j < coastDots.length; j++) {{
        var cd = coastDots[j];
        var cdp = proj(cd.lat, cd.lon, R, cx, cy);
        if (cdp.z > 10) {{
          var cal = Math.min(1, (cdp.z / R) + 0.25);
          ctx.fillStyle = "rgba(180, 252, 255, " + cal.toFixed(2) + ")";
          ctx.fillRect(cdp.x - 1.3, cdp.y - 1.3, 2.6, 2.6);
        }}
      }}

      /* 5) 듀얼 기울어진 사이버 홀로그램 궤도 링 */
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-0.28);
      ctx.strokeStyle = "rgba(0, 240, 255, 0.36)";
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.ellipse(0, 0, R * 1.24, R * 0.34, 0, 0, Math.PI * 2);
      ctx.stroke();
      var ox1 = Math.cos(orbitT) * R * 1.24;
      var oy1 = Math.sin(orbitT) * R * 0.34;
      ctx.fillStyle = "#05f3ad";
      ctx.beginPath();
      ctx.arc(ox1, oy1, 4.2, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(0.42);
      ctx.setLineDash([5, 6]);
      ctx.strokeStyle = "rgba(41, 121, 255, 0.34)";
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.ellipse(0, 0, R * 1.18, R * 0.28, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();

      /* 6) 외곽 다면체 홀로그램 메쉬 케이지 (Reference Constellation Rings) */
      var cPts = [];
      for (var k = 0; k < cageNodes.length; k++) {{
        cPts.push(proj(cageNodes[k].lat, cageNodes[k].lon, R * 1.14, cx, cy));
      }}
      ctx.strokeStyle = "rgba(0, 240, 255, 0.24)";
      ctx.lineWidth = 0.9;
      for (var a = 0; a < cPts.length; a++) {{
        if (cPts[a].z > -30) {{
          ctx.fillStyle = "rgba(0, 240, 255, 0.85)";
          ctx.beginPath();
          ctx.arc(cPts[a].x, cPts[a].y, 2.6, 0, Math.PI * 2);
          ctx.fill();
        }}
        for (var b2 = a + 1; b2 < cPts.length; b2++) {{
          var dx = cPts[a].x - cPts[b2].x;
          var dy = cPts[a].y - cPts[b2].y;
          if (dx * dx + dy * dy < 36000 && (cPts[a].z > -30 || cPts[b2].z > -30)) {{
            ctx.beginPath();
            ctx.moveTo(cPts[a].x, cPts[a].y);
            ctx.lineTo(cPts[b2].x, cPts[b2].y);
            ctx.stroke();
          }}
        }}
      }}

      requestAnimationFrame(renderBgGlobe);
    }}
    renderBgGlobe();
  }})();
  </script>
</body>
</html>"""
    return doc.encode("utf-8")


def render_login_page(error_msg: str | None = None) -> bytes:
    err_html = f'<div class="notice">{html.escape(error_msg)}</div>' if error_msg else ""
    body = f"""
    <div class="panel" style="max-width:440px; margin:48px auto; padding:28px 30px; border-color:rgba(0,240,255,0.38);">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
        <div style="width:42px;height:42px;border-radius:10px;background:rgba(0,240,255,0.12);border:1px solid rgba(0,240,255,0.42);display:flex;align-items:center;justify-content:center;">{_svg_icon("shield", "#00f0ff", 22)}</div>
        <div>
          <h2 style="margin:0;font-size:18px;">관제 담당자 로그인</h2>
          <div style="font-size:12px;color:#8ab0d8;margin-top:2px;">SENTINEL SIEM · SOAR 통합 보안관제 인증</div>
        </div>
      </div>
      {err_html}
      <form method="post" action="/login">
        <p style="margin-bottom:14px;"><label style="font-size:12px;color:#9ec2e6;font-weight:600;">운영자 아이디<br /><input type="text" name="username" required placeholder="담당자 ID 입력" style="width:100%;margin-top:6px;" /></label></p>
        <p style="margin-bottom:18px;"><label style="font-size:12px;color:#9ec2e6;font-weight:600;">비밀번호<br /><input type="password" name="password" required placeholder="••••••••" style="width:100%;margin-top:6px;" /></label></p>
        <p style="margin:0;"><button type="submit" class="btn-emerald" style="width:100%;justify-content:center;padding:10px 14px;font-size:13.5px;">관제 콘솔 접속 →</button></p>
      </form>
    </div>
    """
    return _page_shell("관제 대시보드 · 로그인", body, auth_enabled=True)


def _fmt_ts(ts_val: str | None, *, include_utc: bool = True) -> str:
    """ISO-8601 UTC 시각 문자열을 한국 시간(KST) (+ 선택적 UTC 병기) 형태로 읽기 쉽게 변환한다."""
    if not ts_val or ts_val == "수집 대기":
        return '<span style="color:#64748b;">수집 대기 중</span>'
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
        utc_part = f" ({utc_hm} UTC)" if include_utc else ""
        return (
            f'<span title="{html.escape(raw)}" style="white-space:nowrap;">'
            f'<strong style="color:#f8fafc;font-family:ui-monospace,Consolas,monospace;font-size:12px;">{kst_str}</strong> '
            f'<span style="color:#9ec2e6;font-size:11px;">KST{utc_part}</span>'
            f"</span>"
        )
    except Exception:
        return f"<code>{html.escape(raw)}</code>"


def _fmt_status(status: str) -> str:
    labels = {
        "open": ("b-open", "alert", "#ff4d79", "확인·승인 필요 (open)"),
        "blocked": ("b-blocked", "stop", "#ff4d79", "차단 적용 중 (blocked)"),
        "applied": ("b-applied", "shield_off", "#ff4d79", "방화벽 차단 중 (applied)"),
        "released": ("b-released", "check", "#05f3ad", "차단 해제됨 (released)"),
        "approved": ("b-approved", "check", "#6ea8ff", "승인됨 (approved)"),
        "expired": ("b-expired", "warn", "#05f3ad", "만료됨 (expired)"),
        "pending": ("b-warn", "warn", "#ffd740", "승인 대기 (pending)"),
        "unknown": ("b-warn", "warn", "#ffd740", "결과 미확인 (unknown)"),
        "rejected": ("b-blocked", "stop", "#ff4d79", "거부됨 (rejected)"),
        "closed": ("b-released", "check", "#05f3ad", "종료 (closed)"),
    }
    entry = labels.get(status)
    if entry is None:
        return f'<span class="badge b-{html.escape(status)}">{html.escape(status)}</span>'
    cls, icon, col, text = entry
    return f'<span class="badge {cls}">{_svg_icon(icon, col, 12)} {text}</span>'


def _fmt_event_type(ev_type: str, outcome: str | None = None) -> str:
    esc = html.escape
    if ev_type == "login_success":
        return f'<span class="badge b-ok">{_svg_icon("check", "#05f3ad", 12)} 로그인 성공 <small style="opacity:0.75;">(login_success)</small></span>'
    if ev_type == "login_failed":
        return f'<span class="badge b-blocked">{_svg_icon("alert", "#ff4d79", 12)} 로그인 실패 <small style="opacity:0.75;">(login_failed)</small></span>'
    if ev_type == "logout":
        return f'<span class="badge b-approved">{_svg_icon("lock", "#6ea8ff", 12)} 로그아웃 <small style="opacity:0.75;">(logout)</small></span>'
    if ev_type == "fw_allow":
        return f'<span class="badge b-ok">{_svg_icon("check", "#05f3ad", 12)} 통과·허용 <small style="opacity:0.75;">(fw_allow)</small></span>'
    if ev_type == "fw_deny":
        return f'<span class="badge b-blocked">{_svg_icon("stop", "#ff4d79", 12)} 방화벽 차단 <small style="opacity:0.75;">(fw_deny)</small></span>'
    if ev_type == "http_request":
        cls = "b-blocked" if outcome == "failure" else "b-approved"
        col = "#ff4d79" if outcome == "failure" else "#00f0ff"
        return f'<span class="badge {cls}">{_svg_icon("globe", col, 12)} 웹 요청 <small style="opacity:0.75;">(http_request)</small></span>'
    return f'<span class="badge b-approved">{esc(ev_type)}</span>'


def _fmt_ingest_mode(mode: str) -> str:
    if mode == "live":
        return '<span class="badge b-ok">● 실시간 (live)</span>'
    if mode == "replay":
        return '<span class="badge b-warn">◐ 재현 (replay)</span>'
    if mode == "synthetic":
        return '<span class="badge b-warn">◇ 가상 (synthetic)</span>'
    return f'<span class="badge b-warn">{html.escape(mode)}</span>'


def _fmt_source_badge(source: str) -> str:
    labels = {
        "erp": ("rgba(168,85,247,0.15)", "#c084fc", "rgba(168,85,247,0.38)", "server", "ERP"),
        "gateway": ("rgba(5,243,173,0.14)", "#05f3ad", "rgba(5,243,173,0.38)", "shield", "Gateway"),
        "caddy": ("rgba(0,240,255,0.14)", "#00f0ff", "rgba(0,240,255,0.38)", "globe", "Caddy"),
    }
    entry = labels.get(source)
    if entry is None:
        return f'<span class="badge b-approved">{html.escape(source)}</span>'
    bg, fg, bd, icon, label = entry
    return (
        f'<span class="badge" style="background:{bg};color:{fg};border-color:{bd};" title="{html.escape(source)}">'
        f"{_svg_icon(icon, fg, 12)} {label}</span>"
    )


def _copy_id_chip(value: str | None, *, prefix: str = "") -> str:
    """긴 UUID/해시 추적 식별자를 앞 8자리로 축약 표시하고 클릭 시 전체 값을 클립보드에 복사하는 칩을 생성한다."""
    esc = html.escape
    raw = str(value).strip() if value is not None else ""
    if not raw or raw == "-":
        if prefix:
            return f'<span style="color:#64748b;font-size:11px;">{esc(prefix)} -</span>'
        return '<span style="color:#64748b;">-</span>'
    short = f"{raw[:8]}..." if len(raw) > 8 else raw
    pref_html = f'<span style="color:#64748b;font-weight:500;">{esc(prefix)}</span>' if prefix else ""
    return (
        f'<button type="button" class="id-copy-chip" data-copy="{esc(raw)}" '
        f'title="클릭하여 전체 ID 복사: {esc(raw)}" onclick="copyIdChip(this, event)">'
        f"{pref_html}<span>{esc(short)}</span>{_svg_icon('copy', 'currentColor', 11)}</button>"
    )


def _fmt_ip_badge(ip_val: str | None, *, alert: bool = False) -> str:
    """단말/공격 IP를 고대비 네온 모노스페이스 배지로 강조한다."""
    raw = str(ip_val or "").strip()
    if not raw or raw == "-":
        return '<span style="color:#64748b;">-</span>'
    if alert:
        style = (
            "background:rgba(255,26,83,0.18);border:1px solid rgba(255,26,83,0.6);"
            "color:#ffd6e0;box-shadow:0 0 12px rgba(255,26,83,0.24);"
        )
    else:
        style = (
            "background:rgba(0,240,255,0.14);border:1px solid rgba(0,240,255,0.52);"
            "color:#ffffff;box-shadow:0 0 10px rgba(0,240,255,0.18);"
        )
    return (
        f'<code style="{style}font-weight:800;font-size:12.5px;padding:3px 9px;'
        f'border-radius:7px;letter-spacing:0.02em;white-space:nowrap;">{html.escape(raw)}</code>'
    )


def _fmt_corr_badge(link_type: str) -> str:
    if link_type == "request_id_exact":
        return f'<span class="badge b-ok">{_svg_icon("link", "#05f3ad", 12)} request_id 정확 일치</span>'
    return f'<span class="badge b-warn">{_svg_icon("radar", "#ffd740", 12)} 게이트웨이 근접 후보</span>'


def _fmt_trusted_badge(trusted: bool, *, short: bool = False) -> str:
    if short:
        return '<span style="color:#05f3ad;">신뢰 IP</span>' if trusted else '<span style="color:#ffd740;">미신뢰</span>'
    if trusted:
        return f'<span class="badge b-ok">{_svg_icon("check", "#05f3ad", 12)} 신뢰 확인 (True)</span>'
    return f'<span class="badge b-warn">{_svg_icon("warn", "#ffd740", 12)} 미신뢰 (False)</span>'


def _fmt_action_type(action_type: str) -> str:
    if action_type == "block":
        return f'{_svg_icon("shield_off", "#ff4d79", 12)} IP 차단 (block)'
    return f'{_svg_icon("unlock", "#05f3ad", 12)} 차단 해제 (unblock)'


def _summarize_event_ko(ev: dict[str, Any]) -> str:
    esc = html.escape
    src = ev.get("source")
    et = ev.get("event_type")
    user = esc(str(ev.get("username") or "-"))
    cip = esc(str(ev.get("client_ip") or ev.get("device_ip") or "-"))
    if src == "erp":
        if et == "login_failed":
            return f"계정 <strong style='color:#fb7185;'>{user}</strong> 인증 실패 · 단말 <code>{cip}</code>"
        if et == "login_success":
            return f"계정 <strong style='color:#34d399;'>{user}</strong> 정상 로그인 · 단말 <code>{cip}</code>"
        if et == "logout":
            return f"계정 <strong style='color:#93c5fd;'>{user}</strong> 세션 로그아웃 · 단말 <code>{cip}</code>"
        return f"ERP 이벤트 (<code>{esc(str(et))}</code> · 계정: <strong>{user}</strong>)"
    if src == "gateway":
        sip = esc(str(ev.get("src_ip") or "-"))
        sport = esc(str(ev.get("src_port") or "-"))
        dip = esc(str(ev.get("dst_ip") or "-"))
        dport = esc(str(ev.get("dst_port") or "-"))
        rule_id = esc(str(ev.get("rule_id") or "-"))
        if et == "fw_allow":
            return f"단말 <code>{sip}:{sport}</code> → <code>{dip}:{dport}</code> 트래픽 통과"
        return f"단말 <code>{sip}:{sport}</code> → <code>{dip}:{dport}</code> 방화벽 차단 (규칙: <code>{rule_id}</code>)"
    if src == "caddy":
        method = esc(str(ev.get("http_method") or "-"))
        path = esc(str(ev.get("http_path") or "-"))
        sc = ev.get("status_code")
        sc_str = str(sc) if sc is not None else "-"
        is_err = sc is not None and int(sc) >= 400
        status_note = f"<strong style='color:#fb7185;'>HTTP {esc(sc_str)} 오류</strong>" if is_err else f"<strong style='color:#34d399;'>HTTP {esc(sc_str)} 정상</strong>"
        return f"단말 <code>{cip}</code> → <code>{method} {path}</code> ({status_note})"
    return f"<code>{esc(str(et))}</code> ({esc(str(ev.get('outcome') or '-'))})"


def _ratio_bar(ok_cnt: int, bad_cnt: int, ok_label: str, bad_label: str) -> str:
    total = ok_cnt + bad_cnt
    ok_pct = int(round((ok_cnt / total) * 100)) if total > 0 else 50
    bad_pct = 100 - ok_pct if total > 0 else 0
    bar_bg = (
        f'<div style="display:flex;height:10px;border-radius:999px;overflow:hidden;background:rgba(4,10,24,0.9);border:1px solid rgba(0,240,255,0.28);margin-top:9px;box-shadow:inset 0 0 8px rgba(0,0,0,0.7);">'
        f'<div style="width:{ok_pct}%;background:linear-gradient(90deg,#00f0ff,#05f3ad);box-shadow:0 0 10px rgba(5,243,173,0.45);"></div>'
        f'<div style="width:{bad_pct}%;background:linear-gradient(90deg,#ff1a53,#ff5c8d);box-shadow:0 0 10px rgba(255,26,83,0.45);"></div>'
        f"</div>"
        if total > 0
        else '<div style="height:10px;border-radius:999px;background:repeating-linear-gradient(90deg,rgba(0,240,255,0.14) 0 8px,rgba(4,10,24,0.8) 8px 14px);border:1px solid rgba(0,240,255,0.24);margin-top:9px;"></div>'
    )
    return (
        f'<div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;font-size:12.5px;gap:8px;flex-wrap:wrap;">'
        f'<span style="color:#05f3ad;font-weight:700;text-shadow:0 0 8px rgba(5,243,173,0.28);">● {ok_label} {ok_cnt:,}건</span>'
        f'<span style="color:#ff4d79;font-weight:700;text-shadow:0 0 8px rgba(255,26,83,0.28);">● {bad_label} {bad_cnt:,}건 ({bad_pct}%)</span>'
        f"</div>"
        f"{bar_bg}"
        f'<div class="label" style="margin-top:6px;display:flex;justify-content:space-between;color:#8ab0d8;font-size:11.5px;">'
        f'<span>최근 1시간 합계</span><strong style="color:#e2f1ff;">{total:,}건</strong></div>'
    )


def _svg_sparkline(values: list[int], accent: str = "#05f3ad") -> str:
    vals = values[-10:] if values else [1, 2, 1, 3, 2, 4, 3, 5]
    mx = max(max(vals), 1)
    grad_id = "sp_" + "".join(ch for ch in accent if ch.isalnum())
    bars = []
    for idx, v in enumerate(vals):
        h = max(4, int(round((v / mx) * 26)))
        y = 28 - h
        x = idx * 8
        is_tip = idx >= len(vals) - 2
        op = "0.96" if is_tip else "0.38"
        stroke_attr = f' stroke="{accent}" stroke-width="0.6" stroke-opacity="0.7"' if is_tip else ""
        bars.append(
            f'<rect x="{x}" y="{y}" width="5" height="{h}" rx="2" fill="url(#{grad_id})" fill-opacity="{op}"{stroke_attr}/>'
        )
    w = len(vals) * 8
    return (
        f'<svg width="{w}" height="30" viewBox="0 0 {w} 30" aria-hidden="true">'
        f'<defs><linearGradient id="{grad_id}" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0%" stop-color="{accent}" stop-opacity="1"/>'
        f'<stop offset="100%" stop-color="{accent}" stop-opacity="0.18"/>'
        f"</linearGradient></defs>"
        f'<line x1="0" y1="28.5" x2="{w}" y2="28.5" stroke="{accent}" stroke-opacity="0.28" stroke-width="1"/>'
        f'{"".join(bars)}</svg>'
    )


def _svg_timeline_chart(events: list[dict[str, Any]], stats_map: dict[str, dict[str, Any]]) -> str:
    """실제 수집된 최근 이벤트를 12개 시간 구간으로 집계해 사이버 네온 막대 + 스무스 홀로그램 라인 복합 SVG 차트를 생성한다."""
    from datetime import timedelta

    parsed_items: list[tuple[datetime, str]] = []
    for ev in events:
        raw_ts = str(ev.get("event_ts_utc") or "").strip()
        if not raw_ts:
            continue
        try:
            iso_str = raw_ts[:-1] + "+00:00" if raw_ts.endswith("Z") else raw_ts
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            parsed_items.append((dt.astimezone(timezone(timedelta(hours=9))), str(ev.get("source") or "erp")))
        except Exception:
            continue

    num_buckets = 12
    buckets = [{"label": f"T-{num_buckets - 1 - i}", "erp": 0, "caddy": 0, "gateway": 0} for i in range(num_buckets)]
    if parsed_items:
        parsed_items.sort(key=lambda x: x[0])
        min_dt = parsed_items[0][0]
        max_dt = parsed_items[-1][0]
        span = max((max_dt - min_dt).total_seconds(), 60.0)
        step = span / num_buckets
        for i in range(num_buckets):
            b_dt = min_dt + timedelta(seconds=step * (i + 0.5))
            buckets[i]["label"] = b_dt.strftime("%H:%M")
        for dt, src in parsed_items:
            idx = min(num_buckets - 1, max(0, int((dt - min_dt).total_seconds() // max(step, 1.0))))
            if src in ("erp", "caddy", "gateway"):
                buckets[idx][src] += 1

    totals = [int(b["erp"]) + int(b["caddy"]) + int(b["gateway"]) for b in buckets]
    max_val = max(max(totals), 4)

    chart_w, chart_h = 760, 224
    pad_l, pad_r, pad_t, pad_b = 38, 20, 22, 30
    plot_w = chart_w - pad_l - pad_r
    plot_h = chart_h - pad_t - pad_b
    slot_w = plot_w / num_buckets

    grid_lines = []
    for step_idx in range(5):
        frac = step_idx / 4
        gy = pad_t + plot_h - (frac * plot_h)
        gval = int(round(max_val * frac))
        stroke_col = "rgba(0,240,255,0.28)" if step_idx == 0 else "rgba(0,240,255,0.13)"
        dash_attr = "" if step_idx == 0 else ' stroke-dasharray="3 4"'
        grid_lines.append(
            f'<line x1="{pad_l}" y1="{gy:.1f}" x2="{chart_w - pad_r}" y2="{gy:.1f}" stroke="{stroke_col}"{dash_attr} stroke-width="1"/>'
            f'<text x="{pad_l - 8}" y="{gy + 4:.1f}" text-anchor="end" fill="#8ab0d8" font-size="10.5">{gval}</text>'
        )

    bars_svg = []
    pts: list[tuple[float, float]] = []
    peak_idx = totals.index(max(totals)) if any(totals) else num_buckets - 1

    for i, b in enumerate(buckets):
        cx = pad_l + i * slot_w + slot_w * 0.5
        tot = totals[i]
        bh = (tot / max_val) * plot_h if max_val > 0 else 0
        by = pad_t + plot_h - bh
        pts.append((cx, by))

        bw = min(24.0, slot_w * 0.44)
        bx = cx - bw / 2
        is_peak = i == peak_idx and tot > 0
        bar_fill = "url(#peakBarGrad)" if is_peak else "url(#cyberBarGrad)"
        bar_stroke = "#05f3ad" if is_peak else "rgba(0,240,255,0.45)"
        bar_h = max(bh, 4.0) if tot > 0 else 2.5
        bar_y = (pad_t + plot_h - bar_h)
        bars_svg.append(
            f'<rect x="{bx:.1f}" y="{bar_y:.1f}" width="{bw:.1f}" height="{bar_h:.1f}" rx="4" fill="{bar_fill}" stroke="{bar_stroke}" stroke-width="1">'
            f'<title>{b["label"]} | 합계 {tot}건 (ERP {b["erp"]}, Caddy {b["caddy"]}, Gateway {b["gateway"]})</title></rect>'
        )
        if i % 2 == 0 or i == num_buckets - 1:
            bars_svg.append(
                f'<text x="{cx:.1f}" y="{chart_h - 8}" text-anchor="middle" fill="#8ab0d8" font-size="10.5">{html.escape(str(b["label"]))}</text>'
            )

    smooth_cmds = [f"M {pts[0][0]:.1f},{pts[0][1]:.1f}"]
    for idx_p in range(1, len(pts)):
        x0, y0 = pts[idx_p - 1]
        x1, y1 = pts[idx_p]
        mx_c = (x0 + x1) / 2.0
        smooth_cmds.append(f"C {mx_c:.1f},{y0:.1f} {mx_c:.1f},{y1:.1f} {x1:.1f},{y1:.1f}")
    poly_d = " ".join(smooth_cmds)
    area_d = (
        f"M {pts[0][0]:.1f},{pad_t + plot_h:.1f} L {pts[0][0]:.1f},{pts[0][1]:.1f} "
        + " ".join(smooth_cmds[1:])
        + f" L {pts[-1][0]:.1f},{pad_t + plot_h:.1f} Z"
    )

    dots_svg = []
    for i, (x, y) in enumerate(pts):
        if i == peak_idx and totals[i] > 0:
            dots_svg.append(
                f'<line x1="{x:.1f}" y1="{pad_t}" x2="{x:.1f}" y2="{pad_t + plot_h:.1f}" stroke="rgba(5,243,173,0.4)" stroke-dasharray="3 3" stroke-width="1"/>'
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="9" fill="rgba(5,243,173,0.16)" stroke="rgba(5,243,173,0.55)" stroke-width="1"/>'
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.8" fill="#03060d" stroke="#05f3ad" stroke-width="2.5"/>'
            )
        elif totals[i] > 0:
            dots_svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.4" fill="#03060d" stroke="#00f0ff" stroke-width="2"/>')

    peak_b = buckets[peak_idx]
    peak_tot = totals[peak_idx]
    px, py = pts[peak_idx]
    if px <= chart_w * 0.54:
        box_x = min(chart_w - 182, px + 18)
        conn_x = box_x
    else:
        box_x = max(pad_l + 6, px - 190)
        conn_x = box_x + 172
    box_y = max(pad_t + 2, min(pad_t + plot_h - 54, py - 20))
    callout_svg = (
        f'<line x1="{px:.1f}" y1="{py:.1f}" x2="{conn_x:.1f}" y2="{box_y + 24:.1f}" stroke="#05f3ad" stroke-opacity="0.65" stroke-dasharray="3 2" stroke-width="1.2"/>'
        f'<g transform="translate({box_x:.1f},{box_y:.1f})">'
        f'<rect width="172" height="50" rx="8" fill="#050d1f" fill-opacity="0.92" stroke="#00f0ff" stroke-opacity="0.7" stroke-width="1"/>'
        f'<path d="M 0,10 L 0,2 Q 0,0 2,0 L 14,0" fill="none" stroke="#05f3ad" stroke-width="2"/>'
        f'<text x="11" y="16" fill="#9ec2e6" font-size="10" font-weight="700">{html.escape(str(peak_b["label"]))} 피크 구간</text>'
        f'<text x="11" y="32" fill="#05f3ad" font-size="11" font-weight="800">ERP {peak_b["erp"]} · Caddy {peak_b["caddy"]} · GW {peak_b["gateway"]}</text>'
        f'<text x="11" y="44" fill="#e2f1ff" font-size="9.5">구간 총합: {peak_tot}건</text>'
        f"</g>"
        if peak_tot > 0
        else ""
    )

    return f"""
    <div style="display:flex;justify-content:flex-end;align-items:center;gap:14px;margin-bottom:4px;font-size:11px;color:#9ec2e6;">
      <span style="display:inline-flex;align-items:center;gap:5px;"><span style="width:10px;height:3px;background:#00f0ff;box-shadow:0 0 6px #00f0ff;display:inline-block;border-radius:2px;"></span>이벤트 유입 추세선</span>
      <span style="display:inline-flex;align-items:center;gap:5px;"><span style="width:8px;height:8px;border-radius:2px;background:rgba(0,240,255,0.45);border:1px solid #00f0ff;display:inline-block;"></span>구간 건수</span>
      <span style="display:inline-flex;align-items:center;gap:5px;"><span style="width:8px;height:8px;border-radius:50%;background:#05f3ad;box-shadow:0 0 8px #05f3ad;display:inline-block;"></span>피크 구간</span>
    </div>
    <svg viewBox="0 0 {chart_w} {chart_h}" style="width:100%;height:auto;min-height:210px;max-height:260px;display:block;overflow:visible;">
      <defs>
        <linearGradient id="cyberBarGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#00f0ff" stop-opacity="0.38"/>
          <stop offset="100%" stop-color="#2979ff" stop-opacity="0.06"/>
        </linearGradient>
        <linearGradient id="peakBarGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#05f3ad" stop-opacity="0.92"/>
          <stop offset="100%" stop-color="#00f0ff" stop-opacity="0.22"/>
        </linearGradient>
        <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#00f0ff" stop-opacity="0.24"/>
          <stop offset="55%" stop-color="#05f3ad" stop-opacity="0.08"/>
          <stop offset="100%" stop-color="#03060d" stop-opacity="0.0"/>
        </linearGradient>
        <linearGradient id="holoLineGrad" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stop-color="#00f0ff"/>
          <stop offset="55%" stop-color="#05f3ad"/>
          <stop offset="100%" stop-color="#00f0ff"/>
        </linearGradient>
        <filter id="timelineGlow" x="-10%" y="-15%" width="120%" height="130%">
          <feGaussianBlur stdDeviation="2.5" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      {"".join(grid_lines)}
      {"".join(bars_svg)}
      <path d="{area_d}" fill="url(#areaGrad)"/>
      <path d="{poly_d}" fill="none" stroke="url(#holoLineGrad)" stroke-width="2.4" stroke-linecap="round" filter="url(#timelineGlow)"/>
      {"".join(dots_svg)}
      {callout_svg}
    </svg>
    """


def _svg_donut_chart(stats_map: dict[str, dict[str, Any]]) -> str:
    """출처별 누적 로그 비중을 홀로그램 HUD 도넛 차트와 우측 비례 막대 범례로 렌더링한다."""
    gw_cnt = int(stats_map.get("gateway", {}).get("count", 0))
    caddy_cnt = int(stats_map.get("caddy", {}).get("count", 0))
    erp_cnt = int(stats_map.get("erp", {}).get("count", 0))
    total = gw_cnt + caddy_cnt + erp_cnt

    r = 54.0
    circum = 2 * 3.14159265 * r
    segments = [
        ("Gateway (방화벽)", gw_cnt, "#05f3ad", stats_map.get("gateway", {}).get("last_received_utc")),
        ("Caddy (웹 프록시)", caddy_cnt, "#00f0ff", stats_map.get("caddy", {}).get("last_received_utc")),
        ("ERP (인증 서버)", erp_cnt, "#c084fc", stats_map.get("erp", {}).get("last_received_utc")),
    ]

    circles_svg = []
    offset = 0.0
    for label, cnt, color, _ in segments:
        pct = (cnt / total) if total > 0 else 0.0
        dash = pct * circum
        if dash > 0:
            circles_svg.append(
                f'<circle cx="82" cy="82" r="{r}" fill="none" stroke="{color}" stroke-width="14" '
                f'stroke-dasharray="{dash:.2f} {circum:.2f}" stroke-dashoffset="{-offset:.2f}" '
                f'transform="rotate(-90 82 82)" filter="url(#donutGlow)"><title>{label}: {cnt:,}건</title></circle>'
            )
            offset += dash

    if not circles_svg:
        circles_svg.append(f'<circle cx="82" cy="82" r="{r}" fill="none" stroke="rgba(0,240,255,0.16)" stroke-width="14"/>')

    legend_rows = []
    for label, cnt, color, last_ts in segments:
        pct_int = int(round((cnt / total) * 100)) if total > 0 else 0
        legend_rows.append(
            f'<div style="padding:7px 9px;background:rgba(4,10,24,0.68);border:1px solid rgba(0,240,255,0.2);border-radius:8px;">'
            f'<div style="display:flex;justify-content:space-between;align-items:center;font-size:12px;gap:8px;">'
            f'<div style="display:flex;align-items:center;gap:7px;white-space:nowrap;">'
            f'<span style="width:8px;height:8px;border-radius:50%;background:{color};display:inline-block;box-shadow:0 0 8px {color};flex-shrink:0;"></span>'
            f'<span style="color:#e2f1ff;font-weight:700;">{label}</span>'
            f"</div>"
            f'<div style="display:flex;align-items:center;gap:8px;white-space:nowrap;">'
            f'<strong style="color:#ffffff;font-variant-numeric:tabular-nums;">{cnt:,}건</strong>'
            f'<span style="color:{color};font-weight:800;font-size:11px;min-width:30px;text-align:right;">{pct_int}%</span>'
            f"</div></div>"
            f'<div style="height:3px;border-radius:999px;background:rgba(0,240,255,0.1);margin-top:6px;overflow:hidden;">'
            f'<div style="width:{pct_int}%;height:100%;background:{color};box-shadow:0 0 8px {color};border-radius:999px;"></div>'
            f"</div></div>"
        )

    return f"""
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;justify-content:center;">
      <div style="position:relative;width:144px;height:144px;flex-shrink:0;">
        <svg width="144" height="144" viewBox="0 0 164 164">
          <defs>
            <filter id="donutGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="2.2" result="blur"/>
              <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
          </defs>
          <circle cx="82" cy="82" r="75" fill="none" stroke="rgba(0,240,255,0.34)" stroke-width="1.5" stroke-dasharray="2 5"/>
          <circle cx="82" cy="82" r="69" fill="none" stroke="rgba(0,240,255,0.15)" stroke-width="1"/>
          <circle cx="82" cy="82" r="{r}" fill="none" stroke="rgba(10,24,52,0.92)" stroke-width="14"/>
          {"".join(circles_svg)}
          <circle cx="82" cy="82" r="40" fill="none" stroke="rgba(0,240,255,0.28)" stroke-width="1" stroke-dasharray="4 3"/>
        </svg>
        <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;">
          <div style="font-size:20px;font-weight:900;color:#ffffff;line-height:1.1;text-shadow:0 0 14px rgba(0,240,255,0.5);">{total:,}</div>
          <div style="font-size:10px;color:#00f0ff;letter-spacing:0.04em;margin-top:3px;font-weight:700;">총 수집 이벤트</div>
        </div>
      </div>
      <div style="flex:1;min-width:175px;display:flex;flex-direction:column;gap:7px;">
        {"".join(legend_rows)}
      </div>
    </div>
    """


def _render_incident_swimlane(incidents: list[IncidentView]) -> str:
    """최신 보안 사건의 5단계 공격·상관·조치 타임라인 스윔레인을 시각화한다."""
    if not incidents:
        return (
            '<div style="padding:28px;text-align:center;color:#64748b;font-size:13px;">'
            "현재 탐지된 보안 사건이 없습니다. (5분 내 신뢰 IP 로그인 실패 5회 발생 시 자동 타임라인 생성)</div>"
        )

    inc = incidents[0]
    esc = html.escape
    ev_cnt = len(inc.evidence_events)
    exact_cnt = sum(1 for c in inc.correlations if c.link_type == "request_id_exact")
    gw_cnt = sum(1 for c in inc.correlations if c.link_type == "gateway_candidate")
    ap_cnt = len(inc.approvals)
    is_blocked = inc.status == "blocked"
    is_released = inc.status == "released"

    erp_dots = "".join(
        f'<span style="width:9px;height:9px;border-radius:50%;background:#fb7185;box-shadow:0 0 8px #f43f5e;display:inline-block;margin-right:14px;" title="실패 #{idx + 1}"></span>'
        for idx in range(min(ev_cnt, 6))
    )
    caddy_dots = (
        "".join(
            '<span style="width:9px;height:9px;border-radius:50%;background:#38bdf8;box-shadow:0 0 8px #38bdf8;display:inline-block;margin-right:16px;"></span>'
            for _ in range(min(max(exact_cnt, 1), 5))
        )
        if exact_cnt > 0
        else '<span style="font-size:11px;color:#475569;">매칭된 request_id 대기</span>'
    )
    gw_dots = (
        "".join(
            '<span style="width:9px;height:9px;border-radius:50%;background:#34d399;box-shadow:0 0 8px #10b981;display:inline-block;margin-right:16px;"></span>'
            for _ in range(min(max(gw_cnt, 1), 5))
        )
        if gw_cnt > 0
        else '<span style="font-size:11px;color:#475569;">근접 시각 게이트웨이 후보 없음</span>'
    )
    ap_dot = (
        '<span style="width:10px;height:10px;border-radius:50%;background:#fbbf24;box-shadow:0 0 9px #f59e0b;display:inline-block;margin-right:8px;"></span>'
        f'<span style="font-size:11px;color:#fde68a;">담당자 승인 {ap_cnt}건 기록됨</span>'
        if ap_cnt > 0
        else (
            '<span style="font-size:11px;color:#fbbf24;">● 담당자 차단 승인 대기 중</span>'
            if inc.block_rule_eligible else '<span style="font-size:11px;color:#94a3b8;">조사용 · 차단 불가</span>'
        )
    )
    soar_dot = (
        '<span style="width:10px;height:10px;border-radius:50%;background:#fb7185;box-shadow:0 0 9px #f43f5e;display:inline-block;margin-right:8px;"></span>'
        '<span style="font-size:11px;color:#fda4af;font-weight:700;">게이트웨이 DROP 규칙 활성 중</span>'
        if is_blocked
        else (
            '<span style="width:10px;height:10px;border-radius:50%;background:#34d399;box-shadow:0 0 9px #10b981;display:inline-block;margin-right:8px;"></span>'
            '<span style="font-size:11px;color:#86efac;font-weight:700;">차단 해제 및 단말 통신 복구 완료</span>'
            if is_released
            else '<span style="font-size:11px;color:#64748b;">차단 명령 전송 전 (미조치)</span>'
        )
    )

    return f"""
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;padding:9px 12px;background:#090d16;border:1px solid #1d2b42;border-radius:9px;margin-bottom:12px;font-size:12px;">
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="width:8px;height:8px;border-radius:50%;background:#f43f5e;display:inline-block;"></span>
        <strong style="color:#f8fafc;">{esc(inc.title)}</strong>
        <span style="color:#64748b;">|</span>
        <span>계정 <strong style="color:#38bdf8;">{esc(inc.username or '여러 계정')}</strong></span>
        <span style="color:#64748b;">|</span>
        <span>출발지 <code>{esc(inc.target_ip or '여러 출발지')}</code></span>
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        <code>{esc(inc.incident_id)}</code>
        {_fmt_status(inc.status)}
        <a href="/incidents/{esc(inc.incident_id)}" class="btn-ghost" style="padding:3px 9px;font-size:11px;">사건 상세 →</a>
      </div>
    </div>
    <div>
      <div class="swimlane-row">
        <div><div style="font-size:12px;font-weight:700;color:#e2e8f0;">1. ERP 실패</div><div style="font-size:10.5px;color:#64748b;">반복 인증 실패 ({ev_cnt}건)</div></div>
        <div class="swimlane-track" style="border-color:rgba(244,63,94,0.3);">{erp_dots}<span style="font-size:11px;color:#fda4af;">5분 내 {ev_cnt}회 연속 실패 탐지</span></div>
      </div>
      <div class="swimlane-row">
        <div><div style="font-size:12px;font-weight:700;color:#e2e8f0;">2. Caddy 요청</div><div style="font-size:10.5px;color:#64748b;">request_id 정확 일치 ({exact_cnt}건)</div></div>
        <div class="swimlane-track" style="border-color:rgba(56,189,248,0.28);">{caddy_dots}</div>
      </div>
      <div class="swimlane-row">
        <div><div style="font-size:12px;font-weight:700;color:#e2e8f0;">3. Gateway 연결 <span class="badge b-ok" style="padding:1px 5px;font-size:9px;">후보</span></div><div style="font-size:10.5px;color:#64748b;">시각·IP 근접 후보 ({gw_cnt}건)</div></div>
        <div class="swimlane-track" style="border-color:rgba(16,185,129,0.28);">{gw_dots}</div>
      </div>
      <div class="swimlane-row">
        <div><div style="font-size:12px;font-weight:700;color:#e2e8f0;">4. 담당자 승인</div><div style="font-size:10.5px;color:#64748b;">Human-in-the-Loop</div></div>
        <div class="swimlane-track">{ap_dot}</div>
      </div>
      <div class="swimlane-row">
        <div><div style="font-size:12px;font-weight:700;color:#e2e8f0;">5. 차단 · 해제</div><div style="font-size:10.5px;color:#64748b;">방화벽 Action API</div></div>
        <div class="swimlane-track">{soar_dot}</div>
      </div>
    </div>
    """


def _can_approve_incident(inc: IncidentView, auth_ok: bool) -> bool:
    return (
        auth_ok and inc.block_rule_eligible and inc.live_and_trusted_eligible
        and inc.status in {"open", "released"}
    )


def render_incident_list(
    store: DashboardStore | DbDashboardStore,
    current_user: str | None = None,
    auth_enabled: bool = False,
    csrf_token: str = "",
) -> bytes:
    esc = html.escape
    incidents = store.list_incidents()
    open_incs = [i for i in incidents if i.status == "open"]
    blocked_incs = [i for i in incidents if i.status == "blocked"]
    released_incs = [i for i in incidents if i.status == "released"]
    open_cnt = len(open_incs)
    active_blocked_ips = {
        ap.target_ip
        for i in incidents
        for ap in i.approvals
        if ap.status == "applied" and ap.target_ip
    } or {i.target_ip for i in blocked_incs if i.target_ip}
    blocked_cnt = len(active_blocked_ips)
    active_approval_cnt = sum(1 for i in incidents for ap in i.approvals if ap.status == "applied")
    released_cnt = len(released_incs)
    hourly = store.get_hourly_summary()
    stats_list = store.list_source_stats()
    stats_map = {s["source"]: s for s in stats_list}
    recent_events = store.list_recent_events(limit=120)
    auth_ok = (not auth_enabled) or bool(current_user)

    total_collected = sum(int(s.get("count", 0)) for s in stats_list)
    eligible_open_cnt = sum(1 for inc in open_incs if _can_approve_incident(inc, auth_ok))
    gw_cnt = int(stats_map.get("gateway", {}).get("count", 0))
    caddy_cnt = int(stats_map.get("caddy", {}).get("count", 0))
    erp_cnt = int(stats_map.get("erp", {}).get("count", 0))
    timeline_svg = _svg_timeline_chart(recent_events, stats_map)
    donut_html = _svg_donut_chart(stats_map)
    swimlane_html = _render_incident_swimlane(incidents)

    def _src_status_row(src_key: str, title_ko: str, dot_color: str, link_href: str) -> str:
        st = stats_map.get(src_key)
        cnt = int(st["count"]) if st else 0
        last_ts = st["last_received_utc"] if st else "수집 대기"
        ts_html = _fmt_ts(last_ts, include_utc=False)
        status_txt = "정상 수집 중" if (st and cnt > 0) else "수집 대기"
        status_col = "#05f3ad" if (st and cnt > 0) else "#64748b"
        return (
            f'<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 2px;border-bottom:1px solid rgba(0,240,255,0.14);font-size:12px;gap:8px;min-width:0;">'
            f'<div style="display:flex;align-items:center;gap:7px;white-space:nowrap;flex-shrink:0;">'
            f'<span style="width:8px;height:8px;border-radius:50%;background:{dot_color};box-shadow:0 0 8px {dot_color};display:inline-block;flex-shrink:0;"></span>'
            f'<a href="{link_href}" style="color:#ffffff;font-weight:700;white-space:nowrap;">{esc(title_ko)}</a>'
            f'<span style="color:{status_col};font-size:11.5px;white-space:nowrap;">● {status_txt}</span>'
            f"</div>"
            f'<div style="display:flex;align-items:center;gap:10px;white-space:nowrap;flex-shrink:0;margin-left:auto;">'
            f"{ts_html}"
            f'<strong style="color:#00f0ff;min-width:58px;text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums;">{cnt:,} 이벤트</strong>'
            f"</div></div>"
        )

    def _build_inc_holo_template(inc: IncidentView, idx: int) -> str:
        can_app = _can_approve_incident(inc, auth_ok)
        dis_attr = "" if can_app else "disabled"
        actor_field = (
            f'<span style="font-size:12.5px;color:#dbeafe;">승인자: <strong style="color:#05f3ad;">{esc(current_user)}</strong></span>'
            if auth_enabled and current_user
            else f'<label style="font-size:12.5px;">승인자: <input type="text" name="approved_by" value="soc-operator" required {dis_attr} style="width:120px;" /></label>'
        )
        csrf_hidden = f'<input type="hidden" name="csrf_token" value="{esc(csrf_token)}" />' if csrf_token else ""
        latest_ap = next((ap for ap in reversed(inc.approvals) if ap.status in {"applied", "pending", "unknown"}), None)
        rel_form = ""
        if latest_ap is not None:
            r_dis = "" if auth_ok else "disabled"
            rel_btn = (
                f'<form method="post" action="/incidents/{esc(inc.incident_id)}/release" style="display:inline-block;margin-left:8px;">'
                f"{csrf_hidden}"
                f'<input type="hidden" name="approval_id" value="{esc(latest_ap.approval_id)}" />'
                f'<button type="submit" class="btn-emerald" {r_dis}>{_svg_icon("unlock", "#03060d", 13)} 즉시 차단 해제 ({esc(latest_ap.approval_id)})</button></form>'
                if latest_ap.status == "applied"
                else ""
            )
            rel_form = (
                f"{rel_btn}"
                f'<form method="post" action="/incidents/{esc(inc.incident_id)}/refresh" style="display:inline-block;margin-left:6px;">'
                f"{csrf_hidden}"
                f'<input type="hidden" name="approval_id" value="{esc(latest_ap.approval_id)}" />'
                f'<button type="submit" class="secondary">{_svg_icon("refresh", "#ffffff", 13)} 상태 조회</button></form>'
            )

        ev_tr = "".join(
            f"<tr>"
            f"<td><code>{esc(ev.event_id[:12])}</code></td>"
            f"<td>{_fmt_source_badge(ev.source)}</td>"
            f"<td>{_fmt_ts(ev.event_ts_utc)}</td>"
            f"<td><code style='color:#ff4d79;'>{esc(ev.client_ip or '-')}</code> ({_fmt_trusted_badge(ev.client_ip_trusted, short=True)})</td>"
            f"<td>{esc(ev.username or '-')}</td>"
            f"<td><code>{esc(ev.request_id or '-')}</code></td>"
            f"<td>{_fmt_ingest_mode(ev.ingest_mode)}</td>"
            f"<td><code>{esc(ev.raw_id[:14])}...</code></td>"
            f"</tr>"
            for ev in inc.evidence_events
        )
        corr_tr = "".join(
            f"<tr>"
            f"<td>{_fmt_corr_badge(c.link_type)}</td>"
            f"<td><code>{esc(c.event_id[:12])}</code></td>"
            f"<td>{esc(c.reason)}</td>"
            f"<td><code>{esc(c.raw_id[:14])}...</code></td>"
            f"</tr>"
            for c in inc.correlations
        ) or "<tr><td colspan='4' style='text-align:center;color:#64748b;'>연결된 상관 이벤트 없음</td></tr>"

        return f"""
        <template id="holo-tpl-inc-{idx}">
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;">
            <div style="padding:12px 14px;background:rgba(255,26,83,0.12);border:1px solid rgba(255,26,83,0.45);border-radius:10px;">
              <div style="font-size:11px;color:#ff80a0;font-weight:700;">출발지 IP</div>
              <div style="font-size:18px;font-weight:900;color:#ff4d79;margin-top:4px;font-family:monospace;">{esc(inc.target_ip or '여러 출발지')}</div>
            </div>
            <div style="padding:12px 14px;background:rgba(0,240,255,0.1);border:1px solid rgba(0,240,255,0.4);border-radius:10px;">
              <div style="font-size:11px;color:#8ab0d8;font-weight:700;">대상 계정 / 현재 상태</div>
              <div style="font-size:16px;font-weight:800;color:#00f0ff;margin-top:4px;">{esc(inc.username or '여러 계정')} &nbsp;{_fmt_status(inc.status)}</div>
            </div>
            <div style="padding:12px 14px;background:rgba(5,243,173,0.08);border:1px solid rgba(5,243,173,0.35);border-radius:10px;">
              <div style="font-size:11px;color:#8ab0d8;font-weight:700;">탐지 근거 / 상관 연결</div>
              <div style="font-size:17px;font-weight:800;color:#05f3ad;margin-top:4px;">근거 {len(inc.evidence_events)}건 · 상관 {len(inc.correlations)}건</div>
            </div>
            <div style="padding:12px 14px;background:rgba(41,121,255,0.12);border:1px solid rgba(41,121,255,0.4);border-radius:10px;">
              <div style="font-size:11px;color:#8ab0d8;font-weight:700;">사건 생성 시각</div>
              <div style="margin-top:6px;">{_fmt_ts(inc.created_at_utc)}</div>
            </div>
          </div>

          <div style="padding:14px 16px;background:rgba(4,10,24,0.72);border:1px solid rgba(0,240,255,0.35);border-radius:12px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
              <strong style="color:#00f0ff;display:inline-flex;align-items:center;gap:5px;">{_svg_icon("bolt", "#00f0ff", 14)} SOAR 즉시 조치:</strong>
              <form method="post" action="/incidents/{esc(inc.incident_id)}/approve" style="display:inline-flex;align-items:center;gap:8px;flex-wrap:wrap;">
                {csrf_hidden}
                {actor_field}
                <label style="font-size:12.5px;">차단 시간(분): <input type="number" name="duration_minutes" value="10" min="1" max="30" required {dis_attr} style="width:68px;" /></label>
                <button type="submit" {dis_attr}>{_svg_icon("shield_off", "#ffffff", 13)} 시험 단말 차단 승인</button>
              </form>
              {rel_form}
            </div>
            <a href="/incidents/{esc(inc.incident_id)}" class="btn-ghost">전체 원본 로그(raw_logs) 페이지 열기 →</a>
          </div>

          <div style="margin-bottom:14px;">
            <h4 style="margin:0 0 8px;color:#00f0ff;font-size:13.5px;display:flex;align-items:center;gap:6px;">{_svg_icon("list", "#00f0ff", 14)} 근거 이벤트 (Evidence Events · {len(inc.evidence_events)}건)</h4>
            <table>
              <thead><tr><th>event_id</th><th>출처</th><th>발생 시각</th><th>단말 IP</th><th>계정명</th><th>request_id</th><th>수집 모드</th><th>원본 raw_id</th></tr></thead>
              <tbody>{ev_tr}</tbody>
            </table>
          </div>

          <div>
            <h4 style="margin:0 0 8px;color:#05f3ad;font-size:13.5px;display:flex;align-items:center;gap:6px;">{_svg_icon("link", "#05f3ad", 14)} 3계층 상관 분석 연결 (Caddy &amp; Gateway · {len(inc.correlations)}건)</h4>
            <table>
              <thead><tr><th>연결 구분</th><th>event_id</th><th>상관 분석 근거</th><th>원본 raw_id</th></tr></thead>
              <tbody>{corr_tr}</tbody>
            </table>
          </div>
        </template>
        """

    rows = []
    inc_templates = []
    for idx, inc in enumerate(incidents):
        inc_templates.append(_build_inc_holo_template(inc, idx))
        live_badge = (
            f'<span class="badge b-ok" title="live + trusted">{_svg_icon("check", "#05f3ad", 12)} 즉시 차단 가능 (live + trusted)</span>'
            if inc.live_and_trusted_eligible
            else f'<span class="badge b-warn">{_svg_icon("warn", "#ffd740", 12)} 차단 불가 (비라이브/미신뢰)</span>'
        )
        if not inc.block_rule_eligible:
            live_badge = '<span class="badge b-warn">조사용 · 차단 불가</span>'
        rule_label = "MITRE ATT&CK T1110.001" if inc.block_rule_eligible else "조사용 탐지"
        rows.append(
            f"<tr class='clickable-row' onclick=\"if(event.target.tagName!=='A'&&event.target.tagName!=='BUTTON')openHoloTemplate('holo-tpl-inc-{idx}','사건 상세 홀로그램 · {esc(inc.incident_id)}','{esc(rule_label)}')\">"
            f"<td><a href='/incidents/{esc(inc.incident_id)}'><strong><code>{esc(inc.incident_id)}</code></strong></a></td>"
            f"<td><strong style='color:#ffffff;'>{esc(inc.title)}</strong><div style='font-size:11px;color:#00f0ff;margin-top:2px;'>{esc(rule_label)}</div></td>"
            f"<td>{_fmt_status(inc.status)}</td>"
            f"<td><code style='font-size:12.5px;font-weight:800;color:#ff1a53;border-color:rgba(255,26,83,0.45);'>{esc(inc.target_ip or '여러 출발지')}</code></td>"
            f"<td><strong style='color:#00f0ff;'>{esc(inc.username or '여러 계정')}</strong></td>"
            f"<td>{live_badge}</td>"
            f"<td>{_fmt_ts(inc.created_at_utc)}</td>"
            f"<td style='white-space:nowrap;'><a href='/incidents/{esc(inc.incident_id)}'><button type='button' class='secondary' style='padding:5px 12px;font-size:11.5px;'>상세 · 조치 →</button></a></td>"
            f"</tr>"
        )

    table_body = "".join(rows) if rows else "<tr><td colspan='8' style='text-align:center;padding:24px;color:#64748b;'>탐지된 보안 사건이 없습니다.</td></tr>"

    # 상단 4개 카드 원클릭 대형 홀로그램 상세 데이터 템플릿 생성
    ev_modal_rows = "".join(
        f"<tr>"
        f"<td>{_fmt_ts(ev['event_ts_utc'])}</td>"
        f"<td>{_fmt_source_badge(ev['source'])}</td>"
        f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
        f"<td>{_summarize_event_ko(ev)}</td>"
        f"<td><strong style='color:#ffffff;'>{esc(ev.get('username') or '-')}</strong></td>"
        f"<td><code style='color:#00f0ff;'>{esc(ev.get('device_ip') or '-')}</code></td>"
        f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
        f"<td><code>{esc(ev['raw_id'][:14])}...</code></td>"
        f"</tr>"
        for ev in recent_events[:25]
    ) or "<tr><td colspan='8' style='text-align:center;padding:20px;color:#64748b;'>수집된 이벤트가 없습니다.</td></tr>"

    def _inc_detail_rows_html(subset: list[IncidentView], empty_msg: str) -> str:
        if not subset:
            return f"<tr><td colspan='7' style='text-align:center;padding:22px;color:#8ab0d8;'>{esc(empty_msg)}</td></tr>"
        csrf_hidden = f"<input type='hidden' name='csrf_token' value='{esc(csrf_token)}' />" if csrf_token else ""
        out = []
        for inc in subset:
            can_app = _can_approve_incident(inc, auth_ok)
            latest_ap = next((ap for ap in reversed(inc.approvals) if ap.status == "applied"), None)
            if latest_ap is not None:
                act_html = (
                    f"<form method='post' action='/incidents/{esc(inc.incident_id)}/release' style='display:inline-block;'>"
                    f"{csrf_hidden}<input type='hidden' name='approval_id' value='{esc(latest_ap.approval_id)}' />"
                    f"<button type='submit' class='btn-emerald' style='padding:5px 10px;font-size:11.5px;'>{_svg_icon('unlock', '#03060d', 12)} 즉시 차단 해제</button></form> "
                    f"<a href='/incidents/{esc(inc.incident_id)}' class='btn-ghost' style='padding:5px 10px;font-size:11.5px;'>상세 콘솔 →</a>"
                )
            elif can_app:
                act_field = (
                    ""
                    if (auth_enabled and current_user)
                    else "<input type='hidden' name='approved_by' value='soc-operator' />"
                )
                act_html = (
                    f"<form method='post' action='/incidents/{esc(inc.incident_id)}/approve' style='display:inline-flex;gap:6px;align-items:center;'>"
                    f"{csrf_hidden}{act_field}<input type='hidden' name='duration_minutes' value='10' />"
                    f"<button type='submit' style='padding:5px 10px;font-size:11.5px;'>{_svg_icon('shield_off', '#ffffff', 12)} 10분 즉시 차단 승인</button></form>"
                )
            else:
                act_html = f"<a href='/incidents/{esc(inc.incident_id)}' class='btn-ghost' style='padding:5px 10px;font-size:11.5px;'>상세 분석 보기 →</a>"

            out.append(
                f"<tr>"
                f"<td><a href='/incidents/{esc(inc.incident_id)}'><strong><code>{esc(inc.incident_id)}</code></strong></a></td>"
                f"<td><strong style='color:#ffffff;'>{esc(inc.title)}</strong><div style='font-size:11px;color:#8ab0d8;'>근거 {len(inc.evidence_events)}건 · 상관 연결 {len(inc.correlations)}건</div></td>"
                f"<td>{_fmt_status(inc.status)}</td>"
                f"<td><code style='color:#ff4d79;font-weight:800;'>{esc(inc.target_ip or '여러 출발지')}</code></td>"
                f"<td><strong style='color:#00f0ff;'>{esc(inc.username or '여러 계정')}</strong></td>"
                f"<td>{_fmt_ts(inc.created_at_utc)}</td>"
                f"<td style='white-space:nowrap;'>{act_html}</td>"
                f"</tr>"
            )
        return "".join(out)

    all_approvals_rows = []
    for inc in incidents:
        for ap in inc.approvals:
            all_approvals_rows.append(
                f"<tr>"
                f"<td><code>{esc(ap.approval_id)}</code></td>"
                f"<td><a href='/incidents/{esc(inc.incident_id)}'><code>{esc(inc.incident_id)}</code></a></td>"
                f"<td>{_fmt_status(ap.status)}</td>"
                f"<td><code style='color:#ff4d79;'>{esc(ap.target_ip)}</code></td>"
                f"<td><strong style='color:#05f3ad;'>{esc(ap.approved_by)}</strong></td>"
                f"<td>{_fmt_ts(ap.expires_at_utc)}</td>"
                f"<td><code>{esc(json.dumps(ap.gateway_response, ensure_ascii=False))}</code></td>"
                f"</tr>"
            )
    approvals_table_html = "".join(all_approvals_rows) or "<tr><td colspan='7' style='text-align:center;padding:20px;color:#8ab0d8;'>기록된 방화벽 승인·해제 이력이 없습니다.</td></tr>"

    holo_templates_html = f"""
    {"".join(inc_templates)}
    <template id="holo-tpl-events">
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px;">
        <div style="padding:12px 16px;background:rgba(16,185,129,0.12);border:1px solid rgba(5,243,173,0.4);border-radius:10px;display:flex;justify-content:space-between;align-items:center;">
          <div><div style="font-size:11px;color:#05f3ad;font-weight:800;display:flex;align-items:center;gap:5px;">{_svg_icon("shield", "#05f3ad", 13)} Gateway (방화벽)</div><div style="font-size:20px;font-weight:900;color:#ffffff;margin-top:3px;">{gw_cnt:,}건</div></div>
          <a href="/logs/gateway" class="btn-ghost" style="font-size:11px;">전용 화면 →</a>
        </div>
        <div style="padding:12px 16px;background:rgba(0,240,255,0.12);border:1px solid rgba(0,240,255,0.4);border-radius:10px;display:flex;justify-content:space-between;align-items:center;">
          <div><div style="font-size:11px;color:#00f0ff;font-weight:800;display:flex;align-items:center;gap:5px;">{_svg_icon("globe", "#00f0ff", 13)} Caddy (웹 프록시)</div><div style="font-size:20px;font-weight:900;color:#ffffff;margin-top:3px;">{caddy_cnt:,}건</div></div>
          <a href="/logs/caddy" class="btn-ghost" style="font-size:11px;">전용 화면 →</a>
        </div>
        <div style="padding:12px 16px;background:rgba(168,85,247,0.14);border:1px solid rgba(192,132,252,0.4);border-radius:10px;display:flex;justify-content:space-between;align-items:center;">
          <div><div style="font-size:11px;color:#c084fc;font-weight:800;display:flex;align-items:center;gap:5px;">{_svg_icon("server", "#c084fc", 13)} ERP (인증 서버)</div><div style="font-size:20px;font-weight:900;color:#ffffff;margin-top:3px;">{erp_cnt:,}건</div></div>
          <a href="/logs/erp" class="btn-ghost" style="font-size:11px;">전용 화면 →</a>
        </div>
      </div>
      <table>
        <thead><tr><th>발생 시각</th><th>출처</th><th>이벤트 종류</th><th>한글 로그 요약</th><th>계정</th><th>단말 IP</th><th>수집 방식</th><th>원본 raw_id</th></tr></thead>
        <tbody>{ev_modal_rows}</tbody>
      </table>
    </template>

    <template id="holo-tpl-open">
      <div style="margin-bottom:12px;font-size:12.5px;color:#dbeafe;">
        현재 미처리(<code>open</code>) 상태인 보안 사건 <b>{open_cnt}건</b> (즉시 차단 승인 가능: <b style="color:#05f3ad;">{eligible_open_cnt}건</b>)의 상세 목록입니다. 이 창에서 바로 차단을 승인하거나 상세 콘솔로 이동할 수 있습니다.
      </div>
      <table>
        <thead><tr><th>사건 ID</th><th>탐지 내용 · 근거 수</th><th>상태</th><th>공격 의심 IP</th><th>대상 계정</th><th>발생 시각</th><th>즉시 조치 / 상세</th></tr></thead>
        <tbody>{_inc_detail_rows_html(open_incs, "현재 미처리(open) 상태인 보안 사건이 없습니다.")}</tbody>
      </table>
    </template>

    <template id="holo-tpl-blocked">
      <div style="margin-bottom:12px;font-size:12.5px;color:#dbeafe;">
        현재 게이트웨이 방화벽에 <code>DROP</code> 차단 규칙이 적용 중인 사건 <b>{blocked_cnt}건</b>입니다. 이 창에서 바로 차단을 해제하거나 상태를 조회할 수 있습니다.
      </div>
      <table>
        <thead><tr><th>사건 ID</th><th>탐지 내용 · 근거 수</th><th>상태</th><th>차단된 IP</th><th>대상 계정</th><th>발생 시각</th><th>즉시 해제 / 상세</th></tr></thead>
        <tbody>{_inc_detail_rows_html(blocked_incs, "현재 활성 차단(blocked) 중인 사건이 없습니다.")}</tbody>
      </table>
    </template>

    <template id="holo-tpl-released">
      <div style="margin-bottom:12px;font-size:12.5px;color:#dbeafe;">
        차단 해제 및 통신 복구가 완료된 사건(<b>{released_cnt}건</b>) 및 전체 방화벽 승인·해제 감사 이력입니다.
      </div>
      <h4 style="margin:0 0 8px;color:#05f3ad;font-size:13.5px;display:flex;align-items:center;gap:6px;">{_svg_icon("check", "#05f3ad", 14)} 해제 · 복구 완료 사건 목록</h4>
      <table style="margin-bottom:16px;">
        <thead><tr><th>사건 ID</th><th>탐지 내용 · 근거 수</th><th>상태</th><th>대상 IP</th><th>대상 계정</th><th>발생 시각</th><th>재차단 / 상세</th></tr></thead>
        <tbody>{_inc_detail_rows_html(released_incs, "아직 차단 해제(released)된 사건이 없습니다.")}</tbody>
      </table>
      <h4 style="margin:0 0 8px;color:#00f0ff;font-size:13.5px;display:flex;align-items:center;gap:6px;">{_svg_icon("list", "#00f0ff", 14)} 전체 방화벽 승인 · 해제 감사 이력 (action_approvals)</h4>
      <table>
        <thead><tr><th>승인 ID</th><th>사건 ID</th><th>조치 상태</th><th>대상 IP</th><th>승인 담당자</th><th>만료 시각</th><th>게이트웨이 응답</th></tr></thead>
        <tbody>{approvals_table_html}</tbody>
      </table>
    </template>
    """

    body = f"""
    {holo_templates_html}
    <div style="display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:16px;flex-wrap:wrap;gap:10px;">
      <div>
        <div style="display:flex;align-items:center;gap:10px;">
          <h1 style="margin:0;font-size:23px;font-weight:900;color:#ffffff;letter-spacing:0.02em;text-shadow:0 0 18px rgba(0,240,255,0.45);">Security Operations Center</h1>
          <span class="badge" style="background:rgba(0,240,255,0.14);color:#00f0ff;border-color:rgba(0,240,255,0.45);">REALTIME SIEM · SOAR</span>
        </div>
        <div style="font-size:12.5px;color:#8ab0d8;margin-top:4px;">3계층(Gateway · Caddy · ERP) 실시간 위협 인텔리전스 및 방화벽 승인·차단 통합 관제</div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <a href="/events" class="btn-ghost">{_svg_icon("list", "#00f0ff", 14)} 통합 이벤트</a>
        <a href="/logs/erp" class="btn-ghost">{_svg_icon("lock", "#c084fc", 14)} ERP 로그</a>
        <a href="/logs/gateway" class="btn-ghost">{_svg_icon("shield", "#05f3ad", 14)} 방화벽 로그</a>
        <a href="/logs/caddy" class="btn-ghost">{_svg_icon("globe", "#00f0ff", 14)} 웹(Caddy) 로그</a>
      </div>
    </div>

    <div class="cards">
      <div class="card clickable" onclick="openHoloTemplate('holo-tpl-events', '수집된 전체 이벤트 실시간 스트림 ({total_collected:,}건)', 'LIVE TELEMETRY · 3-TIER')">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span class="label" style="display:inline-flex;align-items:center;gap:6px;">{_svg_icon("database", "#00f0ff", 14)} 수집된 총 이벤트</span>
          <span class="card-expand-icon" title="상세 스트림 열기">↗</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:flex-end;margin-top:4px;">
          <div>
            <div class="val" style="color:#00f0ff;">{total_collected:,}</div>
            <div style="font-size:11.5px;color:#05f3ad;margin-top:6px;font-weight:700;">↑ 실시간 3계층 수집 중</div>
          </div>
          {_svg_sparkline([3, 5, 4, 7, 6, 8, 9, max(total_collected, 10)], "#00f0ff")}
        </div>
      </div>

      <div class="card clickable" style="border-color:{'rgba(255,26,83,0.55)' if open_cnt > 0 else 'rgba(0,240,255,0.24)'};" onclick="openHoloTemplate('holo-tpl-open', '미처리 보안 사건 상세 및 즉시 승인 ({open_cnt}건)', 'OPEN INCIDENTS · ACTION REQUIRED')">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span class="label" style="display:inline-flex;align-items:center;gap:6px;">{_svg_icon("alert", "#ff4d79", 14)} 미처리 사건 (OPEN)</span>
          <span class="card-expand-icon" title="미처리 사건 상세 열기">↗</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:flex-end;margin-top:4px;">
          <div>
            <div class="val" style="color:{'#ff1a53' if open_cnt > 0 else '#ffffff'};text-shadow:0 0 14px rgba(255,26,83,0.45);">{open_cnt}</div>
            <div style="font-size:11.5px;color:#ff4d79;margin-top:6px;font-weight:700;">즉시 승인 가능: {eligible_open_cnt}건</div>
          </div>
          {_svg_sparkline([1, 0, 1, 2, 1, 2, 1, max(open_cnt, 1)], "#ff1a53")}
        </div>
      </div>

      <div class="card clickable" style="border-color:{'rgba(41,121,255,0.6)' if blocked_cnt > 0 else 'rgba(0,240,255,0.24)'};" onclick="openHoloTemplate('holo-tpl-blocked', '활성 IP 차단 현황 및 즉시 해제 ({blocked_cnt}대 IP)', 'ACTIVE FIREWALL BLOCKS')">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span class="label" style="display:inline-flex;align-items:center;gap:6px;">{_svg_icon("shield_off", "#6ea8ff", 14)} 활성 IP 차단 (BLOCKED)</span>
          <span class="card-expand-icon" title="활성 차단 상세 열기">↗</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:flex-end;margin-top:4px;">
          <div>
            <div class="val" style="color:#6ea8ff;text-shadow:0 0 14px rgba(41,121,255,0.5);">{blocked_cnt}</div>
            <div style="font-size:11.5px;color:#6ea8ff;margin-top:6px;font-weight:700;">활성 승인 {active_approval_cnt}건 · DROP 규칙</div>
          </div>
          {_svg_sparkline([0, 1, 0, 1, 1, 0, 1, max(blocked_cnt, 1)], "#2979ff")}
        </div>
      </div>

      <div class="card clickable" onclick="openHoloTemplate('holo-tpl-released', '차단 해제 · 복구 완료 및 전체 승인 감사 이력 ({released_cnt}건)', 'RELEASED & AUDIT LOG')">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span class="label" style="display:inline-flex;align-items:center;gap:6px;">{_svg_icon("check", "#05f3ad", 14)} 해제 · 복구 완료</span>
          <span class="card-expand-icon" title="해제 및 감사 이력 열기">↗</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:flex-end;margin-top:4px;">
          <div>
            <div class="val" style="color:#05f3ad;">{released_cnt}</div>
            <div style="font-size:11.5px;color:#8ab0d8;margin-top:6px;">누적 탐지 사건: 총 {len(incidents)}건</div>
          </div>
          {_svg_sparkline([1, 2, 2, 3, 2, 3, 4, max(released_cnt, 1)], "#05f3ad")}
        </div>
      </div>
    </div>

    <!-- 1행: 파노라마 이벤트 발생 추이 (좌측 와이드) + 홀로그램 도넛 & 수집 상태 (우측) -->
    <div class="grid-2col">
      <div class="panel" style="margin-bottom:0;display:flex;flex-direction:column;justify-content:space-between;">
        <div class="panel-header" style="margin-bottom:6px;">
          <div>
            <h2>{_svg_icon("trend", "#05f3ad", 15)} 이벤트 발생 추이</h2>
            <div class="panel-sub">시간 구간별 3계층(ERP · Caddy · Gateway) 수집 이벤트 유입량</div>
          </div>
        </div>
        {timeline_svg}
      </div>

      <div class="panel" style="margin-bottom:0;display:flex;flex-direction:column;justify-content:space-between;">
        <div class="panel-header" style="margin-bottom:8px;">
          <div>
            <h2>{_svg_icon("donut", "#00f0ff", 15)} 로그 출처 분포 &amp; 수집 상태</h2>
            <div class="panel-sub">전체 이벤트 비중과 계층별 실시간 수신 현황</div>
          </div>
        </div>
        {donut_html}
        <div style="margin-top:12px;padding-top:8px;border-top:1px solid rgba(0,240,255,0.2);">
          {_src_status_row("gateway", "Gateway", "#05f3ad", "/logs/gateway")}
          {_src_status_row("caddy", "Caddy", "#00f0ff", "/logs/caddy")}
          {_src_status_row("erp", "ERP", "#c084fc", "/logs/erp")}
        </div>
      </div>
    </div>

    <!-- 2행: 사건 조사 타임라인 (좌측 와이드) + 최근 1시간 정상 vs 이상 비율 게이지 (우측) -->
    <div class="grid-2col">
      <div class="panel" style="margin-bottom:0;">
        <div class="panel-header" style="margin-bottom:8px;">
          <div>
            <h2>{_svg_icon("bolt", "#00f0ff", 15)} 사건 조사 타임라인 (Correlation Sequence)</h2>
            <div class="panel-sub">최신 사건의 ERP → Caddy → Gateway 연계 및 담당자 승인·차단 흐름</div>
          </div>
        </div>
        {swimlane_html}
      </div>

      <div class="panel" style="margin-bottom:0;display:flex;flex-direction:column;justify-content:space-between;">
        <div class="panel-header" style="margin-bottom:8px;">
          <div>
            <h2>{_svg_icon("radar", "#00f0ff", 15)} 최근 1시간 정상 vs 이상</h2>
            <div class="panel-sub">계층별 실시간 허용/실패 비율</div>
          </div>
        </div>
        <div style="display:flex;flex-direction:column;gap:12px;flex:1;justify-content:center;">
          <div style="padding:12px 14px;background:rgba(4,9,22,0.68);border:1px solid rgba(0,240,255,0.3);box-shadow:inset 0 0 12px rgba(0,240,255,0.05);border-radius:10px;">
            <div class="label" style="font-weight:700;color:#e2f1ff;display:flex;align-items:center;gap:6px;">{_svg_icon("lock", "#c084fc", 13)} ERP 로그인 인증</div>
            {_ratio_bar(hourly["erp_login_success"], hourly["erp_login_failed"], "성공", "실패")}
          </div>
          <div style="padding:12px 14px;background:rgba(4,9,22,0.68);border:1px solid rgba(0,240,255,0.3);box-shadow:inset 0 0 12px rgba(0,240,255,0.05);border-radius:10px;">
            <div class="label" style="font-weight:700;color:#e2f1ff;display:flex;align-items:center;gap:6px;">{_svg_icon("shield", "#05f3ad", 13)} 방화벽(Gateway) · {_svg_icon("globe", "#00f0ff", 13)} 웹(Caddy)</div>
            {_ratio_bar(hourly["fw_allow"] + max(0, hourly["caddy_requests"] - hourly["caddy_errors"]), hourly["fw_deny"] + hourly["caddy_errors"], "정상·허용", "차단·오류")}
          </div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h2>{_svg_icon("alert", "#ff4d79", 16)} 탐지된 보안 사건 목록 (RULE-ERP-LOGIN-BRUTE-001 · 5분 내 로그인 실패 5회 이상)</h2>
          <div class="panel-sub">사건 행을 클릭하면 대형 반투명 홀로그램 창으로 근거·조치가 열리며, 우측 버튼으로 상세 페이지에 들어갈 수 있습니다.</div>
        </div>
        <span class="badge b-approved">총 {len(incidents)}건 탐지됨</span>
      </div>
      <table>
        <thead><tr><th>사건 ID</th><th>사건 내용 · 위협 분류</th><th>현재 상태</th><th>공격 의심 IP</th><th>대상 계정</th><th>방화벽 조치 자격</th><th>발생 시각</th><th>상세 / 조치</th></tr></thead>
        <tbody>{table_body}</tbody>
      </table>
    </div>
    """
    return _page_shell("관제 대시보드 · 현황 및 사건 목록", body, current_user=current_user, auth_enabled=auth_enabled, active_path="/", csrf_token=csrf_token)


def render_source_logs(
    store: DashboardStore | DbDashboardStore,
    log_kind: str,
    current_user: str | None = None,
    auth_enabled: bool = False,
    csrf_token: str = "",
) -> bytes:
    esc = html.escape
    if log_kind == "erp":
        title = "ERP 인증 관제 · 로그인/로그아웃 스트림"
        title_icon = _svg_icon("lock", "#c084fc", 16)
        sub_desc = "ERP 인증 서버에서 수집된 실시간 로그인 성공, 반복 로그인 실패(401), 세션 로그아웃 기록입니다."
        events = store.list_recent_events(
            limit=50, source="erp", event_types=("login_success", "login_failed", "logout")
        )
        ok_cnt = sum(1 for e in events if e.get("event_type") == "login_success")
        fail_cnt = sum(1 for e in events if e.get("event_type") == "login_failed")
        out_cnt = sum(1 for e in events if e.get("event_type") == "logout")
        trust_cnt = sum(1 for e in events if e.get("client_ip_trusted"))

        fail_by_user: dict[str, int] = {}
        for e in events:
            if e.get("event_type") == "login_failed":
                uname = str(e.get("username") or "").strip() or "(미상)"
                fail_by_user[uname] = fail_by_user.get(uname, 0) + 1
        top_fails = sorted(fail_by_user.items(), key=lambda item: (-item[1], item[0]))
        if top_fails:
            fail_badges = "".join(
                f'<span style="display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:999px;'
                f'background:rgba(255,26,83,0.18);border:1px solid rgba(255,26,83,0.52);color:#ffd6e0;font-size:11.5px;font-weight:800;">'
                f'<span>{esc(uname)}</span><span style="color:#ff4d79;">{cnt}건 실패</span></span>'
                for uname, cnt in top_fails[:4]
            )
            fail_banner_html = (
                f'<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;'
                f'margin-top:12px;padding:9px 13px;background:rgba(239,68,68,0.12);border:1px solid rgba(255,26,83,0.42);'
                f'border-left:3px solid #ff1a53;border-radius:8px;font-size:12px;">'
                f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'
                f'<span style="color:#ff4d79;font-weight:800;display:inline-flex;align-items:center;gap:5px;">'
                f'{_svg_icon("alert", "#ff4d79", 14)} 연속 로그인 실패 집중 계정:</span>'
                f"{fail_badges}</div>"
                f'<span style="color:#fda4af;font-size:11px;">최근 {len(events)}건 분석 기준</span></div>'
            )
        else:
            fail_banner_html = (
                f'<div style="display:flex;align-items:center;gap:8px;margin-top:12px;padding:8px 13px;'
                f'background:rgba(5,243,173,0.08);border:1px solid rgba(5,243,173,0.28);border-left:3px solid #05f3ad;'
                f'border-radius:8px;font-size:12px;color:#a7f3d0;">'
                f'{_svg_icon("check", "#05f3ad", 14)} 최근 조회된 이벤트 중 로그인 실패 집중 계정이 없습니다.</div>'
            )

        summary_cards = f"""
        <div class="cards">
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("database", "#c084fc", 14)} 조회된 ERP 인증 이벤트</div><div class="val">{len(events)}<span style="font-size:14px;color:#64748b;font-weight:500;"> / 최신 50건</span></div><div style="font-size:11.5px;color:#c084fc;margin-top:6px;">● 5초 주기 자동 동기화</div></div>
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("check", "#05f3ad", 14)} 정상 로그인 (login_success)</div><div class="val" style="color:#05f3ad;">{ok_cnt}</div><div style="font-size:11.5px;color:#64748b;margin-top:6px;">세션 로그아웃: {out_cnt}건</div></div>
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("alert", "#ff4d79", 14)} 로그인 실패 (login_failed)</div><div class="val" style="color:{'#ff4d79' if fail_cnt > 0 else '#ffffff'};">{fail_cnt}</div><div style="font-size:11.5px;color:#ff4d79;margin-top:6px;">5분 내 5회 이상 시 경보 생성</div></div>
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("shield", "#00f0ff", 14)} 신뢰 단말 IP 확인 (Trusted)</div><div class="val" style="color:#00f0ff;">{trust_cnt}</div><div style="font-size:11.5px;color:#94a3b8;margin-top:6px;">프록시 경유 검증 완료</div></div>
        </div>
        <div class="panel" style="padding:14px 20px;">
          <div class="label" style="font-weight:700;color:#e2f1ff;display:flex;align-items:center;gap:6px;">{_svg_icon("lock", "#c084fc", 14)} 최근 50건 ERP 인증 성공 vs 실패 분포</div>
          {_ratio_bar(ok_cnt, fail_cnt, "로그인 성공", "로그인 실패")}
          {fail_banner_html}
        </div>
        """
        headers = "<tr><th>상태 (인증 구분)</th><th>발생 시각</th><th>단말 IP</th><th>한글 로그 요약</th><th>사용자 계정</th><th>IP 신뢰 검증</th><th>수집 모드</th><th>추적 식별자 (request_id / raw_id)</th></tr>"
        rows = "".join(
            f'<tr class="{"row-erp-failed" if ev.get("event_type") == "login_failed" else ""}">'
            f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
            f"<td>{_fmt_ts(ev['event_ts_utc'])}</td>"
            f"<td>{_fmt_ip_badge(ev.get('client_ip'), alert=(ev.get('event_type') == 'login_failed'))}</td>"
            f"<td>{_summarize_event_ko(ev)}</td>"
            f"<td><strong style='color:#f8fafc;'>{esc(ev.get('username') or '-')}</strong></td>"
            f"<td>{_fmt_trusted_badge(bool(ev['client_ip_trusted']))}</td>"
            f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
            f"<td><div style='display:flex;flex-direction:column;gap:4px;align-items:flex-start;'>{_copy_id_chip(ev.get('request_id'), prefix='req:')}{_copy_id_chip(ev.get('raw_id'), prefix='raw:')}</div></td>"
            f"</tr>"
            for ev in events
        )
        colspan = 8
    elif log_kind == "gateway":
        title = "방화벽(Gateway) 관제 · 트래픽 허용/차단 스트림"
        title_icon = _svg_icon("shield", "#05f3ad", 16)
        sub_desc = "게이트웨이 방화벽의 패킷 통과(fw_allow), 정책 차단(POLICY), 관제 승인 차단(APR) 실시간 기록입니다."
        events = store.list_recent_events(limit=50, source="gateway")
        allow_cnt = sum(1 for e in events if e.get("event_type") == "fw_allow")
        deny_cnt = sum(1 for e in events if e.get("event_type") == "fw_deny")
        apr_cnt = sum(1 for e in events if str(e.get("rule_id") or "").startswith("APR-"))
        pol_cnt = sum(1 for e in events if e.get("rule_id") == "POLICY-CLIENT-CADDY-ONLY")

        port_counts: dict[str, int] = {}
        for e in events:
            dp = e.get("dst_port")
            if dp is not None and str(dp).strip() not in ("", "-"):
                k = str(dp).strip()
                port_counts[k] = port_counts.get(k, 0) + 1
        ordered_ports = ["8443", "8000"] + [
            p for p, _ in sorted(port_counts.items(), key=lambda x: (-x[1], x[0])) if p not in ("8443", "8000")
        ]
        port_labels = {"8443": "Caddy TLS", "8000": "ERP Web"}
        port_badges = "".join(
            f'<span style="display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;'
            f'background:{"rgba(0,240,255,0.14)" if port_counts.get(p, 0) > 0 else "rgba(15,23,42,0.72)"};'
            f'border:1px solid {"rgba(0,240,255,0.44)" if port_counts.get(p, 0) > 0 else "rgba(148,163,184,0.26)"};'
            f'font-size:11.5px;color:#e2f1ff;">'
            f'<span style="color:#00f0ff;font-weight:800;">PORT {esc(p)}</span>'
            f'<span style="color:#8ab0d8;font-size:10.5px;">{esc(port_labels.get(p, "대상 포트"))}</span>'
            f'<strong style="color:#05f3ad;">{port_counts.get(p, 0)}건</strong></span>'
            for p in ordered_ports[:4]
        )
        port_summary_html = (
            f'<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;'
            f'margin-top:11px;padding-top:10px;border-top:1px solid rgba(0,240,255,0.16);">'
            f'<span style="font-size:11.5px;color:#8ab0d8;font-weight:700;">주요 활성 포트 요약</span>'
            f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">{port_badges}</div></div>'
        )

        summary_cards = f"""
        <div class="cards">
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("shield", "#05f3ad", 14)} 조회된 방화벽 이벤트</div><div class="val">{len(events)}<span style="font-size:14px;color:#64748b;font-weight:500;"> / 최신 50건</span></div><div style="font-size:11.5px;color:#05f3ad;margin-top:6px;">● 게이트웨이 실시간 연동</div></div>
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("check", "#05f3ad", 14)} 통신 허용 (fw_allow)</div><div class="val" style="color:#05f3ad;">{allow_cnt}</div><div style="font-size:11.5px;color:#64748b;margin-top:6px;">정상 프록시 경유 트래픽</div></div>
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("stop", "#ff4d79", 14)} 방화벽 차단 (fw_deny)</div><div class="val" style="color:{'#ff4d79' if deny_cnt > 0 else '#ffffff'};">{deny_cnt}</div><div style="font-size:11.5px;color:#ff4d79;margin-top:6px;">비인가 우회 및 차단 단말 패킷</div></div>
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("alert", "#ffd740", 14)} SOAR 승인 차단 / 정책 차단</div><div class="val" style="color:#ffd740;">{apr_cnt} / {pol_cnt}</div><div style="font-size:11.5px;color:#94a3b8;margin-top:6px;">APR 규칙 / 우회 차단 정책</div></div>
        </div>
        <div class="panel" style="padding:14px 20px;">
          <div class="label" style="font-weight:700;color:#e2f1ff;display:flex;align-items:center;gap:6px;">{_svg_icon("shield", "#05f3ad", 14)} 최근 50건 방화벽 허용 vs 차단 트래픽 비율</div>
          {_ratio_bar(allow_cnt, deny_cnt, "트래픽 허용", "트래픽 차단")}
          {port_summary_html}
        </div>
        """
        headers = "<tr><th>상태 (방화벽 동작)</th><th>발생 시각</th><th>IP · 네트워크 흐름 (출발지 → 목적지:포트)</th><th>한글 로그 요약</th><th>적용 규칙 ID / 구분</th><th>수집 모드</th><th>원본 raw_id</th></tr>"
        row_list = []
        for ev in events:
            rule_id = ev.get("rule_id") or "-"
            if rule_id == "POLICY-CLIENT-CADDY-ONLY":
                rule_html = f'<span class="badge b-warn">{_svg_icon("warn", "#ffd740", 12)} 우회 정책 차단 ({esc(rule_id)})</span>'
            elif isinstance(rule_id, str) and rule_id.startswith("APR-"):
                rule_html = f'<span class="badge b-blocked">{_svg_icon("shield_off", "#ff4d79", 12)} SOAR 승인 차단 ({esc(rule_id)})</span>'
            else:
                rule_html = f"<code>{esc(str(rule_id))}</code>"
            src_ep = f"{ev.get('src_ip') or '-'}:{ev.get('src_port') or '-'}"
            dst_ep = f"{ev.get('dst_ip') or '-'}:{ev.get('dst_port') or '-'}"
            is_deny = ev.get("event_type") == "fw_deny"
            arr_col = "#ff4d79" if is_deny else "#05f3ad"
            src_style = (
                "background:rgba(255,26,83,0.18);border:1px solid rgba(255,26,83,0.58);color:#ffd6e0;"
                if is_deny
                else "background:rgba(0,240,255,0.14);border:1px solid rgba(0,240,255,0.52);color:#ffffff;"
            )
            flow_html = (
                f'<div style="display:grid;grid-template-columns:minmax(144px,1fr) 22px minmax(126px,1fr);align-items:center;gap:6px;">'
                f'<code style="{src_style}font-weight:800;font-size:12px;padding:3px 8px;border-radius:6px;text-align:right;white-space:nowrap;">{esc(src_ep)}</code>'
                f'<span style="color:{arr_col};text-align:center;font-weight:900;font-size:13px;" title="트래픽 흐름">→</span>'
                f'<code style="color:{arr_col};font-weight:700;text-align:left;white-space:nowrap;">{esc(dst_ep)}</code>'
                f"</div>"
            )
            row_list.append(
                f"<tr>"
                f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
                f"<td>{_fmt_ts(ev['event_ts_utc'])}</td>"
                f"<td>{flow_html}</td>"
                f"<td>{_summarize_event_ko(ev)}</td>"
                f"<td>{rule_html}</td>"
                f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
                f"<td>{_copy_id_chip(ev['raw_id'])}</td>"
                f"</tr>"
            )
        rows = "".join(row_list)
        colspan = 7
    else:
        title = "웹(Caddy HTTPS) 프록시 관제 · 요청/응답 스트림"
        title_icon = _svg_icon("globe", "#00f0ff", 16)
        sub_desc = "Caddy 리버스 프록시를 통과하는 HTTPS 웹 요청과 응답 상태 코드(200, 401, 403 등), 상관 추적 request_id 기록입니다."
        events = store.list_recent_events(limit=50, source="caddy")
        ok_cnt = sum(1 for e in events if e.get("status_code") is not None and int(e["status_code"]) < 400)
        err_cnt = sum(1 for e in events if e.get("status_code") is not None and int(e["status_code"]) >= 400)
        auth_err_cnt = sum(1 for e in events if e.get("status_code") in (401, 403))

        ep_stats: dict[str, dict[str, int]] = {}
        for e in events:
            p = str(e.get("http_path") or "").strip() or "-"
            sc_v = e.get("status_code")
            rec_ep = ep_stats.setdefault(p, {"total": 0, "err": 0})
            rec_ep["total"] += 1
            if sc_v is not None and int(sc_v) >= 400:
                rec_ep["err"] += 1
        for default_ep in ("/api/login", "/api/session"):
            ep_stats.setdefault(default_ep, {"total": 0, "err": 0})
        top_eps = sorted(ep_stats.items(), key=lambda x: (-x[1]["err"], -x[1]["total"], x[0]))[:4]
        ep_cards = []
        for ep_path, st_ep in top_eps:
            ep_tot = st_ep["total"]
            ep_err = st_ep["err"]
            ep_pct = int(round((ep_err / ep_tot) * 100)) if ep_tot > 0 else 0
            bar_col = "#ff1a53" if ep_err > 0 else "#05f3ad"
            txt_col = "#ff4d79" if ep_err > 0 else "#05f3ad"
            ep_cards.append(
                f'<div style="padding:7px 10px;background:rgba(4,9,20,0.72);border:1px solid rgba(0,240,255,0.22);border-radius:8px;min-width:170px;flex:1;">'
                f'<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:11.5px;">'
                f'<code style="color:#00f0ff;font-weight:700;">{esc(ep_path)}</code>'
                f'<span style="color:{txt_col};font-weight:800;white-space:nowrap;">오류 {ep_err}/{ep_tot} ({ep_pct}%)</span>'
                f"</div>"
                f'<div style="height:3px;border-radius:999px;background:rgba(0,240,255,0.12);margin-top:6px;overflow:hidden;">'
                f'<div style="width:{ep_pct if ep_err > 0 else (100 if ep_tot > 0 else 0)}%;height:100%;background:{bar_col};border-radius:999px;"></div>'
                f"</div></div>"
            )
        ep_strip_html = (
            f'<div style="margin-top:11px;padding-top:10px;border-top:1px solid rgba(0,240,255,0.16);">'
            f'<div style="font-size:11.5px;color:#8ab0d8;font-weight:700;margin-bottom:7px;">주요 엔드포인트별 오류 집중도</div>'
            f'<div style="display:flex;gap:10px;flex-wrap:wrap;">{"".join(ep_cards)}</div></div>'
        )

        summary_cards = f"""
        <div class="cards">
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("globe", "#00f0ff", 14)} 조회된 웹 프록시 요청</div><div class="val">{len(events)}<span style="font-size:14px;color:#64748b;font-weight:500;"> / 최신 50건</span></div><div style="font-size:11.5px;color:#00f0ff;margin-top:6px;">● HTTPS TLS 종단 프록시</div></div>
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("check", "#05f3ad", 14)} 정상 응답 (2xx / 3xx)</div><div class="val" style="color:#05f3ad;">{ok_cnt}</div><div style="font-size:11.5px;color:#64748b;margin-top:6px;">정상 페이지 및 API 응답</div></div>
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("alert", "#ff4d79", 14)} 오류 응답 (4xx / 5xx)</div><div class="val" style="color:{'#ff4d79' if err_cnt > 0 else '#ffffff'};">{err_cnt}</div><div style="font-size:11.5px;color:#ff4d79;margin-top:6px;">비정상 응답 감시</div></div>
          <div class="card"><div class="label" style="display:flex;align-items:center;gap:6px;">{_svg_icon("lock", "#ffd740", 14)} 인증·권한 실패 (401 / 403)</div><div class="val" style="color:#ffd740;">{auth_err_cnt}</div><div style="font-size:11.5px;color:#94a3b8;margin-top:6px;">ERP 로그인 실패 상관 대상</div></div>
        </div>
        <div class="panel" style="padding:14px 20px;">
          <div class="label" style="font-weight:700;color:#e2f1ff;display:flex;align-items:center;gap:6px;">{_svg_icon("globe", "#00f0ff", 14)} 최근 50건 웹(Caddy) 정상 응답 vs 오류 응답 비율</div>
          {_ratio_bar(ok_cnt, err_cnt, "정상 응답", "오류 응답")}
          {ep_strip_html}
        </div>
        """
        headers = "<tr><th>상태 (HTTP)</th><th>발생 시각</th><th>단말 IP</th><th>한글 로그 요약</th><th>메서드 · 요청 경로</th><th>상관 추적 request_id</th><th>수집 모드</th></tr>"
        row_list = []
        for ev in events:
            sc = ev.get("status_code")
            is_err = sc is not None and int(sc) >= 400
            sc_html = (
                f'<span class="badge" style="background:rgba(255,26,83,0.22);color:#ff4d79;border-color:rgba(255,26,83,0.68);box-shadow:0 0 12px rgba(255,26,83,0.26);">{_svg_icon("warn", "#ff4d79", 12)} HTTP {int(sc)}</span>'
                if is_err
                else f'<span class="badge" style="background:rgba(5,243,173,0.18);color:#05f3ad;border-color:rgba(5,243,173,0.62);box-shadow:0 0 10px rgba(5,243,173,0.2);">{_svg_icon("check", "#05f3ad", 12)} HTTP {sc if sc is not None else "-"}</span>'
            )
            method = str(ev.get("http_method") or "-").upper()
            path_str = str(ev.get("http_path") or "-")
            if method == "POST":
                m_style = "background:rgba(0,240,255,0.22);color:#ffffff;border-color:#00f0ff;box-shadow:0 0 8px rgba(0,240,255,0.24);"
            elif method == "GET":
                m_style = "background:rgba(5,243,173,0.18);color:#05f3ad;border-color:rgba(5,243,173,0.62);"
            else:
                m_style = "background:rgba(255,215,64,0.18);color:#ffd740;border-color:rgba(255,215,64,0.55);"
            req_html = f'<span class="badge" style="{m_style}margin-right:6px;">{esc(method)}</span><code>{esc(path_str)}</code>'
            row_list.append(
                f"<tr>"
                f"<td>{sc_html}</td>"
                f"<td>{_fmt_ts(ev['event_ts_utc'])}</td>"
                f"<td>{_fmt_ip_badge(ev.get('client_ip'), alert=is_err)}</td>"
                f"<td>{_summarize_event_ko(ev)}</td>"
                f"<td>{req_html}</td>"
                f"<td>{_copy_id_chip(ev.get('request_id'))}</td>"
                f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
                f"</tr>"
            )
        rows = "".join(row_list)
        colspan = 7

    table_body = rows or f"<tr><td colspan='{colspan}' style='text-align:center;padding:24px;color:#64748b;'>수집된 로그가 없습니다.</td></tr>"
    body = f"""
    {summary_cards}
    <div class="panel">
      <div class="panel-header">
        <div>
          <h2>{title_icon} {esc(title)}</h2>
          <div class="panel-sub">{esc(sub_desc)}</div>
        </div>
        <a href="/logs/{esc(log_kind)}"><button type="button" class="secondary">{_svg_icon("refresh", "#ffffff", 13)} 지금 새로고침</button></a>
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
        csrf_token=csrf_token,
    )


def render_recent_events(
    store: DashboardStore | DbDashboardStore,
    current_user: str | None = None,
    auth_enabled: bool = False,
    csrf_token: str = "",
) -> bytes:
    esc = html.escape
    stats = store.list_source_stats()
    stats_map = {s["source"]: s for s in stats}
    events = store.list_recent_events(limit=50)

    tier_defs = [
        ("caddy", "#00f0ff"),
        ("erp", "#c084fc"),
        ("gateway", "#05f3ad"),
    ]
    tier_parts = []
    for idx_t, (src_key, col_hex) in enumerate(tier_defs):
        st = stats_map.get(src_key)
        cnt_t = int(st["count"]) if st else 0
        last_ts_t = st.get("last_received_utc") if st else None
        status_pill = (
            '<span style="color:#05f3ad;font-size:11px;">● ACTIVE</span>'
            if cnt_t > 0
            else '<span style="color:#64748b;font-size:11px;">○ STANDBY</span>'
        )
        tier_parts.append(
            f'<div class="card"><div class="label" style="display:flex;justify-content:space-between;align-items:center;">'
            f'<span>{_fmt_source_badge(src_key)} 실시간 수집</span>{status_pill}</div>'
            f'<div class="val" style="font-size:24px;margin:8px 0;color:{col_hex};">{cnt_t:,} <span style="font-size:13px;color:#64748b;font-weight:500;">이벤트</span></div>'
            f'<div class="label">마지막 수신: {_fmt_ts(last_ts_t)}</div></div>'
        )
        if idx_t < len(tier_defs) - 1:
            tier_parts.append(
                f'<div class="tier-flow-arrow" aria-hidden="true" title="계층 간 상관 연계 흐름">'
                f'{_svg_icon("arrow_right", "#00f0ff", 22)}</div>'
            )
    stat_cards = "".join(tier_parts)

    row_items = []
    for ev in events:
        src_raw = str(ev.get("source") or "erp").lower()
        src_cls = esc(src_raw) if src_raw in ("gateway", "caddy", "erp") else "erp"
        sc_ev = ev.get("status_code")
        is_anomaly = (
            ev.get("event_type") in ("login_failed", "fw_deny")
            or ev.get("outcome") == "failure"
            or (sc_ev is not None and int(sc_ev) >= 400)
        )
        row_items.append(
            f'<tr class="tier-row-{src_cls}" data-source="{src_cls}" data-anomaly="{"1" if is_anomaly else "0"}">'
            f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
            f"<td>{_fmt_ts(ev['event_ts_utc'])}</td>"
            f"<td>{_fmt_ip_badge(ev.get('device_ip'), alert=is_anomaly)}</td>"
            f"<td>{_fmt_source_badge(ev['source'])}</td>"
            f"<td>{_summarize_event_ko(ev)}</td>"
            f"<td><strong style='color:#f8fafc;'>{esc(ev.get('username') or '-')}</strong></td>"
            f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
            f"<td>{_copy_id_chip(ev['raw_id'])}</td>"
            f"</tr>"
        )
    rows = "".join(row_items) or "<tr><td colspan='8' style='text-align:center;padding:24px;color:#64748b;'>수집된 이벤트가 없습니다.</td></tr>"

    body = f"""
    <div class="tier-flow-grid">{stat_cards}</div>
    <div class="panel">
      <div class="panel-header">
        <div>
          <h2>{_svg_icon("list", "#00f0ff", 16)} 전 계층 통합 이벤트 스트림 (최신 50건 · 5초 자동 동기화)</h2>
          <div class="panel-sub">ERP, Caddy, Gateway 3개 계층에서 정규화된 모든 이벤트를 시간순으로 통합 조회합니다.</div>
        </div>
        <a href="/events"><button type="button" class="secondary">{_svg_icon("refresh", "#ffffff", 13)} 지금 새로고침</button></a>
      </div>
      <div class="filter-chip-bar" role="toolbar" aria-label="계층 및 이상 징후 필터">
        <button type="button" class="filter-chip active" data-filter="all" onclick="setEventFilterChip('all')">전체</button>
        <button type="button" class="filter-chip" data-filter="gateway" onclick="setEventFilterChip('gateway')">Gateway</button>
        <button type="button" class="filter-chip" data-filter="caddy" onclick="setEventFilterChip('caddy')">Caddy</button>
        <button type="button" class="filter-chip" data-filter="erp" onclick="setEventFilterChip('erp')">ERP</button>
        <button type="button" class="filter-chip" data-filter="anomaly" onclick="setEventFilterChip('anomaly')">{_svg_icon("alert", "#ff4d79", 12)} 이상 징후만 보기</button>
        <span id="eventsFilterCount" style="margin-left:auto;font-size:11.5px;color:#8ab0d8;font-weight:700;">표시: {len(events)} / {len(events)}건</span>
      </div>
      <table>
        <thead><tr><th>상태 (이벤트 종류)</th><th>발생 시각</th><th>단말 IP</th><th>출처</th><th>한글 로그 요약</th><th>계정</th><th>수집 방식</th><th>원본 raw_id</th></tr></thead>
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
        csrf_token=csrf_token,
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
    csrf_token: str = "",
    *,
    followup_success: FollowupLoginSuccess | None = None,
) -> bytes:
    esc = html.escape
    err_html = f'<div class="notice">{esc(error_msg)}</div>' if error_msg else ""
    # 기존 규칙은 실패 횟수를, 새 규칙은 서로 다른 계정명 또는 출발지 수를 보여준다.
    failure_labels = {
        MULTI_ACCOUNT_RULE_ID: "개 계정명 실패",
        MULTI_SOURCE_RULE_ID: "개 출발지 실패",
    }

    alert_rows = "".join(
        f"<tr><td><code>{esc(a.alert_id)}</code></td><td><code>{esc(a.rule_id)}</code></td>"
        f"<td><strong style='color:#f8fafc;'>{esc(a.rule_name)}</strong></td>"
        f"<td><span class='badge b-blocked'>{a.failure_count}{failure_labels.get(a.rule_id, '회 연속 실패')}</span></td>"
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
        f"<td><code style='color:#ff4d79;'>{esc(ev.client_ip or '-')}</code> ({_fmt_trusted_badge(ev.client_ip_trusted, short=True)})</td>"
        f"<td>{_fmt_ingest_mode(ev.ingest_mode)}</td>"
        f"<td><a href='#raw-{esc(ev.raw_id)}'><code>{esc(ev.raw_id[:16])}...</code></a></td>"
        f"</tr>"
        for ev in inc.evidence_events
    )

    corr_rows = "".join(
        f"<tr>"
        f"<td>{_fmt_corr_badge(c.link_type)} <small>(<code>{esc(c.link_type)}</code>)</small></td>"
        f"<td><code>{esc(c.event_id[:12])}</code></td>"
        f"<td>{esc(c.reason)}</td>"
        f"<td><a href='#raw-{esc(c.raw_id)}'><code>{esc(c.raw_id[:16])}...</code></a></td></tr>"
        for c in inc.correlations
    ) or "<tr><td colspan='4' style='text-align:center;color:#64748b;'>연결된 Caddy/게이트웨이 상관 이벤트가 없습니다.</td></tr>"

    raw_blocks = "".join(
        f"<div id='raw-{esc(rid)}' style='margin-bottom:12px;padding:14px;background:rgba(4,8,18,0.85);border:1px solid rgba(0,240,255,0.22);border-radius:10px;'>"
        f"<div style='margin-bottom:8px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;'>"
        f"{_fmt_source_badge(rec.source)} {_fmt_ingest_mode(rec.ingest_mode)} "
        f"<span style='font-size:12px;color:#cbd5e1;'><strong>원본 ID:</strong> <code>{esc(rid)}</code></span> "
        f"<span style='color:#64748b;font-size:11.5px;'>(파일 오프셋: <code>{rec.line_offset}</code>)</span></div>"
        f"<pre style='margin:0;border-color:#152033;'>{esc(_pretty_json_payload(rec.raw_payload))}</pre></div>"
        for rid, rec in inc.raw_logs_by_id.items()
    )

    approval_rows = "".join(
        f"<tr><td><code>{esc(ap.approval_id)}</code></td>"
        f"<td>{_fmt_action_type(ap.action_type)}</td>"
        f"<td>{_fmt_status(ap.status)}</td>"
        f"<td><code style='color:#ff4d79;'>{esc(ap.target_ip)}</code></td><td><strong style='color:#f8fafc;'>{esc(ap.approved_by)}</strong></td>"
        f"<td>{_fmt_ts(ap.expires_at_utc)}</td>"
        f"<td><code>{esc(json.dumps(ap.gateway_response, ensure_ascii=False))}</code></td></tr>"
        for ap in inc.approvals
    ) or "<tr><td colspan='7' style='text-align:center;color:#64748b;'>아직 승인·조치 이력이 없습니다.</td></tr>"

    auth_ok = (not auth_enabled) or bool(current_user)
    # 로그인한 담당자라도 조사용 사건에서는 차단 승인 버튼을 누를 수 없다.
    can_approve = _can_approve_incident(inc, auth_ok)
    disabled_attr = "" if can_approve else "disabled"

    notices: list[str] = []
    if auth_enabled and not current_user:
        notices.append('<div class="notice">조치 승인 및 해제를 실행하려면 먼저 <a href="/login">로그인</a>해야 합니다.</div>')
    if not inc.block_rule_eligible:
        notices.append('<div class="notice">조사용 사건입니다. 방화벽 차단을 승인할 수 없습니다.</div>')
    elif not inc.live_and_trusted_eligible:
        notices.append('<div class="notice">합성(synthetic)·재생(replay) 또는 미신뢰 IP(client_ip_trusted=false) 근거에서는 실제 차단을 승인할 수 없습니다.</div>')
    gate_msg = "".join(notices)
    rule_label = "MITRE ATT&CK · T1110.001" if inc.block_rule_eligible else "조사용 · 차단 불가"

    # 성공은 담당자가 상황을 판단할 때만 쓰는 정보다. 경보나 차단 조건을 바꾸지 않는다.
    followup_panel = ""
    if inc.block_rule_eligible:
        result = '<p>현재 저장된 기록에서 조건에 맞는 로그인 성공을 확인하지 못했습니다.</p>'
        if followup_success is not None:
            result = (
                f'<p><strong>로그인 성공 확인</strong> · {_fmt_ts(followup_success.event_ts_utc)}</p>'
                f'<p>성공 원본 기록 번호 {_copy_id_chip(followup_success.raw_id, prefix="raw:")}</p>'
            )
        followup_panel = f"""
        <div class="panel">
          <h2>반복 실패 뒤 로그인 성공 여부</h2>
          <p>이 사건의 마지막 실패 뒤 {FOLLOWUP_LOGIN_MINUTES}분 안에 같은 계정과 신뢰된 같은 IP에서 성공했는지 확인합니다.</p>
          {result}
          <p>성공 기록만으로 정상 사용으로 판단할 수 없습니다. 담당자가 실패 기록과 함께 확인하세요.</p>
        </div>
        """

    actor_input = (
        f'<span style="font-size:13px;color:#cbd5e1;">승인 담당자: <strong style="color:#05f3ad;">{esc(current_user)}</strong></span>'
        if auth_enabled and current_user
        else f'<label style="font-size:13px;">승인자: <input type="text" name="approved_by" value="soc-operator" required {disabled_attr} /></label>'
    )

    csrf_hidden = f'<input type="hidden" name="csrf_token" value="{esc(csrf_token)}" />' if csrf_token else ""
    latest_applied = next((ap for ap in reversed(inc.approvals) if ap.status in {"applied", "pending", "unknown"}), None)
    release_html = ""
    if latest_applied is not None:
        rel_disabled = "" if auth_ok else "disabled"
        rel_btn = (
            f"""
        <form method="post" action="/incidents/{esc(inc.incident_id)}/release" style="display:inline-block; margin-left:10px;">
          {csrf_hidden}
          <input type="hidden" name="approval_id" value="{esc(latest_applied.approval_id)}" />
          <button type="submit" class="btn-emerald" {rel_disabled}>{_svg_icon("unlock", "#03060d", 13)} 차단 해제 요청 ({esc(latest_applied.approval_id)})</button>
        </form>"""
            if latest_applied.status == "applied"
            else ""
        )
        release_html = f"""{rel_btn}
        <form method="post" action="/incidents/{esc(inc.incident_id)}/refresh" style="display:inline-block; margin-left:8px;">
          {csrf_hidden}
          <input type="hidden" name="approval_id" value="{esc(latest_applied.approval_id)}" />
          <button type="submit" class="secondary">{_svg_icon("refresh", "#ffffff", 13)} 상태 조회</button>
        </form>
        """

    body = f"""
    <div style="margin-bottom:14px;"><a href="/" class="btn-ghost">← 통합 전광판 · 사건 목록으로 돌아가기</a></div>
    {err_html}
    <div class="panel" style="border-color:rgba(255,26,83,0.38);">
      <div class="panel-header" style="margin-bottom:12px;">
        <div>
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
            <h2 style="font-size:18px;">{_svg_icon("alert", "#ff4d79", 18)} 사건 상세 분석 콘솔: <code>{esc(inc.incident_id)}</code></h2>
            {_fmt_status(inc.status)}
            <span class="badge b-approved">{esc(rule_label)}</span>
          </div>
          <div class="panel-sub" style="margin-top:6px;">{esc(inc.title)} — 3계층(ERP · Caddy · Gateway) 상관 추적 및 SOAR 수동 승인 조치</div>
        </div>
      </div>
      <div class="cards" style="margin-bottom:0;">
        <div class="card" style="padding:12px 15px;"><div class="label">출발지 IP</div><div class="val" style="font-size:19px;color:#ff4d79;"><code>{esc(inc.target_ip or '여러 출발지')}</code></div></div>
        <div class="card" style="padding:12px 15px;"><div class="label">관련 계정</div><div class="val" style="font-size:19px;color:#00f0ff;">{esc(inc.username or '여러 계정')}</div></div>
        <div class="card" style="padding:12px 15px;"><div class="label">근거 이벤트 / 상관 연결</div><div class="val" style="font-size:19px;">{len(inc.evidence_events)}건 / {len(inc.correlations)}건</div></div>
        <div class="card" style="padding:12px 15px;"><div class="label">사건 생성 시각</div><div style="margin-top:8px;">{_fmt_ts(inc.created_at_utc)}</div></div>
      </div>
    </div>

    {followup_panel}
    <div class="panel" style="border-color:rgba(0,240,255,0.38);">
      <div class="panel-header">
        <div>
          <h2>{_svg_icon("bolt", "#00f0ff", 16)} 4. 사람 승인 및 방화벽 조치 (SOAR Action Console)</h2>
          <div class="panel-sub">실시간(live) 및 신뢰 IP(client_ip_trusted=true) 조건이 검증된 사건만 게이트웨이 차단 API를 호출합니다.</div>
        </div>
      </div>
      {gate_msg}
      <div style="padding:14px 16px;background:rgba(4,8,18,0.85);border:1px solid rgba(0,240,255,0.22);border-radius:10px;display:flex;align-items:center;flex-wrap:wrap;gap:10px;">
        <form method="post" action="/incidents/{esc(inc.incident_id)}/approve" style="display:inline-flex;align-items:center;gap:10px;flex-wrap:wrap;">
          {csrf_hidden}
          {actor_input}
          <label style="font-size:13px;color:#cbd5e1;">차단 유지 시간(분, 최대 30): <input type="number" name="duration_minutes" value="10" min="1" max="30" required {disabled_attr} style="width:72px;margin-left:4px;" /></label>
          <button type="submit" {disabled_attr}>{_svg_icon("shield_off", "#ffffff", 13)} 시험 단말 차단 승인</button>
        </form>
        {release_html}
      </div>
      <h3 style="font-size:13.5px; color:#94a3b8; margin:16px 0 10px;">승인 · 게이트웨이 조치 감사 이력</h3>
      <table>
        <thead><tr><th>승인 ID</th><th>유형</th><th>상태</th><th>대상 IP</th><th>승인자</th><th>만료 시각</th><th>게이트웨이 API 응답</th></tr></thead>
        <tbody>{approval_rows}</tbody>
      </table>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h2>{_svg_icon("link", "#05f3ad", 16)} 3. 연결 보기 (3계층 통합 관제 상관 분석)</h2>
          <div class="panel-sub">ERP 인증 실패와 정확히 일치하는 Caddy 웹 요청 및 시각·IP가 근접한 게이트웨이 트래픽 후보입니다.</div>
        </div>
      </div>
      <div class="chain">
        <span class="chain-step"><strong style="color:#ff4d79;">1. ERP 로그인 실패</strong> ({len(inc.evidence_events)}건)</span>
        <span style="color:#00f0ff;">──(<code>request_id</code> 정확 일치)──▶</span>
        <span class="chain-step"><strong style="color:#00f0ff;">2. Caddy 웹 요청</strong> ({sum(1 for c in inc.correlations if c.link_type == "request_id_exact")}건)</span>
        <span style="color:#05f3ad;">──(IP·포트·시각 근접 후보)──▶</span>
        <span class="chain-step"><strong style="color:#05f3ad;">3. 게이트웨이 접속</strong> ({sum(1 for c in inc.correlations if c.link_type == "gateway_candidate")}건 · 단정 금지)</span>
      </div>
      <table>
        <thead><tr><th>연결 유형</th><th>event_id</th><th>상관 분석 근거 설명</th><th>원본 raw_id</th></tr></thead>
        <tbody>{corr_rows}</tbody>
      </table>
    </div>

    <div class="panel">
      <div class="panel-header"><h2>{_svg_icon("alert", "#ffd740", 15)} 1. 탐지 경보 (Alerts)</h2></div>
      <div style="overflow-x:auto;">
        <table>
          <thead><tr><th>경보 ID</th><th>규칙 ID</th><th>규칙명</th><th>실패 횟수</th><th>탐지 시간창</th></tr></thead>
          <tbody>{alert_rows}</tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><h2>{_svg_icon("list", "#00f0ff", 15)} 2. 근거 이벤트 (Evidence Events → raw_id)</h2></div>
      <div style="overflow-x:auto;">
        <table>
          <thead><tr><th>event_id</th><th>출처</th><th>발생 시각</th><th>request_id</th><th>계정명</th><th>client_ip</th><th>수집 모드</th><th>원본 raw_id</th></tr></thead>
          <tbody>{ev_rows}</tbody>
        </table>
      </div>
    </div>

    <div class="panel" style="margin-top:18px;">
      <div class="panel-header">
        <div>
          <h2>{_svg_icon("terminal", "#00f0ff", 16)} 5. 원본 로그 추적 (Immutable raw_logs)</h2>
          <div class="panel-sub">정규화 전 수집된 원본 JSON 페이로드와 바이트 오프셋 증거입니다.</div>
        </div>
      </div>
      {raw_blocks}
    </div>
    """
    return _page_shell(f"사건 {inc.incident_id}", body, current_user=current_user, auth_enabled=auth_enabled, csrf_token=csrf_token)


def make_handler(
    store: DashboardStore | DbDashboardStore,
    auth_config: AuthConfig | None = None,
) -> type[BaseHTTPRequestHandler]:
    auth_enabled = auth_config is not None
    action_lock = threading.Lock()

    def _is_db_error(exc: Exception) -> bool:
        mod = type(exc).__module__
        name = type(exc).__name__
        return (
            isinstance(exc, (ConnectionError, OSError))
            or ("psycopg" in mod and name in {"OperationalError", "InterfaceError", "DatabaseError"})
        )

    class SocDashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _session_token(self) -> str | None:
            cookie_header = self.headers.get("Cookie", "")
            cookie: SimpleCookie[str] = SimpleCookie()
            cookie.load(cookie_header)
            morsel = cookie.get("soc_session")
            return morsel.value if morsel else None

        def _current_user(self) -> str | None:
            if auth_config is None:
                return None
            return auth_config.verify_session(self._session_token())

        def _csrf_token(self) -> str:
            if auth_config is None:
                return ""
            tok = self._session_token()
            return auth_config.sign_csrf(tok) if tok else ""

        def _verify_origin(self) -> bool:
            host = (self.headers.get("Host") or "").strip().lower()
            origin = (self.headers.get("Origin") or "").strip()
            referer = (self.headers.get("Referer") or "").strip()
            if origin:
                if origin == "null" or not host:
                    return False
                return urllib.parse.urlparse(origin).netloc.lower() == host
            if referer:
                if not host:
                    return False
                return urllib.parse.urlparse(referer).netloc.lower() == host
            return True

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_db_unavailable(self) -> None:
            html_body = (
                "<!doctype html><html lang='ko'><head><meta charset='utf-8'/>"
                "<meta http-equiv='refresh' content='3'/>"
                "<title>관제 DB 복구 중</title></head>"
                "<body style='background:#03060d;color:#e2f1ff;font-family:sans-serif;padding:48px;text-align:center;'>"
                "<h2 style='color:#00f0ff;'>관제 데이터베이스 재연결 중입니다</h2>"
                "<p style='color:#9ec2e6;'>잠시 후 자동으로 다시 연결됩니다 (3초 후 새로고침).</p>"
                "</body></html>"
            ).encode("utf-8")
            self._send(HTTPStatus.SERVICE_UNAVAILABLE, "text/html; charset=utf-8", html_body)

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
            csrf_tok = self._csrf_token() if user else ""

            if path == "/login" and auth_enabled:
                qs = urllib.parse.parse_qs(parsed.query)
                self._send(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    render_login_page(qs.get("error", [None])[0]),
                )
                return

            try:
                if path == "/":
                    if auth_enabled and not user:
                        self._redirect("/login")
                        return
                    self._send(
                        HTTPStatus.OK,
                        "text/html; charset=utf-8",
                        render_incident_list(store, current_user=user, auth_enabled=auth_enabled, csrf_token=csrf_tok),
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
                        render_source_logs(store, kind, current_user=user, auth_enabled=auth_enabled, csrf_token=csrf_tok),
                    )
                    return

                if path in {"/events", "/logs/events"}:
                    if auth_enabled and not user:
                        self._redirect("/login")
                        return
                    self._send(
                        HTTPStatus.OK,
                        "text/html; charset=utf-8",
                        render_recent_events(store, current_user=user, auth_enabled=auth_enabled, csrf_token=csrf_tok),
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
                    # 사건 상세를 열 때만 성공 기록을 조회한다. 차단 판단에는 사용하지 않는다.
                    followup_success = None
                    if isinstance(store, DbDashboardStore):
                        followup_success = store.repo.find_followup_login_success(inc)
                    self._send(
                        HTTPStatus.OK,
                        "text/html; charset=utf-8",
                        render_incident_detail(
                            inc, err, current_user=user, auth_enabled=auth_enabled,
                            csrf_token=csrf_tok, followup_success=followup_success,
                        ),
                    )
                    return
            except Exception as exc:
                if _is_db_error(exc):
                    self._send_db_unavailable()
                    return
                raise

            self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"Not found")

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
            form = urllib.parse.parse_qs(raw_body)

            if not self._verify_origin():
                self._send(HTTPStatus.FORBIDDEN, "text/plain; charset=utf-8", b"Forbidden: Origin mismatch")
                return

            if path == "/login" and auth_config is not None:
                uname = form.get("username", [""])[0]
                pw = form.get("password", [""])[0]
                client_ip = self.client_address[0] if self.client_address else "unknown"
                limit_key = f"{client_ip}|{uname}"
                wait_sec = auth_config.rate_limiter.check_lockout(limit_key)
                if wait_sec > 0:
                    self._send(
                        HTTPStatus.TOO_MANY_REQUESTS,
                        "text/html; charset=utf-8",
                        render_login_page(f"로그인 시도가 너무 많습니다. {wait_sec}초 후 다시 시도하세요."),
                    )
                    return
                if not auth_config.verify_credentials(uname, pw):
                    lock_sec = auth_config.rate_limiter.record_failure(limit_key)
                    err_txt = (
                        f"로그인 시도가 너무 많습니다. {lock_sec}초 후 다시 시도하세요."
                        if lock_sec > 0
                        else "아이디 또는 비밀번호가 올바르지 않습니다."
                    )
                    self._send(
                        HTTPStatus.UNAUTHORIZED,
                        "text/html; charset=utf-8",
                        render_login_page(err_txt),
                    )
                    return
                auth_config.rate_limiter.reset(limit_key)
                token = auth_config.sign_session(uname)
                self._redirect("/", set_cookie=f"soc_session={token}; Path=/; HttpOnly; SameSite=Lax")
                return

            if path == "/logout" and auth_enabled:
                user = self._current_user()
                if user and not auth_config.verify_csrf(self._session_token(), form.get("csrf_token", [""])[0]):
                    self._send(HTTPStatus.FORBIDDEN, "text/plain; charset=utf-8", b"Forbidden: Invalid CSRF token")
                    return
                self._redirect("/login", set_cookie="soc_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
                return

            if path.startswith("/incidents/") and (
                path.endswith("/approve") or path.endswith("/release") or path.endswith("/refresh")
            ):
                user = self._current_user()
                if auth_enabled and not user:
                    self._send(HTTPStatus.UNAUTHORIZED, "text/plain; charset=utf-8", b"Authentication required")
                    return
                if auth_enabled and not auth_config.verify_csrf(
                    self._session_token(), form.get("csrf_token", [""])[0]
                ):
                    self._send(HTTPStatus.FORBIDDEN, "text/plain; charset=utf-8", b"Forbidden: Invalid CSRF token")
                    return

                action_suffix = "/" + path.rsplit("/", 1)[-1]
                inc_id = urllib.parse.unquote(path[len("/incidents/") : -len(action_suffix)])

                try:
                    with action_lock:
                        if isinstance(store, DbDashboardStore) and store.practice_reset_in_progress():
                            self._send(HTTPStatus.SERVICE_UNAVAILABLE, "text/plain; charset=utf-8", "관제 기록 초기화 중입니다.".encode("utf-8"))
                            return
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
                                    existing_incidents=store.list_incidents(),
                                    on_before_call=lambda rec: store.persist_approval(inc, rec),
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
                                if ap.status != "released" and ap.gateway_response.get("error"):
                                    q = urllib.parse.urlencode({"error": f"차단 해제 실패: {ap.gateway_response.get('message') or ap.gateway_response.get('error')}"})
                                    self._redirect(f"/incidents/{urllib.parse.quote(inc_id)}?{q}")
                                    return
                        elif action_suffix == "/refresh":
                            approval_id = form.get("approval_id", [""])[0]
                            ap = refresh_approval_status(inc, approval_id=approval_id, action_client=store.action_client)
                            if ap is not None:
                                store.persist_approval(inc, ap)
                except Exception as exc:
                    if _is_db_error(exc):
                        self._send_db_unavailable()
                        return
                    raise

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
