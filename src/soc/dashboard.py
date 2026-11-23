from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
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

from .detector import (
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW_SECONDS,
    DOC_DENIED_RULE_ID,
    LOGIN_SOURCE_CHANGE_RULE_ID,
    LOGIN_SUCCESS_REVIEW_RULE_ID,
    MULTI_ACCOUNT_RULE_ID,
    MULTI_SOURCE_RULE_ID,
)
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


# ───────────── 아이디별 역할 (비밀번호는 모두 같고, 아이디로 권한을 나눈다) ─────────────
ROLE_LABELS = {"analyst": "분석가", "approver": "승인자", "admin": "관리자"}
ROLE_PERMISSIONS = {
    "analyst": frozenset({"view"}),                              # 조회만
    "approver": frozenset({"view", "approve", "release"}),       # 차단 승인·해제
    "admin": frozenset({"view", "approve", "release", "reset"}), # 승인자 권한 + 관제 기록 초기화
}
DEFAULT_USER_ROLES = {"analyst1": "analyst", "approver1": "approver", "admin1": "admin"}
_ACTIVE_ROLES: dict[str, str] = {}


def parse_user_roles(spec: str, operator_user: str) -> dict[str, str]:
    """'아이디:역할,아이디:역할' 문자열을 아이디→역할 표로 바꾼다. 기존 운영자 아이디는 항상 관리자다.

    spec이 비어 있으면 기본 계정(analyst1, approver1, admin1)을 쓴다. 알 수 없는 역할은 건너뛴다.
    """
    roles: dict[str, str] = {operator_user: "admin"}
    items = spec.strip()
    if not items:
        roles.update(DEFAULT_USER_ROLES)
        return roles
    for part in items.split(","):
        name, _, role = part.partition(":")
        name, role = name.strip(), role.strip()
        if name and role in ROLE_PERMISSIONS:
            roles[name] = role
    return roles


def role_of(username: str | None) -> str | None:
    return _ACTIVE_ROLES.get(username) if username else None


def role_can(username: str | None, permission: str) -> bool:
    """로그인한 아이디가 그 권한을 가졌는지. 역할이 없는 아이디는 아무것도 못 한다."""
    role = role_of(username)
    return bool(role) and permission in ROLE_PERMISSIONS[role]


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
        roles: dict[str, str] | None = None,
    ) -> None:
        self.username = username
        self.password = password
        # 역할표가 없으면 기존처럼 운영자 한 명(관리자)만 있다.
        self.roles = dict(roles) if roles else {username: "admin"}
        _ACTIVE_ROLES.clear()
        _ACTIVE_ROLES.update(self.roles)
        self.secret = (secret or secrets.token_hex(32)).encode("utf-8")
        self.ttl_seconds = ttl_seconds
        self.rate_limiter = LoginRateLimiter(
            max_failures=max_login_failures,
            lockout_seconds=lockout_seconds,
        )

    def verify_credentials(self, username: str, password: str) -> bool:
        if not self.password:
            return False
        # 등록된 아이디 중 하나와 같은지 모두 비교한다(어디서 멈추는지로 아이디 존재를 추측하지 못하게).
        user_ok = False
        for known in self.roles:
            if hmac.compare_digest(username.encode("utf-8"), known.encode("utf-8")):
                user_ok = True
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
        offset: int = 0,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
        since_utc: datetime | None = None,
        until_utc: datetime | None = None,
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
                if since_utc is not None or until_utc is not None:
                    try:
                        dt = datetime.fromisoformat(str(ev.event_ts_utc).replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        if since_utc is not None and dt < since_utc:
                            continue
                        if until_utc is not None and dt >= until_utc:
                            continue
                    except Exception:
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
        off = max(0, int(offset))
        return rows[off : off + max(1, int(limit))]

    def count_recent_events(
        self,
        *,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
        since_utc: datetime | None = None,
        until_utc: datetime | None = None,
    ) -> int:
        return len(
            self.list_recent_events(
                limit=100000,
                source=source,
                event_types=event_types,
                since_utc=since_utc,
                until_utc=until_utc,
            )
        )

    def get_login_events(self, since_utc: datetime) -> list[tuple[datetime, str, str, str]]:
        out: list[tuple[datetime, str, str, str]] = []
        for row in self.list_recent_events(limit=500, source="erp", event_types=("login_failed", "login_success")):
            dt = datetime.fromisoformat(str(row["event_ts_utc"]).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt >= since_utc:
                out.append(
                    (
                        dt.astimezone(timezone.utc),
                        str(row["event_type"]),
                        str(row.get("client_ip") or row.get("device_ip") or ""),
                        str(row.get("username") or ""),
                    )
                )
        return out

    def get_trend_events(self, since_utc: datetime) -> list[tuple[datetime, str, str, str, int | None]]:
        out: list[tuple[datetime, str, str, str, int | None]] = []
        for row in self.list_recent_events(limit=1000):
            dt = datetime.fromisoformat(str(row["event_ts_utc"]).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt >= since_utc:
                sc = row.get("status_code")
                out.append(
                    (
                        dt.astimezone(timezone.utc),
                        str(row.get("source") or ""),
                        str(row.get("event_type") or ""),
                        str(row.get("outcome") or ""),
                        int(sc) if sc is not None else None,
                    )
                )
        return out

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
        offset: int = 0,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
        since_utc: datetime | None = None,
        until_utc: datetime | None = None,
    ) -> list[dict[str, Any]]:
        return self.repo.fetch_recent_events(
            limit=limit,
            offset=offset,
            source=source,
            event_types=event_types,
            since_utc=since_utc,
            until_utc=until_utc,
        )

    def count_recent_events(
        self,
        *,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
        since_utc: datetime | None = None,
        until_utc: datetime | None = None,
    ) -> int:
        return self.repo.count_recent_events(
            source=source,
            event_types=event_types,
            since_utc=since_utc,
            until_utc=until_utc,
        )

    def get_hourly_summary(self) -> dict[str, int]:
        return self.repo.fetch_hourly_summary()

    def get_login_events(self, since_utc: datetime) -> list[tuple[datetime, str, str, str]]:
        return self.repo.fetch_login_events(since_utc)

    def get_trend_events(self, since_utc: datetime) -> list[tuple[datetime, str, str, str, int | None]]:
        return self.repo.fetch_trend_events(since_utc)

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
        "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
        "x": '<path d="M6 6l12 12M18 6 6 18"/>',
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
    bare: bool = False,
) -> bytes:
    body_cls = ' class="bare"' if bare else ""
    practice_reset_form = ""
    if (auth_enabled and current_user and csrf_token and role_can(current_user, "reset")
            and os.environ.get("SOC_ENABLE_PRACTICE_RESET") == "1"):
        practice_reset_form = (
            '<form method="post" onsubmit="return beginPracticeReset(event,this)" style="margin-top:14px;">'
            f'<input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}" />'
            '<input type="hidden" name="confirm" value="reset-practice-logs" />'
            '<button type="submit" class="btn-ghost" style="width:100%;justify-content:center;color:var(--danger);border:1px solid var(--danger);">관제 기록 초기화</button>'
            '<div role="status" class="practice-reset-status" style="font-size:11px;color:var(--text-3);margin-top:6px;">백업 없이 삭제 · 활성 차단 시 불가</div></form>'
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
                f'<div style="font-size:13px;font-weight:700;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{html.escape(current_user)}</div>'
                f'<div style="font-size:11px;color:var(--ok);">● {html.escape(ROLE_LABELS.get(role_of(current_user) or "", "역할 없음"))}</div>'
                f"</div></div>"
                f"{practice_reset_form}"
                f'<form method="post" action="/logout" style="margin-top:10px;">'
                f"{csrf_field}"
                f'<button type="submit" class="btn-ghost" style="width:100%;justify-content:center;padding:6px 10px;font-size:12px;">세션 로그아웃</button></form></div>'
            )
        else:
            auth_box = '<div class="side-user"><a href="/login" class="btn-ghost" style="display:flex;justify-content:center;">담당자 로그인 →</a></div>'

    def _nav_link(href: str, label: str, icon: str, is_active: bool) -> str:
        return (
            f'<a class="nav-link{" active" if is_active else ""}" href="{href}"'
            f'{" aria-current=\"page\"" if is_active else ""}>'
            f'<span class="nav-icon">{icon}</span><span>{label}</span></a>'
        )

    in_incident_detail = active_path.startswith("/incidents/")
    nav_groups = [
        ("관제", [
            ("/", "개요", _svg_icon("dashboard", "currentColor", 16), active_path == "/"),
            ("/#incidents", "사건", _svg_icon("alert", "currentColor", 16), in_incident_detail),
            ("/events", "이벤트", _svg_icon("list", "currentColor", 16), active_path == "/events"),
        ]),
        ("로그 소스", [
            ("/logs/erp", "ERP 인증", _svg_icon("lock", "currentColor", 16), active_path == "/logs/erp"),
            ("/logs/gateway", "방화벽", _svg_icon("shield", "currentColor", 16), active_path == "/logs/gateway"),
            ("/logs/caddy", "웹 프록시", _svg_icon("globe", "currentColor", 16), active_path == "/logs/caddy"),
        ]),
    ]
    nav_html = "".join(
        f'<div class="nav-section">{title}</div>' + "".join(_nav_link(*item) for item in items)
        for title, items in nav_groups
    )

    logo_svg = (
        '<svg width="30" height="30" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
        '<path d="M12 2.5 4.5 5.6v5.7c0 4.6 3.1 8.5 7.5 10.2 4.4-1.7 7.5-5.6 7.5-10.2V5.6L12 2.5Z" '
        'fill="var(--accent)" fill-opacity="0.18" stroke="var(--accent)" stroke-width="1.7" stroke-linejoin="round"/>'
        '<path d="m8.7 12.1 2.4 2.4 4.3-4.6" stroke="var(--accent)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>'
        "</svg>"
    )

    refresh_ms = int(refresh_seconds) * 1000 if refresh_seconds else 0
    refresh_meta = f'<noscript><meta http-equiv="refresh" content="{int(refresh_seconds)}" /></noscript>' if refresh_seconds else ""
    sync_pill = (
        f'<span id="socSyncPill" class="live-pill"><span class="pulse-dot"></span>{int(refresh_seconds)}초 자동 동기화</span>'
        if refresh_seconds
        else '<span id="socSyncPill" class="live-pill"><span class="pulse-dot"></span>실시간 연결</span>'
    )
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
  <link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin />
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable-dynamic-subset.min.css" />
  {refresh_meta}
  <title>{html.escape(title)}</title>
  <script>(function(){{try{{var t=localStorage.getItem("soc-theme");document.documentElement.setAttribute("data-theme",t==="light"?"light":"dark");}}catch(e){{document.documentElement.setAttribute("data-theme","dark");}}}})();</script>
  <style>
    /* ===== Design tokens: 중간 회색 바탕 위의 어두운 카드, 보라 단색 포인트. 상태색만 별도. ===== */
    :root {{
      color-scheme: dark;
      --bg: #4f5054; --sunken: #2c2d31; --surface: #36373b; --raised: #404146;
      --line: #4a4b50; --line-soft: #414248;
      --text: #f5f5f7; --text-2: #d0d1d7; --text-3: #a4a6ae;
      --accent: #bfd48e; --on-accent: #1d2610; --on-danger: #2a0a14; --on-ok: #06201c;
      --ok: #55c7b8; --danger: #ea7d90; --warn: #e8bb6a; --purple: #b9a6f5; --info: #bfd48e;
      --c1: #bfd48e; --c2: #7cc4f2; --c3: #b9a6f5;
      --text-rgb: 245 245 247; --sunken-rgb: 44 45 49; --surface-rgb: 54 55 59;
      --accent-rgb: 191 212 142; --ok-rgb: 85 199 184; --danger-rgb: 234 125 144;
      --warn-rgb: 232 187 106; --purple-rgb: 185 166 245; --info-rgb: 191 212 142;
      --side-bg: #3a3b3f; --side-line: #4a4b50;
      --shadow: 0 4px 14px rgb(0 0 0 / 0.28); --overlay: rgb(10 10 14 / 0.6);
      --ease: cubic-bezier(0.23, 1, 0.32, 1);
      --radius: 10px; --radius-sm: 8px;
    }}
    :root[data-theme="light"] {{
      color-scheme: light;
      --bg: #e6e7eb; --sunken: #eeeef2; --surface: #ffffff; --raised: #f6f6f9;
      --line: #dcdde3; --line-soft: #ececf1;
      --text: #1d1e24; --text-2: #4b4d58; --text-3: #6a6c78;
      --accent: #587a2a; --on-accent: #ffffff; --on-danger: #ffffff; --on-ok: #ffffff;
      --ok: #0f8576; --danger: #c23a55; --warn: #96600a; --purple: #7a56d8; --info: #587a2a;
      --c1: #587a2a; --c2: #2a86c0; --c3: #7a56d8;
      --text-rgb: 29 30 36; --sunken-rgb: 238 238 242; --surface-rgb: 255 255 255;
      --accent-rgb: 88 122 42; --ok-rgb: 15 133 118; --danger-rgb: 194 58 85;
      --warn-rgb: 150 96 10; --purple-rgb: 122 86 216; --info-rgb: 88 122 42;
      --side-bg: #f7f7f9; --side-line: #dcdde3;
      --shadow: 0 2px 8px rgb(20 20 40 / 0.08); --overlay: rgb(20 20 30 / 0.4);
    }}
    * {{ box-sizing: border-box; }}
    html {{ -webkit-text-size-adjust: 100%; }}
    body {{
      margin: 0;
      font-family: "Pretendard Variable", Pretendard, -apple-system, BlinkMacSystemFont, "Segoe UI Variable", "Segoe UI", "Malgun Gothic", system-ui, sans-serif;
      font-feature-settings: "tnum" 1;
      letter-spacing: -0.005em;
      font-size: 14px;
      line-height: 1.5;
      color: var(--text);
      background: var(--bg);
      -webkit-font-smoothing: antialiased;
    }}
    :focus-visible {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
    .layout {{ display: flex; min-height: 100vh; }}

    /* ----- 사이드바 ----- */
    aside.sidebar {{
      width: 232px;
      flex-shrink: 0;
      background: var(--side-bg);
      border-right: 1px solid var(--side-line);
      padding: 20px 12px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      position: sticky;
      top: 0;
      height: 100vh;
      z-index: 20;
    }}
    .brand {{
      display: flex; align-items: center; gap: 10px;
      padding: 4px 10px 18px;
      margin-bottom: 8px;
      cursor: pointer;
    }}
    .brand-title {{ font-size: 15px; font-weight: 700; color: var(--text); letter-spacing: -0.01em; }}
    .brand-sub {{ font-size: 11px; color: var(--text-3); margin-top: 1px; }}
    .nav-section {{ font-size: 11px; color: var(--text-3); margin: 18px 10px 6px; font-weight: 600; letter-spacing: 0.04em; }}
    .nav-link {{
      display: flex; align-items: center; gap: 10px;
      min-height: 36px;
      padding: 7px 10px;
      border-radius: var(--radius-sm);
      color: var(--text-2);
      font-size: 13.5px;
      font-weight: 500;
      margin-bottom: 2px;
      text-decoration: none;
      transition: background-color 150ms var(--ease), color 150ms var(--ease);
    }}
    .nav-icon {{ display: inline-flex; align-items: center; opacity: 0.85; }}
    /* ----- 개요 레이아웃 ----- */
    main.content {{ max-width: 1360px; }}
    .page-head {{ margin: 2px 0 22px; }}
    .eyebrow {{ font-size: 12px; font-weight: 600; letter-spacing: 0.04em; color: var(--text-3); margin-bottom: 6px; }}
    .page-head h1 {{ margin: 0; font-size: 26px; font-weight: 650; letter-spacing: -0.025em; color: var(--text); }}
    .page-head p {{ margin: 6px 0 0; font-size: 14px; color: var(--text-2); }}
    .metrics {{
      display: grid; grid-template-columns: repeat(4, 1fr);
      background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
      box-shadow: var(--shadow); margin-bottom: 20px; overflow: hidden;
    }}
    .metric {{ padding: 18px 22px; cursor: pointer; border-left: 1px solid var(--line); transition: background-color 150ms var(--ease); }}
    .metric:first-child {{ border-left: none; }}
    @media (hover: hover) {{ .metric:hover {{ background: var(--raised); }} }}
    .metric:active {{ background: var(--raised); }}
    .metric-label {{ font-size: 13px; color: var(--text-2); font-weight: 500; }}
    .metric-val {{ font-size: 32px; font-weight: 650; letter-spacing: -0.03em; margin-top: 6px; color: var(--text); font-variant-numeric: tabular-nums; line-height: 1.1; }}
    .metric-val.is-danger {{ color: var(--danger); }}
    .metric-val.is-accent {{ color: var(--accent); }}
    .metric-sub {{ font-size: 12.5px; color: var(--text-3); margin-top: 8px; }}
    @media (max-width: 900px) {{
      .metrics {{ grid-template-columns: repeat(2, 1fr); }}
      .metric:nth-child(3) {{ border-left: none; }}
      .metric:nth-child(n+3) {{ border-top: 1px solid var(--line); }}
    }}
    .panel {{ overflow-x: auto; }}
    .tbl-incidents td {{ padding-top: 14px; padding-bottom: 14px; }}
    .cell-title {{ color: var(--text); font-weight: 600; font-size: 14px; }}
    .cell-title:hover {{ color: var(--accent); text-decoration: none; }}
    .cell-sub {{ font-size: 12px; color: var(--text-3); margin-top: 3px; }}
    .range-bar {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
    a.range-chip {{ display: inline-flex; align-items: center; min-height: 30px; padding: 5px 13px; border: 1px solid var(--line); border-radius: 999px; font-size: 13px; font-weight: 500; color: var(--text-2); }}
    @media (hover: hover) {{ a.range-chip:hover {{ background: rgb(var(--text-rgb) / 0.06); color: var(--text); text-decoration: none; }} }}
    a.range-chip.active {{ background: rgb(var(--accent-rgb) / 0.16); color: var(--accent); border-color: rgb(var(--accent-rgb) / 0.5); }}
    .lf-hit {{ fill: transparent; }}
    .lf-col:hover .lf-hit {{ fill: rgb(var(--text-rgb) / 0.07); }}
    .lf-col:hover .lf-bar {{ filter: brightness(1.2); }}
    .title-en {{ font-size: 11px; font-weight: 500; letter-spacing: 0.01em; color: var(--text-3); }}
    .cell-sub .title-en::after {{ content: " · "; }}
    h1 + .title-en {{ display: block; margin-top: 4px; }}
    .cell-sub code {{ background: none; border: none; padding: 0; color: var(--text-3); }}
    code.ip {{ color: var(--text); font-weight: 600; }}
    .nowrap {{ white-space: nowrap; }}
    td.empty {{ text-align: center; padding: 32px; color: var(--text-3); }}
    .src-list {{ margin-top: 4px; }}
    .ratio-block {{ margin-top: 18px; }}
    .ratio-title {{ font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 2px; }}
    /* ----- 동적 차트 (Bklit 스타일: 그라디언트 면, 점선 격자, 크로스헤어, 툴팁) ----- */
    .bk-chart {{ position: relative; width: 100%; user-select: none; }}
    .bk-svg {{ display: block; width: 100%; overflow: visible; }}
    .bk-legend {{ display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 6px; }}
    .bk-legend button {{
      background: none; border: none; box-shadow: none; padding: 3px 6px; min-height: 0;
      color: var(--text-2); font: inherit; font-size: 13px; font-weight: 500;
      display: inline-flex; align-items: center; gap: 7px; cursor: pointer; border-radius: 6px;
    }}
    .bk-legend button i {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
    .bk-legend button.off {{ opacity: 0.4; text-decoration: line-through; }}
    @media (hover: hover) {{ .bk-legend button:hover:not(:disabled) {{ background: rgb(var(--text-rgb) / 0.06); filter: none; }} }}
    .bk-tip {{
      position: absolute; top: 0; left: 0; pointer-events: none; opacity: 0; z-index: 5;
      transition: opacity 120ms var(--ease);
      background: var(--surface); border: 1px solid var(--line); border-radius: 10px;
      padding: 10px 12px; min-width: 150px; font-size: 12.5px;
      box-shadow: 0 10px 28px rgb(0 0 0 / 0.3);
    }}
    .bk-tip .t {{ font-weight: 600; color: var(--text); margin-bottom: 6px; }}
    .bk-tip .r {{ display: flex; align-items: center; gap: 8px; color: var(--text-2); line-height: 1.75; }}
    .bk-tip .r i {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
    .bk-tip .r b {{ margin-left: auto; padding-left: 14px; color: var(--text); font-variant-numeric: tabular-nums; }}
    .bk-tip .sum {{ border-top: 1px solid var(--line-soft); margin-top: 4px; padding-top: 4px; }}
    .bk-donut-wrap {{ display: flex; align-items: center; gap: 22px; flex-wrap: wrap; }}
    .bk-donut-svg {{ width: 168px; height: 168px; flex-shrink: 0; }}
    .bk-donut-legend {{ flex: 1; min-width: 190px; display: flex; flex-direction: column; gap: 2px; }}
    .bk-donut-row {{
      display: grid; grid-template-columns: 10px 1fr auto 40px; align-items: center; gap: 10px;
      padding: 8px 10px; border-radius: 8px; font-size: 13px; color: var(--text-2);
      transition: background-color 150ms var(--ease), opacity 150ms var(--ease);
    }}
    .bk-donut-row i {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
    .bk-donut-row b {{ color: var(--text); font-weight: 600; font-variant-numeric: tabular-nums; }}
    .bk-donut-row em {{ font-style: normal; color: var(--text-3); text-align: right; font-variant-numeric: tabular-nums; }}
    @media (hover: hover) {{ .bk-donut-row:hover {{ background: rgb(var(--text-rgb) / 0.06); }} }}
    .bk-donut-row.dim {{ opacity: 0.4; }}
    .nav-link-quiet {{ min-height: 32px; font-size: 12.5px; color: var(--text-3); }}
    #incidents {{ scroll-margin-top: 16px; }}
    @media (prefers-reduced-motion: no-preference) {{ html {{ scroll-behavior: smooth; }} }}
    .nav-link.active {{ background: rgb(var(--accent-rgb) / 0.16); color: var(--text); font-weight: 600; }}
    .nav-link.active .nav-icon {{ opacity: 1; color: var(--accent); }}
    @media (hover: hover) {{
      .nav-link:hover {{ background: rgb(var(--text-rgb) / 0.06); color: var(--text); text-decoration: none; }}
      .nav-link.active:hover {{ background: rgb(var(--accent-rgb) / 0.2); }}
    }}
    .side-user {{ border-top: 1px solid var(--side-line); padding-top: 14px; margin-top: 16px; font-size: 12px; color: var(--text-2); }}
    .user-avatar {{
      width: 32px; height: 32px; border-radius: 50%;
      background: rgb(var(--accent-rgb) / 0.2); color: var(--accent);
      font-weight: 700; font-size: 13px;
      display: flex; align-items: center; justify-content: center; flex-shrink: 0;
    }}

    /* ----- 본문 / 상단바 ----- */
    main.content {{ flex: 1; min-width: 0; padding: 20px 32px 48px; max-width: 1480px; margin: 0 auto; }}
    .topbar {{
      display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
      padding-bottom: 16px; margin-bottom: 20px;
      border-bottom: 1px solid var(--line);
    }}
    .breadcrumb {{ font-size: 12.5px; color: var(--text-3); display: flex; align-items: center; gap: 8px; }}
    .breadcrumb strong {{ color: var(--text); font-weight: 600; }}
    .topbar-right {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
    .search-box-wrap {{ position: relative; display: inline-flex; align-items: center; }}
    .search-box-wrap svg {{ position: absolute; left: 10px; pointer-events: none; color: var(--text-3); }}
    .search-box {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      padding: 7px 12px 7px 30px;
      color: var(--text);
      font-size: 13px;
      width: 240px;
      min-height: 34px;
      transition: border-color 150ms var(--ease), box-shadow 150ms var(--ease);
    }}
    .search-box::placeholder {{ color: var(--text-3); }}
    .search-box:focus {{ outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgb(var(--accent-rgb) / 0.18); }}
    .live-pill {{
      display: inline-flex; align-items: center; gap: 7px;
      background: rgb(var(--ok-rgb) / 0.12);
      color: var(--ok);
      padding: 5px 11px;
      border-radius: 999px;
      font-size: 12px; font-weight: 600;
    }}
    .pulse-dot {{ width: 7px; height: 7px; border-radius: 50%; background: var(--ok); display: inline-block; }}
    @keyframes softPulse {{ 0% {{ box-shadow: 0 0 0 0 rgb(var(--ok-rgb) / 0.5); }} 70%, 100% {{ box-shadow: 0 0 0 6px rgb(var(--ok-rgb) / 0); }} }}
    .live-pill .pulse-dot {{ animation: softPulse 2.4s var(--ease) infinite; }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}

    /* ----- 카드 / 패널 ----- */
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 20px; }}
    .card, .panel {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      min-width: 0;
    }}
    .card {{ padding: 16px 18px; position: relative; transition: border-color 150ms var(--ease), background-color 150ms var(--ease); }}
    .card.clickable {{ cursor: pointer; }}
    @media (hover: hover) {{ .card.clickable:hover {{ border-color: rgb(var(--accent-rgb) / 0.6); background: var(--raised); }} }}
    .card.clickable:active {{ background: var(--raised); }}
    .card-expand-icon {{
      width: 24px; height: 24px; border-radius: 6px;
      color: var(--text-3);
      display: inline-flex; align-items: center; justify-content: center; font-size: 12px;
      transition: color 150ms var(--ease), background-color 150ms var(--ease);
    }}
    .card.clickable:hover .card-expand-icon {{ color: var(--accent); background: rgb(var(--accent-rgb) / 0.12); }}
    .card .label {{ font-size: 12.5px; color: var(--text-2); font-weight: 500; }}
    .card .val {{ font-size: 28px; font-weight: 700; margin-top: 6px; color: var(--text); letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }}
    .grid-2col {{ display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr); gap: 16px; margin-bottom: 20px; }}
    .grid-2col-eq {{ display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: 16px; margin-bottom: 20px; }}
    @media (max-width: 1120px) {{ .grid-2col, .grid-2col-eq {{ grid-template-columns: 1fr; }} }}
    .panel {{ padding: 18px 20px; margin-bottom: 20px; position: relative; }}
    .panel-header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 14px; flex-wrap: wrap; }}
    .panel h2 {{ margin: 0; font-size: 15px; font-weight: 600; color: var(--text); display: flex; align-items: center; gap: 8px; letter-spacing: -0.01em; }}
    .panel-sub {{ font-size: 12.5px; color: var(--text-3); margin-top: 3px; }}
    .chain {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 14px; font-size: 12.5px; }}
    .chain-step {{ background: var(--sunken); border: 1px solid var(--line); border-radius: var(--radius-sm); padding: 7px 12px; color: var(--text); }}

    /* ----- 표 ----- */
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13px; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line-soft); vertical-align: middle; }}
    th {{ color: var(--text-3); font-weight: 600; font-size: 12px; background: transparent; border-bottom: 1px solid var(--line); }}
    tbody tr {{ transition: background-color 120ms var(--ease); }}
    tbody tr.clickable-row {{ cursor: pointer; }}
    @media (hover: hover) {{ tbody tr:hover {{ background: rgb(var(--text-rgb) / 0.04); }} }}
    tbody tr:last-child td {{ border-bottom: none; }}

    /* ----- 상태 배지 (색 + 글자, 색만으로 구분하지 않음) ----- */
    .badge {{
      display: inline-flex; align-items: center; gap: 5px;
      padding: 3px 10px; border-radius: 999px;
      font-size: 12px; font-weight: 600; white-space: nowrap;
      border: 1px solid transparent;
    }}
    .b-open {{ background: rgb(var(--danger-rgb) / 0.14); color: var(--danger); }}
    .b-approved {{ background: rgb(var(--info-rgb) / 0.14); color: var(--info); }}
    .b-blocked, .b-applied, .b-rejected {{ background: rgb(var(--danger-rgb) / 0.14); color: var(--danger); }}
    .b-released, .b-expired, .b-ok {{ background: rgb(var(--ok-rgb) / 0.14); color: var(--ok); }}
    .b-warn {{ background: rgb(var(--warn-rgb) / 0.16); color: var(--warn); }}
    code, pre {{
      font-family: ui-monospace, "Cascadia Mono", "JetBrains Mono", "SF Mono", Consolas, monospace;
      background: var(--sunken); border: 1px solid var(--line); border-radius: 6px;
      padding: 2px 7px; font-size: 12px; color: var(--text);
    }}
    pre {{ padding: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; line-height: 1.55; }}

    /* ----- 버튼: 기본=위험 조치(차단 승인), .secondary=파랑, .btn-emerald=복구, .btn-ghost=중립 ----- */
    button {{
      background: var(--danger); color: var(--on-danger); border: 1px solid transparent;
      border-radius: var(--radius-sm);
      padding: 8px 14px; min-height: 34px;
      font: inherit; font-weight: 600; font-size: 13px;
      cursor: pointer;
      display: inline-flex; align-items: center; justify-content: center; gap: 6px;
      transition: transform 120ms var(--ease), filter 150ms var(--ease), background-color 150ms var(--ease);
    }}
    @media (hover: hover) {{ button:hover:not(:disabled) {{ filter: brightness(1.08); }} }}
    button:active:not(:disabled) {{ transform: scale(0.97); }}
    button.secondary {{ background: var(--accent); color: var(--on-accent); }}
    button.btn-emerald {{ background: var(--ok); color: var(--on-ok); }}
    .btn-ghost {{
      background: transparent; color: var(--text-2);
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      padding: 6px 12px; min-height: 34px;
      font-size: 13px; font-weight: 500;
      cursor: pointer;
      display: inline-flex; align-items: center; justify-content: center; gap: 6px;
      text-decoration: none;
    }}
    @media (hover: hover) {{ .btn-ghost:hover:not(:disabled) {{ background: rgb(var(--text-rgb) / 0.06); color: var(--text); text-decoration: none; filter: none; }} }}
    button:disabled {{ background: var(--sunken); color: var(--text-3); border-color: var(--line); cursor: not-allowed; filter: none; }}
    input, select {{
      background: var(--surface); color: var(--text);
      border: 1px solid var(--line); border-radius: var(--radius-sm);
      padding: 8px 11px; min-height: 34px; font: inherit; font-size: 13px;
      transition: border-color 150ms var(--ease), box-shadow 150ms var(--ease);
    }}
    input:focus, select:focus {{ outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgb(var(--accent-rgb) / 0.18); }}
    @media (pointer: coarse) {{ button, .btn-ghost, input, select, .nav-link {{ min-height: 44px; }} }}
    .notice {{
      background: rgb(var(--danger-rgb) / 0.1);
      border: 1px solid rgb(var(--danger-rgb) / 0.35);
      color: var(--danger);
      padding: 11px 14px; border-radius: var(--radius-sm);
      font-size: 13px; margin-bottom: 14px;
    }}
    .swimlane-row {{ display: grid; grid-template-columns: 140px 1fr; align-items: center; gap: 10px; padding: 7px 0; border-bottom: 1px solid var(--line-soft); }}
    .swimlane-row:last-child {{ border-bottom: none; }}
    .swimlane-track {{ position: relative; height: 24px; background: var(--sunken); border: 1px solid var(--line); border-radius: 999px; display: flex; align-items: center; padding: 0 12px; overflow: hidden; }}

    /* ----- 상세 창(모달) ----- */
    .holo-modal-backdrop {{
      display: none; position: fixed; inset: 0;
      background: var(--overlay);
      z-index: 9999; align-items: center; justify-content: center; padding: 24px;
    }}
    .holo-modal-backdrop.open {{ display: flex; animation: fadeIn 160ms var(--ease); }}
    .holo-modal {{
      width: 100%; max-width: 1240px; max-height: 90vh;
      display: flex; flex-direction: column;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 16px;
      box-shadow: 0 24px 64px rgb(0 0 0 / 0.35);
      padding: 22px 26px;
      position: relative; overflow: hidden; color: var(--text);
      animation: modalIn 200ms var(--ease);
    }}
    .holo-modal-body {{ overflow-y: auto; padding-right: 4px; font-size: 13.5px; line-height: 1.6; }}
    @keyframes fadeIn {{ from {{ opacity: 0; }} }}
    @keyframes modalIn {{ from {{ opacity: 0; transform: translateY(8px) scale(0.985); }} }}

    /* ----- 식별자 칩 / 토스트 ----- */
    button.id-copy-chip {{
      display: inline-flex; align-items: center; gap: 4px;
      background: none; color: var(--text-2);
      border: none; border-radius: 4px;
      padding: 1px 3px; min-height: 0;
      font-family: ui-monospace, "Cascadia Mono", "JetBrains Mono", "SF Mono", Consolas, monospace;
      font-size: 11px; font-weight: 500; cursor: pointer; white-space: nowrap; line-height: 1.5;
    }}
    @media (hover: hover) {{ button.id-copy-chip:hover:not(:disabled) {{ color: var(--accent); background: rgb(var(--text-rgb) / 0.06); filter: none; }} }}
    button.id-copy-chip.copied {{ color: var(--ok); background: rgb(var(--ok-rgb) / 0.12); }}
    .holo-copy-toast {{
      position: fixed; right: 24px; bottom: 24px; z-index: 10000;
      padding: 10px 16px; border-radius: 10px;
      background: var(--surface); border: 1px solid var(--line); color: var(--text);
      font-size: 13px; font-weight: 600;
      box-shadow: 0 12px 32px rgb(0 0 0 / 0.3);
      opacity: 0; transform: translateY(8px); pointer-events: none;
      transition: opacity 180ms var(--ease), transform 180ms var(--ease);
    }}
    .holo-copy-toast.show {{ opacity: 1; transform: translateY(0); }}

    /* ----- 행 강조 / 계층 표시 ----- */
    tr.row-erp-failed td {{ background: rgb(var(--danger-rgb) / 0.07); }}
    tr.row-erp-failed td:first-child {{ box-shadow: inset 3px 0 0 var(--danger); }}
    tr.tier-row-gateway td:first-child {{ box-shadow: inset 3px 0 0 var(--ok); }}
    tr.tier-row-caddy td:first-child {{ box-shadow: inset 3px 0 0 var(--accent); }}
    tr.tier-row-erp td:first-child {{ box-shadow: inset 3px 0 0 var(--purple); }}
    /* ----- 이벤트 탭: 같은 request_id를 잇는 색 띠 ----- */
    td.flow-cell {{ position: relative; width: 74px; min-width: 74px; padding-left: 28px; white-space: nowrap; }}
    .flow-dot {{ position: absolute; left: 14px; top: 50%; width: 9px; height: 9px; border-radius: 50%; background: var(--fc); transform: translate(-50%, -50%); z-index: 1; }}
    td.flow-cell::before {{ content: ""; position: absolute; left: 14px; top: -1px; bottom: -1px; width: 2px; background: var(--fc); transform: translateX(-50%); }}
    td.flow-cell:not([style])::before {{ display: none; }}
    tr.flow-start td.flow-cell::before {{ top: 50%; }}
    tr.flow-end td.flow-cell::before {{ bottom: 50%; }}
    tr.flow-solo td.flow-cell::before, tr.flow-solo .flow-dot, tr.flow-solo .flow-tag {{ display: none; }}
    .flow-tag {{ font: 500 11px/1 var(--mono, ui-monospace, monospace); color: var(--text-2); }}
    .flow-note {{ margin-top: 12px; }}
    .tier-flow-grid {{ display: grid; grid-template-columns: minmax(0, 1fr) 34px minmax(0, 1fr) 34px minmax(0, 1fr); gap: 8px; align-items: stretch; margin-bottom: 16px; }}
    .tier-flow-arrow {{ display: flex; align-items: center; justify-content: center; color: var(--text-3); }}
    @media (max-width: 1020px) {{
      .tier-flow-grid {{ grid-template-columns: 1fr; }}
      .tier-flow-arrow {{ transform: rotate(90deg); justify-self: center; padding: 2px 0; }}
    }}
    .filter-chip-bar {{ display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid var(--line-soft); }}
    button.filter-chip {{
      background: transparent; color: var(--text-2);
      border: 1px solid var(--line); border-radius: 999px;
      padding: 5px 13px; min-height: 30px; font-size: 13px; font-weight: 500;
    }}
    @media (hover: hover) {{ button.filter-chip:hover:not(:disabled) {{ background: rgb(var(--text-rgb) / 0.06); color: var(--text); filter: none; }} }}
    button.filter-chip.active {{ background: rgb(var(--accent-rgb) / 0.16); color: var(--accent); border-color: rgb(var(--accent-rgb) / 0.5); }}
    button.filter-chip[data-filter="gateway"].active {{ background: rgb(var(--ok-rgb) / 0.16); color: var(--ok); border-color: rgb(var(--ok-rgb) / 0.5); }}
    button.filter-chip[data-filter="erp"].active {{ background: rgb(var(--purple-rgb) / 0.16); color: var(--purple); border-color: rgb(var(--purple-rgb) / 0.5); }}
    button.filter-chip[data-filter="anomaly"].active {{ background: rgb(var(--danger-rgb) / 0.16); color: var(--danger); border-color: rgb(var(--danger-rgb) / 0.5); }}
    /* ----- 절제된 색 체계: 중립 칩 + 작은 색 점, 얇은 막대, 윤곽선 버튼 ----- */
    .badge {{
      background: rgb(var(--text-rgb) / 0.08) !important;
      border: none !important;
      color: var(--text) !important;
      padding: 3px 10px 3px 8px; gap: 6px; font-weight: 500;
    }}
    .badge::before {{ content: ""; width: 6px; height: 6px; border-radius: 50%; background: var(--text-3); flex-shrink: 0; }}
    .badge svg {{ display: none !important; }}
    .b-open::before, .b-blocked::before, .b-applied::before, .b-rejected::before {{ background: var(--danger); }}
    .b-approved::before {{ background: var(--accent); }}
    .b-released::before, .b-expired::before, .b-ok::before {{ background: var(--ok); }}
    .b-warn::before {{ background: var(--warn); }}
    .src-erp::before {{ background: var(--c1); }}
    .src-caddy::before {{ background: var(--c2); }}
    .src-gateway::before {{ background: var(--c3); }}
    .live-pill {{ background: none; padding: 5px 4px; color: var(--text-2); font-weight: 500; }}
    button.btn-emerald {{
      background: transparent; color: var(--ok);
      border: 1px solid rgb(var(--ok-rgb) / 0.55);
    }}
    button.btn-emerald svg {{ stroke: currentColor; }}
    @media (hover: hover) {{ button.btn-emerald:hover:not(:disabled) {{ background: rgb(var(--ok-rgb) / 0.12); filter: none; }} }}
    .rbar {{ display: flex; gap: 2px; height: 6px; border-radius: 999px; overflow: hidden; background: var(--line-soft); margin-top: 10px; }}
    .rbar-ok {{ background: var(--ok); }}
    .rbar-bad {{ background: var(--danger); }}
    .rbar-top {{ display: flex; justify-content: space-between; gap: 10px; flex-wrap: wrap; font-size: 13px; color: var(--text-2); margin-top: 8px; }}
    .rbar-top b {{ color: var(--text); font-weight: 600; }}
    .rbar-top em {{ font-style: normal; color: var(--text-3); }}
    .rbar-top .d {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 6px; }}
    .rbar-top .d.ok {{ background: var(--ok); }}
    .rbar-top .d.bad {{ background: var(--danger); }}
    .rbar-foot {{ display: flex; justify-content: space-between; font-size: 12px; color: var(--text-3); margin-top: 6px; }}
    .rbar-foot b {{ color: var(--text-2); font-weight: 600; }}
    /* ----- 로그인 전용 레이아웃 ----- */
    body.bare aside.sidebar, body.bare .topbar {{ display: none; }}
    body.bare .layout {{ display: block; }}
    body.bare main.content {{ max-width: none; min-height: 100vh; display: grid; place-items: center; padding: 24px; }}
    .login-wrap {{ width: 100%; max-width: 400px; }}
    .login-card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 14px; box-shadow: var(--shadow); padding: 32px; }}
    .login-brand {{ display: flex; align-items: center; gap: 12px; margin-bottom: 26px; }}
    .login-logo {{ width: 42px; height: 42px; border-radius: 10px; display: grid; place-items: center; background: rgb(var(--accent-rgb) / 0.14); flex-shrink: 0; }}
    .login-card h1 {{ margin: 0; font-size: 20px; font-weight: 650; letter-spacing: -0.02em; color: var(--text); }}
    .login-card .sub {{ font-size: 13px; color: var(--text-2); margin-top: 2px; }}
    .field {{ display: block; margin-bottom: 16px; }}
    .field span {{ display: block; font-size: 13px; font-weight: 500; color: var(--text-2); margin-bottom: 6px; }}
    .field input {{ width: 100%; min-height: 42px; }}
    .login-card button[type="submit"] {{ width: 100%; min-height: 44px; margin-top: 6px; font-size: 14px; }}
    .login-foot {{ margin-top: 20px; font-size: 12.5px; color: var(--text-3); text-align: center; }}
    /* ----- 팝업(상세 창) ----- */
    .pop-head {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; padding-bottom: 16px; margin-bottom: 18px; border-bottom: 1px solid var(--line); flex-shrink: 0; }}
    .pop-head h3 {{ margin: 8px 0 0; font-size: 19px; font-weight: 650; letter-spacing: -0.02em; color: var(--text); line-height: 1.35; }}
    .pop-badge {{ display: inline-block; font-size: 12px; font-weight: 500; color: var(--text-2); background: rgb(var(--text-rgb) / 0.08); padding: 3px 10px; border-radius: 999px; }}
    button.pop-close {{ background: transparent; color: var(--text-2); border: 1px solid var(--line); width: 34px; height: 34px; min-height: 34px; padding: 0; flex-shrink: 0; }}
    @media (hover: hover) {{ button.pop-close:hover:not(:disabled) {{ background: rgb(var(--text-rgb) / 0.08); color: var(--text); filter: none; }} }}
    .pop-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 18px; }}
    .pop-stats.three {{ grid-template-columns: repeat(3, 1fr); }}
    @media (max-width: 820px) {{ .pop-stats.three {{ grid-template-columns: 1fr; }} }}
    .pop-stat {{ padding: 14px 16px; background: var(--sunken); border: 1px solid var(--line-soft); border-radius: 10px; min-width: 0; }}
    .pop-stat .k {{ font-size: 12.5px; color: var(--text-3); display: flex; align-items: center; gap: 6px; }}
    .pop-stat .v {{ font-size: 16px; font-weight: 600; color: var(--text); margin-top: 6px; overflow-wrap: anywhere; }}
    .pop-stat .v.mono {{ font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; }}
    .pop-stat .note {{ font-size: 13px; color: var(--text-2); margin-top: 8px; line-height: 1.6; }}
    .pop-stat a {{ display: inline-block; margin-top: 8px; font-size: 12.5px; }}
    .d.c1, .d.c2, .d.c3 {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }}
    .d.c1 {{ background: var(--c1); }} .d.c2 {{ background: var(--c2); }} .d.c3 {{ background: var(--c3); }}
    .pop-actions {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; padding: 14px 16px; background: var(--sunken); border: 1px solid var(--line-soft); border-radius: 10px; margin-bottom: 18px; }}
    .pop-actions-main {{ display: flex; align-items: center; gap: 12px 14px; flex-wrap: wrap; }}
    .pop-actions-main strong {{ font-size: 13.5px; color: var(--text); }}
    .pop-form {{ display: inline-flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
    .pop-form label, .pop-actions label {{ font-size: 13px; color: var(--text-2); display: inline-flex; align-items: center; gap: 8px; }}
    .pop-actions form {{ margin: 0; }}
    .pop-section {{ margin-top: 20px; }}
    .pop-h {{ margin: 0 0 10px; font-size: 14px; font-weight: 600; color: var(--text); display: flex; align-items: baseline; gap: 8px; }}
    .pop-h span {{ font-size: 12.5px; font-weight: 400; color: var(--text-3); }}
    .pop-note {{ margin-bottom: 14px; font-size: 13.5px; line-height: 1.65; color: var(--text-2); }}
    .pop-note b {{ color: var(--text); }}
    .holo-modal-body table {{ margin-bottom: 4px; }}
    th {{ white-space: nowrap; }}
    td code {{ white-space: nowrap; }}
    .pop-actions > a {{ margin-left: auto; }}
    body {{ word-break: keep-all; overflow-wrap: break-word; }}
    .card .val {{ color: var(--text) !important; }}
    .card .val[style*="var(--danger)"] {{ color: var(--danger) !important; }}
    .detail-head {{ display: flex; align-items: center; gap: 10px 12px; flex-wrap: wrap; }}
    .detail-head h1 {{ margin: 0; font-size: 22px; font-weight: 650; letter-spacing: -0.02em; color: var(--text); }}
    .chain {{ gap: 10px; }}
    .chain-step {{ display: inline-flex; align-items: center; gap: 8px; }}
    .chain-step b {{ font-weight: 600; }}
    .chain-step em {{ font-style: normal; font-size: 12px; color: var(--text-3); }}
    .chain-arrow {{ color: var(--text-3); font-size: 12.5px; white-space: nowrap; }}
    .chain-arrow code {{ background: none; border: none; padding: 0; color: var(--text-2); }}
    details.panel > summary {{ cursor: pointer; list-style: none; display: flex; justify-content: space-between; align-items: center; gap: 12px; }}
    details.panel > summary::-webkit-details-marker {{ display: none; }}
    details.panel > summary::after {{ content: "펼치기"; font-size: 12.5px; color: var(--text-3); flex-shrink: 0; }}
    details.panel[open] > summary::after {{ content: "접기"; }}
    details.panel[open] > summary {{ margin-bottom: 14px; }}
    .holo-modal-body {{ overflow-x: auto; }}
    .holo-modal-body td.wide {{ min-width: 260px; }}
    /* ----- 이벤트 한 줄 요약 ----- */
    .ev-line {{ display: inline-flex; align-items: center; gap: 8px; white-space: nowrap; }}
    .ev-act {{ font-weight: 600; color: var(--text); display: inline-flex; align-items: center; gap: 6px; }}
    .ev-act::before {{ content: ""; width: 6px; height: 6px; border-radius: 50%; background: var(--text-3); }}
    .ev-act.bad::before {{ background: var(--danger); }}
    .ev-act.good::before {{ background: var(--ok); }}
    .ev-chip {{
      font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12.5px;
      color: var(--text-2); background: none; border: none; padding: 0;
    }}
    .ev-chip + .ev-chip::before {{ content: "·"; color: var(--text-3); margin-right: 8px; }}
    .ev-chip.bad {{ color: var(--danger); }}
    .ev-chip.good {{ color: var(--ok); }}
    .ev-arrow {{ color: var(--text-3); }}
    table.tbl-ev3 th:nth-child(1) {{ width: 230px; }}
    table.tbl-ev3 th:nth-child(2) {{ width: 130px; }}
    table.tbl-ev3 td {{ padding-top: 11px; padding-bottom: 11px; }}
    .pop-foot {{ margin-top: 16px; font-size: 13px; }}
    /* ----- 관제 실무 구성: 수집 상태 · 경과 시간 · Top-N · pivot ----- */
    .health {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px; }}
    @media (max-width: 900px) {{ .health {{ grid-template-columns: 1fr; }} }}
    .hitem {{
      display: grid; grid-template-columns: auto 1fr auto; grid-template-areas: "dot name state" "dot meta meta";
      align-items: center; column-gap: 10px; row-gap: 2px;
      background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
      padding: 12px 16px; box-shadow: var(--shadow); color: inherit; text-decoration: none;
    }}
    @media (hover: hover) {{ .hitem:hover {{ border-color: rgb(var(--accent-rgb) / 0.5); text-decoration: none; }} }}
    .hdot {{ grid-area: dot; width: 9px; height: 9px; border-radius: 50%; background: var(--text-3); }}
    .hitem.ok .hdot {{ background: var(--ok); }}
    .hitem.stale .hdot {{ background: var(--warn); }}
    .hname {{ grid-area: name; font-weight: 600; color: var(--text); display: inline-flex; align-items: center; gap: 7px; }}
    .hname i {{ width: 7px; height: 7px; border-radius: 50%; display: inline-block; }}
    .hstate {{ grid-area: state; font-size: 12.5px; font-weight: 600; color: var(--text-3); }}
    .hitem.ok .hstate {{ color: var(--ok); }}
    .hitem.stale .hstate {{ color: var(--warn); }}
    .hmeta {{ grid-area: meta; font-size: 12.5px; color: var(--text-3); }}
    .rel {{ color: var(--text-2); font-variant-numeric: tabular-nums; }}
    .muted {{ color: var(--text-3); }}
    a.pv {{ color: inherit; text-decoration: none; border-bottom: 1px dotted var(--text-3); cursor: pointer; white-space: nowrap; }}
    a.pv:hover {{ color: var(--accent); border-bottom-color: var(--accent); text-decoration: none; }}
    .topn-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
    @media (max-width: 700px) {{ .topn-grid {{ grid-template-columns: 1fr; }} }}
    .topn-title {{ font-size: 12px; color: var(--text-3); font-weight: 600; margin-bottom: 8px; }}
    .topn-row {{ display: grid; grid-template-columns: minmax(max-content, auto) 1fr auto; align-items: center; gap: 10px; padding: 6px 0; font-size: 13px; color: var(--text); }}
    .topn-bar {{ height: 6px; border-radius: 999px; background: var(--line-soft); overflow: hidden; display: block; }}
    .topn-bar i {{ display: block; height: 100%; background: var(--danger); border-radius: 999px; opacity: 0.85; }}
    .topn-row b {{ font-variant-numeric: tabular-nums; color: var(--text-2); font-weight: 600; min-width: 1.5em; text-align: right; }}
    .empty-note {{ font-size: 13px; color: var(--text-3); padding: 10px 0; }}
    /* ----- 로그 화면(이벤트 · ERP · 방화벽 · 웹 프록시) ----- */
    .metric.static {{ cursor: default; }}
    @media (hover: hover) {{ .metric.static:hover {{ background: none; }} }}
    .insight {{ display: flex; align-items: baseline; flex-wrap: wrap; gap: 6px 18px; margin: -6px 2px 18px; font-size: 13px; color: var(--text-2); }}
    .insight-k {{ color: var(--text-3); font-weight: 600; }}
    .insight-item b {{ color: var(--text); font-weight: 600; margin-left: 4px; font-variant-numeric: tabular-nums; }}
    .insight-item b.bad {{ color: var(--danger); }}
    .insight-item code {{ background: none; border: none; padding: 0; color: var(--text); }}
    .ev-act.warn::before {{ background: var(--warn); }}
    code.ip.is-bad {{ color: var(--danger); }}
    .flow {{ display: inline-flex; align-items: baseline; gap: 6px; white-space: nowrap; }}
    .flow code {{ background: none; border: none; padding: 0; }}
    .flow .port {{ color: var(--text-3); margin-left: -6px; font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12px; }}
    .flow.bad code {{ color: var(--danger); }}
    .mth {{ display: inline-block; min-width: 3.2em; font-size: 12px; font-weight: 600; color: var(--text-3); }}
    .idstack {{ display: flex; flex-direction: column; gap: 0; align-items: flex-start; }}
    tr.row-erp-failed td {{ background: rgb(var(--danger-rgb) / 0.04); }}
    .mth + code {{ background: none; border: none; padding: 0; color: var(--text); }}
    .grid-2col-eq {{ align-items: start; }}
    .cell-sub.ok {{ color: var(--ok); }}
    .cell-sub.warn {{ color: var(--warn); }}
    .cell-sub.bad {{ color: var(--danger); }}
    details.resp summary {{ cursor: pointer; list-style: none; color: var(--text-3); font-size: 12.5px; white-space: nowrap; }}
    details.resp summary::-webkit-details-marker {{ display: none; }}
    details.resp summary::before {{ content: "▸ "; }}
    details.resp[open] summary::before {{ content: "▾ "; }}
    details.resp[open] summary {{ color: var(--text); }}
    details.resp pre {{ margin: 8px 0 0; width: 340px; max-width: 100%; white-space: pre-wrap; word-break: break-all; font-size: 12px; }}
    .foot {{ margin-top: 36px; padding-top: 16px; border-top: 1px solid var(--line-soft); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px 20px; font-size: 12.5px; color: var(--text-3); }}
    .foot a {{ color: var(--text-2); }}
    body.bare .foot {{ display: none; }}
    @media (prefers-reduced-motion: reduce) {{
      *, *::before, *::after {{ animation: none !important; transition: none !important; }}
    }}
  </style>
  <script>
  function toggleTheme() {{
    var next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    try {{ localStorage.setItem("soc-theme", next); }} catch (e) {{}}
  }}
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
      var scrolled = (window.scrollY || document.documentElement.scrollTop || 0) > 120;
      return Boolean(searching || modalOpen || scrolled || window.__bkHover);
    }}
    window.addEventListener("scroll", function() {{ updateAutoRefreshState(); }}, {{ passive: true }});
    function updateAutoRefreshState() {{
      if (!autoRefreshMs) return;
      var pill = document.getElementById("socSyncPill");
      if (!pill) return;
      if (isAutoRefreshPaused()) {{
        pill.innerHTML = '<span class="pulse-dot" style="background:var(--warn);"></span>' + (window.__bkHover ? '차트 확인 중 · 일시정지' : ((window.scrollY || document.documentElement.scrollTop || 0) > 120 ? '아래로 내려서 일시정지' : '검색 중 · 일시정지'));
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
          }} else if (activeEventChip === "flow") {{
            okChip = !!r.getAttribute("data-flow");
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
      updateFlowBands(rows);
    }}
    function updateFlowBands(rows) {{
      var vis = [];
      for (var i = 0; i < rows.length; i++) {{
        if (rows[i].style.display !== "none") vis.push(rows[i]);
      }}
      for (var j = 0; j < vis.length; j++) {{
        var r = vis[j], f = r.getAttribute("data-flow");
        r.classList.remove("flow-start", "flow-end", "flow-solo");
        if (!f) continue;
        var prev = j > 0 && vis[j - 1].getAttribute("data-flow") === f;
        var next = j < vis.length - 1 && vis[j + 1].getAttribute("data-flow") === f;
        if (!prev && !next) r.classList.add("flow-solo");
        else if (!prev) r.classList.add("flow-start");
        else if (!next) r.classList.add("flow-end");
      }}
    }}
    function openRawForHash() {{
      var h = window.location.hash;
      if (!h || h.length < 2) return;
      var el = document.getElementById(decodeURIComponent(h.slice(1)));
      var d = el && el.closest ? el.closest("details") : null;
      if (d) {{ d.open = true; el.scrollIntoView({{ block: "start" }}); }}
    }}
    window.addEventListener("hashchange", openRawForHash);
    window.addEventListener("DOMContentLoaded", openRawForHash);
    function pivotFilter(v) {{
      var sb = document.getElementById("socSearchBox");
      if (!sb) return;
      sb.value = v;
      filterSocTables(v);
      sb.focus();
    }}
    document.addEventListener("click", function(e) {{
      var a = e.target.closest ? e.target.closest(".pv") : null;
      if (!a) return;
      e.preventDefault();
      pivotFilter(a.getAttribute("data-pv"));
    }});
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
      document.getElementById("holoModalTitle").innerText = title || "상세 정보";
      document.getElementById("holoModalBadge").innerText = badgeText || "상세";
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
        "3계층 방어 구조",
        "SIEM · SOAR",
        "<div class='pop-stats three'>" +
        "<div class='pop-stat'><div class='k'><i class='d c3'></i>1. Gateway · 방화벽</div>" +
        "<div class='note'>직접 우회 접근(<code>POLICY-CLIENT-CADDY-ONLY</code>)을 차단하고, 승인된 사건에는 <code>APR-*</code> DROP 규칙을 집행합니다.</div></div>" +
        "<div class='pop-stat'><div class='k'><i class='d c2'></i>2. Caddy · TLS 프록시</div>" +
        "<div class='note'>HTTPS를 종단하고 고유 <code>request_id</code>를 부여해 ERP 인증 이벤트와 웹 요청을 1:1로 상관 분석합니다.</div></div>" +
        "<div class='pop-stat'><div class='k'><i class='d c1'></i>3. ERP · 탐지 엔진</div>" +
        "<div class='note'><code>RULE-ERP-LOGIN-BRUTE-001</code>(5분 내 5회 실패)과 신뢰 IP · 실시간(<code>live</code>) 검증을 통과하면 담당자 승인으로 차단합니다.</div></div>" +
        "</div>"
      );
    }}
  </script>
</head>
<body{body_cls}>
  <!-- 상세 팝업 -->
  <div id="holoModalBackdrop" class="holo-modal-backdrop" onclick="if(event.target===this)closeHoloModal()">
    <div class="holo-modal" role="dialog" aria-modal="true" aria-labelledby="holoModalTitle">
      <div class="pop-head">
        <div>
          <span id="holoModalBadge" class="pop-badge">상세</span>
          <h3 id="holoModalTitle">상세 정보</h3>
        </div>
        <button type="button" class="pop-close" onclick="closeHoloModal()" aria-label="닫기 (ESC)" title="닫기 (ESC)">{_svg_icon("x", "currentColor", 16)}</button>
      </div>
      <div id="holoModalBody" class="holo-modal-body"></div>
    </div>
  </div>

  <div id="holoCopyToast" class="holo-copy-toast" role="status" aria-live="polite"></div>

  <div class="layout" style="position:relative;z-index:2;">
    <aside class="sidebar">
      <div>
        <div class="brand" onclick="openShieldBriefing()" title="시스템 개요 보기">
          {logo_svg}
          <div>
            <div class="brand-title">Sentinel</div>
            <div class="brand-sub">SIEM · SOAR 보안관제</div>
          </div>
        </div>
        {nav_html}
      </div>
      {auth_box}
    </aside>
    <main class="content{subpage_cls}">
      <div class="topbar">
        <div class="breadcrumb">
          <span>보안관제</span> <span>/</span> <strong>{html.escape(title)}</strong>
        </div>
        <div class="topbar-right">
          <div class="search-box-wrap">
            {_svg_icon("search", "var(--accent)", 13)}
            <input id="socSearchBox" type="search" class="search-box" placeholder="로그, 사건, IP, 계정 즉시 필터..." oninput="filterSocTables(this.value)" onfocus="updateAutoRefreshState()" onblur="updateAutoRefreshState()" />
          </div>
          {sync_pill}
          <button type="button" class="btn-ghost" id="themeToggle" onclick="toggleTheme()" title="라이트·다크 전환" aria-label="라이트·다크 전환">{_svg_icon("sun", "currentColor", 14)} 테마</button>
          <a href="{html.escape(active_path)}" class="btn-ghost" title="새로고침">{_svg_icon("refresh", "var(--accent)", 13)} 새로고침</a>
        </div>
      </div>
      {body_html}
      <footer class="foot">
        <span>Sentinel · SIEM · SOAR 보안관제</span>
        <span class="foot-api">연동 API (읽기 전용 JSON, 로그인 필요):
          <a href="/api/incidents">사건</a> · <a href="/api/events">이벤트</a></span>
      </footer>
    </main>
  </div>
  <script>{_BK_CHARTS_JS}</script>
</body>
</html>"""
    return doc.encode("utf-8")


def render_login_page(error_msg: str | None = None) -> bytes:
    err_html = f'<div class="notice" role="alert">{html.escape(error_msg)}</div>' if error_msg else ""
    body = f"""
    <div class="login-wrap">
      <div class="login-card">
        <div class="login-brand">
          <div class="login-logo">{_svg_icon("shield", "var(--accent)", 22)}</div>
          <div>
            <h1>Sentinel</h1>
            <div class="sub">SIEM · SOAR 보안관제</div>
          </div>
        </div>
        {err_html}
        <form method="post" action="/login">
          <label class="field"><span>운영자 아이디</span>
            <input type="text" name="username" required autocomplete="username" autofocus placeholder="담당자 ID" /></label>
          <label class="field"><span>비밀번호</span>
            <input type="password" name="password" required autocomplete="current-password" placeholder="비밀번호" /></label>
          <button type="submit" class="secondary">로그인</button>
        </form>
        <div class="login-foot">승인된 관제 담당자만 접근할 수 있습니다.</div>
      </div>
    </div>
    """
    return _page_shell("관제 대시보드 · 로그인", body, auth_enabled=True, bare=True)


def _fmt_ts(ts_val: str | None, *, include_utc: bool = True) -> str:
    """ISO-8601 UTC 시각 문자열을 한국 시간(KST) (+ 선택적 UTC 병기) 형태로 읽기 쉽게 변환한다."""
    if not ts_val or ts_val == "수집 대기":
        return '<span style="color:var(--text-3);">수집 대기 중</span>'
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
            f'<strong style="color:var(--text);font-family:ui-monospace,Consolas,monospace;font-size:12px;">{kst_str}</strong> '
            f'<span style="color:var(--text-2);font-size:11px;">KST{utc_part}</span>'
            f"</span>"
        )
    except Exception:
        return f"<code>{html.escape(raw)}</code>"


def _fmt_status(status: str) -> str:
    labels = {
        "open": ("b-open", "alert", "var(--danger)", "확인·승인 필요 (open)"),
        "blocked": ("b-blocked", "stop", "var(--danger)", "차단 적용 중 (blocked)"),
        "applied": ("b-applied", "shield_off", "var(--danger)", "방화벽 차단 중 (applied)"),
        "released": ("b-released", "check", "var(--ok)", "차단 해제됨 (released)"),
        "approved": ("b-approved", "check", "var(--info)", "승인됨 (approved)"),
        "expired": ("b-expired", "warn", "var(--ok)", "만료됨 (expired)"),
        "pending": ("b-warn", "warn", "var(--warn)", "승인 대기 (pending)"),
        "unknown": ("b-warn", "warn", "var(--warn)", "결과 미확인 (unknown)"),
        "rejected": ("b-blocked", "stop", "var(--danger)", "거부됨 (rejected)"),
        "closed": ("b-released", "check", "var(--ok)", "종료 (closed)"),
    }
    entry = labels.get(status)
    if entry is None:
        return f'<span class="badge b-{html.escape(status)}">{html.escape(status)}</span>'
    cls, icon, col, text = entry
    text = re.sub(r"\s*\([^)]*\)\s*$", "", text)
    return f'<span class="badge {cls}" title="{html.escape(status)}">{_svg_icon(icon, col, 12)} {text}</span>'


def _fmt_event_type(ev_type: str, outcome: str | None = None) -> str:
    """이벤트 종류: 한글 라벨이 주, 로그 코드는 아래 보조줄(검색과 감사에 쓰이므로 남긴다)."""
    labels = {
        "login_success": ("로그인 성공", "good"),
        "login_failed": ("로그인 실패", "bad"),
        "logout": ("로그아웃", ""),
        "fw_allow": ("통과 · 허용", "good"),
        "fw_deny": ("방화벽 차단", "bad"),
    }
    if ev_type == "http_request":
        label, tone = "웹 요청", ("bad" if outcome == "failure" else "")
    elif ev_type == "document_read":
        label, tone = ("문서 열람 거부", "bad") if outcome == "failure" else ("문서 열람", "good")
    elif ev_type in labels:
        label, tone = labels[ev_type]
    else:
        label, tone = html.escape(ev_type), ""
    return f'<span class="ev-act {tone}">{label}</span><div class="cell-sub">{html.escape(ev_type)}</div>'


def _fmt_ingest_mode(mode: str) -> str:
    if mode == "live":
        return '<span class="badge b-ok">실시간 (live)</span>'
    if mode == "replay":
        return '<span class="badge b-warn">재현 (replay)</span>'
    if mode == "synthetic":
        return '<span class="badge b-warn">가상 (synthetic)</span>'
    return f'<span class="badge b-warn">{html.escape(mode)}</span>'


def _fmt_source_badge(source: str) -> str:
    labels = {"erp": "ERP", "gateway": "Gateway", "caddy": "Caddy"}
    label = labels.get(source)
    if label is None:
        return f'<span class="badge b-approved">{html.escape(source)}</span>'
    return f'<span class="badge src-{source}" title="{html.escape(source)}">{label}</span>'


_TITLE_LOGIN_FAILURES = re.compile(r"^Repeated login failures: (?P<user>.+) from (?P<ip>\S+)$")
_TITLE_DOC_DENIED = re.compile(r"^Repeated document access denials: (?P<user>.+) from (?P<ip>\S+)$")


def _title_parts(title: str) -> tuple[str, str]:
    """사건 제목을 (한국어 본문, 영어 원문) 으로 나눈다. 번역 대상이 아니면 영어 원문은 비운다.
    저장된 제목은 바꾸지 않고 화면에서만 바꾸므로 이미 쌓인 사건에도 똑같이 적용된다."""
    m = _TITLE_LOGIN_FAILURES.match(title or "")
    if m:
        return f"{m['user']} 계정 로그인 반복 실패 · {m['ip']}", "Repeated login failures"
    m = _TITLE_DOC_DENIED.match(title or "")
    if m:
        return f"{m['user']} 계정 문서 열람 거부 반복 · {m['ip']}", "Repeated document access denials"
    return title, ""


def _title_en_tag(en: str) -> str:
    return f"<span class='title-en'>{html.escape(en)}</span>" if en else ""


def _copy_id_chip(value: str | None, *, prefix: str = "") -> str:
    """긴 UUID/해시 추적 식별자를 앞 8자리로 축약 표시하고 클릭 시 전체 값을 클립보드에 복사하는 칩을 생성한다."""
    esc = html.escape
    raw = str(value).strip() if value is not None else ""
    if not raw or raw == "-":
        if prefix:
            return f'<span style="color:var(--text-3);font-size:11px;">{esc(prefix)} -</span>'
        return '<span style="color:var(--text-3);">-</span>'
    short = f"{raw[:8]}..." if len(raw) > 8 else raw
    pref_html = f'<span style="color:var(--text-3);font-weight:500;">{esc(prefix)}</span>' if prefix else ""
    return (
        f'<button type="button" class="id-copy-chip" data-copy="{esc(raw)}" '
        f'title="클릭하여 전체 ID 복사: {esc(raw)}" onclick="copyIdChip(this, event)">'
        f"{pref_html}<span>{esc(short)}</span>{_svg_icon('copy', 'currentColor', 11)}</button>"
    )


def _pv(value: Any, *, mono: bool = False, bad: bool = False) -> str:
    """값을 누르면 현재 화면의 표가 그 값으로 필터되는(pivot) 링크."""
    raw = str(value or "").strip()
    if not raw or raw == "-":
        return '<span class="muted">-</span>'
    inner = f'<code class="ip{" is-bad" if bad else ""}">{html.escape(raw)}</code>' if mono else html.escape(raw)
    return f'<a class="pv" href="#" data-pv="{html.escape(raw)}" title="이 값으로 필터">{inner}</a>'


def _fmt_ip_badge(ip_val: str | None, *, alert: bool = False) -> str:
    return _pv(ip_val, mono=True, bad=alert)


def _fmt_corr_badge(link_type: str) -> str:
    if link_type == "request_id_exact":
        return f'<span class="badge b-ok">{_svg_icon("link", "var(--ok)", 12)} request_id 정확 일치</span>'
    return f'<span class="badge b-warn">{_svg_icon("radar", "var(--warn)", 12)} 게이트웨이 근접 후보</span>'


def _fmt_trusted_badge(trusted: bool, *, short: bool = False) -> str:
    if short:
        return '<span style="color:var(--ok);">신뢰 IP</span>' if trusted else '<span style="color:var(--warn);">미신뢰</span>'
    if trusted:
        return '<span class="badge b-ok">신뢰 IP</span>'
    return '<span class="badge b-warn">미신뢰</span>'


def _event_line(ev: dict[str, Any], detail_only: bool = False, no_action: bool = False) -> str:
    """이벤트를 '행동 + 핵심 값 칩' 한 줄로 요약한다. 색은 보조 점이며 행동은 항상 글자로 표시한다.

    detail_only=True 는 상태·계정·IP 열이 이미 있는 표에서 중복을 피하려고 요청 경로·포트·규칙 같은 추가 정보만 보여준다.
    """
    esc = html.escape
    src = ev.get("source")
    et = str(ev.get("event_type") or "-")

    def act(text: str, tone: str = "") -> str:
        return f'<span class="ev-act {tone}">{esc(text)}</span>'

    def chip(value: Any, tone: str = "") -> str:
        return f'<span class="ev-chip {tone}">{esc(str(value))}</span>'

    user = ev.get("username") or "-"
    cip = ev.get("client_ip") or ev.get("device_ip") or "-"
    arrow = '<span class="ev-arrow">→</span>'
    if src == "erp":
        if et == "login_failed":
            parts = [act("인증 실패", "bad"), chip(user), chip(cip)]
        elif et == "login_success":
            parts = [act("로그인 성공", "good"), chip(user), chip(cip)]
        elif et == "logout":
            parts = [act("로그아웃"), chip(user), chip(cip)]
        else:
            parts = [act(et), chip(user)]
    elif src == "gateway":
        a = f"{ev.get('src_ip') or '-'}"
        b = f"{ev.get('dst_ip') or '-'}:{ev.get('dst_port') or '-'}"
        if et == "fw_allow":
            parts = [act("트래픽 통과", "good"), chip(a), arrow, chip(b)]
        else:
            parts = [act("방화벽 차단", "bad"), chip(a), arrow, chip(b), chip(ev.get("rule_id") or "-")]
    elif src == "caddy":
        sc = ev.get("status_code")
        try:
            is_err = sc is not None and int(sc) >= 400
        except (TypeError, ValueError):
            is_err = False
        method = ev.get("http_method") or "-"
        path = ev.get("http_path") or "-"
        parts = [act("웹 요청"), chip(cip), chip(f"{method} {path}"), chip(f"HTTP {sc if sc is not None else '-'}", "bad" if is_err else "good")]
    else:
        parts = [act(et), chip(ev.get("outcome") or "-")]
    if no_action:
        parts = parts[1:]
    if detail_only:
        parts = [x for x in parts if 'class="ev-chip' in x or 'class="ev-arrow' in x]
        if src == "erp":
            path = ev.get("http_path")
            parts = [chip(f"{ev.get('http_method') or 'POST'} {path}")] if path else []
        elif src in ("gateway", "caddy"):
            parts = [x for x in parts if x != chip(cip)]
        if not parts:
            return '<span class="ev-arrow">—</span>'
    return '<span class="ev-line">' + "".join(parts) + "</span>"


def _ratio_bar(ok_cnt: int, bad_cnt: int, ok_label: str, bad_label: str) -> str:
    total = ok_cnt + bad_cnt
    ok_pct = int(round((ok_cnt / total) * 100)) if total > 0 else 0
    bad_pct = 100 - ok_pct if total > 0 else 0
    track = (
        f'<div class="rbar"><span class="rbar-ok" style="width:{ok_pct}%"></span>'
        f'<span class="rbar-bad" style="width:{bad_pct}%"></span></div>'
        if total > 0
        else '<div class="rbar"></div>'
    )
    return (
        f'<div class="rbar-top"><span><i class="d ok"></i>{ok_label} <b>{ok_cnt:,}건</b></span>'
        f'<span><i class="d bad"></i>{bad_label} <b>{bad_cnt:,}건</b> <em>{bad_pct}%</em></span></div>'
        f"{track}"
        f'<div class="rbar-foot"><span>최근 1시간 합계</span><b>{total:,}건</b></div>'
    )


_BK_CHARTS_JS = r"""(function () {
  if (window.__bkCharts) return;
  window.__bkCharts = true;
  var NS = "http://www.w3.org/2000/svg";
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function el(name, attrs, parent) {
    var e = document.createElementNS(NS, name);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function bezier(x1, y1, x2, y2) {
    function bx(t) { return 3 * x1 * t * (1 - t) * (1 - t) + 3 * x2 * t * t * (1 - t) + t * t * t; }
    function by(t) { return 3 * y1 * t * (1 - t) * (1 - t) + 3 * y2 * t * t * (1 - t) + t * t * t; }
    return function (x) {
      if (x <= 0) return 0;
      if (x >= 1) return 1;
      var lo = 0, hi = 1, t = x;
      for (var i = 0; i < 24; i++) { t = (lo + hi) / 2; if (bx(t) < x) lo = t; else hi = t; }
      return by(t);
    };
  }
  var easeReveal = bezier(0.85, 0, 0.15, 1);
  var easeOut = bezier(0.23, 1, 0.32, 1);

  // d3 curveMonotoneX 와 같은 단조 3차 베지어 (Fritsch-Carlson)
  function monotone(p) {
    var n = p.length, i;
    if (n === 0) return "";
    if (n === 1) return "M" + p[0][0] + "," + p[0][1];
    var dx = [], m = [], t = [];
    for (i = 0; i < n - 1; i++) {
      dx[i] = p[i + 1][0] - p[i][0];
      m[i] = dx[i] ? (p[i + 1][1] - p[i][1]) / dx[i] : 0;
    }
    t[0] = m[0];
    t[n - 1] = m[n - 2];
    for (i = 1; i < n - 1; i++) {
      if (m[i - 1] * m[i] <= 0) { t[i] = 0; }
      else {
        var w1 = 2 * dx[i] + dx[i - 1], w2 = dx[i] + 2 * dx[i - 1];
        t[i] = (w1 + w2) / (w1 / m[i - 1] + w2 / m[i]);
      }
    }
    var d = "M" + p[0][0] + "," + p[0][1];
    for (i = 0; i < n - 1; i++) {
      var h = dx[i] / 3;
      d += "C" + (p[i][0] + h) + "," + (p[i][1] + t[i] * h) + " " + (p[i + 1][0] - h) + "," + (p[i + 1][1] - t[i + 1] * h) + " " + p[i + 1][0] + "," + p[i + 1][1];
    }
    return d;
  }
  function niceMax(v) {
    var steps = [4, 8, 12, 20, 40, 60, 80, 100, 120, 200, 400, 800, 1000, 2000, 4000, 8000];
    for (var i = 0; i < steps.length; i++) if (v <= steps[i]) return steps[i];
    return Math.ceil(v / 1000) * 1000;
  }
  function setHover(on) {
    if (!!window.__bkHover === on) return;
    window.__bkHover = on;
    if (typeof updateAutoRefreshState === "function") updateAutoRefreshState();
  }
  function recentlyAnimated(key) {
    try {
      var t = Number(sessionStorage.getItem(key) || 0);
      return Date.now() - t < 20000;
    } catch (e) { return false; }
  }
  function markAnimated(key) { try { sessionStorage.setItem(key, String(Date.now())); } catch (e) {} }

  /* ================= 면적 차트 ================= */
  function initArea(root) {
    var data = JSON.parse(root.getAttribute("data-chart"));
    var rows = data.rows, series = data.series, n = rows.length;
    var hidden = {};
    var H = 310, M = { l: 38, r: 16, t: 14, b: 30 };
    var uid = "bk" + Math.random().toString(36).slice(2, 8);
    var animKey = "bkAnim:" + (root.id || "area");

    var legend = document.createElement("div");
    legend.className = "bk-legend";
    root.appendChild(legend);
    series.forEach(function (s) {
      var b = document.createElement("button");
      b.type = "button";
      b.innerHTML = '<i style="background:' + s.color + '"></i>' + s.label;
      b.addEventListener("click", function () {
        hidden[s.key] = !hidden[s.key];
        b.classList.toggle("off", !!hidden[s.key]);
        draw(false);
      });
      legend.appendChild(b);
    });
    var svg = el("svg", { "class": "bk-svg", height: H });
    root.appendChild(svg);
    var tip = document.createElement("div");
    tip.className = "bk-tip";
    root.appendChild(tip);

    var W = 0, iw = 0, ih = 0, ymax = 4, xs = [], visible = [];
    var cross, pill, pillRect, pillText, dots = {}, halos = {};
    var cur = { x: 0, ys: {} }, target = { x: 0, ys: {} }, active = -1, raf = 0;

    function X(i) { return n === 1 ? M.l + iw / 2 : M.l + (i * iw) / (n - 1); }
    function Y(v) { return M.t + ih - (v / ymax) * ih; }

    function draw(animate) {
      while (svg.firstChild) svg.removeChild(svg.firstChild);
      W = Math.max(root.clientWidth, 280);
      svg.setAttribute("width", W);
      svg.setAttribute("viewBox", "0 0 " + W + " " + H);
      iw = W - M.l - M.r;
      ih = H - M.t - M.b;
      visible = series.filter(function (s) { return !hidden[s.key]; });
      var mx = 0;
      rows.forEach(function (r) { visible.forEach(function (s) { mx = Math.max(mx, r[s.key] || 0); }); });
      ymax = niceMax(Math.max(mx, 1));
      xs = rows.map(function (_, i) { return X(i); });

      var defs = el("defs", {}, svg);
      series.forEach(function (s) {
        var g = el("linearGradient", { id: uid + "f" + s.key, x1: "0", x2: "0", y1: "0", y2: "1" }, defs);
        el("stop", { offset: "0%", style: "stop-color:" + s.color + ";stop-opacity:0.3" }, g);
        el("stop", { offset: "100%", style: "stop-color:" + s.color + ";stop-opacity:0" }, g);
      });
      var cg = el("linearGradient", { id: uid + "x", gradientUnits: "userSpaceOnUse", x1: "0", x2: "0", y1: M.t, y2: M.t + ih }, defs);
      [[0, 0], [0.12, 1], [0.88, 1], [1, 0]].forEach(function (st) {
        el("stop", { offset: st[0], style: "stop-color:var(--text-3);stop-opacity:" + st[1] }, cg);
      });
      var clip = el("clipPath", { id: uid + "c" }, defs);
      var clipRect = el("rect", { x: 0, y: 0, width: animate ? 0 : W + 2, height: H }, clip);

      // 점선 가로 격자 + y 눈금 (5행)
      for (var k = 0; k <= 4; k++) {
        var gy = M.t + ih - (ih * k) / 4;
        el("line", { x1: M.l, x2: W - M.r, y1: gy, y2: gy, stroke: "var(--line)", "stroke-width": 1, "stroke-dasharray": k === 0 ? "none" : "4 4" }, svg);
        var tx = el("text", { x: M.l - 8, y: gy + 4, "text-anchor": "end", fill: "var(--text-3)", "font-size": 11 }, svg);
        tx.textContent = Math.round((ymax * k) / 4);
      }
      // x 라벨 (겹치지 않게 간격 조정)
      var every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 70))));
      rows.forEach(function (r, i) {
        if (i !== n - 1 && (i % every !== 0 || n - 1 - i < every * 0.6)) return;
        var t = el("text", { x: xs[i], y: H - 8, "text-anchor": i === 0 ? "start" : i === n - 1 ? "end" : "middle", fill: "var(--text-3)", "font-size": 11 }, svg);
        t.textContent = r.t;
      });

      var layer = el("g", { "clip-path": "url(#" + uid + "c)" }, svg);
      visible.forEach(function (s) {
        var pts = rows.map(function (r, i) { return [xs[i], Y(r[s.key] || 0)]; });
        var line = monotone(pts);
        el("path", { d: line + "L" + xs[n - 1] + "," + (M.t + ih) + "L" + xs[0] + "," + (M.t + ih) + "Z", fill: "url(#" + uid + "f" + s.key + ")" }, layer);
        el("path", { d: line, fill: "none", stroke: s.color, "stroke-width": 1.75, "stroke-linecap": "round", "stroke-linejoin": "round" }, layer);
      });

      // 크로스헤어 · 점 · 날짜 필
      cross = el("line", { y1: M.t, y2: M.t + ih, stroke: "url(#" + uid + "x)", "stroke-width": 1, opacity: 0 }, svg);
      dots = {}; halos = {};
      visible.forEach(function (s) {
        halos[s.key] = el("circle", { r: 11, fill: s.color, opacity: 0 }, svg);
        dots[s.key] = el("circle", { r: 4.5, fill: s.color, stroke: "var(--surface)", "stroke-width": 2, opacity: 0 }, svg);
      });
      pill = el("g", { opacity: 0 }, svg);
      pillRect = el("rect", { height: 20, rx: 10, fill: "var(--text)" }, pill);
      pillText = el("text", { y: 14, "text-anchor": "middle", fill: "var(--bg)", "font-size": 11, "font-weight": 600 }, pill);

      var overlay = el("rect", { x: M.l, y: 0, width: iw, height: H, fill: "transparent", style: "cursor:crosshair;touch-action:pan-y" }, svg);
      overlay.addEventListener("pointermove", onMove);
      overlay.addEventListener("pointerdown", onMove);
      overlay.addEventListener("pointerleave", hide);
      overlay.addEventListener("click", function () {
        if (active >= 0 && rows[active] && rows[active].href) {
          window.location.href = rows[active].href;
        }
      });
      active = -1;
      tip.style.opacity = 0;

      if (animate) {
        var t0 = null;
        (function step(ts) {
          if (t0 === null) t0 = ts;
          var p = Math.min(1, (ts - t0) / 1100);
          clipRect.setAttribute("width", easeReveal(p) * (W + 2));
          if (p < 1) requestAnimationFrame(step);
        })(performance.now());
      }
    }

    function onMove(e) {
      var r = svg.getBoundingClientRect();
      var x = e.clientX - r.left;
      var i = n === 1 ? 0 : Math.round(((x - M.l) / iw) * (n - 1));
      i = Math.max(0, Math.min(n - 1, i));
      if (i === active) return;
      var first = active === -1;
      active = i;
      if (e && e.currentTarget && e.currentTarget.style) {
        e.currentTarget.style.cursor = (rows[i] && rows[i].href) ? "pointer" : "crosshair";
      }
      target.x = xs[i];
      visible.forEach(function (s) { target.ys[s.key] = Y(rows[i][s.key] || 0); });
      if (first) {
        cur.x = target.x;
        visible.forEach(function (s) { cur.ys[s.key] = target.ys[s.key]; });
      }
      setHover(true);
      cross.setAttribute("opacity", 1);
      pill.setAttribute("opacity", 1);
      visible.forEach(function (s) { dots[s.key].setAttribute("opacity", 1); halos[s.key].setAttribute("opacity", 0.3); });
      renderTip(i);
      if (first) paint();
      if (!raf) raf = requestAnimationFrame(follow);
      if (reduce) { cur.x = target.x; visible.forEach(function (s) { cur.ys[s.key] = target.ys[s.key]; }); paint(); }
    }
    function hide() {
      active = -1;
      setHover(false);
      if (cross) cross.setAttribute("opacity", 0);
      if (pill) pill.setAttribute("opacity", 0);
      visible.forEach(function (s) { if (dots[s.key]) { dots[s.key].setAttribute("opacity", 0); halos[s.key].setAttribute("opacity", 0); } });
      tip.style.opacity = 0;
    }
    function follow() {
      raf = 0;
      var k = 0.32, moving = false;
      var dxp = target.x - cur.x;
      cur.x += dxp * k;
      if (Math.abs(dxp) > 0.3) moving = true; else cur.x = target.x;
      visible.forEach(function (s) {
        var d = target.ys[s.key] - cur.ys[s.key];
        cur.ys[s.key] += d * k;
        if (Math.abs(d) > 0.3) moving = true; else cur.ys[s.key] = target.ys[s.key];
      });
      paint();
      if (moving && active !== -1) raf = requestAnimationFrame(follow);
    }
    function paint() {
      cross.setAttribute("x1", cur.x); cross.setAttribute("x2", cur.x);
      visible.forEach(function (s) {
        dots[s.key].setAttribute("cx", cur.x); dots[s.key].setAttribute("cy", cur.ys[s.key]);
        halos[s.key].setAttribute("cx", cur.x); halos[s.key].setAttribute("cy", cur.ys[s.key]);
      });
      var label = rows[Math.max(0, active)] ? rows[Math.max(0, active)].t : "";
      pillText.textContent = label;
      var w = (pillText.getComputedTextLength ? pillText.getComputedTextLength() : 40) + 18;
      pillRect.setAttribute("width", w); pillRect.setAttribute("x", -w / 2);
      pillText.setAttribute("x", 0);
      var px = Math.max(w / 2, Math.min(W - w / 2, cur.x));
      pill.setAttribute("transform", "translate(" + px + "," + (M.t + ih + 4) + ")");
      var tw = tip.offsetWidth || 160;
      var left = cur.x + 16;
      if (left + tw > W) left = cur.x - 16 - tw;
      tip.style.transform = "translate(" + Math.max(0, left) + "px," + (M.t + 34) + "px)";
    }
    function renderTip(i) {
      var r = rows[i], total = 0;
      var html = '<div class="t">' + r.t + (r.span ? ' <span style="font-weight:400;color:var(--text-3);font-size:11px;">(' + r.span + ')</span>' : '') + "</div>";
      visible.forEach(function (s) {
        var v = r[s.key] || 0; total += v;
        html += '<div class="r"><i style="background:' + s.color + '"></i>' + s.label + "<b>" + v + "건</b></div>";
      });
      if (visible.length > 1) html += '<div class="r sum">합계<b>' + total + "건</b></div>";
      if (r.href) html += '<div class="r" style="margin-top:4px;color:var(--accent);font-size:11px;font-weight:600;">클릭하여 상세 로그 보기 →</div>';
      tip.innerHTML = html;
      tip.style.opacity = 1;
    }

    var animate = !reduce && !recentlyAnimated(animKey);
    draw(animate);
    if (animate) markAnimated(animKey);
    var lastW = root.clientWidth, pending = 0;
    if (window.ResizeObserver) {
      new ResizeObserver(function () {
        if (Math.abs(root.clientWidth - lastW) < 2 || pending) return;
        pending = requestAnimationFrame(function () { pending = 0; lastW = root.clientWidth; draw(false); });
      }).observe(root);
    }
  }

  /* ================= 도넛 차트 ================= */
  function initDonut(root) {
    var d = JSON.parse(root.getAttribute("data-donut"));
    var items = d.items, total = 0;
    items.forEach(function (it) { total += it.value; });
    var R = 58, SW = 16, C = 2 * Math.PI * R, GAP = total > 0 && items.filter(function (i) { return i.value > 0; }).length > 1 ? 3 : 0;
    var animKey = "bkAnim:" + (root.id || "donut");

    root.innerHTML = '<div class="bk-donut-wrap"><svg viewBox="0 0 160 160" class="bk-donut-svg"></svg><div class="bk-donut-legend"></div></div>';
    var svg = root.querySelector("svg"), legend = root.querySelector(".bk-donut-legend");
    el("circle", { cx: 80, cy: 80, r: R, fill: "none", stroke: "var(--line-soft)", "stroke-width": SW }, svg);
    var segs = [], start = 0;
    items.forEach(function (it, idx) {
      var len = total ? (it.value / total) * C : 0;
      var seg = el("circle", { cx: 80, cy: 80, r: R, fill: "none", stroke: it.color, "stroke-width": SW, transform: "rotate(-90 80 80)", style: "transition:opacity 150ms,stroke-width 150ms;cursor:pointer" }, svg);
      segs.push({ el: seg, start: start, len: len });
      start += len;
      var row = document.createElement("div");
      row.className = "bk-donut-row";
      var pct = total ? Math.round((it.value / total) * 100) : 0;
      row.innerHTML = '<i style="background:' + it.color + '"></i><span>' + it.label + "</span><b>" + it.value.toLocaleString() + "건</b><em>" + pct + "%</em>";
      legend.appendChild(row);
      row.addEventListener("pointerenter", function () { focus(idx); });
      row.addEventListener("pointerleave", function () { focus(-1); });
      seg.addEventListener("pointerenter", function () { focus(idx); });
      seg.addEventListener("pointerleave", function () { focus(-1); });
      it._row = row;
    });
    var big = el("text", { x: 80, y: 84, "text-anchor": "middle", fill: "var(--text)", "font-size": 24, "font-weight": 650 }, svg);
    var sub = el("text", { x: 80, y: 102, "text-anchor": "middle", fill: "var(--text-3)", "font-size": 11 }, svg);
    function rest() { big.textContent = total.toLocaleString(); sub.textContent = "총 수집 이벤트"; }
    function focus(i) {
      segs.forEach(function (s, k) {
        s.el.style.opacity = i === -1 || i === k ? 1 : 0.28;
        s.el.setAttribute("stroke-width", i === k ? SW + 3 : SW);
        items[k]._row.classList.toggle("dim", i !== -1 && i !== k);
      });
      if (i === -1) { rest(); return; }
      big.textContent = items[i].value.toLocaleString();
      sub.textContent = items[i].label + " · " + (total ? Math.round((items[i].value / total) * 100) : 0) + "%";
    }
    function setProgress(p) {
      var vis = p * C;
      segs.forEach(function (s) {
        var a = Math.max(0, Math.min(s.len, vis - s.start));
        var drawLen = Math.max(0, a - (a > 0 ? GAP : 0));
        s.el.setAttribute("stroke-dasharray", drawLen + " " + C);
        s.el.setAttribute("stroke-dashoffset", -s.start);
      });
    }
    rest();
    if (!reduce && !recentlyAnimated(animKey)) {
      markAnimated(animKey);
      setProgress(0);
      var t0 = null;
      requestAnimationFrame(function step(ts) {
        if (t0 === null) t0 = ts;
        var p = Math.min(1, (ts - t0) / 900);
        setProgress(easeOut(p));
        if (p < 1) requestAnimationFrame(step);
      });
    } else { setProgress(1); }
  }

  function boot() {
    document.querySelectorAll(".bk-chart[data-chart]").forEach(function (r) { if (!r.__bk) { r.__bk = 1; initArea(r); } });
    document.querySelectorAll(".bk-donut[data-donut]").forEach(function (r) { if (!r.__bk) { r.__bk = 1; initDonut(r); } });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
"""


def _bk_json_attr(obj: Any) -> str:
    return html.escape(json.dumps(obj, ensure_ascii=False), quote=True)


_BK_SERIES = [
    {"key": "erp", "label": "ERP", "color": "var(--c1)"},
    {"key": "caddy", "label": "Caddy", "color": "var(--c2)"},
    {"key": "gateway", "label": "Gateway", "color": "var(--c3)"},
]


_EVENT_TREND_TABS = {
    "hourly": "시간별 (24h)",
    "daily": "일별",
    "suspect": "실패·의심",
}


def _is_suspect_event(source: str, event_type: str, outcome: str, status_code: int | None) -> bool:
    """실패·거부·차단·HTTP 오류 등 보안상 의심 이벤트 여부를 판정한다."""
    if source == "erp":
        return event_type == "login_failed" or outcome in {"failure", "denied"} or "denied" in event_type
    if source == "gateway":
        return event_type == "fw_deny" or outcome in {"failure", "denied", "deny", "drop"}
    if source == "caddy":
        return (status_code is not None and int(status_code) >= 400) or outcome == "failure"
    return False


def _bk_area_chart(
    store: DashboardStore | DbDashboardStore,
    tab: str,
    stats_map: dict[str, dict[str, Any]],
    now_utc: datetime | None = None,
) -> tuple[str, str]:
    """수집 이벤트를 시간별(오늘 24h) · 일별(최근 7일) · 실패·의심(오늘 24h) 기준으로 집계한다."""
    if tab not in _EVENT_TREND_TABS:
        tab = "hourly"
    kst = timezone(timedelta(hours=9))
    now_kst = (now_utc or datetime.now(timezone.utc)).astimezone(kst)
    total_all = sum(int(stats_map.get(s, {}).get("count", 0)) for s in ("erp", "caddy", "gateway"))

    def _attach_spans(rows_list: list[dict[str, Any]], bounds: list[list[datetime | None]]) -> None:
        for idx, (lo_dt, hi_dt) in enumerate(bounds):
            if lo_dt is None or hi_dt is None:
                continue
            lo_s = lo_dt.strftime("%H:%M:%S")
            hi_s = hi_dt.strftime("%H:%M:%S")
            rows_list[idx]["span"] = lo_s if lo_s == hi_s else f"{lo_s} ~ {hi_s}"

    if tab == "daily":
        num_days = 7
        start_day_kst = (now_kst - timedelta(days=num_days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        since_utc = start_day_kst.astimezone(timezone.utc)
        rows = [
            {"t": (start_day_kst + timedelta(days=d)).strftime("%m-%d"), "erp": 0, "caddy": 0, "gateway": 0}
            for d in range(num_days)
        ]
        bounds: list[list[datetime | None]] = [[None, None] for _ in range(num_days)]
        try:
            events = store.get_trend_events(since_utc)
        except Exception:
            events = []
        for dt_utc, src, _ev_type, _outcome, _sc in events:
            dt_kst = dt_utc.astimezone(kst)
            day_idx = (dt_kst.date() - start_day_kst.date()).days
            if 0 <= day_idx < num_days and src in ("erp", "caddy", "gateway"):
                rows[day_idx][src] += 1
                if bounds[day_idx][0] is None or dt_kst < bounds[day_idx][0]:
                    bounds[day_idx][0] = dt_kst
                if bounds[day_idx][1] is None or dt_kst > bounds[day_idx][1]:
                    bounds[day_idx][1] = dt_kst
        _attach_spans(rows, bounds)
        for d in range(num_days):
            if rows[d]["erp"] + rows[d]["caddy"] + rows[d]["gateway"] > 0:
                d_start = (start_day_kst + timedelta(days=d)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                d_end = (start_day_kst + timedelta(days=d + 1)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                rows[d]["href"] = f"/events?from={d_start}&to={d_end}"
        period_total = sum(r["erp"] + r["caddy"] + r["gateway"] for r in rows)
        subtitle = (
            f"최근 7일 ({start_day_kst.strftime('%m-%d')} ~ {now_kst.strftime('%m-%d')} KST) · "
            f"기간 {period_total:,}건 · 전체 누적 {total_all:,}건"
        )
    else:
        day_start_kst = now_kst.replace(hour=0, minute=0, second=0, microsecond=0)
        since_utc = day_start_kst.astimezone(timezone.utc)
        rows = [{"t": f"{h:02d}시", "erp": 0, "caddy": 0, "gateway": 0} for h in range(24)]
        bounds = [[None, None] for _ in range(24)]
        try:
            events = store.get_trend_events(since_utc)
        except Exception:
            events = []
        for dt_utc, src, ev_type, outcome, sc in events:
            if tab == "suspect" and not _is_suspect_event(src, ev_type, outcome, sc):
                continue
            dt_kst = dt_utc.astimezone(kst)
            if dt_kst.date() == now_kst.date() and src in ("erp", "caddy", "gateway"):
                h_idx = dt_kst.hour
                rows[h_idx][src] += 1
                if bounds[h_idx][0] is None or dt_kst < bounds[h_idx][0]:
                    bounds[h_idx][0] = dt_kst
                if bounds[h_idx][1] is None or dt_kst > bounds[h_idx][1]:
                    bounds[h_idx][1] = dt_kst
        _attach_spans(rows, bounds)
        for h_idx in range(24):
            if rows[h_idx]["erp"] + rows[h_idx]["caddy"] + rows[h_idx]["gateway"] > 0:
                h_start = (day_start_kst + timedelta(hours=h_idx)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                h_end = (day_start_kst + timedelta(hours=h_idx + 1)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                rows[h_idx]["href"] = f"/events?from={h_start}&to={h_end}" + ("&anomaly=1" if tab == "suspect" else "")
        period_total = sum(r["erp"] + r["caddy"] + r["gateway"] for r in rows)
        date_str = now_kst.strftime("%Y-%m-%d")
        if tab == "suspect":
            subtitle = f"{date_str} KST (00:00~23:59) · 실패·의심 {period_total:,}건 · 전체 누적 {total_all:,}건"
        else:
            subtitle = f"{date_str} KST (00:00~23:59) · 오늘 {period_total:,}건 · 전체 누적 {total_all:,}건"

    payload = {"rows": rows, "series": _BK_SERIES}
    return f'<div class="bk-chart" id="bk-area-events" data-chart="{_bk_json_attr(payload)}"></div>', subtitle


def _bk_donut(stats_map: dict[str, dict[str, Any]]) -> str:
    def cnt(key: str) -> int:
        return int(stats_map.get(key, {}).get("count", 0))

    items = [
        {"label": "ERP", "value": cnt("erp"), "color": "var(--c1)"},
        {"label": "Caddy", "value": cnt("caddy"), "color": "var(--c2)"},
        {"label": "Gateway", "value": cnt("gateway"), "color": "var(--c3)"},
    ]
    return f'<div class="bk-donut" id="bk-donut-src" data-donut="{_bk_json_attr({"items": items})}"></div>'


def _render_incident_swimlane(incidents: list[IncidentView]) -> str:
    """최신 보안 사건의 5단계 공격·상관·조치 타임라인 스윔레인을 시각화한다."""
    if not incidents:
        return (
            '<div style="padding:28px;text-align:center;color:var(--text-3);font-size:13px;">'
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
        f'<span style="width:9px;height:9px;border-radius:50%;background:var(--danger);display:inline-block;margin-right:14px;" title="실패 #{idx + 1}"></span>'
        for idx in range(min(ev_cnt, 6))
    )
    caddy_dots = (
        "".join(
            '<span style="width:9px;height:9px;border-radius:50%;background:var(--accent);display:inline-block;margin-right:16px;"></span>'
            for _ in range(min(max(exact_cnt, 1), 5))
        )
        if exact_cnt > 0
        else '<span style="font-size:11px;color:var(--text-3);">매칭된 request_id 대기</span>'
    )
    gw_dots = (
        "".join(
            '<span style="width:9px;height:9px;border-radius:50%;background:var(--ok);display:inline-block;margin-right:16px;"></span>'
            for _ in range(min(max(gw_cnt, 1), 5))
        )
        if gw_cnt > 0
        else '<span style="font-size:11px;color:var(--text-3);">근접 시각 게이트웨이 후보 없음</span>'
    )
    ap_dot = (
        '<span style="width:10px;height:10px;border-radius:50%;background:var(--warn);display:inline-block;margin-right:8px;"></span>'
        f'<span style="font-size:11px;color:var(--warn);">담당자 승인 {ap_cnt}건 기록됨</span>'
        if ap_cnt > 0
        else (
            '<span style="font-size:11px;color:var(--warn);">● 담당자 차단 승인 대기 중</span>'
            if inc.block_rule_eligible else '<span style="font-size:11px;color:var(--text-3);">조사용 · 차단 불가</span>'
        )
    )
    soar_dot = (
        '<span style="width:10px;height:10px;border-radius:50%;background:var(--danger);display:inline-block;margin-right:8px;"></span>'
        '<span style="font-size:11px;color:var(--danger);font-weight:700;">게이트웨이 DROP 규칙 활성 중</span>'
        if is_blocked
        else (
            '<span style="width:10px;height:10px;border-radius:50%;background:var(--ok);display:inline-block;margin-right:8px;"></span>'
            '<span style="font-size:11px;color:var(--ok);font-weight:700;">차단 해제 및 단말 통신 복구 완료</span>'
            if is_released
            else '<span style="font-size:11px;color:var(--text-3);">차단 명령 전송 전 (미조치)</span>'
        )
    )

    return f"""
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;padding:9px 12px;background:var(--sunken);border:1px solid var(--line);border-radius:9px;margin-bottom:12px;font-size:12px;">
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="width:8px;height:8px;border-radius:50%;background:var(--danger);display:inline-block;"></span>
        <strong style="color:var(--text);">{esc(_title_parts(inc.title)[0])}</strong> {_title_en_tag(_title_parts(inc.title)[1])}
        <span style="color:var(--text-3);">|</span>
        <span>계정 <strong style="color:var(--accent);">{esc(inc.username or '여러 계정')}</strong></span>
        <span style="color:var(--text-3);">|</span>
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
        <div><div style="font-size:12px;font-weight:700;color:var(--text);">1. ERP 실패</div><div style="font-size:10.5px;color:var(--text-3);">반복 인증 실패 ({ev_cnt}건)</div></div>
        <div class="swimlane-track" style="border-color:rgb(var(--danger-rgb) / 0.3);">{erp_dots}<span style="font-size:11px;color:var(--danger);">5분 내 {ev_cnt}회 연속 실패 탐지</span></div>
      </div>
      <div class="swimlane-row">
        <div><div style="font-size:12px;font-weight:700;color:var(--text);">2. Caddy 요청</div><div style="font-size:10.5px;color:var(--text-3);">request_id 정확 일치 ({exact_cnt}건)</div></div>
        <div class="swimlane-track" style="border-color:rgb(var(--accent-rgb) / 0.28);">{caddy_dots}</div>
      </div>
      <div class="swimlane-row">
        <div><div style="font-size:12px;font-weight:700;color:var(--text);">3. Gateway 연결 <span class="badge b-ok" style="padding:1px 5px;font-size:9px;">후보</span></div><div style="font-size:10.5px;color:var(--text-3);">시각·IP 근접 후보 ({gw_cnt}건)</div></div>
        <div class="swimlane-track" style="border-color:rgb(var(--ok-rgb) / 0.28);">{gw_dots}</div>
      </div>
      <div class="swimlane-row">
        <div><div style="font-size:12px;font-weight:700;color:var(--text);">4. 담당자 승인</div><div style="font-size:10.5px;color:var(--text-3);">Human-in-the-Loop</div></div>
        <div class="swimlane-track">{ap_dot}</div>
      </div>
      <div class="swimlane-row">
        <div><div style="font-size:12px;font-weight:700;color:var(--text);">5. 차단 · 해제</div><div style="font-size:10.5px;color:var(--text-3);">방화벽 Action API</div></div>
        <div class="swimlane-track">{soar_dot}</div>
      </div>
    </div>
    """


def _can_approve_incident(inc: IncidentView, auth_ok: bool) -> bool:
    return (
        auth_ok and inc.block_rule_eligible and inc.live_and_trusted_eligible
        and inc.status in {"open", "released"}
    )


def _parse_utc(ts: Any) -> datetime | None:
    if not ts:
        return None
    raw = str(ts).strip()
    try:
        dt = datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    except Exception:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _fmt_dur(seconds: float) -> str:
    sec = int(max(0, seconds))
    if sec < 60:
        return f"{sec}초"
    if sec < 3600:
        m, r = divmod(sec, 60)
        return f"{m}분 {r}초" if (r and m < 10) else f"{m}분"
    if sec < 86400:
        h, m = divmod(sec // 60, 60)
        return f"{h}시간 {m}분" if m else f"{h}시간"
    d, h = divmod(sec // 3600, 24)
    return f"{d}일 {h}시간" if h else f"{d}일"


def _abs_title(ts: Any, dt: datetime) -> str:
    kst = dt.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")
    return html.escape(f"{kst} KST · {ts}")


def _rel_time(ts: Any, *, plain: bool = False) -> str:
    """경과 시간('3분 전'). 정확한 시각은 마우스를 올리면 KST와 UTC 원본으로 보인다."""
    dt = _parse_utc(ts)
    if dt is None:
        return "-" if plain else '<span class="muted">-</span>'
    secs = (datetime.now(timezone.utc) - dt).total_seconds()
    label = "방금" if secs < 10 else _fmt_dur(secs) + " 전"
    return label if plain else f'<span class="rel" title="{_abs_title(ts, dt)}">{label}</span>'


def _remaining(ts: Any, *, plain: bool = False) -> str:
    dt = _parse_utc(ts)
    if dt is None:
        return "-" if plain else '<span class="muted">-</span>'
    secs = (dt - datetime.now(timezone.utc)).total_seconds()
    label = "만료됨" if secs <= 0 else _fmt_dur(secs) + " 남음"
    return label if plain else f'<span class="rel" title="{_abs_title(ts, dt)}">{label}</span>'


def _stat_strip(items: list[tuple[str, str, str, str]]) -> str:
    """한 줄 지표 띠. items = (라벨, 값, 보조 설명, 톤)"""
    cells = "".join(
        f'<div class="metric static"><div class="metric-label">{label}</div>'
        f'<div class="metric-val {tone}">{value}</div><div class="metric-sub">{sub}</div></div>'
        for label, value, sub, tone in items
    )
    return f'<div class="metrics">{cells}</div>'


def _insight(label: str, inner: str) -> str:
    return f'<div class="insight"><span class="insight-k">{label}</span>{inner}</div>'


def _page_head(eyebrow: str, title: str, desc: str) -> str:
    return f'<div class="page-head"><div class="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{desc}</p></div>'


def _health_strip(stats_map: dict[str, dict[str, Any]]) -> str:
    """수집 상태(맹점 감시): 마지막 수신이 10분 넘게 없으면 지연."""
    now_utc = datetime.now(timezone.utc)
    items = []
    for key, name, color in (("erp", "ERP", "var(--c1)"), ("gateway", "Gateway", "var(--c3)"), ("caddy", "Caddy", "var(--c2)")):
        st = stats_map.get(key)
        cnt = int(st["count"]) if st else 0
        last = st["last_received_utc"] if st else None
        last_dt = _parse_utc(last)
        if not cnt or last_dt is None:
            state, label = "wait", "수집 대기"
        elif (now_utc - last_dt).total_seconds() > 600:
            state, label = "stale", "수신 지연"
        else:
            state, label = "ok", "정상"
        items.append(
            f'<a class="hitem {state}" href="/logs/{key}"><span class="hdot"></span>'
            f'<span class="hname"><i style="background:{color}"></i>{name}</span>'
            f'<span class="hstate">{label}</span>'
            f'<span class="hmeta">{cnt:,}건 · 마지막 수신 {_rel_time(last)}</span></a>'
        )
    return f'<div class="health" aria-label="로그 수집 상태">{"".join(items)}</div>'


def _block_effects(store: Any, approvals: list[Any]) -> dict[str, dict[str, Any]]:
    """승인 차단별 효과. 새 기록을 만들지 않고 이미 수집된 로그를 승인 ID로 묶어 센다.

    - attempts: 차단 규칙(APR)이 막고 기록한 접속 시도 수. 같은 연결(출발지 포트)의 재전송은 한 번으로 센다.
    - success: 조회한 ERP 로그 중 차단 기간에 같은 IP에서 로그인에 성공한 수.
    """
    blocks = [ap for ap in approvals if getattr(ap, "action_type", "") == "block"]
    if not blocks:
        return {}
    try:
        gw = store.list_recent_events(limit=500, source="gateway")
        erp_ok = store.list_recent_events(limit=500, source="erp", event_types=("login_success",))
    except Exception:
        return {}
    now = datetime.now(timezone.utc)
    out: dict[str, dict[str, Any]] = {}
    for ap in blocks:
        start = _parse_utc(ap.approved_at_utc)
        gr = ap.gateway_response if isinstance(ap.gateway_response, dict) else {}
        ends = [d for d in (_parse_utc(gr.get("released_at_utc")), _parse_utc(ap.expires_at_utc), now) if d is not None]
        end = min(ends) if ends else now
        conns: set[tuple[Any, ...]] = set()
        last: str | None = None
        for ev in gw:
            if ev.get("event_type") != "fw_deny" or ev.get("rule_id") != ap.approval_id:
                continue
            conns.add((ev.get("src_ip"), ev.get("src_port"), ev.get("dst_ip"), ev.get("dst_port"), ev.get("event_ts_utc") if ev.get("src_port") in (None, "") else None))
            ts = ev.get("event_ts_utc")
            if ts and (last is None or str(ts) > last):
                last = str(ts)
        success = 0
        for ev in erp_ok:
            ts = _parse_utc(ev.get("event_ts_utc"))
            if ev.get("client_ip") == ap.target_ip and ts is not None and start is not None and start <= ts <= end:
                success += 1
        out[ap.approval_id] = {"attempts": len(conns), "last": last, "success": success}
    return out


def _effect_cell(eff: dict[str, Any] | None) -> str:
    if eff is None:
        return '<span class="muted">-</span>'
    tone = "muted" if eff["success"] == 0 else "bad"
    tip = "게이트웨이 차단 규칙이 막고 기록한 접속 시도입니다. 같은 연결(출발지 포트)의 재전송은 한 번으로 셉니다."
    return (
        f'<span title="{tip}"><b>{eff["attempts"]}건</b> 막음</span>'
        f'<div class="cell-sub {tone}">조회 로그 내 로그인 성공 {eff["success"]}건</div>'
    )


def _block_scope_note(ip: Any) -> str:
    """승인 전에 무엇이 막히는지 분명히 알려 준다(계정이 아니라 IP 단위 조치)."""
    if not ip:
        return ""
    return (
        f'<div class="pop-note" style="margin:12px 0 0;">승인하면 <b>{html.escape(str(ip))}</b> (IP)에서 오는 '
        f"<b>모든 계정</b>의 접속이 입력한 시간 동안 게이트웨이에서 차단됩니다. 계정(예: alice)은 잠기지 않고, "
        f"다른 단말(대조 단말)은 영향이 없습니다.</div>"
    )


def _approval_head(with_incident: bool = False) -> str:
    inc_th = "<th>사건</th>" if with_incident else ""
    return f"<tr><th>승인 시각</th><th>조치</th><th>대상 IP</th><th>결과</th><th>만료</th>{inc_th}<th>승인 ID</th><th>응답</th></tr>"


def _approval_row(ap: Any, inc_id: str | None = None, effect: dict[str, Any] | None = None) -> str:
    """승인 · 조치 이력 한 행. 게이트웨이 응답은 결과 요약으로 보여주고 원문은 접어 둔다(감사용)."""
    esc = html.escape
    gr = ap.gateway_response if isinstance(ap.gateway_response, dict) else {}
    is_block = ap.action_type == "block"
    action = (
        f'<span class="ev-act {"bad" if is_block else "good"}">{"IP 차단" if is_block else "차단 해제"}</span>'
        f'<div class="cell-sub">{esc(ap.approved_by)}</div>'
    )
    note = ""
    if gr.get("error"):
        note = f'<div class="cell-sub bad">{esc(str(gr.get("message") or gr.get("error")))}</div>'
    elif ap.status == "applied" and "rule_present" in gr:
        note = (
            '<div class="cell-sub ok">차단 규칙 적용 확인</div>'
            if gr.get("rule_present")
            else '<div class="cell-sub warn">차단 규칙 미확인</div>'
        )
    elif ap.status == "released" and gr.get("released_at_utc"):
        note = f'<div class="cell-sub">해제 {_rel_time(gr.get("released_at_utc"))}</div>'
    if is_block and effect is not None:
        note += f'<div class="cell-sub">차단 중 막은 접속 시도 <b>{effect["attempts"]}건</b></div>'
        if effect["success"]:
            note += f'<div class="cell-sub bad">차단 중 로그인 성공 {effect["success"]}건</div>'
    expiry = _remaining(ap.expires_at_utc) if ap.status == "applied" else _fmt_ts(ap.expires_at_utc, include_utc=False)
    inc_td = f"<td class='nowrap'><a href='/incidents/{esc(inc_id)}'>{esc(inc_id)}</a></td>" if inc_id else ""
    raw = json.dumps(gr, ensure_ascii=False, indent=2)
    return (
        f"<tr>"
        f"<td class='nowrap'>{_rel_time(ap.approved_at_utc)}</td>"
        f"<td class='nowrap'>{action}</td>"
        f"<td class='nowrap'>{_pv(ap.target_ip, mono=True)}</td>"
        f"<td>{_fmt_status(ap.status)}{note}</td>"
        f"<td class='nowrap'>{expiry}</td>"
        f"{inc_td}"
        f"<td>{_copy_id_chip(ap.approval_id)}</td>"
        f"<td><details class='resp'><summary>원문 보기</summary><pre>{esc(raw)}</pre></details></td>"
        f"</tr>"
    )


_LOGIN_RANGES = {"1h": (60, "최근 1시간"), "6h": (360, "최근 6시간")}


def _login_window(range_key: str) -> tuple[str, int, int, datetime]:
    """선택한 범위를 (범위 키, 5분 칸 수, 첫 칸 번호, 시작 시각 UTC)로 바꾼다."""
    if range_key not in _LOGIN_RANGES:
        range_key = "1h"
    n = _LOGIN_RANGES[range_key][0] * 60 // DEFAULT_WINDOW_SECONDS
    start_idx = int(datetime.now(timezone.utc).timestamp() // DEFAULT_WINDOW_SECONDS) - n + 1
    return range_key, n, start_idx, datetime.fromtimestamp(start_idx * DEFAULT_WINDOW_SECONDS, tz=timezone.utc)


def _login_failure_panel(
    store: DashboardStore | DbDashboardStore,
    range_key: str,
    events: list[tuple[datetime, str, str, str]] | None = None,
    event_tab: str = "hourly",
) -> str:
    """ERP 로그인 실패를 5분 단위 막대로 보여 주고, 탐지 룰 임계(5회/5분)를 점선으로 겹친다."""
    range_key, n, start_idx, since = _login_window(range_key)
    range_label = _LOGIN_RANGES[range_key][1]
    bucket_s = DEFAULT_WINDOW_SECONDS
    thr = DEFAULT_THRESHOLD
    if events is None:
        try:
            events = store.get_login_events(since)
        except Exception:
            events = []
    fails = [0] * n
    oks = [0] * n
    kst = timezone(timedelta(hours=9))
    bounds: list[list[datetime | None]] = [[None, None] for _ in range(n)]
    for dt, ev_type, *_rest in events:
        i = int(dt.timestamp() // bucket_s) - start_idx
        if 0 <= i < n:
            if ev_type == "login_failed":
                fails[i] += 1
            else:
                oks[i] += 1
            dt_kst = dt.astimezone(kst)
            if bounds[i][0] is None or dt_kst < bounds[i][0]:
                bounds[i][0] = dt_kst
            if bounds[i][1] is None or dt_kst > bounds[i][1]:
                bounds[i][1] = dt_kst
    total_fail, total_ok = sum(fails), sum(oks)
    over_cnt = sum(1 for f in fails if f >= thr)
    recent = max(fails[-2:])

    w, h = 900, 200
    ml, mr, mt, mb = 34, 18, 14, 26
    pw, ph = w - ml - mr, h - mt - mb
    ymax = max(thr + 1, max(fails))
    slot = pw / n
    bw = min(36.0, slot * 0.7)

    def y_of(v: float) -> float:
        return mt + ph - (v / ymax) * ph

    def hhmm(idx: int) -> str:
        return (datetime.fromtimestamp(idx * bucket_s, tz=timezone.utc) + timedelta(hours=9)).strftime("%H:%M")

    start_kst = datetime.fromtimestamp(start_idx * bucket_s, tz=timezone.utc).astimezone(kst)
    end_kst = datetime.fromtimestamp((start_idx + n) * bucket_s, tz=timezone.utc).astimezone(kst)

    parts: list[str] = []
    for tick in sorted({0, ymax // 2, ymax}):
        parts.append(
            f'<line x1="{ml}" x2="{w - mr}" y1="{y_of(tick):.1f}" y2="{y_of(tick):.1f}" stroke="var(--line-soft)" stroke-width="1"/>'
            f'<text x="{ml - 6}" y="{y_of(tick) + 4:.1f}" text-anchor="end" font-size="11" style="fill:var(--text-2)">{tick}</text>'
        )
    step = 3 if n <= 12 else 12
    x_indices = list(range(0, n, step))
    if (n - 1) not in x_indices and (n - 1 - x_indices[-1]) >= max(2, step // 2):
        x_indices.append(n - 1)
    for i in x_indices:
        parts.append(
            f'<text x="{ml + i * slot + slot / 2:.1f}" y="{h - 7}" text-anchor="middle" font-size="11" style="fill:var(--text-2)">{hhmm(start_idx + i)}</text>'
        )
    for i in range(n):
        x = ml + i * slot
        bar_h = (fails[i] / ymax) * ph
        over = fails[i] >= thr
        fill = "var(--danger)" if over else "rgb(var(--danger-rgb) / 0.45)"
        title_rng = f"{hhmm(start_idx + i)}~{hhmm(start_idx + i + 1)} KST"
        lo_dt, hi_dt = bounds[i]
        span_str = ""
        if lo_dt is not None and hi_dt is not None:
            lo_s, hi_s = lo_dt.strftime("%H:%M:%S"), hi_dt.strftime("%H:%M:%S")
            span_str = lo_s if lo_s == hi_s else f"{lo_s} ~ {hi_s}"
        href_str = ""
        if fails[i] + oks[i] > 0:
            b_start = datetime.fromtimestamp((start_idx + i) * bucket_s, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            b_end = datetime.fromtimestamp((start_idx + i + 1) * bucket_s, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            href_str = f"/events?from={b_start}&to={b_end}"
        bar = (
            f'<rect class="lf-bar" x="{x + (slot - bw) / 2:.1f}" y="{mt + ph - bar_h:.1f}" width="{bw:.1f}" height="{bar_h:.1f}" rx="2" fill="{fill}"/>'
            if fails[i] > 0
            else ""
        )
        cur_style = ' style="cursor:pointer"' if href_str else ""
        parts.append(
            f'<g class="lf-col"{cur_style} data-title="{html.escape(title_rng)}" '
            f'data-span="{html.escape(span_str)}" data-fail="{fails[i]}" data-ok="{oks[i]}" '
            f'data-over="{"1" if over else "0"}" data-href="{html.escape(href_str)}">'
            f'<rect class="lf-hit" x="{x:.1f}" y="{mt}" width="{slot:.1f}" height="{ph}"/>{bar}</g>'
        )
    parts.append(
        f'<line x1="{ml}" x2="{w - mr}" y1="{y_of(thr):.1f}" y2="{y_of(thr):.1f}" stroke="var(--warn)" stroke-width="1.5" stroke-dasharray="5 4"/>'
        f'<text x="{w - mr}" y="{y_of(thr) - 5:.1f}" text-anchor="end" font-size="11" font-weight="600" style="fill:var(--text)">룰 임계 {thr}회</text>'
    )
    if total_fail == 0 and total_ok == 0:
        parts.append(
            f'<text x="{ml + pw / 2:.1f}" y="{mt + ph / 2 + 22:.1f}" text-anchor="middle" font-size="13" style="fill:var(--text-2)">이 구간에 로그인 기록이 없습니다</text>'
        )
    aria = f"{range_label} 5분 단위 로그인 실패 {total_fail}건, 성공 {total_ok}건, 룰 임계 {thr}회 이상 구간 {over_cnt}개"
    status = (
        '<span class="badge b-open">최근 10분 임계 이상</span>'
        if recent >= thr
        else '<span class="badge b-ok">최근 10분 임계 미만</span>'
    )
    et_safe = event_tab if event_tab in _EVENT_TREND_TABS else "hourly"
    chip_items = []
    for key, lab in _LOGIN_RANGES.items():
        is_cur = key == range_key
        chip_items.append(
            f'<a class="range-chip{" active" if is_cur else ""}" href="/?lf={key}&et={et_safe}#login-failures"'
            + ' onclick="try{sessionStorage.setItem(\'soc_scroll_y\',String(window.scrollY))}catch(e){}"'
            + (' aria-current="true"' if is_cur else "")
            + f'>{lab[1].replace("최근 ", "")}</a>'
        )
    chips = "".join(chip_items)
    range_span_label = f"{start_kst.strftime('%m-%d %H:%M')} ~ {end_kst.strftime('%H:%M')} KST"
    return f"""
    <div class="panel" id="login-failures" style="scroll-margin-top:20px;">
      <div class="panel-header">
        <div>
          <h2>로그인 실패 추이</h2>
          <div class="panel-sub">{html.escape(range_label)} ({html.escape(range_span_label)}) · 5분 단위 · 실패 {total_fail}건 · 성공 {total_ok}건 · 임계 이상 {over_cnt}구간. 룰은 IP별 기준이고 막대는 전체 합계입니다.</div>
        </div>
        <div class="range-bar">{status}{chips}</div>
      </div>
      <div class="lf-wrap" style="position:relative;">
        <svg class="lf-svg" viewBox="0 0 {w} {h}" role="img" aria-label="{html.escape(aria)}" style="width:100%;height:auto;max-height:230px;display:block;">{"".join(parts)}</svg>
        <div class="bk-tip" id="lfTip" style="opacity:0;"></div>
      </div>
      <script>(function(){{
        var wrap=document.querySelector("#login-failures .lf-wrap"),tip=document.getElementById("lfTip");
        if(!wrap||!tip)return;
        wrap.querySelectorAll(".lf-col").forEach(function(col){{
          col.addEventListener("pointerenter",function(e){{
            var t=col.getAttribute("data-title")||"",sp=col.getAttribute("data-span")||"",
                f=col.getAttribute("data-fail")||"0",ok=col.getAttribute("data-ok")||"0",
                ov=col.getAttribute("data-over")==="1",hr=col.getAttribute("data-href")||"";
            var h='<div class="t">'+t+(sp?' <span style="font-weight:400;color:var(--text-3);font-size:11px;">('+sp+')</span>':'')+'</div>';
            h+='<div class="r"><i style="background:var(--danger)"></i>실패<b>'+f+'건</b></div>';
            h+='<div class="r"><i style="background:var(--ok)"></i>성공<b>'+ok+'건</b></div>';
            if(ov)h+='<div class="r sum" style="color:var(--danger);">룰 임계 이상 (5회+)</div>';
            if(hr)h+='<div class="r" style="margin-top:4px;color:var(--accent);font-size:11px;font-weight:600;">클릭하여 상세 로그 보기 →</div>';
            tip.innerHTML=h;tip.style.opacity="1";
            var wr=wrap.getBoundingClientRect(),cx=e.clientX-wr.left;
            tip.style.left=Math.max(110,Math.min(wr.width-110,cx))+"px";
            tip.style.top="8px";
            tip.style.transform="translateX(-50%)";
          }});
          col.addEventListener("pointermove",function(e){{
            var wr=wrap.getBoundingClientRect(),cx=e.clientX-wr.left;
            tip.style.left=Math.max(110,Math.min(wr.width-110,cx))+"px";
          }});
          col.addEventListener("click",function(){{
            var hr=col.getAttribute("data-href");
            if(hr)window.location.href=hr;
          }});
        }});
        wrap.addEventListener("pointerleave",function(){{tip.style.opacity="0";}});
      }})();</script>
    </div>
    """


def render_incident_list(
    store: DashboardStore | DbDashboardStore,
    current_user: str | None = None,
    auth_enabled: bool = False,
    csrf_token: str = "",
    login_range: str = "1h",
    event_tab: str = "hourly",
) -> bytes:
    esc = html.escape
    incidents = store.list_incidents()
    block_effects = _block_effects(store, [ap for i in incidents for ap in i.approvals])
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
    auth_ok = (not auth_enabled) or (bool(current_user) and role_can(current_user, "approve"))

    total_collected = sum(int(s.get("count", 0)) for s in stats_list)
    eligible_open_cnt = sum(1 for inc in open_incs if _can_approve_incident(inc, auth_ok))
    gw_cnt = int(stats_map.get("gateway", {}).get("count", 0))
    caddy_cnt = int(stats_map.get("caddy", {}).get("count", 0))
    erp_cnt = int(stats_map.get("erp", {}).get("count", 0))
    et_key = event_tab if event_tab in _EVENT_TREND_TABS else "hourly"
    lf_safe = login_range if login_range in _LOGIN_RANGES else "1h"
    timeline_svg, timeline_sub = _bk_area_chart(store, et_key, stats_map)
    et_chips = "".join(
        f'<a class="range-chip{" active" if key == et_key else ""}" href="/?lf={lf_safe}&et={key}#event-trend"'
        + ' onclick="try{sessionStorage.setItem(\'soc_scroll_y\',String(window.scrollY))}catch(e){}"'
        + (' aria-current="true"' if key == et_key else "")
        + f'>{esc(label)}</a>'
        for key, label in _EVENT_TREND_TABS.items()
    )
    swimlane_html = _render_incident_swimlane(incidents)

    def _src_status_row(src_key: str, title_ko: str, dot_color: str, link_href: str) -> str:
        st = stats_map.get(src_key)
        cnt = int(st["count"]) if st else 0
        last_ts = st["last_received_utc"] if st else "수집 대기"
        ts_html = _fmt_ts(last_ts, include_utc=False)
        status_txt = "정상 수집 중" if (st and cnt > 0) else "수집 대기"
        status_col = "var(--ok)" if (st and cnt > 0) else "var(--text-3)"
        return (
            f'<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 2px;border-bottom:1px solid var(--line-soft);font-size:13px;gap:8px;min-width:0;">'
            f'<div style="display:flex;align-items:center;gap:7px;white-space:nowrap;flex-shrink:0;">'
            f'<span style="width:8px;height:8px;border-radius:50%;background:{dot_color};display:inline-block;flex-shrink:0;"></span>'
            f'<a href="{link_href}" style="color:var(--text);font-weight:700;white-space:nowrap;">{esc(title_ko)}</a>'
            f'<span style="color:{status_col};font-size:11.5px;white-space:nowrap;">● {status_txt}</span>'
            f"</div>"
            f'<div style="display:flex;align-items:center;gap:10px;white-space:nowrap;flex-shrink:0;margin-left:auto;">'
            f"{ts_html}"
            f'<strong style="color:var(--text);min-width:58px;text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums;">{cnt:,} 이벤트</strong>'
            f"</div></div>"
        )

    def _build_inc_holo_template(inc: IncidentView, idx: int) -> str:
        can_app = _can_approve_incident(inc, auth_ok)
        dis_attr = "" if can_app else "disabled"
        actor_field = (
            f'<span style="font-size:12.5px;color:var(--text);">승인자: <strong style="color:var(--ok);">{esc(current_user)}</strong></span>'
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
                f'<button type="submit" class="btn-emerald" {r_dis}>{_svg_icon("unlock", "var(--on-accent)", 13)} 즉시 차단 해제 ({esc(latest_ap.approval_id)})</button></form>'
                if latest_ap.status == "applied"
                else ""
            )
            rel_form = (
                f"{rel_btn}"
                f'<form method="post" action="/incidents/{esc(inc.incident_id)}/refresh" style="display:inline-block;margin-left:6px;">'
                f"{csrf_hidden}"
                f'<input type="hidden" name="approval_id" value="{esc(latest_ap.approval_id)}" />'
                f'<button type="submit" class="secondary" {"" if auth_ok else "disabled"}>{_svg_icon("refresh", "var(--text)", 13)} 상태 조회</button></form>'
            )

        ev_tr = "".join(
            f"<tr>"
            f"<td><code>{esc(ev.event_id[:12])}</code></td>"
            f"<td>{_fmt_source_badge(ev.source)}</td>"
            f"<td>{_fmt_event_type(ev.event_type, ev.outcome)}</td>"
            f"<td>{_fmt_ts(ev.event_ts_utc, include_utc=False)}</td>"
            f"<td class='nowrap'>{_fmt_ip_badge(ev.client_ip, alert=True)} <span class='cell-sub' style='display:inline'>{_fmt_trusted_badge(ev.client_ip_trusted, short=True)}</span></td>"
            f"<td>{_pv(ev.username)}</td>"
            f"<td>{_copy_id_chip(ev.request_id)}</td>"
            f"<td>{_fmt_ingest_mode(ev.ingest_mode)}</td>"
            f"<td>{_copy_id_chip(ev.raw_id)}</td>"
            f"</tr>"
            for ev in inc.evidence_events
        )
        corr_tr = "".join(
            f"<tr>"
            f"<td>{_fmt_corr_badge(c.link_type)}</td>"
            f"<td><code>{esc(c.event_id[:12])}</code></td>"
            f"<td>{esc(c.reason)}</td>"
            f"<td>{_copy_id_chip(c.raw_id)}</td>"
            f"</tr>"
            for c in inc.correlations
        ) or "<tr><td colspan='4' style='text-align:center;color:var(--text-3);'>연결된 상관 이벤트 없음</td></tr>"

        return f"""
        <template id="holo-tpl-inc-{idx}">
          <div class="pop-stats">
            <div class="pop-stat"><div class="k">출발지 IP</div><div class="v mono">{esc(inc.target_ip or '여러 출발지')}</div></div>
            <div class="pop-stat"><div class="k">대상 계정</div><div class="v">{esc(inc.username or '여러 계정')}</div></div>
            <div class="pop-stat"><div class="k">현재 상태</div><div class="v">{_fmt_status(inc.status)}</div></div>
            <div class="pop-stat"><div class="k">근거 · 상관</div><div class="v">근거 {len(inc.evidence_events)}건 · 상관 {len(inc.correlations)}건</div></div>
            <div class="pop-stat"><div class="k">사건 생성</div><div class="v">{_fmt_ts(inc.created_at_utc, include_utc=False)}</div></div>
          </div>

          <div class="pop-actions">
            <div class="pop-actions-main">
              <strong>즉시 조치</strong>
              <form method="post" action="/incidents/{esc(inc.incident_id)}/approve" class="pop-form">
                {csrf_hidden}
                {actor_field}
                <label>차단 시간(분) <input type="number" name="duration_minutes" value="10" min="1" max="30" required {dis_attr} style="width:68px;" /></label>
                <button type="submit" {dis_attr}>{_svg_icon("shield_off", "currentColor", 13)} 시험 단말 차단 승인</button>
              </form>
              {rel_form}
            </div>
            <a href="/incidents/{esc(inc.incident_id)}" class="btn-ghost">상세 페이지 {_svg_icon("arrow_right", "currentColor", 13)}</a>
          </div>
          {_block_scope_note(inc.target_ip)}

          <div class="pop-section">
            <h4 class="pop-h">근거 이벤트 <span>{len(inc.evidence_events)}건</span></h4>
            <table>
              <thead><tr><th>event_id</th><th>출처</th><th>결과</th><th>발생 시각</th><th>단말 IP</th><th>계정명</th><th>request_id</th><th>수집 모드</th><th>원본 raw_id</th></tr></thead>
              <tbody>{ev_tr}</tbody>
            </table>
          </div>

          <div class="pop-section">
            <h4 class="pop-h">3계층 상관 분석 <span>{len(inc.correlations)}건</span></h4>
            <table>
              <thead><tr><th>연결 구분</th><th>event_id</th><th>상관 분석 근거</th><th>원본 raw_id</th></tr></thead>
              <tbody>{corr_tr}</tbody>
            </table>
          </div>
        </template>
        """

    rows = []
    inc_templates = []
    sorted_incidents = sorted(incidents, key=lambda i: 0 if i.status == "open" else 1)
    for idx, inc in enumerate(sorted_incidents):
        inc_templates.append(_build_inc_holo_template(inc, idx))
        if not inc.block_rule_eligible:
            live_badge = '<span class="badge b-warn">조사용 · 차단 불가</span>'
        elif inc.live_and_trusted_eligible:
            live_badge = '<span class="badge b-ok" title="live + trusted">차단 가능</span>'
        else:
            live_badge = '<span class="badge b-warn" title="비라이브 또는 미신뢰 출처">차단 불가</span>'
        rule_label = "MITRE ATT&CK T1110.001" if inc.block_rule_eligible else "조사용 탐지"
        if any(alert.rule_id == LOGIN_SUCCESS_REVIEW_RULE_ID for alert in inc.alerts):
            rule_label = "주의 · 인증 성공 확인 필요"
        if any(alert.rule_id == LOGIN_SOURCE_CHANGE_RULE_ID for alert in inc.alerts):
            rule_label = "주의 · 실패와 성공의 출발지가 다름"
        ip_txt = inc.target_ip or "여러 출발지"
        user_txt = inc.username or "여러 계정"
        ip_html = f'<a class="pv" href="#" data-pv="{esc(ip_txt)}" title="이 값으로 필터"><code class="ip">{esc(ip_txt)}</code></a>' if inc.target_ip else f'<code class="ip">{esc(ip_txt)}</code>'
        user_html = f'<a class="pv" href="#" data-pv="{esc(user_txt)}" title="이 값으로 필터">{esc(user_txt)}</a>' if inc.username else esc(user_txt)
        rows.append(
            f"<tr class='clickable-row' onclick=\"if(event.target.tagName!=='A'&&event.target.tagName!=='BUTTON')openHoloTemplate('holo-tpl-inc-{idx}','사건 상세 · {esc(inc.incident_id)}','{esc(rule_label)}')\">"
            f"<td>{_fmt_status(inc.status)}</td>"
            f"<td><a class='cell-title' href='/incidents/{esc(inc.incident_id)}'>{esc(_title_parts(inc.title)[0])}</a>"
            f"<div class='cell-sub'>{_title_en_tag(_title_parts(inc.title)[1])}<code>{esc(inc.incident_id)}</code> · {esc(rule_label)}</div></td>"
            f"<td>{ip_html}<div class='cell-sub'>{user_html}</div></td>"
            f"<td class='nowrap'>{_rel_time(inc.created_at_utc)}</td>"
            f"<td>{live_badge}</td>"
            f"<td class='nowrap'><a class='btn-ghost' href='/incidents/{esc(inc.incident_id)}'>상세 · 조치 {_svg_icon('arrow_right', 'currentColor', 13)}</a></td>"
            f"</tr>"
        )

    table_body = "".join(rows) if rows else "<tr><td colspan='6' class='empty'>탐지된 보안 사건이 없습니다.</td></tr>"

    # 상단 4개 카드 원클릭 대형 홀로그램 상세 데이터 템플릿 생성
    ev_modal_rows = "".join(
        f"<tr>"
        f"<td>{_fmt_ts(ev['event_ts_utc'], include_utc=False)}</td>"
        f"<td>{_fmt_source_badge(ev['source'])}</td>"
        f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
        f"<td>{_event_line(ev, no_action=True)}</td>"
        f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
        f"<td>{_copy_id_chip(ev['raw_id'])}</td>"
        f"</tr>"
        for ev in recent_events[:25]
    ) or "<tr><td colspan='8' style='text-align:center;padding:20px;color:var(--text-3);'>수집된 이벤트가 없습니다.</td></tr>"

    def _inc_detail_rows_html(subset: list[IncidentView], empty_msg: str) -> str:
        if not subset:
            return f"<tr><td colspan='7' style='text-align:center;padding:22px;color:var(--text-2);'>{esc(empty_msg)}</td></tr>"
        csrf_hidden = f"<input type='hidden' name='csrf_token' value='{esc(csrf_token)}' />" if csrf_token else ""
        out = []
        for inc in subset:
            can_app = _can_approve_incident(inc, auth_ok)
            latest_ap = next((ap for ap in reversed(inc.approvals) if ap.status == "applied"), None)
            if latest_ap is not None:
                act_html = (
                    f"<form method='post' action='/incidents/{esc(inc.incident_id)}/release' style='display:inline-block;'>"
                    f"{csrf_hidden}<input type='hidden' name='approval_id' value='{esc(latest_ap.approval_id)}' />"
                    f"<button type='submit' class='btn-emerald' style='padding:5px 10px;font-size:11.5px;'>{_svg_icon('unlock', 'var(--on-accent)', 12)} 즉시 차단 해제</button></form> "
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
                    f"<button type='submit' style='padding:5px 10px;font-size:11.5px;'>{_svg_icon('shield_off', 'var(--text)', 12)} 10분 즉시 차단 승인</button></form>"
                )
            else:
                act_html = f"<a href='/incidents/{esc(inc.incident_id)}' class='btn-ghost' style='padding:5px 10px;font-size:11.5px;'>상세 분석 보기 →</a>"

            out.append(
                f"<tr>"
                f"<td><a href='/incidents/{esc(inc.incident_id)}'><strong><code>{esc(inc.incident_id)}</code></strong></a></td>"
                f"<td><strong style='color:var(--text);'>{esc(_title_parts(inc.title)[0])}</strong><div style='font-size:11px;color:var(--text-2);'>{_title_en_tag(_title_parts(inc.title)[1])}근거 {len(inc.evidence_events)}건 · 상관 연결 {len(inc.correlations)}건</div></td>"
                f"<td>{_fmt_status(inc.status)}</td>"
                f"<td><code style='color:var(--danger);font-weight:800;'>{esc(inc.target_ip or '여러 출발지')}</code></td>"
                f"<td><strong style='color:var(--accent);'>{esc(inc.username or '여러 계정')}</strong></td>"
                f"<td>{_fmt_ts(inc.created_at_utc, include_utc=False)}</td>"
                f"<td style='white-space:nowrap;'>{act_html}</td>"
                f"</tr>"
            )
        return "".join(out)

    all_approvals_rows = [_approval_row(ap, inc.incident_id, block_effects.get(ap.approval_id)) for inc in incidents for ap in inc.approvals]
    approvals_table_html = "".join(all_approvals_rows) or "<tr><td colspan='8' class='empty'>기록된 방화벽 승인·해제 이력이 없습니다.</td></tr>"

    holo_templates_html = f"""
    {"".join(inc_templates)}
    <template id="holo-tpl-events">
      <div class="pop-stats three">
        <div class="pop-stat"><div class="k"><i class="d c3"></i>Gateway · 방화벽</div><div class="v">{gw_cnt:,}건</div><a href="/logs/gateway">전용 화면 →</a></div>
        <div class="pop-stat"><div class="k"><i class="d c2"></i>Caddy · 웹 프록시</div><div class="v">{caddy_cnt:,}건</div><a href="/logs/caddy">전용 화면 →</a></div>
        <div class="pop-stat"><div class="k"><i class="d c1"></i>ERP · 인증 서버</div><div class="v">{erp_cnt:,}건</div><a href="/logs/erp">전용 화면 →</a></div>
      </div>
      <table>
        <thead><tr><th>발생 시각</th><th>출처</th><th>이벤트 종류</th><th>내용</th><th>수집 방식</th><th>원본 raw_id</th></tr></thead>
        <tbody>{ev_modal_rows}</tbody>
      </table>
    </template>

    <template id="holo-tpl-open">
      <div class="pop-note">
        현재 미처리(<code>open</code>) 상태인 보안 사건 <b>{open_cnt}건</b> (즉시 차단 승인 가능: <b>{eligible_open_cnt}건</b>)의 상세 목록입니다. 이 창에서 바로 차단을 승인하거나 상세 콘솔로 이동할 수 있습니다.
      </div>
      <table>
        <thead><tr><th>사건 ID</th><th>탐지 내용 · 근거 수</th><th>상태</th><th>공격 의심 IP</th><th>대상 계정</th><th>발생 시각</th><th>즉시 조치 / 상세</th></tr></thead>
        <tbody>{_inc_detail_rows_html(open_incs, "현재 미처리(open) 상태인 보안 사건이 없습니다.")}</tbody>
      </table>
    </template>

    <template id="holo-tpl-blocked">
      <div class="pop-note">
        현재 게이트웨이 방화벽에 <code>DROP</code> 차단 규칙이 적용 중인 사건 <b>{blocked_cnt}건</b>입니다. 이 창에서 바로 차단을 해제하거나 상태를 조회할 수 있습니다.
      </div>
      <table>
        <thead><tr><th>사건 ID</th><th>탐지 내용 · 근거 수</th><th>상태</th><th>차단된 IP</th><th>대상 계정</th><th>발생 시각</th><th>즉시 해제 / 상세</th></tr></thead>
        <tbody>{_inc_detail_rows_html(blocked_incs, "현재 활성 차단(blocked) 중인 사건이 없습니다.")}</tbody>
      </table>
    </template>

    <template id="holo-tpl-released">
      <div class="pop-note">
        차단 해제 및 통신 복구가 완료된 사건(<b>{released_cnt}건</b>) 및 전체 방화벽 승인·해제 감사 이력입니다.
      </div>
      <h4 class="pop-h">해제 · 복구 완료 사건 목록</h4>
      <table style="margin-bottom:20px;">
        <thead><tr><th>사건 ID</th><th>탐지 내용 · 근거 수</th><th>상태</th><th>대상 IP</th><th>대상 계정</th><th>발생 시각</th><th>재차단 / 상세</th></tr></thead>
        <tbody>{_inc_detail_rows_html(released_incs, "아직 차단 해제(released)된 사건이 없습니다.")}</tbody>
      </table>
      <h4 class="pop-h">승인 · 해제 감사 이력</h4>
      <table>
        <thead>{_approval_head(True)}</thead>
        <tbody>{approvals_table_html}</tbody>
      </table>
    </template>
    """

    donut_html = _bk_donut(stats_map)
    now_utc = datetime.now(timezone.utc)
    csrf_hidden_w = f'<input type="hidden" name="csrf_token" value="{esc(csrf_token)}" />' if csrf_token else ""

    health_html = _health_strip(stats_map)

    # --- 대응 시간(사건 생성 → 첫 승인) ---
    resp_secs = []
    for inc in incidents:
        c_dt = _parse_utc(inc.created_at_utc)
        a_dts = [d for d in (_parse_utc(ap.approved_at_utc) for ap in inc.approvals) if d is not None]
        if c_dt is not None and a_dts:
            resp_secs.append(max(0.0, (min(a_dts) - c_dt).total_seconds()))
    mttr_txt = f"평균 대응 시간 {_fmt_dur(sum(resp_secs) / len(resp_secs))} (생성 → 첫 승인, {len(resp_secs)}건)" if resp_secs else "대응 이력 없음"
    oldest_open = min((d for d in (_parse_utc(i.created_at_utc) for i in open_incs) if d is not None), default=None)
    oldest_txt = f" · 최장 {_fmt_dur((now_utc - oldest_open).total_seconds())}" if oldest_open else ""

    # --- 활성 차단(남은 시간) ---
    active_aps = [(inc, ap) for inc in incidents for ap in inc.approvals if ap.status == "applied"]
    blocks_rows = "".join(
        f"<tr><td><a class='pv' href='#' data-pv='{esc(ap.target_ip)}' title='이 값으로 필터'><code class='ip'>{esc(ap.target_ip)}</code></a>"
        f"<div class='cell-sub'>{esc(ap.approved_by)} 승인</div></td>"
        f"<td><a href='/incidents/{esc(inc.incident_id)}'>{esc(inc.incident_id)}</a></td>"
        f"<td class='nowrap'>{_remaining(ap.expires_at_utc)}</td>"
        f"<td class='nowrap'>{_effect_cell(block_effects.get(ap.approval_id))}</td>"
        f"<td class='nowrap'><form method='post' action='/incidents/{esc(inc.incident_id)}/release' style='display:inline'>"
        f"{csrf_hidden_w}<input type='hidden' name='approval_id' value='{esc(ap.approval_id)}' />"
        f"<button type='submit' class='btn-emerald' {'' if auth_ok else 'disabled'}>해제</button></form></td></tr>"
        for inc, ap in active_aps
    ) or "<tr><td colspan='5' class='empty'>현재 차단 중인 IP가 없습니다.</td></tr>"
    next_expiry = min((d for d in (_parse_utc(ap.expires_at_utc) for _, ap in active_aps) if d is not None), default=None)
    next_txt = f" · 다음 해제 {_remaining(next_expiry.isoformat(), plain=True)}" if next_expiry else ""

    # --- 최다 의심 출발지 · 계정 (최근 인증 실패 기준) ---
    # 로그인 실패 추이 그래프와 같은 기간·같은 데이터로 집계해 숫자가 어긋나지 않게 한다.
    from collections import Counter
    lf_key, _lf_n, _lf_start, lf_since = _login_window(login_range)
    try:
        login_events = store.get_login_events(lf_since)
    except Exception:
        login_events = []
    fail_ip: Counter[str] = Counter()
    fail_user: Counter[str] = Counter()
    for _dt, ev_type, ev_ip, ev_user in login_events:
        if ev_type == "login_failed":
            fail_ip[ev_ip or "-"] += 1
            fail_user[ev_user or "-"] += 1

    def _topn(counter: Counter[str], empty: str) -> str:
        items = counter.most_common(5)
        if not items:
            return f'<div class="empty-note">{empty}</div>'
        top = items[0][1]
        return "".join(
            f'<div class="topn-row"><a class="pv" href="#" data-pv="{esc(k)}" title="이 값으로 필터">{esc(k)}</a>'
            f'<span class="topn-bar"><i style="width:{max(4, int(v / top * 100))}%"></i></span><b>{v}</b></div>'
            for k, v in items
        )

    fail_total = sum(fail_ip.values())

    # --- 최근 이벤트 · 승인 이력 ---
    recent_ev_rows = "".join(
        f"<tr><td>{_fmt_ts(ev['event_ts_utc'], include_utc=False)}</td><td>{_fmt_source_badge(ev['source'])}</td>"
        f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
        f"<td>{_event_line(ev, no_action=True)}</td>"
        f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
        f"<td>{_copy_id_chip(ev['raw_id'])}</td></tr>"
        for ev in recent_events[:8]
    ) or "<tr><td colspan='6' class='empty'>수집된 이벤트가 없습니다.</td></tr>"
    recent_aps = sorted(
        [(inc, ap) for inc in incidents for ap in inc.approvals],
        key=lambda t: t[1].approved_at_utc or "",
        reverse=True,
    )[:6]
    history_rows = "".join(
        f"<tr><td class='nowrap'>{_rel_time(ap.approved_at_utc)}</td><td>{_fmt_status(ap.status)}</td>"
        f"<td><code class='ip'>{esc(ap.target_ip)}</code><div class='cell-sub'>{esc(ap.approved_by)}</div></td>"
        f"<td class='nowrap'><a href='/incidents/{esc(inc.incident_id)}'>{esc(inc.incident_id)}</a></td></tr>"
        for inc, ap in recent_aps
    ) or "<tr><td colspan='4' class='empty'>승인·해제 이력이 없습니다.</td></tr>"

    def _metric(tpl: str, modal_title: str, modal_badge: str, label: str, value: str, sub: str, tone: str = "") -> str:
        return (
            f'<div class="metric" tabindex="0" onclick="openHoloTemplate(\'{tpl}\', \'{modal_title}\', \'{modal_badge}\')" '
            f'onkeydown="if(event.key===\'Enter\')this.click()">'
            f'<div class="metric-label">{label}</div>'
            f'<div class="metric-val {tone}">{value}</div>'
            f'<div class="metric-sub">{sub}</div></div>'
        )

    metrics_html = (
        _metric("holo-tpl-open", f"미처리 보안 사건 ({open_cnt}건)", "조치 필요", "미처리 사건", f"{open_cnt}",
                f"즉시 승인 가능 {eligible_open_cnt}건{oldest_txt}", "is-danger" if open_cnt > 0 else "")
        + _metric("holo-tpl-blocked", f"활성 IP 차단 현황 ({blocked_cnt}대 IP)", "활성 차단", "활성 차단", f"{blocked_cnt}",
                  f"활성 승인 {active_approval_cnt}건{next_txt}", "is-accent" if blocked_cnt > 0 else "")
        + _metric("holo-tpl-released", f"차단 해제·복구 이력 ({released_cnt}건)", "복구 이력", "해제 · 복구", f"{released_cnt}",
                  f"누적 사건 {len(incidents)}건")
        + _metric("holo-tpl-events", f"수집된 전체 이벤트 ({total_collected:,}건)", "수집 현황", "수집 이벤트", f"{total_collected:,}",
                  "Gateway · Caddy · ERP")
    )

    body = f"""
    {holo_templates_html}
    <div class="page-head">
      <div class="eyebrow">Security Operations Center</div>
      <h1>개요</h1>
    </div>

    {health_html}

    <div class="metrics">{metrics_html}</div>

    {_login_failure_panel(store, lf_key, login_events, event_tab=et_key)}

    <div class="panel" id="incidents">
      <div class="panel-header">
        <div>
          <h2>사건 대기열</h2>
          <div class="panel-sub">미처리 사건이 위에 표시됩니다 · {mttr_txt} · IP와 계정을 누르면 그 값으로 필터됩니다.</div>
        </div>
        <span class="badge b-approved">총 {len(incidents)}건</span>
      </div>
      <table class="tbl-incidents">
        <thead><tr><th>상태</th><th>사건</th><th>출발지 · 계정</th><th>경과</th><th>조치 자격</th><th></th></tr></thead>
        <tbody>{table_body}</tbody>
      </table>
    </div>

    <div class="grid-2col-eq">
      <div class="panel" style="margin-bottom:0;">
        <div class="panel-header">
          <div>
            <h2>활성 차단</h2>
            <div class="panel-sub">게이트웨이에 적용 중인 차단 규칙. 만료되면 자동 해제됩니다.</div>
          </div>
          <span class="badge {'b-applied' if active_aps else 'b-ok'}">{len(active_aps)}건</span>
        </div>
        <table>
          <thead><tr><th>대상 IP</th><th>사건</th><th>남은 시간</th><th>차단 후 효과</th><th></th></tr></thead>
          <tbody>{blocks_rows}</tbody>
        </table>
      </div>

      <div class="panel" style="margin-bottom:0;">
        <div class="panel-header">
          <div>
            <h2>최다 의심 출발지 · 계정</h2>
            <div class="panel-sub">{_LOGIN_RANGES[lf_key][1]} 로그인 실패 {fail_total}건 기준 · 위 그래프와 같은 기간 · 값을 누르면 필터</div>
          </div>
        </div>
        <div class="topn-grid">
          <div><div class="topn-title">출발지 IP</div>{_topn(fail_ip, "집계할 인증 실패가 없습니다.")}</div>
          <div><div class="topn-title">계정</div>{_topn(fail_user, "집계할 인증 실패가 없습니다.")}</div>
        </div>
      </div>
    </div>

    <div class="grid-2col" style="margin-top:20px;">
      <div class="panel" id="event-trend" style="margin-bottom:0;scroll-margin-top:20px;">
        <div class="panel-header" style="margin-bottom:6px;flex-wrap:nowrap;align-items:flex-start;gap:12px;">
          <div style="min-width:0;flex:1;">
            <h2>이벤트 추이</h2>
            <div class="panel-sub">{esc(timeline_sub)}</div>
          </div>
          <div class="range-bar" style="flex-shrink:0;">{et_chips}</div>
        </div>
        {timeline_svg}
        <script>(function(){{try{{var sy=sessionStorage.getItem("soc_scroll_y");if(sy!==null){{sessionStorage.removeItem("soc_scroll_y");window.scrollTo(0,Number(sy)||0);}}}}catch(e){{}}}})();</script>
      </div>

      <div class="panel" style="margin-bottom:0;">
        <div class="panel-header" style="margin-bottom:6px;">
          <div>
            <h2>로그 출처</h2>
            <div class="panel-sub">계층별 수집 비중과 최근 1시간 정상 · 이상 비율</div>
          </div>
        </div>
        {donut_html}
        <div class="ratio-block">
          <div class="ratio-title">ERP 로그인 인증 (최근 1시간)</div>
          {_ratio_bar(hourly["erp_login_success"], hourly["erp_login_failed"], "성공", "실패")}
        </div>
        <div class="ratio-block">
          <div class="ratio-title">방화벽 · 웹 프록시 (최근 1시간)</div>
          {_ratio_bar(hourly["fw_allow"] + max(0, hourly["caddy_requests"] - hourly["caddy_errors"]), hourly["fw_deny"] + hourly["caddy_errors"], "정상·허용", "차단·오류")}
        </div>
      </div>
    </div>

    <div class="panel" style="margin-top:20px;">
      <div class="panel-header">
        <div>
          <h2>최근 이벤트</h2>
          <div class="panel-sub">가장 최근에 수집된 3계층 이벤트</div>
        </div>
        <a class="btn-ghost" href="/events">전체 보기 {_svg_icon("arrow_right", "currentColor", 13)}</a>
      </div>
      <table>
        <thead><tr><th>발생 시각</th><th>출처</th><th>이벤트 종류</th><th>내용</th><th>수집 방식</th><th>원본 raw_id</th></tr></thead>
        <tbody>{recent_ev_rows}</tbody>
      </table>
    </div>

    <div class="grid-2col-eq" style="margin-top:20px;">
      <div class="panel" style="margin-bottom:0;">
        <div class="panel-header">
          <div>
            <h2>승인 · 조치 이력</h2>
            <div class="panel-sub">최근 방화벽 차단 승인과 해제 기록</div>
          </div>
        </div>
        <table>
          <thead><tr><th>경과</th><th>상태</th><th>대상 IP · 승인자</th><th>사건</th></tr></thead>
          <tbody>{history_rows}</tbody>
        </table>
      </div>

      <div class="panel" style="margin-bottom:0;">
        <div class="panel-header" style="margin-bottom:8px;">
          <div>
            <h2>최신 사건 흐름</h2>
            <div class="panel-sub">ERP → Caddy → Gateway 연계와 승인 · 차단 단계</div>
          </div>
        </div>
        {swimlane_html}
      </div>
    </div>
    """
    return _page_shell("관제 대시보드 · 현황 및 사건 목록", body, current_user=current_user, auth_enabled=auth_enabled, refresh_seconds=5, active_path="/", csrf_token=csrf_token)


_STREAM_HEAD = (
    '<div class="panel-header"><div><h2>스트림</h2>'
    '<div class="panel-sub">최근 50건 · 5초마다 자동 갱신 · IP와 계정을 누르면 그 값으로 필터됩니다.</div></div>'
    '<a class="btn-ghost" href="{href}">{icon} 지금 새로고침</a></div>'
)


def _stream_head(href: str) -> str:
    return _STREAM_HEAD.format(href=html.escape(href), icon=_svg_icon("refresh", "currentColor", 13))


def render_source_logs(
    store: DashboardStore | DbDashboardStore,
    log_kind: str,
    current_user: str | None = None,
    auth_enabled: bool = False,
    csrf_token: str = "",
) -> bytes:
    esc = html.escape
    if log_kind == "erp":
        events = store.list_recent_events(
            limit=50, source="erp", event_types=("login_success", "login_failed", "logout")
        )
        ok_cnt = sum(1 for e in events if e.get("event_type") == "login_success")
        fail_cnt = sum(1 for e in events if e.get("event_type") == "login_failed")
        out_cnt = sum(1 for e in events if e.get("event_type") == "logout")
        trust_cnt = sum(1 for e in events if e.get("client_ip_trusted"))
        head = _page_head("로그 소스", "ERP 인증", "ERP 서버의 로그인 성공 · 실패(401) · 로그아웃 기록입니다.")
        metrics = _stat_strip([
            ("조회 이벤트", f"{len(events)}", "최근 50건 기준", ""),
            ("로그인 성공", f"{ok_cnt}", f"로그아웃 {out_cnt}건", ""),
            ("로그인 실패", f"{fail_cnt}", "5분 안에 5회 이상이면 경보", "is-danger" if fail_cnt else ""),
            ("신뢰 IP", f"{trust_cnt}", "프록시 경유로 검증된 단말", ""),
        ])
        fail_by_user: dict[str, int] = {}
        for e in events:
            if e.get("event_type") == "login_failed":
                uname = str(e.get("username") or "").strip() or "(미상)"
                fail_by_user[uname] = fail_by_user.get(uname, 0) + 1
        top_fails = sorted(fail_by_user.items(), key=lambda item: (-item[1], item[0]))[:4]
        insight = _insight(
            "실패 집중 계정",
            "".join(f'<span class="insight-item">{_pv(u)} <b>{c}건</b></span>' for u, c in top_fails)
            if top_fails
            else '<span class="muted">최근 로그인 실패가 없습니다.</span>',
        )
        headers = "<tr><th>이벤트</th><th>발생 시각</th><th>단말 IP</th><th>계정</th><th>IP 신뢰</th><th>수집 방식</th><th>추적 ID</th></tr>"
        rows = "".join(
            f'<tr class="{"row-erp-failed" if ev.get("event_type") == "login_failed" else ""}">'
            f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
            f"<td>{_fmt_ts(ev['event_ts_utc'], include_utc=False)}</td>"
            f"<td>{_fmt_ip_badge(ev.get('client_ip'), alert=(ev.get('event_type') == 'login_failed'))}</td>"
            f"<td>{_pv(ev.get('username'))}</td>"
            f"<td>{_fmt_trusted_badge(bool(ev['client_ip_trusted']))}</td>"
            f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
            f"<td><div class='idstack'>{_copy_id_chip(ev.get('request_id'), prefix='req:')}{_copy_id_chip(ev.get('raw_id'), prefix='raw:')}</div></td>"
            f"</tr>"
            for ev in events
        )
        colspan = 7
    elif log_kind == "gateway":
        events = store.list_recent_events(limit=50, source="gateway")
        allow_cnt = sum(1 for e in events if e.get("event_type") == "fw_allow")
        deny_cnt = sum(1 for e in events if e.get("event_type") == "fw_deny")
        apr_cnt = sum(1 for e in events if str(e.get("rule_id") or "").startswith("APR-"))
        pol_cnt = sum(1 for e in events if e.get("rule_id") == "POLICY-CLIENT-CADDY-ONLY")
        head = _page_head("로그 소스", "방화벽", "게이트웨이의 패킷 통과(fw_allow), 정책 차단(POLICY), 관제 승인 차단(APR) 기록입니다.")
        metrics = _stat_strip([
            ("조회 이벤트", f"{len(events)}", "최근 50건 기준", ""),
            ("통과 · 허용", f"{allow_cnt}", "정상 프록시 경유 트래픽", ""),
            ("차단", f"{deny_cnt}", "비인가 우회와 차단 단말 패킷", "is-danger" if deny_cnt else ""),
            ("승인 차단 · 정책 차단", f"{apr_cnt} · {pol_cnt}", "APR 규칙 · 우회 차단 정책", ""),
        ])
        port_counts: dict[str, int] = {}
        for e in events:
            dp = e.get("dst_port")
            if dp is not None and str(dp).strip() not in ("", "-"):
                port_counts[str(dp).strip()] = port_counts.get(str(dp).strip(), 0) + 1
        port_labels = {"8443": "Caddy TLS", "8000": "ERP Web"}
        ordered = ["8443", "8000"] + [p for p, _ in sorted(port_counts.items(), key=lambda x: (-x[1], x[0])) if p not in ("8443", "8000")]
        try:
            active_aps_fw = [ap for inc_fw in store.list_incidents() for ap in inc_fw.approvals if ap.status == "applied"]
        except Exception:
            active_aps_fw = []
        fw_eff = _block_effects(store, active_aps_fw) if active_aps_fw else {}
        rule_items = ['<span class="insight-item">상시 정책 <b>단말망은 Caddy(8443)로만 접속 허용</b></span>']
        for ap_fw in active_aps_fw:
            e_fw = fw_eff.get(ap_fw.approval_id)
            rule_items.append(
                f'<span class="insight-item">승인 차단 {_pv(ap_fw.target_ip, mono=True)} <b>{_remaining(ap_fw.expires_at_utc, plain=True)}</b>'
                + (f" · 막은 시도 <b>{e_fw['attempts']}건</b>" if e_fw is not None else "")
                + "</span>"
            )
        if not active_aps_fw:
            rule_items.append('<span class="insight-item muted">승인 차단 없음</span>')
        insight = _insight("적용 중 규칙", "".join(rule_items)) + _insight(
            "대상 포트",
            "".join(
                f'<span class="insight-item"><code>{esc(p)}</code> {esc(port_labels.get(p, ""))} <b>{port_counts.get(p, 0)}건</b></span>'
                for p in ordered[:4]
            ),
        )
        has_rule = any(str(e.get("rule_id") or "").strip() not in ("", "-") for e in events)
        headers = (
            "<tr><th>이벤트</th><th>발생 시각</th><th>흐름 (출발지 → 목적지:포트)</th>"
            + ("<th>적용 규칙</th>" if has_rule else "")
            + "<th>수집 방식</th><th>원본 raw_id</th></tr>"
        )
        row_list = []
        for ev in events:
            rule_id = str(ev.get("rule_id") or "-")
            if rule_id == "POLICY-CLIENT-CADDY-ONLY":
                rule_html = f'<span class="ev-act warn">우회 정책 차단</span><div class="cell-sub">{esc(rule_id)}</div>'
            elif rule_id.startswith("APR-"):
                rule_html = f'<span class="ev-act bad">SOAR 승인 차단</span><div class="cell-sub">{esc(rule_id)}</div>'
            else:
                rule_html = f'<span class="muted">{esc(rule_id)}</span>'
            is_deny = ev.get("event_type") == "fw_deny"
            src_port = ev.get("src_port")
            flow_html = (
                f'<span class="flow{" bad" if is_deny else ""}">{_pv(ev.get("src_ip"), mono=True, bad=is_deny)}'
                f'<span class="port">{":" + esc(str(src_port)) if src_port else ""}</span>'
                f'<span class="ev-arrow">→</span><code>{esc(str(ev.get("dst_ip") or "-"))}:{esc(str(ev.get("dst_port") or "-"))}</code></span>'
            )
            row_list.append(
                f"<tr>"
                f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
                f"<td>{_fmt_ts(ev['event_ts_utc'], include_utc=False)}</td>"
                f"<td>{flow_html}</td>"
                + (f"<td>{rule_html}</td>" if has_rule else "")
                + f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
                f"<td>{_copy_id_chip(ev['raw_id'])}</td>"
                f"</tr>"
            )
        rows = "".join(row_list)
        colspan = 6
    else:
        events = store.list_recent_events(limit=50, source="caddy")
        ok_cnt = sum(1 for e in events if e.get("status_code") is not None and int(e["status_code"]) < 400)
        err_cnt = sum(1 for e in events if e.get("status_code") is not None and int(e["status_code"]) >= 400)
        auth_err_cnt = sum(1 for e in events if e.get("status_code") in (401, 403))
        head = _page_head("로그 소스", "웹 프록시", "Caddy를 통과하는 HTTPS 요청과 응답 상태 코드, 상관 추적 request_id 기록입니다.")
        metrics = _stat_strip([
            ("조회 요청", f"{len(events)}", "최근 50건 기준", ""),
            ("정상 응답", f"{ok_cnt}", "2xx · 3xx", ""),
            ("오류 응답", f"{err_cnt}", "4xx · 5xx", "is-danger" if err_cnt else ""),
            ("인증 · 권한 실패", f"{auth_err_cnt}", "401 · 403, ERP 로그인 실패와 상관", ""),
        ])
        ep_stats: dict[str, dict[str, int]] = {}
        for e in events:
            path = str(e.get("http_path") or "").strip() or "-"
            sc_v = e.get("status_code")
            rec = ep_stats.setdefault(path, {"total": 0, "err": 0})
            rec["total"] += 1
            if sc_v is not None and int(sc_v) >= 400:
                rec["err"] += 1
        top_eps = sorted(ep_stats.items(), key=lambda x: (-x[1]["err"], -x[1]["total"], x[0]))[:4]
        insight = _insight(
            "엔드포인트별 오류",
            "".join(
                f'<span class="insight-item"><code>{esc(path)}</code> '
                f'<b class="{"bad" if st["err"] else ""}">{st["err"]}/{st["total"]}</b></span>'
                for path, st in top_eps
            ) or '<span class="muted">요청이 없습니다.</span>',
        )
        headers = "<tr><th>응답</th><th>발생 시각</th><th>단말 IP</th><th>메서드 · 요청 경로</th><th>request_id</th><th>수집 방식</th></tr>"
        row_list = []
        for ev in events:
            sc = ev.get("status_code")
            is_err = sc is not None and int(sc) >= 400
            sc_html = f'<span class="ev-act {"bad" if is_err else "good"}">HTTP {sc if sc is not None else "-"}</span>'
            method = str(ev.get("http_method") or "-").upper()
            req_html = f'<span class="mth">{esc(method)}</span><code>{esc(str(ev.get("http_path") or "-"))}</code>'
            row_list.append(
                f"<tr>"
                f"<td>{sc_html}</td>"
                f"<td>{_fmt_ts(ev['event_ts_utc'], include_utc=False)}</td>"
                f"<td>{_fmt_ip_badge(ev.get('client_ip'), alert=is_err)}</td>"
                f"<td class='nowrap'>{req_html}</td>"
                f"<td>{_copy_id_chip(ev.get('request_id'))}</td>"
                f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
                f"</tr>"
            )
        rows = "".join(row_list)
        colspan = 6

    table_body = rows or f"<tr><td colspan='{colspan}' class='empty'>수집된 로그가 없습니다.</td></tr>"
    body = f"""
    {head}
    {metrics}
    {insight}
    <div class="panel">
      {_stream_head(f"/logs/{log_kind}")}
      <table><thead>{headers}</thead><tbody>{table_body}</tbody></table>
    </div>
    """
    return _page_shell(
        f"관제 대시보드 · {({'erp': 'ERP 인증', 'gateway': '방화벽', 'caddy': '웹 프록시'}).get(log_kind, log_kind)}",
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
    since_utc: datetime | None = None,
    until_utc: datetime | None = None,
    anomaly_only: bool = False,
    page: int = 1,
    page_size: int = 50,
) -> bytes:
    esc = html.escape
    stats = store.list_source_stats()
    stats_map = {s["source"]: s for s in stats}
    is_time_filtered = since_utc is not None or until_utc is not None or anomaly_only
    total_count = 0
    total_pages = 1
    cur_page = max(1, int(page))
    if is_time_filtered:
        events = store.list_recent_events(limit=500, since_utc=since_utc, until_utc=until_utc)
    else:
        total_count = store.count_recent_events()
        total_pages = max(1, (total_count + page_size - 1) // page_size)
        cur_page = min(cur_page, total_pages)
        events = store.list_recent_events(limit=page_size, offset=(cur_page - 1) * page_size)
    if anomaly_only:
        events = [
            ev
            for ev in events
            if _is_suspect_event(
                str(ev.get("source") or ""),
                str(ev.get("event_type") or ""),
                str(ev.get("outcome") or ""),
                int(ev["status_code"]) if ev.get("status_code") is not None else None,
            )
        ]

    # 같은 request_id를 가진 이벤트(Caddy → ERP)를 이웃하게 모으고 색 띠로 잇는다.
    # Gateway 기록에는 request_id가 없어 묶지 않는다(사건 상세에서 IP·시각 후보로만 보여 준다).
    members: dict[str, list[dict[str, Any]]] = {}
    for ev in events:
        rid_key = str(ev.get("request_id") or "").strip()
        if rid_key:
            members.setdefault(rid_key, []).append(ev)
    layer_order = {"caddy": 0, "erp": 1}
    ordered_events: list[dict[str, Any]] = []
    emitted: set[str] = set()
    for ev in events:
        rid_key = str(ev.get("request_id") or "").strip()
        if rid_key and len(members[rid_key]) >= 2:
            if rid_key in emitted:
                continue
            emitted.add(rid_key)
            ordered_events.extend(
                sorted(members[rid_key], key=lambda m: (layer_order.get(str(m.get("source")), 9), str(m.get("event_ts_utc"))))
            )
        else:
            ordered_events.append(ev)
    events = ordered_events
    flow_colors = ("accent", "purple", "warn", "info", "ok")

    row_items = []
    for ev in events:
        rid_key = str(ev.get("request_id") or "").strip()
        in_flow = bool(rid_key) and len(members.get(rid_key, [])) >= 2
        if in_flow:
            hue = flow_colors[int(hashlib.sha256(rid_key.encode()).hexdigest()[:4], 16) % len(flow_colors)]
            flow_cell = (
                f"<td class='flow-cell' style='--fc: rgb(var(--{hue}-rgb))' title='같은 요청(request_id {esc(rid_key)})'>"
                f"<i class='flow-dot'></i><span class='flow-tag'>#{esc(rid_key[:4])}</span></td>"
            )
            flow_attr = f' data-flow="{esc(rid_key)}"'
        else:
            flow_cell = "<td class='flow-cell'></td>"
            flow_attr = ""
        src_raw = str(ev.get("source") or "erp").lower()
        src_cls = esc(src_raw) if src_raw in ("gateway", "caddy", "erp") else "erp"
        sc_ev = ev.get("status_code")
        is_anomaly = (
            ev.get("event_type") in ("login_failed", "fw_deny")
            or ev.get("outcome") == "failure"
            or (sc_ev is not None and int(sc_ev) >= 400)
        )
        who = f'<div class="cell-sub">{_pv(ev.get("username"))}</div>' if ev.get("username") else ""
        row_items.append(
            f'<tr class="tier-row-{src_cls}" data-source="{src_cls}" data-anomaly="{"1" if is_anomaly else "0"}"{flow_attr}>'
            f"{flow_cell}"
            f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
            f"<td>{_fmt_ts(ev['event_ts_utc'], include_utc=False)}</td>"
            f"<td>{_fmt_source_badge(ev['source'])}</td>"
            f"<td>{_fmt_ip_badge(ev.get('device_ip'), alert=is_anomaly)}{who}</td>"
            f"<td>{_event_line(ev, detail_only=True)}</td>"
            f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
            f"<td>{_copy_id_chip(ev['raw_id'])}</td>"
            f"</tr>"
        )
    rows = "".join(row_items) or "<tr><td colspan='8' class='empty'>수집된 이벤트가 없습니다.</td></tr>"
    flow_cnt = sum(1 for k, v in members.items() if len(v) >= 2)
    filter_banner = ""
    if since_utc is not None or until_utc is not None or anomaly_only:
        kst = timezone(timedelta(hours=9))
        parts_desc: list[str] = []
        if since_utc is not None and until_utc is not None:
            s_kst = since_utc.astimezone(kst)
            e_kst = (until_utc - timedelta(seconds=1)).astimezone(kst)
            parts_desc.append(f"{s_kst.strftime('%Y-%m-%d %H:%M')} ~ {e_kst.strftime('%H:%M')} KST")
        elif since_utc is not None:
            parts_desc.append(f"{since_utc.astimezone(kst).strftime('%Y-%m-%d %H:%M')} KST 이후")
        if anomaly_only:
            parts_desc.append("이상 징후만")
        filter_banner = (
            '<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;'
            'padding:10px 14px;margin-bottom:14px;border-radius:10px;'
            'background:rgb(var(--accent-rgb) / 0.12);border:1px solid rgb(var(--accent-rgb) / 0.35);font-size:13px;">'
            f'<span><strong>시간대 필터 적용 중:</strong> {esc(" · ".join(parts_desc))} ({len(events)}건)</span>'
            '<a class="range-chip" href="/events">전체 보기로 해제</a>'
            "</div>"
        )

    body = f"""
    {_page_head("이벤트", "이벤트 스트림", "ERP · Caddy · Gateway 3개 계층의 정규화된 이벤트를 최신순으로 통합 조회합니다. 같은 요청(request_id)의 Caddy → ERP 기록은 한데 모아 색 띠로 이어 보여 주므로, 이 묶음 안에서는 시간순이 아니라 Caddy → ERP 순서입니다.")}
    {_health_strip(stats_map)}
    <div class="panel">
      {filter_banner}
      {_stream_head("/events")}
      <div class="filter-chip-bar" role="toolbar" aria-label="계층 및 이상 징후 필터">
        <button type="button" class="filter-chip active" data-filter="all" onclick="setEventFilterChip('all')">전체</button>
        <button type="button" class="filter-chip" data-filter="gateway" onclick="setEventFilterChip('gateway')">Gateway</button>
        <button type="button" class="filter-chip" data-filter="caddy" onclick="setEventFilterChip('caddy')">Caddy</button>
        <button type="button" class="filter-chip" data-filter="erp" onclick="setEventFilterChip('erp')">ERP</button>
        <button type="button" class="filter-chip" data-filter="flow" onclick="setEventFilterChip('flow')">요청 흐름만 ({flow_cnt})</button>
        <button type="button" class="filter-chip" data-filter="anomaly" onclick="setEventFilterChip('anomaly')">이상 징후만</button>
        <span id="eventsFilterCount" class="muted" style="margin-left:auto;font-size:13px;">표시: {len(events)} / {len(events)}건</span>
      </div>
      <table>
        <thead><tr><th>흐름</th><th>이벤트</th><th>발생 시각</th><th>출처</th><th>단말 IP · 계정</th><th>요청 · 대상</th><th>수집 방식</th><th>원본 raw_id</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      {"" if is_time_filtered else (lambda: (
          lambda p_links: (
              f'<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:14px;padding-top:12px;border-top:1px solid var(--line-soft);font-size:13px;">'
              f'<span class="muted">총 <b>{total_count:,}</b>건 중 {((cur_page - 1) * page_size + 1) if total_count else 0:,}~{min(cur_page * page_size, total_count):,}건 · {cur_page} / {total_pages} 페이지</span>'
              f'<div class="range-bar">{p_links}</div>'
              f'</div>'
          )
      )(
          "".join(
              ([f'<a class="range-chip" href="/events?page={cur_page - 1}">← 이전</a>'] if cur_page > 1 else ['<span class="range-chip" style="opacity:0.4;pointer-events:none;">← 이전</span>'])
              + [
                  f'<a class="range-chip{" active" if p == cur_page else ""}" href="/events?page={p}">{p}</a>'
                  for p in sorted({1, total_pages} | set(range(max(1, cur_page - 2), min(total_pages, cur_page + 2) + 1)))
              ]
              + ([f'<a class="range-chip" href="/events?page={cur_page + 1}">다음 →</a>'] if cur_page < total_pages else ['<span class="range-chip" style="opacity:0.4;pointer-events:none;">다음 →</span>'])
          )
      ))()}
      <div class="note flow-note">Gateway 방화벽 기록에는 request_id가 없어 요청에 묶지 않았습니다. 사건 상세에서 IP · 시각이 맞는 후보로만 보여 줍니다.</div>
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
    block_effects: dict[str, dict[str, Any]] | None = None,
) -> bytes:
    esc = html.escape
    block_effects = block_effects or {}
    err_html = f'<div class="notice">{esc(error_msg)}</div>' if error_msg else ""
    # 기존 규칙은 실패 횟수를, 새 규칙은 서로 다른 계정명 또는 출발지 수를 보여준다.
    failure_labels = {
        MULTI_ACCOUNT_RULE_ID: "개 계정명 실패",
        MULTI_SOURCE_RULE_ID: "개 출발지 실패",
        LOGIN_SUCCESS_REVIEW_RULE_ID: "회 실패 뒤 성공",
        LOGIN_SOURCE_CHANGE_RULE_ID: "회 실패 뒤 다른 IP에서 성공",
        DOC_DENIED_RULE_ID: "회 열람 거부",
    }

    alert_rows = "".join(
        f"<tr><td><code>{esc(a.alert_id)}</code></td><td><code>{esc(a.rule_id)}</code></td>"
        f"<td><strong style='color:var(--text);'>{esc(a.rule_name)}</strong></td>"
        f"<td><span class='badge b-blocked'>{a.failure_count}{failure_labels.get(a.rule_id, '회 연속 실패')}</span></td>"
        f"<td>{_fmt_ts(a.window_start_utc)} ~ {_fmt_ts(a.window_end_utc)}</td></tr>"
        for a in inc.alerts
    )

    ev_rows = "".join(
        f"<tr>"
        f"<td><code>{esc(ev.event_id[:12])}</code></td>"
        f"<td>{_fmt_source_badge(ev.source)}</td>"
        f"<td>{_fmt_event_type(ev.event_type, ev.outcome)}</td>"
        f"<td>{_fmt_ts(ev.event_ts_utc)}</td>"
        f"<td>{_copy_id_chip(ev.request_id)}</td>"
        f"<td>{_pv(ev.username)}</td>"
        f"<td class='nowrap'>{_fmt_ip_badge(ev.client_ip, alert=True)} <span class='cell-sub' style='display:inline'>{_fmt_trusted_badge(ev.client_ip_trusted, short=True)}</span></td>"
        f"<td>{_fmt_ingest_mode(ev.ingest_mode)}</td>"
        f"<td class='nowrap'><a href='#raw-{esc(ev.raw_id)}' title='원본 로그로 이동'><code>{esc(ev.raw_id[:10])}…</code></a></td>"
        f"</tr>"
        for ev in inc.evidence_events
    )

    corr_rows = "".join(
        f"<tr>"
        f"<td>{_fmt_corr_badge(c.link_type)}<div class='cell-sub'>{esc(c.link_type)}</div></td>"
        f"<td><code>{esc(c.event_id[:12])}</code></td>"
        f"<td>{esc(c.reason)}</td>"
        f"<td class='nowrap'><a href='#raw-{esc(c.raw_id)}' title='원본 로그로 이동'><code>{esc(c.raw_id[:10])}…</code></a></td></tr>"
        for c in inc.correlations
    ) or "<tr><td colspan='4' style='text-align:center;color:var(--text-3);'>연결된 Caddy/게이트웨이 상관 이벤트가 없습니다.</td></tr>"

    raw_blocks = "".join(
        f"<div id='raw-{esc(rid)}' style='margin-bottom:12px;padding:14px;background:rgb(var(--sunken-rgb) / 0.85);border:1px solid rgb(var(--accent-rgb) / 0.22);border-radius:10px;'>"
        f"<div style='margin-bottom:8px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;'>"
        f"{_fmt_source_badge(rec.source)} {_fmt_ingest_mode(rec.ingest_mode)} "
        f"<span style='font-size:12px;color:var(--text-2);'><strong>원본 ID:</strong> <code>{esc(rid)}</code></span> "
        f"<span style='color:var(--text-3);font-size:11.5px;'>(파일 오프셋: <code>{rec.line_offset}</code>)</span></div>"
        f"<pre style='margin:0;border-color:var(--line);'>{esc(_pretty_json_payload(rec.raw_payload))}</pre></div>"
        for rid, rec in inc.raw_logs_by_id.items()
    )

    latest_block = next((ap for ap in reversed(inc.approvals) if ap.action_type == "block" and ap.approval_id in block_effects), None)
    if latest_block is not None:
        eff = block_effects[latest_block.approval_id]
        status_txt = "적용 중" if latest_block.status == "applied" else "종료"
        remain = _remaining(latest_block.expires_at_utc) if latest_block.status == "applied" else "-"
        effect_summary = (
            '<div class="pop-stats three" style="margin:18px 0 0;">'
            f'<div class="pop-stat"><div class="k">차단 후 막은 접속 시도</div><div class="v">{eff["attempts"]}건</div>'
            f'<div class="note">마지막 시도 {_rel_time(eff["last"])}</div></div>'
            f'<div class="pop-stat"><div class="k">차단 후 같은 IP의 로그인 성공</div>'
            f'<div class="v" style="color:var(--{"ok" if eff["success"] == 0 else "danger"});">{eff["success"]}건</div>'
            f'<div class="note">최근 ERP 로그인 성공 로그 최대 500건 중 해당 차단 기간과 IP가 일치한 건수입니다.</div></div>'
            f'<div class="pop-stat"><div class="k">차단 상태</div><div class="v">{status_txt}</div>'
            f'<div class="note">남은 시간 {remain}</div></div></div>'
        )
    else:
        effect_summary = ""
    approval_rows = "".join(_approval_row(ap, effect=block_effects.get(ap.approval_id)) for ap in inc.approvals) or "<tr><td colspan='7' class='empty'>아직 승인 · 조치 이력이 없습니다.</td></tr>"

    auth_ok = (not auth_enabled) or (bool(current_user) and role_can(current_user, "approve"))
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
    success_review = any(alert.rule_id == LOGIN_SUCCESS_REVIEW_RULE_ID for alert in inc.alerts)
    source_change_review = any(alert.rule_id == LOGIN_SOURCE_CHANGE_RULE_ID for alert in inc.alerts)
    if success_review:
        rule_label = "주의 · 인증 성공 확인 필요"
    if source_change_review:
        rule_label = "주의 · 실패와 성공의 출발지가 다름"

    # 성공은 담당자가 상황을 판단할 때만 쓰는 정보다. 경보나 차단 조건을 바꾸지 않는다.
    followup_panel = ""
    if source_change_review:
        followup_panel = """
        <div class="panel">
          <h2>주의 · 반복 실패 후 다른 출발지에서 로그인 성공</h2>
          <p>한 IP에서 실패가 이어진 뒤 같은 계정명으로 다른 IP에서 로그인에 성공했습니다. 아래 근거 표에서 실패와 성공의 출발지, 시각, 원본 기록을 대조할 수 있습니다.</p>
          <p>기기나 네트워크를 바꾼 직원도 같은 기록을 남길 수 있습니다. 계정 사용 여부와 로그인 이후 활동을 함께 확인하세요.</p>
        </div>
        """
    elif success_review:
        followup_panel = """
        <div class="panel">
          <h2>주의 · 반복 실패 후 로그인 성공</h2>
          <p>같은 계정명과 출발지에서 인증 실패가 이어진 뒤 성공했습니다. 아래 근거에서 실패와 성공의 시각 및 원본 기록을 확인할 수 있습니다.</p>
          <p>정상 직원의 오입력과 의심스러운 인증이 같은 모양으로 기록될 수 있으므로, 담당자가 계정 사용 여부와 로그인 이후 활동을 확인합니다.</p>
        </div>
        """
    elif inc.block_rule_eligible:
        result = '<p>현재 저장된 기록에서 조건에 맞는 로그인 성공을 확인하지 못했습니다.</p>'
        if followup_success is not None:
            result = (
                f'<p><strong>로그인 성공 확인</strong> · {_fmt_ts(followup_success.event_ts_utc)}</p>'
                f'<p>성공 원본 기록 번호 {_copy_id_chip(followup_success.raw_id, prefix="raw:")}</p>'
            )
        followup_panel = f"""
        <div class="panel">
          <div class="panel-header"><div><h2>반복 실패 뒤 로그인 성공 여부</h2>
            <div class="panel-sub">마지막 실패 뒤 {FOLLOWUP_LOGIN_MINUTES}분 안에 같은 계정과 신뢰된 같은 IP에서 성공했는지 확인합니다.</div></div></div>
          <div class="pop-note">{result}</div>
          <div class="panel-sub">성공 기록만으로 정상 사용으로 판단할 수 없습니다. 담당자가 실패 기록과 함께 확인하세요.</div>
        </div>
        """

    actor_input = (
        f'<span style="font-size:13px;color:var(--text-2);">승인 담당자: <strong style="color:var(--ok);">{esc(current_user)}</strong></span>'
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
          <button type="submit" class="btn-emerald" {rel_disabled}>{_svg_icon("unlock", "var(--on-accent)", 13)} 차단 해제 요청 ({esc(latest_applied.approval_id)})</button>
        </form>"""
            if latest_applied.status == "applied"
            else ""
        )
        release_html = f"""{rel_btn}
        <form method="post" action="/incidents/{esc(inc.incident_id)}/refresh" style="display:inline-block; margin-left:8px;">
          {csrf_hidden}
          <input type="hidden" name="approval_id" value="{esc(latest_applied.approval_id)}" />
          <button type="submit" class="secondary" {rel_disabled}>{_svg_icon("refresh", "var(--text)", 13)} 상태 조회</button>
        </form>
        """

    body = f"""
    <div style="margin-bottom:14px;"><a href="/#incidents" class="btn-ghost">{_svg_icon("arrow_right", "currentColor", 13).replace("<svg ", '<svg style="transform:rotate(180deg)" ', 1)} 사건 목록</a></div>
    {err_html}

    <div class="panel">
      <div class="detail-head">
        <h1>{esc(_title_parts(inc.title)[0])}</h1>{_title_en_tag(_title_parts(inc.title)[1])}
        {_fmt_status(inc.status)}
        <span class="badge b-approved">{esc(rule_label)}</span>
      </div>
      <div class="panel-sub" style="margin:6px 0 16px;"><code>{esc(inc.incident_id)}</code> · ERP · Caddy · Gateway 상관 추적과 담당자 승인 조치</div>
      <div class="pop-stats" style="margin-bottom:0;">
        <div class="pop-stat"><div class="k">출발지 IP</div><div class="v mono">{esc(inc.target_ip or '여러 출발지')}</div></div>
        <div class="pop-stat"><div class="k">관련 계정</div><div class="v">{esc(inc.username or '여러 계정')}</div></div>
        <div class="pop-stat"><div class="k">근거 · 상관 연결</div><div class="v">{len(inc.evidence_events)}건 · {len(inc.correlations)}건</div></div>
        <div class="pop-stat"><div class="k">사건 생성</div><div class="v" style="font-size:14px;">{_fmt_ts(inc.created_at_utc)}</div></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h2>조치</h2>
          <div class="panel-sub">실시간(live)이고 신뢰된 IP(client_ip_trusted=true)로 검증된 사건만 게이트웨이 차단 API를 호출합니다.</div>
        </div>
      </div>
      {gate_msg}
      <div class="pop-actions" style="margin-bottom:0;display:inline-flex;max-width:100%;">
        <div class="pop-actions-main">
          <form method="post" action="/incidents/{esc(inc.incident_id)}/approve" class="pop-form">
            {csrf_hidden}
            {actor_input}
            <label>차단 유지 시간(분, 최대 30) <input type="number" name="duration_minutes" value="10" min="1" max="30" required {disabled_attr} style="width:72px;" /></label>
            <button type="submit" {disabled_attr}>{_svg_icon("shield_off", "currentColor", 13)} 시험 단말 차단 승인</button>
          </form>
          {release_html}
        </div>
      </div>
      {_block_scope_note(inc.target_ip)}
      {effect_summary}
      <h3 class="pop-h" style="margin:20px 0 10px;">승인 · 게이트웨이 조치 이력</h3>
      <table>
        <thead>{_approval_head()}</thead>
        <tbody>{approval_rows}</tbody>
      </table>
    </div>

    {followup_panel}

    <div class="panel">
      <div class="panel-header"><div><h2>탐지 경보</h2><div class="panel-sub">이 사건을 만든 탐지 규칙과 시간창</div></div></div>
      <table>
        <thead><tr><th>경보 ID</th><th>규칙 ID</th><th>규칙명</th><th>실패 횟수</th><th>탐지 시간창</th></tr></thead>
        <tbody>{alert_rows}</tbody>
      </table>
    </div>

    <div class="panel">
      <div class="panel-header"><div><h2>근거 이벤트</h2><div class="panel-sub">경보의 근거가 된 정규화 이벤트와 원본 raw_id</div></div></div>
      <table>
        <thead><tr><th>event_id</th><th>출처</th><th>결과</th><th>발생 시각</th><th>request_id</th><th>계정명</th><th>client_ip</th><th>수집 모드</th><th>원본 raw_id</th></tr></thead>
        <tbody>{ev_rows}</tbody>
      </table>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h2>3계층 상관 분석</h2>
          <div class="panel-sub">ERP 인증 기록과 정확히 일치하는 Caddy 요청, 시각 · IP가 가까운 게이트웨이 트래픽 후보</div>
        </div>
      </div>
      <div class="chain">
        <span class="chain-step"><span class="d c1"></span> ERP 인증 기록 <b>{len(inc.evidence_events)}건</b></span>
        <span class="chain-arrow"><code>request_id</code> 정확 일치 →</span>
        <span class="chain-step"><span class="d c2"></span> Caddy 웹 요청 <b>{sum(1 for c in inc.correlations if c.link_type == "request_id_exact")}건</b></span>
        <span class="chain-arrow">IP · 포트 · 시각 근접 후보 →</span>
        <span class="chain-step"><span class="d c3"></span> 게이트웨이 접속 <b>{sum(1 for c in inc.correlations if c.link_type == "gateway_candidate")}건</b> <em>단정 금지</em></span>
      </div>
      <table>
        <thead><tr><th>연결 유형</th><th>event_id</th><th>상관 분석 근거 설명</th><th>원본 raw_id</th></tr></thead>
        <tbody>{corr_rows}</tbody>
      </table>
    </div>

    <details class="panel">
      <summary>
        <div>
          <h2>원본 로그 (raw_logs)</h2>
          <div class="panel-sub">정규화 전에 수집한 원본 JSON 페이로드와 바이트 오프셋 증거</div>
        </div>
      </summary>
      {raw_blocks}
    </details>
    """
    return _page_shell(f"사건 {inc.incident_id}", body, current_user=current_user, auth_enabled=auth_enabled, active_path=f"/incidents/{inc.incident_id}", csrf_token=csrf_token)


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
                        render_incident_list(
                            store,
                            current_user=user,
                            auth_enabled=auth_enabled,
                            csrf_token=csrf_tok,
                            login_range=urllib.parse.parse_qs(parsed.query).get("lf", ["1h"])[0],
                            event_tab=urllib.parse.parse_qs(parsed.query).get("et", ["hourly"])[0],
                        ),
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
                    qs = urllib.parse.parse_qs(parsed.query)
                    def _parse_utc(raw_val: str) -> datetime | None:
                        s = raw_val.strip()
                        if not s:
                            return None
                        try:
                            dt = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
                            return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
                        except Exception:
                            return None
                    since_q = _parse_utc(qs.get("from", [""])[0])
                    until_q = _parse_utc(qs.get("to", [""])[0])
                    anomaly_q = qs.get("anomaly", [""])[0] == "1"
                    try:
                        page_q = max(1, int(qs.get("page", ["1"])[0]))
                    except Exception:
                        page_q = 1
                    self._send(
                        HTTPStatus.OK,
                        "text/html; charset=utf-8",
                        render_recent_events(
                            store,
                            current_user=user,
                            auth_enabled=auth_enabled,
                            csrf_token=csrf_tok,
                            since_utc=since_q,
                            until_utc=until_q,
                            anomaly_only=anomaly_q,
                            page=page_q,
                        ),
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
                            block_effects=_block_effects(store, inc.approvals),
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
                # 상태 조회(/refresh)도 게이트웨이 확인 결과를 DB에 저장하므로 승인 권한이 필요하다(조회 전용 역할은 불가).
                needed = {"/approve": "approve", "/release": "release", "/refresh": "approve"}.get(action_suffix)
                if auth_enabled and needed and not role_can(user, needed):
                    self._send(
                        HTTPStatus.FORBIDDEN,
                        "text/plain; charset=utf-8",
                        "이 계정의 역할로는 차단 승인·해제를 할 수 없습니다.".encode("utf-8"),
                    )
                    return

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
        auth = AuthConfig(
            username=op_user, password=op_pass, secret=sess_secret or None,
            roles=parse_user_roles(os.environ.get("SOC_USERS", ""), op_user),
        )
        run_server(host=bind_host, port=port_env, store=db_store, auth_config=auth)
    else:
        run_server(host=bind_host, port=port_env)
