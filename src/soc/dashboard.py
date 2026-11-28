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
    AUTO_ACCOUNT_LOCK_RULE_ID,
    DEFAULT_THRESHOLD,
    DOC_DENIED_RULE_ID,
    IP_MULTI_ACCOUNT_FAILURE_RULE_ID,
    LOGIN_FAILURE_RULE_ID,
    LOGIN_FAILURE_REVIEW_RULE_ID,
    LOGIN_SOURCE_CHANGE_RULE_ID,
    LOGIN_SOURCE_DENIED_RULE_ID,
    LOGIN_SUCCESS_REVIEW_RULE_ID,
    MULTI_ACCOUNT_RULE_ID,
    MULTI_SOURCE_RULE_ID,
    X_LOGIN_IP,
)
from .incident_service import (
    ActionApiClient,
    ActionPolicyError,
    IncidentView,
    MAX_ACCOUNT_LOCK_MINUTES,
    MAX_BLOCK_MINUTES,
    build_incidents,
    group_login_incidents,
    refresh_approval_status,
    release_approval,
    request_human_approval,
)
from .models import NormalizedEvent, RawLogRecord
from .audit import (audit_for_store, release_with_audit, release_fields, release_audit_panel, collection_error_panel)
from .login_access import LoginAccessClient, LoginAccessError
from .normalizer import normalize_log_line
from .repository import FOLLOWUP_LOGIN_MINUTES, FollowupLoginSuccess, SocRepository, is_lock_denied_failure
from .reports import (FIELDS as REPORT_FIELDS, KST, ReportRepository, calculated_draft, followup_freeze, period_end,
                      report_body, report_key, report_period, standalone_page, validate_followup_change, validate_followup_new, weekly_snapshot)
from .storage import PostgresSocStorage, SocStorage
from .exports import UI as EXPORT_UI, build_export, export_controls
from .source_trends import source_scope
from .access_time import event_time_context, case_time_context, night_bands


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
    "approver": frozenset({"view", "approve", "release", "report_write"}),
    "admin": frozenset({"view", "approve", "release", "reset", "report_write"}),
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
            group_login_incidents(list(self.incidents.values())),
            key=lambda item: item.created_at_utc,
            reverse=True,
        )

    def get_incident(self, incident_id: str) -> IncidentView | None:
        return next(
            (inc for inc in self.list_incidents() if inc.incident_id == incident_id),
            self.incidents.get(incident_id),
        )

    def list_recent_events(
        self,
        limit: int = 50,
        *,
        offset: int = 0,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
        since_utc: datetime | None = None,
        until_utc: datetime | None = None,
        ingest_mode: str | None = None,
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
                if ingest_mode is not None and ev.ingest_mode != ingest_mode:
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
                        "protocol": ev.protocol,
                        "device_ip": ev.client_ip or ev.src_ip or "-",
                        "client_ip_trusted": ev.client_ip_trusted,
                        "request_id": ev.request_id,
                        "http_method": ev.http_method,
                        "http_path": ev.http_path,
                        "status_code": ev.status_code,
                        "ingest_mode": ev.ingest_mode,
                        "raw_id": ev.raw_id,
                        "rule_id": ev.details.get("rule_id"),
                        "access_time": ev.details.get("access_time"),
                        "lock_denied_failure": is_lock_denied_failure(ev.event_type, ev.status_code, ev.details),
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
        ingest_mode: str | None = None,
    ) -> int:
        return len(
            self.list_recent_events(
                ingest_mode=ingest_mode,
                limit=100000,
                source=source,
                event_types=event_types,
                since_utc=since_utc,
                until_utc=until_utc,
            )
        )

    def _events_for_ingest(self, source, event_types, exclude_event_types, since_utc, until_utc, ingest_mode=None) -> list[dict[str, Any]]:
        rows = self.list_recent_events(limit=100000, ingest_mode=ingest_mode, source=source, event_types=event_types,
                                       since_utc=since_utc, until_utc=until_utc)
        return [r for r in rows if not exclude_event_types or r["event_type"] not in exclude_event_types]

    def get_event_hours(self, *, source=None, event_types=None, exclude_event_types=None,
                        since_utc=None, until_utc=None, ingest_mode=None) -> list[tuple[str, int]]:
        """수집 공백 계산용 시간별 이벤트 수(메모리 저장소). DB 저장소와 같은 'YYYY-MM-DDTHH'(UTC) 형태."""
        counts: dict[str, int] = {}
        for row in self._events_for_ingest(source, event_types, exclude_event_types, since_utc, until_utc, ingest_mode):
            dt = datetime.fromisoformat(str(row["event_ts_utc"]).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            hour = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H")
            counts[hour] = counts.get(hour, 0) + 1
        return sorted(counts.items())

    def get_first_event_utc(self, *, source=None, event_types=None, exclude_event_types=None, until_utc=None, ingest_mode=None) -> str | None:
        rows = self._events_for_ingest(source, event_types, exclude_event_types, None, until_utc, ingest_mode)
        return min((str(r["event_ts_utc"]) for r in rows), default=None)

    def get_icmp_denial_hours(self, since_utc: datetime, until_utc: datetime) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for row in self.list_recent_events(limit=100000, source="gateway", event_types=("fw_deny",),
                                           since_utc=since_utc, until_utc=until_utc):
            if row.get("protocol") == "ICMP" and row.get("ingest_mode") == "live":
                hour = str(row["event_ts_utc"])[:13]
                counts[hour] = counts.get(hour, 0) + 1
        return sorted(counts.items())

    def get_recent_icmp_denials(self, limit: int = 10) -> list[dict[str, Any]]:
        return [row for row in self.list_recent_events(limit=100000, source="gateway", event_types=("fw_deny",))
                if row.get("protocol") == "ICMP" and row.get("ingest_mode") == "live"][:limit]

    def get_login_events(self, since_utc: datetime) -> list[tuple[datetime, str, str, str]]:
        out: list[tuple[datetime, str, str, str]] = []
        for row in self.list_recent_events(limit=500, source="erp", event_types=("login_failed", "login_success", "login_blocked")):
            if row["event_type"] == "login_blocked" and not row.get("lock_denied_failure"):
                continue
            if row["event_type"] == "login_failed" and row.get("status_code") == 400:
                continue  # 입력 형식 오류는 인증 실패 그래프에서 제외한다.
            dt = datetime.fromisoformat(str(row["event_ts_utc"]).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt >= since_utc:
                out.append(
                    (
                        dt.astimezone(timezone.utc),
                        "login_failed" if row["event_type"] == "login_blocked" else str(row["event_type"]),
                        str(row.get("client_ip") or row.get("device_ip") or ""),
                        str(row.get("username") or ""),
                    )
                )
        return out

    def get_trend_events(self, since_utc: datetime) -> list[tuple[datetime, str, str, str, int | None, str]]:
        out: list[tuple[datetime, str, str, str, int | None, str]] = []
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
                        str(row.get("http_path") or ""),
                    )
                )
        return out

    def get_hourly_summary(self) -> dict[str, int]:
        return {
            "erp_login_success": 0,
            "erp_login_failed": sum(
                1 for row in self.list_recent_events(limit=500, source="erp", event_types=("login_failed", "login_blocked"))
                if (row["event_type"] == "login_failed" and row.get("status_code") != 400) or row.get("lock_denied_failure")
            ),
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
        if hasattr(self, "_audit_storage"):
            self._audit_storage.close()


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
                    audit_for_store(self).observe_release(ap.approval_id, ap.gateway_response)
                    if ap.status != prev_status or inc.status != prev_inc_status:
                        self.persist_approval(inc, ap)
                elif self.action_client is None and ap.status == "applied" and is_past_exp:
                    ap.status = "expired"
                    inc.status = "blocked" if any(a.status == "applied" for a in inc.approvals) else "released"
                    inc.updated_at_utc = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
                    self.persist_approval(inc, ap)
        return incidents

    def list_incidents(self) -> list[IncidentView]:
        return group_login_incidents(self._sync_active_or_expired(self.repo.load_incidents()))

    def get_incident(self, incident_id: str) -> IncidentView | None:
        incidents = self._sync_active_or_expired(self.repo.load_incidents())
        return next(
            (inc for inc in group_login_incidents(incidents) if inc.incident_id == incident_id),
            next((inc for inc in incidents if inc.incident_id == incident_id), None),
        )

    def list_recent_events(
        self,
        limit: int = 50,
        *,
        offset: int = 0,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
        since_utc: datetime | None = None,
        until_utc: datetime | None = None,
        ingest_mode: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.repo.fetch_recent_events(ingest_mode=ingest_mode, 
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
        ingest_mode: str | None = None,
    ) -> int:
        return self.repo.count_recent_events(ingest_mode=ingest_mode, 
            source=source,
            event_types=event_types,
            since_utc=since_utc,
            until_utc=until_utc,
        )

    def get_event_hours(self, *, source=None, event_types=None, exclude_event_types=None,
                        since_utc=None, until_utc=None, ingest_mode=None) -> list[tuple[str, int]]:
        return self.repo.fetch_event_hours(ingest_mode=ingest_mode, source=source, event_types=event_types,
                                           exclude_event_types=exclude_event_types,
                                           since_utc=since_utc, until_utc=until_utc)

    def get_first_event_utc(self, *, source=None, event_types=None, exclude_event_types=None, until_utc=None, ingest_mode=None) -> str | None:
        return self.repo.fetch_first_event_utc(ingest_mode=ingest_mode, source=source, event_types=event_types,
                                               exclude_event_types=exclude_event_types, until_utc=until_utc)

    def get_icmp_denial_hours(self, since_utc: datetime, until_utc: datetime) -> list[tuple[str, int]]:
        return self.repo.fetch_icmp_denial_hours(since_utc, until_utc)

    def get_recent_icmp_denials(self, limit: int = 10) -> list[dict[str, Any]]:
        return self.repo.fetch_recent_icmp_denials(limit)

    def get_hourly_summary(self) -> dict[str, int]:
        return self.repo.fetch_hourly_summary()

    def get_login_events(self, since_utc: datetime) -> list[tuple[datetime, str, str, str]]:
        return self.repo.fetch_login_events(since_utc)

    def get_trend_events(self, since_utc: datetime) -> list[tuple[datetime, str, str, str, int | None, str]]:
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
    if not bare and active_path != "/reports":
        body_html = export_controls(active_path) + body_html + EXPORT_UI
    practice_reset_form = ""
    if (auth_enabled and current_user and csrf_token and role_can(current_user, "reset")
            and os.environ.get("SOC_ENABLE_PRACTICE_RESET") == "1"):
        practice_reset_form = (
            '<form method="post" onsubmit="return beginPracticeReset(event,this)" style="margin-top:14px;">'
            f'<input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}" />'
            '<input type="hidden" name="confirm" value="reset-practice-logs" />'
            '<button type="submit" class="btn-ghost" style="width:100%;justify-content:center;color:var(--danger);border:1px solid var(--danger);">관제 기록 초기화</button>'
            '<div role="status" class="practice-reset-status" style="font-size:12px;color:var(--text-3);margin-top:6px;">백업 없이 삭제 · 활성 차단 시 불가</div></form>'
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
                f'<div style="font-size:13px;font-weight: 600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{html.escape(current_user)}</div>'
                f'<div style="font-size:12px;color:var(--ok);">● {html.escape(ROLE_LABELS.get(role_of(current_user) or "", "역할 없음"))}</div>'
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

    in_incidents = active_path == "/incidents" or active_path.startswith("/incidents/")
    in_permissions = active_path == "/permissions" or active_path.startswith("/permissions/")
    nav_groups = [
        ("관제", [
            ("/", "개요", _svg_icon("dashboard", "currentColor", 16), active_path == "/"),
            ("/incidents", "사건", _svg_icon("alert", "currentColor", 16), in_incidents),
            ("/events", "이벤트", _svg_icon("list", "currentColor", 16), active_path == "/events"),
            ("/reports", "보고서", _svg_icon("list", "currentColor", 16), active_path == "/reports"),
            ("/permissions", "권한 부여", _svg_icon("unlock", "currentColor", 16), in_permissions),
        ]),
        ("로그 소스", [
            ("/logs/erp", "ERP 인증", _svg_icon("lock", "currentColor", 16), active_path == "/logs/erp"),
            ("/logs/gateway", "방화벽", _svg_icon("shield", "currentColor", 16), active_path == "/logs/gateway"),
            ("/logs/caddy", "웹 프록시", _svg_icon("globe", "currentColor", 16), active_path == "/logs/caddy"),
            ("/logs/waf", "WAF", _svg_icon("globe", "currentColor", 16), active_path == "/logs/waf"),
        ]),
    ]
    nav_html = "".join(
        f'<div class="nav-section">{title}</div>' + "".join(_nav_link(*item) for item in items)
        for title, items in nav_groups
    )

    logo_svg = (
        '<svg width="30" height="30" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
        '<path d="M12 2.5 4.5 5.6v5.7c0 4.6 3.1 8.5 7.5 10.2 4.4-1.7 7.5-5.6 7.5-10.2V5.6L12 2.5Z" '
        'fill="var(--brand-mark)" fill-opacity="0.18" stroke="var(--brand-mark)" stroke-width="1.7" stroke-linejoin="round"/>'
        '<path d="m8.7 12.1 2.4 2.4 4.3-4.6" stroke="var(--brand-mark)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>'
        "</svg>"
    )

    refresh_ms = int(refresh_seconds) * 1000 if refresh_seconds else 0
    refresh_meta = f'<noscript><meta http-equiv="refresh" content="{int(refresh_seconds)}" /></noscript>' if refresh_seconds else ""
    sync_pill = (
        f'<span id="socSyncPill" class="live-pill" role="button" tabindex="0" title="누르면 자동 갱신을 멈추거나 다시 시작합니다"><span class="pulse-dot"></span>{int(refresh_seconds)}초 자동 동기화</span>'
        if refresh_seconds
        else '<span id="socSyncPill" class="live-pill"><span class="pulse-dot"></span>실시간 연결</span>'
    )
    subpage_cls = (
        " subpage-glass"
        if active_path in {"/logs/erp", "/logs/gateway", "/logs/caddy", "/logs/waf", "/events", "/logs/events"}
        else ""
    )

    doc = f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  {refresh_meta}
  <title>{html.escape(title)}</title>
  <script>(function(){{try{{var t=localStorage.getItem("soc-theme");document.documentElement.setAttribute("data-theme",t==="light"?"light":"dark");}}catch(e){{document.documentElement.setAttribute("data-theme","dark");}}}})();</script>
  <style>
    /* 중립 기본색, 상태색, 로그 출처색을 각각 정의한다. */
    :root {{
      color-scheme: dark;
      --bg: #4f5054; --sunken: #2c2d31; --surface: #36373b; --raised: #404146;
      --line: #4a4b50; --line-soft: #414248;
      --text: #f5f5f7; --text-2: #d0d1d7; --text-3: #a4a6ae;
      --accent: #dce1e9; --on-accent: #21252c; --on-danger: #2a0a14; --on-ok: #122415;
      --brand-mark: #bfd48e;
      --ok: #99d889; --danger: #ff939e; --warn: #f3c267;
      --source-erp: #83bdff; --source-caddy: #c9a8ff; --source-gateway: #66ddd6;
      --text-rgb: 245 245 247; --sunken-rgb: 44 45 49; --surface-rgb: 54 55 59;
      --accent-rgb: 220 225 233; --ok-rgb: 153 216 137; --danger-rgb: 255 147 158;
      --warn-rgb: 243 194 103;
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
      --accent: #3e495b; --on-accent: #ffffff; --on-danger: #ffffff; --on-ok: #ffffff;
      --brand-mark: #587a2a;
      --ok: #2b6b30; --danger: #ad273d; --warn: #805500;
      --source-erp: #185ea5; --source-caddy: #7147ad; --source-gateway: #086d69;
      --text-rgb: 29 30 36; --sunken-rgb: 238 238 242; --surface-rgb: 255 255 255;
      --accent-rgb: 62 73 91; --ok-rgb: 43 107 48; --danger-rgb: 173 39 61;
      --warn-rgb: 128 85 0;
      --side-bg: #f7f7f9; --side-line: #dcdde3;
      --shadow: 0 2px 8px rgb(20 20 40 / 0.08); --overlay: rgb(20 20 30 / 0.4);
    }}
    @font-face {{
      font-family: "Pretendard Variable"; font-weight: 45 920; font-style: normal; font-display: swap;
      src: url("/static/fonts/PretendardVariable.woff2") format("woff2-variations");
    }}
    * {{ box-sizing: border-box; }}
    html {{ -webkit-text-size-adjust: 100%; }}
    body {{
      margin: 0;
      font-family: "Pretendard Variable", Pretendard, -apple-system, BlinkMacSystemFont, "Segoe UI Variable", "Segoe UI", "Malgun Gothic", system-ui, sans-serif;
      font-feature-settings: "tnum" 1;
      letter-spacing: -0.005em;
      font-size: 13px;
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
    .brand-title {{ font-size: 14px; font-weight: 600; color: var(--text); letter-spacing: -0.01em; }}
    .brand-sub {{ font-size: 12px; color: var(--text-3); margin-top: 1px; }}
    .nav-section {{ font-size: 12px; color: var(--text-3); margin: 18px 10px 6px; font-weight: 600; letter-spacing: 0.04em; }}
    .nav-link {{
      display: flex; align-items: center; gap: 10px;
      min-height: 36px;
      padding: 7px 10px;
      border-radius: var(--radius-sm);
      color: var(--text-2);
      font-size: 13px;
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
    .page-head h1 {{ margin: 0; font-size: 28px; font-weight: 600; letter-spacing: -0.025em; color: var(--text); }}
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
    .metric-val {{ font-size: 28px; font-weight: 600; letter-spacing: -0.03em; margin-top: 6px; color: var(--text); font-variant-numeric: tabular-nums; line-height: 1.1; }}
    .metric-val.is-danger {{ color: var(--danger); }}
    .metric-val.is-accent {{ color: var(--accent); }}
    .metric-sub {{ font-size: 13px; color: var(--text-3); margin-top: 8px; }}
    @media (max-width: 900px) {{
      .layout {{ display: block; }}
      aside.sidebar {{ width: auto; height: auto; position: static; border-right: none; border-bottom: 1px solid var(--side-line);
        padding: 10px 12px; gap: 8px; }}
      .side-top {{ display: flex; flex-wrap: wrap; align-items: center; gap: 4px 6px; }}
      .side-top .brand {{ padding: 4px 8px; margin: 0; }}
      .nav-section {{ display: none; }}
      .nav-link {{ margin: 0; }}
      main.content {{ padding: 16px 14px 40px; margin: 0; max-width: none; width: auto; }}
      .metrics {{ grid-template-columns: repeat(2, 1fr); }}
      .metric:nth-child(3) {{ border-left: none; }}
      .metric:nth-child(n+3) {{ border-top: 1px solid var(--line); }}
    }}
    .panel {{ overflow-x: auto; }}
    .tbl-incidents td {{ padding-top: 14px; padding-bottom: 14px; }}
    .incident-filters {{ display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin-bottom:12px; }}
    /* 필터 이름은 보조 정보라 제목보다 약하게, 이름과 자기 상자는 가깝게(6px), 다른 그룹과는 멀게(20px) 둔다. */
    .incident-filters label {{ display:inline-flex; align-items:center; gap:6px; margin-right:12px; font-size:12.5px; font-weight:500; color:var(--text-2); }}
    /* 선택 상자 높이를 옆의 버튼(34px)과 같게 맞춘다. */
    .incident-filters select {{ box-sizing:border-box; height:34px; min-width:112px; padding:0 10px; font-weight:400; }}
    .cell-title {{ color: var(--text); font-weight: 600; font-size: 14px; }}
    .cell-title:hover {{ color: var(--accent); text-decoration: none; }}
    .cell-sub {{ font-size: 13px; color: var(--text-3); margin-top: 3px; }}
    .range-bar {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
    .event-pager {{ display:flex;align-items:center;gap:4px;flex-wrap:wrap; }}
    .event-pager a,.event-pager span {{ display:inline-flex;align-items:center;justify-content:center;min-width:32px;min-height:32px;padding:5px 8px;font-size:12px;color:var(--text-2);border-radius:var(--radius-sm); }}
    .event-pager a:hover {{ background:var(--raised);color:var(--text); }}
    .event-pager [aria-current="page"] {{ color:var(--text);font-weight:700;background:rgb(var(--accent-rgb) / .12);box-shadow:inset 0 -2px var(--accent);border-radius:var(--radius-sm) var(--radius-sm) 0 0; }}
    .event-pager [aria-disabled="true"] {{ color:var(--text-3);opacity:.55; }}
    .event-pager .pager-gap {{ min-width:20px;padding-inline:2px;color:var(--text-3); }}
    .source-scope {{ display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 14px;font-size:12px; }}
    .source-scope label {{ display:inline-flex;align-items:center;gap:6px;color:var(--text-2); }}
    .source-scope select {{ font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:var(--radius-sm);padding:6px 8px; }}
    @media(pointer:coarse) {{ .event-pager a,.event-pager span {{ min-width:44px;min-height:44px; }} }}
    a.range-chip {{ display: inline-flex; align-items: center; min-height: 30px; padding: 5px 13px; border: 1px solid var(--line); border-radius: 999px; font-size: 13px; font-weight: 500; color: var(--text-2); }}
    @media (hover: hover) {{ a.range-chip:hover {{ background: rgb(var(--text-rgb) / 0.06); color: var(--text); text-decoration: none; }} }}
    a.range-chip.active {{ background: rgb(var(--accent-rgb) / 0.16); color: var(--accent); border-color: rgb(var(--accent-rgb) / 0.5); }}
    .chart-periods {{ display: flex; flex-wrap: wrap; gap: 4px 14px; border-bottom: 1px solid var(--line); margin: 0 0 10px; }}
    .chart-periods a.range-chip {{
      min-height: 40px; padding: 6px 4px; border: 0; border-bottom: 2px solid transparent;
      border-radius: 0; background: none; margin-bottom: -1px; white-space: nowrap;
    }}
    .chart-periods a.range-chip:hover {{ color: var(--text); background: none; }}
    .chart-periods a.range-chip[aria-current="true"] {{ border-bottom-color: var(--accent); color: var(--text); font-weight: 600; }}
    .chart-periods a.range-chip:focus-visible {{ outline: 2px solid var(--accent); outline-offset: -3px; }}
    .lf-hit {{ fill: transparent; }}
    .lf-col:hover .lf-hit {{ fill: rgb(var(--text-rgb) / 0.07); }}
    .lf-col:hover .lf-bar {{ filter: brightness(1.2); }}
    .title-en {{ font-size: 12px; font-weight: 500; letter-spacing: 0.01em; color: var(--text-3); }}
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
      padding: 10px 12px; min-width: 150px; font-size: 12px;
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
    .nav-link-quiet {{ min-height: 32px; font-size: 12px; color: var(--text-3); }}
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
      font-weight: 600; font-size: 13px;
      display: flex; align-items: center; justify-content: center; flex-shrink: 0;
    }}

    /* ----- 본문 / 상단바 ----- */
    main.content {{ flex: 1; min-width: 0; padding: 20px 32px 48px; max-width: 1480px; margin: 0 auto; }}
    .topbar {{
      display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
      padding-bottom: 16px; margin-bottom: 20px;
      border-bottom: 1px solid var(--line);
    }}
    .breadcrumb {{ font-size: 12px; color: var(--text-3); display: flex; align-items: center; gap: 8px; }}
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
    .card .label {{ font-size: 12px; color: var(--text-2); font-weight: 500; }}
    .card .val {{ font-size: 28px; font-weight: 600; margin-top: 6px; color: var(--text); letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }}
    .grid-2col {{ display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr); gap: 16px; margin-bottom: 20px; }}
    .grid-2col-eq {{ display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: 16px; margin-bottom: 20px; }}
    @media (max-width: 1120px) {{ .grid-2col, .grid-2col-eq {{ grid-template-columns: 1fr; }} }}
    .panel {{ padding: 18px 20px; margin-bottom: 20px; position: relative; }}
    .panel-header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 14px; flex-wrap: wrap; }}
    .panel h2 {{ margin: 0; font-size: 14px; font-weight: 600; color: var(--text); display: flex; align-items: center; gap: 8px; letter-spacing: -0.01em; }}
    .panel-sub {{ font-size: 13px; color: var(--text-3); margin-top: 3px; }}
    .chain {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 14px; font-size: 12px; }}
    .chain-step {{ background: var(--sunken); border: 1px solid var(--line); border-radius: var(--radius-sm); padding: 7px 12px; color: var(--text); }}

    /* ----- 표 ----- */
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13px; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line-soft); vertical-align: middle; }}
    th {{ color: var(--text-3); font-weight: 600; font-size: 12px; background: transparent; border-bottom: 1px solid var(--line); }}
    tbody tr {{ transition: background-color 120ms var(--ease); }}
    tbody tr.clickable-row {{ cursor: pointer; }}
    #holoModalBody tr.clickable-row:focus-within {{ background: var(--sunken); }}
    @media (hover: hover) {{ tbody tr:hover {{ background: rgb(var(--text-rgb) / 0.04); }} }}
    tbody tr:last-child td {{ border-bottom: none; }}

    /* ----- 상태 배지 (색 + 글자, 색만으로 구분하지 않음) ----- */
    .badge {{
      display: inline-flex; align-items: center; gap: 5px;
      padding: 3px 10px; border-radius: 999px;
      font-size: 12px; font-weight: 600; white-space: nowrap;
      border: 1px solid transparent;
    }}
    .b-open {{ background: rgb(var(--warn-rgb) / 0.16); color: var(--warn); }}
    .b-approved {{ background: rgb(var(--accent-rgb) / 0.14); color: var(--accent); }}
    .b-blocked, .b-applied, .b-rejected {{ background: rgb(var(--danger-rgb) / 0.14); color: var(--danger); }}
    .b-released, .b-ok {{ background: rgb(var(--ok-rgb) / 0.14); color: var(--ok); }}
    .b-warn {{ background: rgb(var(--warn-rgb) / 0.16); color: var(--warn); }}
    /* 기계값(IP·ID·경로)은 상자 없이 고정폭 글자만. 상자는 여러 줄 원문(pre)에만 쓴다. */
    /* 고정폭은 같은 크기에서 작아 보이므로 12.5px로 광학 보정(본문 13px과 같은 크기로 보이게) */
    code {{ font-family: var(--font-mono); font-size: 12.5px; font-weight: 400; color: inherit; background: none; border: 0; padding: 0; }}
    pre {{
      font-family: var(--font-mono); font-size: 12px;
      background: var(--sunken); border: 1px solid var(--line); border-radius: 4px; color: var(--text);
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
    .holo-modal-body {{ overflow-y: auto; padding-right: 4px; font-size: 13px; line-height: 1.6; }}
    @keyframes fadeIn {{ from {{ opacity: 0; }} }}
    @keyframes modalIn {{ from {{ opacity: 0; transform: translateY(8px) scale(0.985); }} }}

    /* ----- 식별자 칩 / 토스트 ----- */
    button.id-copy-chip {{
      display: inline-flex; align-items: center; gap: 4px;
      background: none; color: var(--text-2);
      border: none; border-radius: 4px;
      padding: 1px 3px; min-height: 0;
      font-family: ui-monospace, "Cascadia Mono", "JetBrains Mono", "SF Mono", Consolas, monospace;
      font-size: 12px; font-weight: 500; cursor: pointer; white-space: nowrap; line-height: 1.5;
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
    .request-feed {{ --request-columns: 4.2rem minmax(0,1.65fr) minmax(10.5rem,1fr) 7.5rem 5.2rem 1.25rem; display: grid; gap: 8px; margin-top: 12px; }}
    .request-card {{ background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; transition: border-color 150ms var(--ease), background-color 150ms var(--ease); }}
    .request-card[data-anomaly="1"] {{ border-color: rgb(var(--danger-rgb) / 0.42); box-shadow: inset 3px 0 0 var(--danger); }}
    .request-card[open] {{ border-color: rgb(var(--accent-rgb) / 0.45); }}
    .request-feed-head, .request-card > summary {{ display: grid; grid-template-columns: var(--request-columns); align-items: center; gap: 12px; padding-inline: 16px; }}
    .request-feed-head {{ padding-block: 6px; margin-inline: 1px; font-size: 12px; font-weight: 600; color: var(--text-3); border-bottom: 1px solid var(--line-soft); }}
    .request-card > summary {{ padding-block: 10px; min-height: 46px; cursor: pointer; list-style: none; transition: background-color 120ms var(--ease); }}
    .request-card > summary::-webkit-details-marker {{ display: none; }}
    .request-card > summary:hover, .request-card[open] > summary {{ background: var(--raised); }}
    .request-card > summary:focus-visible {{ outline: 2px solid var(--accent); outline-offset: -2px; }}
    .request-main {{ display: flex; align-items: center; flex-wrap: wrap; gap: 6px 10px; min-width: 0; }}
    .request-main > .ev-act {{ flex: none; }}
    .request-path {{ display: inline-flex; align-items: center; flex-wrap: nowrap; gap: 5px; color: var(--text-2); font-size: 12px; min-width: 0; white-space: nowrap; }}
    .request-path-arrow {{ color: var(--text-3); font-size: 11px; }}
    .request-summary-ctx {{ display: inline-flex; align-items: center; gap: 6px; font-family: var(--font-mono); font-size: 12px; color: var(--text-2); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; padding-left: 8px; border-left: 1px solid var(--line-soft); }}
    .request-summary-ctx .is-bad {{ color: var(--danger); font-weight: 500; }}
    .request-peer {{ display: flex; align-items: center; flex-wrap: wrap; gap: 4px 8px; min-width: 0; color: var(--text-2); font-size: 12px; overflow: hidden; }}
    .request-feed-time, .request-feed-count {{ text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }}
    .request-feed-count {{ color: var(--text-2); font-size: 12px; }}
    .request-count-pill {{ display: inline-flex; align-items: center; justify-content: flex-end; gap: 4px; padding: 2px 7px; border-radius: var(--radius-sm); background: rgb(var(--text-rgb) / 0.05); color: var(--text-2); font-size: 12px; font-weight: 500; }}
    .request-count-pill.is-flow {{ background: rgb(var(--accent-rgb) / 0.12); color: var(--text); font-weight: 600; }}
    .request-chevron {{ justify-self: center; border: solid var(--text-3); border-width: 0 1.6px 1.6px 0; padding: 3px; transform: rotate(45deg); margin-bottom: 3px; transition: transform 150ms var(--ease); }}
    .request-card[open] .request-chevron {{ transform: rotate(225deg); margin-bottom: -2px; border-color: var(--text); }}
    .request-status {{ justify-self: start; display: inline-flex; align-items: center; gap: 5px; font-size: 12px; font-weight: 600; padding: 3px 9px; border-radius: var(--radius-sm); color: var(--ok); background: rgb(var(--ok-rgb) / 0.12); white-space: nowrap; }}
    .request-status::before {{ content: ""; width: 6px; height: 6px; border-radius: 50%; background: var(--ok); flex-shrink: 0; }}
    .request-status.is-anomaly {{ color: var(--danger); background: rgb(var(--danger-rgb) / 0.15); }}
    .request-status.is-anomaly::before {{ background: var(--danger); }}
    .request-layers {{ padding: 12px 16px 14px; border-top: 1px solid var(--line); background: var(--sunken); }}
    .request-id-line {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px 16px; font-size: 12px; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid var(--line-soft); }}
    .request-id-left, .request-id-right {{ display: inline-flex; align-items: center; flex-wrap: wrap; gap: 8px; }}
    .request-stages-wrap {{ border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface); overflow: hidden; }}
    .request-stages-head {{ display: grid; grid-template-columns: 7.5rem minmax(9.5rem, 1.1fr) minmax(10rem, 2fr) 8.5rem 8.5rem; gap: 12px; align-items: center; padding: 7px 14px; background: rgb(var(--text-rgb) / 0.03); border-bottom: 1px solid var(--line); font-size: 11.5px; font-weight: 600; color: var(--text-3); }}
    .request-stages-head span:nth-child(4), .request-stages-head span:nth-child(5) {{ text-align: right; }}
    .request-stages {{ display: grid; gap: 0; margin: 0; padding: 0; list-style: none; }}
    .request-stage {{ display: grid; grid-template-columns: 7.5rem minmax(9.5rem, 1.1fr) minmax(10rem, 2fr) 8.5rem 8.5rem; grid-template-areas: "source result info time raw"; align-items: center; gap: 12px; padding: 10px 14px; }}
    .request-stage + .request-stage {{ border-top: 1px solid var(--line-soft); }}
    .request-stage-source {{ grid-area: source; display: inline-flex; align-items: center; gap: 6px; }}
    .request-step-num {{ display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; border-radius: 50%; background: rgb(var(--text-rgb) / 0.08); color: var(--text-2); font-size: 11px; font-weight: 600; font-variant-numeric: tabular-nums; flex-shrink: 0; }}
    .request-stage-result {{ grid-area: result; min-width: 0; }}
    .request-stage-info {{ grid-area: info; display: flex; align-items: center; flex-wrap: wrap; gap: 6px 8px; min-width: 0; }}
    .request-stage-time {{ grid-area: time; text-align: right; font-variant-numeric: tabular-nums; }}
    .request-stage-raw {{ grid-area: raw; min-width: 0; text-align: right; }}
    .request-stage-meta-label {{ display: none; font-size: 11px; color: var(--text-3); margin-bottom: 2px; }}
    .request-stage .cell-sub {{ overflow-wrap: anywhere; }}
    .request-main .cell-sub {{ display: none; }}
    @media (max-width: 1050px) {{
      .request-feed-head {{ display: none; }}
      .request-card > summary {{ grid-template-columns: 4.2rem minmax(0,1fr) 5.2rem 1.25rem; gap: 7px 10px; }}
      .request-peer, .request-feed-time {{ grid-column: 2 / -1; text-align: left; }}
      .request-feed-count {{ grid-column: 3; grid-row: 1; }}
      .request-chevron {{ grid-column: 4; grid-row: 1; }}
    }}
    @media (max-width: 1150px) {{
      .request-stages-head {{ display: none; }}
      .request-stage-meta-label {{ display: block; }}
      .request-stage {{ grid-template-columns: minmax(0,1fr) minmax(0,1fr); grid-template-areas: "source result" "info info" "time raw"; align-items: start; }}
    }}
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
    /* ----- 절제된 색 체계: 중립 칩 + 작은 색 점, 얇은 막대, 윤곽선 버튼 ----- */
    .badge {{
      background: rgb(var(--text-rgb) / 0.08) !important;
      border: none !important;
      color: var(--text) !important;
      padding: 3px 10px 3px 8px; gap: 6px; font-weight: 500;
    }}
    .badge::before {{ content: ""; width: 6px; height: 6px; border-radius: 50%; background: var(--text-3); flex-shrink: 0; }}
    .badge svg {{ display: none !important; }}
    .b-open::before {{ background: var(--warn); }}
    .b-blocked::before, .b-applied::before, .b-rejected::before {{ background: var(--danger); }}
    .b-approved::before {{ background: var(--accent); }}
    .b-released::before, .b-ok::before {{ background: var(--ok); }}
    .b-expired::before, .b-closed::before {{ background: var(--text-3); }}
    .b-locked::before {{ background: var(--danger); }}
    .b-allow::before {{ background: var(--ok); }}
    .b-warn::before {{ background: var(--warn); }}
    .src-erp::before {{ background: var(--source-erp); }}
    .src-caddy::before {{ background: var(--source-caddy); }}
    .src-gateway::before {{ background: var(--source-gateway); }}
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
    .login-logo {{ width: 42px; height: 42px; border-radius: 10px; display: grid; place-items: center; background: color-mix(in srgb, var(--brand-mark) 14%, transparent); flex-shrink: 0; }}
    .login-card h1 {{ margin: 0; font-size: 20px; font-weight: 600; letter-spacing: -0.02em; color: var(--text); }}
    .login-card .sub {{ font-size: 13px; color: var(--text-2); margin-top: 2px; }}
    .field {{ display: block; margin-bottom: 16px; }}
    .field span {{ display: block; font-size: 13px; font-weight: 500; color: var(--text-2); margin-bottom: 6px; }}
    .field input {{ width: 100%; min-height: 42px; }}
    .login-card button[type="submit"] {{ width: 100%; min-height: 44px; margin-top: 6px; font-size: 14px; }}
    .login-foot {{ margin-top: 20px; font-size: 12px; color: var(--text-3); text-align: center; }}
    /* ----- 팝업(상세 창) ----- */
    .pop-head {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; padding-bottom: 16px; margin-bottom: 18px; border-bottom: 1px solid var(--line); flex-shrink: 0; }}
    .pop-head h3 {{ margin: 8px 0 0; font-size: 20px; font-weight: 600; letter-spacing: -0.02em; color: var(--text); line-height: 1.35; }}
    .pop-badge {{ display: inline-block; font-size: 12px; font-weight: 500; color: var(--text-2); background: rgb(var(--text-rgb) / 0.08); padding: 3px 10px; border-radius: 999px; }}
    button.pop-close {{ background: transparent; color: var(--text-2); border: 1px solid var(--line); width: 34px; height: 34px; min-height: 34px; padding: 0; flex-shrink: 0; }}
    @media (hover: hover) {{ button.pop-close:hover:not(:disabled) {{ background: rgb(var(--text-rgb) / 0.08); color: var(--text); filter: none; }} }}
    .pop-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 18px; }}
    .pop-stats.three {{ grid-template-columns: repeat(3, 1fr); }}
    @media (max-width: 820px) {{ .pop-stats.three {{ grid-template-columns: 1fr; }} }}
    .pop-stat {{ padding: 14px 16px; background: var(--sunken); border: 1px solid var(--line-soft); border-radius: 10px; min-width: 0; }}
    .pop-stat .k {{ font-size: 12px; color: var(--text-3); display: flex; align-items: center; gap: 6px; }}
    .pop-stat .v {{ font-size: 14px; font-weight: 600; color: var(--text); margin-top: 6px; overflow-wrap: anywhere; }}
    .pop-stat .v.mono {{ font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; }}
    /* 시각(KST·UTC)이 카드보다 길면 두 덩어리로 나눠 줄바꿈한다(인라인 nowrap을 덮어쓴다) */
    .pop-stat .v > span[title] {{ white-space: normal !important; }}
    .pop-stat .v > span[title] > span {{ display: inline-block; }}
    .pop-stat .note {{ font-size: 13px; color: var(--text-2); margin-top: 8px; line-height: 1.6; }}
    .pop-stat a {{ display: inline-block; margin-top: 8px; font-size: 12px; }}
    .d.source-erp, .d.source-caddy, .d.source-gateway {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }}
    .d.source-erp {{ background: var(--source-erp); }} .d.source-caddy {{ background: var(--source-caddy); }} .d.source-gateway {{ background: var(--source-gateway); }}
    .pop-actions {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; padding: 14px 16px; background: var(--sunken); border: 1px solid var(--line-soft); border-radius: 10px; margin-bottom: 18px; }}
    .pop-actions-main {{ display: flex; align-items: center; gap: 12px 14px; flex-wrap: wrap; }}
    .pop-actions-main strong {{ font-size: 13px; color: var(--text); }}
    .pop-form {{ display: inline-flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
    .pop-form label, .pop-actions label {{ font-size: 13px; color: var(--text-2); display: inline-flex; align-items: center; gap: 8px; }}
    .pop-actions form {{ margin: 0; }}
    .pop-section {{ margin-top: 20px; }}
    .pop-h {{ margin: 0 0 10px; font-size: 14px; font-weight: 600; color: var(--text); display: flex; align-items: baseline; gap: 8px; }}
    .pop-h span {{ font-size: 12px; font-weight: 400; color: var(--text-3); }}
    .pop-note {{ margin-bottom: 14px; font-size: 13px; line-height: 1.65; color: var(--text-2); }}
    .pop-note b {{ color: var(--text); }}
    .holo-modal-body table {{ margin-bottom: 4px; }}
    th {{ white-space: nowrap; }}
    td code {{ white-space: nowrap; }}
    .pop-actions > a {{ margin-left: auto; }}
    body {{ word-break: keep-all; overflow-wrap: break-word; }}
    .card .val {{ color: var(--text) !important; }}
    .card .val[style*="var(--danger)"] {{ color: var(--danger) !important; }}
    .detail-head {{ display: flex; align-items: center; gap: 10px 12px; flex-wrap: wrap; }}
    .detail-head h1 {{ margin: 0; font-size: 20px; font-weight: 600; letter-spacing: -0.02em; color: var(--text); }}
    .chain {{ gap: 10px; }}
    .chain-step {{ display: inline-flex; align-items: center; gap: 8px; }}
    .chain-step b {{ font-weight: 600; }}
    .chain-step em {{ font-style: normal; font-size: 12px; color: var(--text-3); }}
    .chain-arrow {{ color: var(--text-3); font-size: 12px; white-space: nowrap; }}
    .chain-arrow code {{ background: none; border: none; padding: 0; color: var(--text-2); }}
    details.panel > summary {{ cursor: pointer; list-style: none; display: flex; justify-content: space-between; align-items: center; gap: 12px; }}
    details.panel > summary::-webkit-details-marker {{ display: none; }}
    details.panel > summary::after {{ content: "펼치기"; font-size: 12px; color: var(--text-3); flex-shrink: 0; }}
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
      font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12px;
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
    .waf-type {{ font-weight: 600; color: var(--text); }}
    .waf-rule-id {{ margin-top: 3px; font-size: 11px; color: var(--text-3); font-variant-numeric: tabular-nums; }}
    .icmp-chart-scroll {{ overflow-x: auto; }}
    .icmp-chart {{ display: grid; grid-template-columns: repeat(24, minmax(19px, 1fr)); gap: 5px; min-width: 620px; height: 164px; align-items: end; border-bottom: 1px solid var(--line); }}
    .icmp-hour {{ height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; gap: 3px; font-size: 11px; color: var(--text-3); font-variant-numeric: tabular-nums; }}
    .icmp-hour b {{ color: var(--text); font-weight: 600; }}
    .icmp-hour .icmp-bar {{ display: block; width: min(100%, 18px); min-height: 1px; border-radius: 3px 3px 0 0; background: var(--warn); }}
    .icmp-hour .icmp-bar.zero {{ background: var(--line); }}
    /* ICMP 차단 상세 기록: 바로 아래 로그 표와 같은 줄 높이(--log-row-h)에 맞춘다.
       칸 안의 줄(거부 · 설명 · 규칙 코드)은 하나도 빼거나 옮기지 않고 줄 간격과 위아래 여백만 줄인다. */
    .icmp-trace td {{ padding-top: 4px; padding-bottom: 4px; line-height: 15px; }}
    .icmp-trace tbody tr {{ height: var(--log-row-h); }}
    .icmp-trace .ev-act {{ display: flex; font-size: 12.5px; line-height: 15px; }}
    .icmp-trace .cell-sub {{ margin: 0; font-size: 11.5px; line-height: 15px; }}
    .icmp-trace .waf-rule-id {{ margin: 0; line-height: 15px; }}
    /* ----- 관제 실무 구성: 수집 상태 · 경과 시간 · Top-N · pivot ----- */
    .health {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }}
    @media (max-width: 900px) {{ .health {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} }}
    @media (max-width: 560px) {{ .health {{ grid-template-columns: 1fr; }} }}
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
    .hstate {{ grid-area: state; font-size: 12px; font-weight: 600; color: var(--text-3); }}
    .hitem.ok .hstate {{ color: var(--ok); }}
    .hitem.stale .hstate {{ color: var(--warn); }}
    .hmeta {{ grid-area: meta; font-size: 12px; color: var(--text-3); }}
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
    code.ip.is-bad {{ color: var(--text); font-weight: 600; }}
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
    details.resp summary {{ cursor: pointer; list-style: none; color: var(--text-3); font-size: 12px; white-space: nowrap; }}
    details.resp summary::-webkit-details-marker {{ display: none; }}
    details.resp summary::before {{ content: "▸ "; }}
    details.resp[open] summary::before {{ content: "▾ "; }}
    details.resp[open] summary {{ color: var(--text); }}
    details.resp pre {{ margin: 8px 0 0; width: 340px; max-width: 100%; white-space: pre-wrap; word-break: break-all; font-size: 12px; }}
    /* 개요의 우선 확인 사건: 넓은 화면에서는 왼쪽 대기열 + 오른쪽 최근 처리 사건을 항상 나란히 보여 준다. */
    .pq-split {{ display: grid; grid-template-columns: minmax(0, 1fr); gap: 0 14px; margin-bottom: 20px; }}
    .pq-split > .panel, .pq-side .panel {{ margin-bottom: 0; min-width: 0; }}
    .pq-side {{ min-width: 0; margin-top: 20px; }}
    .pq-side .panel {{ height: 100%; }}
    @media (min-width: 1121px) {{
      .pq-split {{ grid-template-columns: minmax(0, var(--split-main)) minmax(0, 1fr); }}
      .pq-side {{ margin-top: 0; }}
    }}
    .pq-list {{ list-style: none; margin: 4px 0 0; padding: 0; }}
    .pq-item {{ position: relative; display: block; padding: 10px 8px 10px 26px; margin: 0 -8px; border-radius: 8px; color: var(--text); text-decoration: none; }}
    .pq-item::before {{ content: ""; position: absolute; left: 9px; top: 0; bottom: 0; width: 1px; background: var(--line-soft); }}
    .pq-list li:first-child .pq-item::before {{ top: 18px; }}
    .pq-list li:last-child .pq-item::before {{ bottom: calc(100% - 18px); }}
    .pq-dot {{ position: absolute; left: 5px; top: 15px; width: 8px; height: 8px; border-radius: 50%; background: var(--text-3); box-shadow: 0 0 0 3px var(--surface, var(--bg)); }}
    .pq-dot.is-danger {{ background: var(--danger); }}
    .pq-dot.is-released {{ background: var(--ok); }}
    .pq-row {{ display: flex; align-items: baseline; justify-content: space-between; gap: 10px; }}
    .pq-row b {{ min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .pq-time {{ flex: none; font-size: 12px; color: var(--text-3); }}
    .pq-meta {{ display: block; margin-top: 2px; font-size: 12px; color: var(--text-3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .pq-meta .pq-state {{ color: var(--text-2); font-weight: 600; }}
    .pq-empty {{ padding: 18px 0 6px; color: var(--text-3); font-size: 13px; }}
    @media (hover: hover) {{ .pq-item:hover {{ background: rgb(var(--text-rgb) / 0.04); text-decoration: none; }} }}
    .pq-item:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 1px; }}
    /* ----- 로그 표: 실무 관제 도구처럼 한 줄에 한 건, 조밀하게 ----- */
    /* 로그 표 글자 위계 3단계: 무슨 일(13px·진함) > 언제·어디서(12px·보통) > 추적 식별자(11px·흐림) */
    table.log-tbl {{ font-size: 13px; }}
    .log-tbl th {{ font-size: 12px; font-weight: 600; color: var(--text-3); }}
    .log-tbl .lt {{ font-size: 12px; color: var(--text-2); font-variant-numeric: tabular-nums; white-space: nowrap; }}
    .log-tbl td > .badge {{ font-size: 12px; font-weight: 600; }}
    .log-tbl .ev-act {{ font-size: 13px; font-weight: 600; color: var(--text); }}
    .log-tbl .ev-chip, .log-tbl td code {{ font-size: 12px; color: var(--text); }}
    .log-tbl .ev-chip.bad {{ color: var(--danger); }} .log-tbl .ev-chip.good {{ color: var(--ok); }}
    .log-tbl button.id-copy-chip {{ font-size: 12px; color: var(--text-3); }}
    .log-tbl .raw-col {{ text-align: right; white-space: nowrap; }}
    /* 이벤트 탭도 로그 표와 같은 글자 위계 3단계 */
    .request-feed {{ font-size: 13px; }}
    .request-feed-head {{ font-size: 12px; font-weight: 600; color: var(--text-3); }}
    .request-feed .lt {{ font-size: 12px; color: var(--text-2); font-variant-numeric: tabular-nums; white-space: nowrap; }}
    .request-status {{ font-size: 12px; }}
    .request-main > .ev-act, .request-stage-result .ev-act {{ font-size: 13px; font-weight: 600; color: var(--text); }}
    .request-path, .request-path .badge {{ font-size: 12px; }}
    .request-peer {{ font-size: 12px; }}
    .request-peer > span:first-child {{ font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12px; color: var(--text); }}
    .request-feed-count {{ font-size: 12px; color: var(--text-3); }}
    .request-stage-source .badge {{ font-size: 12px; }}
    .request-stage .ev-chip, .request-stage code {{ font-size: 12px; color: var(--text); }}
    .request-stage .ev-chip.bad {{ color: var(--danger); }} .request-stage .ev-chip.good {{ color: var(--ok); }}
    .request-stage .cell-sub {{ font-size: 12px; color: var(--text-3); font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; }}
    .request-stage-meta-label {{ font-size: 12px; }}
    .request-feed button.id-copy-chip, .request-id-line {{ font-size: 12px; }}
    .request-feed button.id-copy-chip {{ color: var(--text-3); }}
    /* 글꼴 역할: 한글·설명은 Pretendard, 기계값(IP·경로·ID·로그 코드)만 고정폭 하나로.
       고정폭은 같은 크기에서 더 굵고 커 보이므로 굵기 500, 합자는 꺼서 원문 그대로 보이게 한다. */
    /* 좌우 2단 패널의 왼쪽 폭 비율. 같은 화면의 모든 줄이 이 값을 써야 세로 경계선이 맞는다. */
    /* 로그 소스 네 탭(ERP·방화벽·웹 프록시·WAF)의 줄 높이. 기준은 방화벽 탭(이벤트 이름 + 보조 코드 줄)의 자연 높이다. */
    :root {{ --font-mono: "SF Mono", Menlo, Consolas, "Cascadia Mono", ui-monospace, "D2Coding", monospace; --split-main: 1.6fr; --log-row-h: 54px; }}
    .log-source-tbl tbody tr {{ height: var(--log-row-h); }}
    /* ERP는 추적 ID 칩 두 개(req·raw)가 위아래로 쌓여 줄이 3px 커진다. 칩을 옆으로 옮기지 않고 칩 높이만 줄인다. */
    .log-source-tbl .idstack button.id-copy-chip {{ padding-block: 0; line-height: 18px; }}
    code, kbd, samp, pre, .ev-chip, button.id-copy-chip, .mono, .pop-stat .v.mono {{
      font-family: var(--font-mono) !important; font-variant-ligatures: none; letter-spacing: 0;
    }}
    code, code.ip, .ev-chip, .flow code, .flow {{ font-weight: 400 !important; }}
    .request-peer > span:first-child {{ font-family: var(--font-mono); font-weight: 500; font-variant-ligatures: none; }}
    .log-tbl td .cell-sub, .request-stage .cell-sub {{ font-family: var(--font-mono); font-weight: 400; }}
    .ev-act, .cell-title, .panel h2 {{ letter-spacing: -0.01em; }}
    /* 무게 정리: Windows 고정폭 글꼴은 같은 크기에서 Pretendard보다 크고 굵게 그려진다.
       기계값은 12px·보통 굵기·상자 없음, 강조가 필요한 IP만 본문색. 이벤트 이름만 굵게(요약 600, 단계 500). */
    .log-tbl td code, .log-tbl .ev-chip, .request-feed code, .request-feed .ev-chip,
    .request-peer > span:first-child, .tbl-incidents code {{
      font-size: 12.5px !important; font-weight: 400 !important; background: none !important;
      border: 0 !important; padding: 0 !important; box-shadow: none !important;
    }}
    .log-tbl .ev-chip, .request-feed .ev-chip {{ color: var(--text-2); }}
    .log-tbl code.ip, .request-feed code.ip, .request-peer > span:first-child {{ color: var(--text) !important; }}
    .log-tbl .ev-chip.bad, .request-feed .ev-chip.bad {{ color: var(--danger); }}
    .log-tbl .ev-chip.good, .request-feed .ev-chip.good {{ color: var(--ok); }}
    .log-tbl .ev-act, .request-stage-result .ev-act {{ font-weight: 500; }}
    .request-main > .ev-act {{ font-weight: 600; }}
    .log-tbl td .cell-sub, .request-stage .cell-sub {{ font-size: 12px !important; }}
    button.filter-chip {{ border-radius: 4px; padding: 4px 10px; min-height: 28px; font-size: 12px; }}
    /* 출처는 출처색으로, 상태 점은 의미색으로 구분한다.
       정상·허용·해제는 초록, 차단·실패·거부는 빨강, 주의는 노랑. 글자 라벨도 유지한다. */
    /* 출처 꼬리표: 출처 색 점 + 옅은 같은 색 바탕, 글자는 본문색(작은 글자 대비 확보) */
    .badge.src-erp, .badge.src-caddy, .badge.src-gateway, .badge.src-waf {{ color: var(--text) !important; }}
    .badge.src-erp {{ background: color-mix(in srgb, var(--source-erp) 16%, transparent) !important; }}
    .badge.src-caddy {{ background: color-mix(in srgb, var(--source-caddy) 16%, transparent) !important; }}
    .badge.src-gateway {{ background: color-mix(in srgb, var(--source-gateway) 16%, transparent) !important; }}
    .badge.src-waf {{ background: color-mix(in srgb, var(--source-waf) 18%, transparent) !important; }}
    .src-waf::before {{ background: var(--source-waf); }}
    .request-path .badge, .request-stage-source .badge {{ padding: 2px 8px !important; border-radius: 4px !important; }}
    .ev-act.good::before {{ background: var(--ok); }}
    .ev-chip.good, .log-tbl .ev-chip.good, .request-feed .ev-chip.good, .request-stage .ev-chip.good {{ color: var(--text-2) !important; }}
    .request-status:not(.is-anomaly) {{ color: var(--text-2); background: rgb(var(--text-rgb) / 0.07); }}
    .b-ok, .b-released {{ color: var(--text-2); background: rgb(var(--text-rgb) / 0.07); }}
    .b-ok::before, .b-released::before {{ background: var(--ok) !important; }}
    .b-replay {{ color: var(--text-2) !important; background: rgb(var(--text-rgb) / 0.07) !important; }}
    .b-replay::before {{ background: var(--text-3) !important; }}
    .b-allow {{ background: rgb(var(--ok-rgb) / 0.14) !important; color: var(--ok) !important; }}
    .b-allow::before {{ background: var(--ok) !important; }}
    .b-suspect {{ background: rgb(var(--warn-rgb) / 0.18) !important; color: var(--warn) !important; box-shadow: inset 0 0 0 1px rgb(var(--warn-rgb) / 0.38); }}
    .b-suspect::before {{ background: var(--warn) !important; }}
    .b-locked {{ background: rgb(var(--danger-rgb) / 0.18) !important; color: var(--sev-high) !important; box-shadow: inset 0 0 0 1px rgb(var(--danger-rgb) / 0.38); }}
    .b-locked::before {{ background: var(--sev-high) !important; }}
    tr.row-suspect > td {{ background: rgb(var(--warn-rgb) / 0.085); }}
    tr.row-suspect > td:first-child {{ box-shadow: inset 3px 0 0 var(--warn); }}
    tr.row-locked > td {{ background: rgb(var(--danger-rgb) / 0.09); }}
    tr.row-locked > td:first-child {{ box-shadow: inset 3px 0 0 var(--sev-high); }}
    tr.row-allow > td {{ background: rgb(var(--ok-rgb) / 0.06); }}
    tr.row-allow > td:first-child {{ box-shadow: inset 3px 0 0 var(--ok); }}
    button.btn-danger-outline {{
      background: rgb(var(--danger-rgb) / 0.08); color: var(--danger);
      border: 1px solid rgb(var(--danger-rgb) / 0.45);
    }}
    @media (hover: hover) {{ button.btn-danger-outline:hover:not(:disabled) {{ background: rgb(var(--danger-rgb) / 0.18); filter: none; }} }}
    button.btn-warn-outline {{
      background: rgb(var(--warn-rgb) / 0.08); color: var(--warn);
      border: 1px solid rgb(var(--warn-rgb) / 0.45);
    }}
    @media (hover: hover) {{ button.btn-warn-outline:hover:not(:disabled) {{ background: rgb(var(--warn-rgb) / 0.18); filter: none; }} }}
    .alert-banner {{
      display: flex; align-items: center; justify-content: space-between; gap: 12px;
      padding: 11px 16px; margin-bottom: 16px; border-radius: var(--radius);
      font-size: 13px; font-weight: 500;
    }}
    .alert-banner.is-error {{ background: rgb(var(--danger-rgb) / 0.12); border: 1px solid rgb(var(--danger-rgb) / 0.42); color: var(--danger); }}
    .alert-banner.is-ok {{ background: rgb(var(--ok-rgb) / 0.12); border: 1px solid rgb(var(--ok-rgb) / 0.42); color: var(--ok); }}
    .alert-banner.is-info {{ background: rgb(var(--accent-rgb) / 0.1); border: 1px solid rgb(var(--accent-rgb) / 0.32); color: var(--text); }}
    .perm-form-card {{
      padding: 14px 16px; margin-bottom: 16px;
      border-radius: var(--radius); background: var(--sunken); border: 1px solid var(--line-soft);
    }}
    /* 위아래 두 줄이 같은 2단 격자를 써서 칸의 왼쪽 선이 맞는다(계정↔유지 시간, 문서↔사유). 제출 버튼은 확인 정보 옆 맨 아래 한 줄. */
    .perm-form-row1, .perm-form-row2 {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.35fr); gap: 12px; }}
    .perm-form-row1 {{ margin-bottom: 12px; }}
    .perm-form-foot {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px 16px; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--line-soft); }}
    .perm-submit {{ height: 34px; min-height: 34px; min-width: 120px; padding: 0 18px; }}
    @media (max-width: 720px) {{
      .perm-form-row1, .perm-form-row2 {{ grid-template-columns: 1fr; }}
    }}
    .perm-field-label {{ display: block; font-size: 12px; color: var(--text-2); margin-bottom: 6px; font-weight: 600; }}
    .perm-input {{ width: 100%; height: 34px; min-height: 34px; padding: 6px 10px; font-size: 13px; border-radius: var(--radius-sm); border: 1px solid var(--line); background: var(--surface); color: var(--text); }}
    .perm-scope-bar {{
      display: flex; flex-direction: column; gap: 2px; flex: 1 1 260px; min-width: 0;
      font-size: 12px; color: var(--text-2);
    }}
    .perm-scope-bar .muted {{ font-size: 11.5px; }}
    /* 부여 목록 아래 쪽 이동 줄: 이벤트 탭의 쪽 이동(.event-pager)을 그대로 쓰고 총 건수만 왼쪽에 둔다. */
    .perm-grant-pager {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px 16px; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--line-soft); font-size: 12px; }}
    .tbl-perm-grants {{ table-layout: fixed; width: 100%; }}
    .tbl-perm-grants th:nth-child(1), .tbl-perm-grants td:nth-child(1) {{ width: 96px; overflow: hidden; }}
    .tbl-perm-grants th:nth-child(3), .tbl-perm-grants td:nth-child(3) {{ width: 218px; text-align: right; }}
    /* 두 표 모두 조치 칸(사유 입력 + 버튼)이 넓어야 한 행이 2줄로 끝난다. 그래서 1700px 이상에서만 나란히 놓고(왼쪽이 담을 것이 많아 조금 더 넓게),
       그보다 좁으면 위아래로 쌓아 각 표가 가로 전체를 쓰게 한다. */
    .grid-2col-half.perm-split {{ grid-template-columns: minmax(0, 1fr); }}
    @media (min-width: 1700px) {{ .grid-2col-half.perm-split {{ grid-template-columns: minmax(0, 1.15fr) minmax(0, 1fr); }} }}
    .tbl-perm-grants td:nth-child(2) {{ overflow: hidden; }}
    .tbl-retire {{ table-layout: fixed; width: 100%; }}
    .tbl-retire th:nth-child(1), .tbl-retire td:nth-child(1) {{ width: 114px; overflow: hidden; }}
    .tbl-retire th:nth-child(3), .tbl-retire td:nth-child(3) {{ width: 244px; text-align: right; }}
    .tbl-retire td:nth-child(2) {{ overflow: hidden; }}
    .tbl-retire .badge {{ min-width: 88px; justify-content: center; }}
    /* 권한 부여 화면의 두 표: 한 행이 2줄(주 정보 + 보조 정보)로 끝나도록 글자와 여백만 줄인다. 보여 주는 정보는 그대로다. */
    .tbl-perm-grants th, .tbl-retire th {{ padding: 8px 10px; }}
    .tbl-perm-grants td, .tbl-retire td {{ padding: 7px 10px; line-height: 1.3; }}
    .tbl-perm-grants .cell-title {{ font-size: 13px; }}
    .tbl-perm-grants .badge, .tbl-retire .badge {{ padding: 1px 8px 1px 7px; font-size: 11px; line-height: 18px; }}
    .tbl-perm-grants td .cell-sub, .tbl-retire td .cell-sub {{ margin-top: 3px; font-size: 11px; line-height: 15px; }}
    /* 사유 입력칸의 기본 문구가 잘려 보이지 않도록 문구 길이에 맞춰 넓힌다. */
    .tbl-perm-grants .action-reason-input, .tbl-retire .action-reason-input {{ width: 136px; height: 28px; min-height: 28px; padding: 2px 7px; font-size: 11.5px; }}
    .tbl-perm-grants .action-btn-sm, .tbl-retire .action-btn-sm {{ height: 28px; min-height: 28px; padding: 2px 9px; font-size: 11.5px; }}
    .action-inline-form {{ display: inline-flex; align-items: center; justify-content: flex-end; gap: 6px; flex-wrap: nowrap; max-width: 100%; }}
    .action-reason-input {{ width: 106px; height: 32px; min-height: 32px; padding: 4px 7px; font-size: 12px; border-radius: var(--radius-sm); }}
    .action-btn-sm {{ height: 32px; min-height: 32px; padding: 4px 9px; font-size: 12px; white-space: nowrap; justify-content: center; }}
    /* 권한 격자: 행 = 계정, 열 = 문서. 칸에는 기호만 둔다. 문서의 부서는 열 묶음 제목에 한 번, 기밀 여부는 문서 제목 아래에 한 번만 적는다.
       크기는 이 화면의 다른 표와 같은 규칙(여백 6~8px, 보조 글자 11px)을 쓰고, 계정 칸은 가로로 넘겨 볼 때도 왼쪽에 고정한다. */
    .pm-legend {{ display: flex; flex-wrap: wrap; align-items: center; gap: 6px 16px; margin: 0 0 10px; font-size: 11.5px; color: var(--text-3); }}
    .pm-legend > span {{ display: inline-flex; align-items: center; gap: 6px; }}
    .pm-scroll {{ overflow-x: auto; }}
    .tbl-perm-grid {{ width: 100%; }}
    .tbl-perm-grid th, .tbl-perm-grid td {{ padding: 6px 8px; text-align: center; vertical-align: middle; }}
    .tbl-perm-grid .pm-acct-h, .tbl-perm-grid .pm-acct {{ position: sticky; left: 0; z-index: 1; width: 196px; min-width: 176px; text-align: left; background: var(--surface); }}
    .tbl-perm-grid thead .pm-acct-h {{ vertical-align: bottom; }}
    .tbl-perm-grid .pm-group {{ padding-bottom: 4px; font-size: 11.5px; font-weight: 600; color: var(--text-2); border-bottom: 1px solid var(--line-soft); }}
    /* 기밀 표시가 있어도 모든 문서 제목은 같은 높이에서 시작한다. */
    .tbl-perm-grid .pm-doc {{ min-width: 64px; vertical-align: top; white-space: normal; word-break: keep-all; font-size: 11.5px; font-weight: 500; line-height: 1.3; color: var(--text-2); }}
    .tbl-perm-grid .pm-gs {{ border-left: 1px solid var(--line); }}
    .pm-secret {{ display: block; margin-top: 2px; font-size: 10.5px; font-weight: 600; color: var(--warn); }}
    .pm-sub {{ margin-top: 2px; font-size: 11px; line-height: 15px; }}
    .pm-status {{ color: var(--text-3); white-space: nowrap; }}
    .pm-status.is-ok {{ color: var(--ok); font-weight: 500; }}
    .pm-status.is-bad {{ color: var(--sev-high); font-weight: 500; }}
    .pm-mark {{ display: inline-flex; align-items: center; justify-content: center; min-width: 18px; font-size: 11px; line-height: 18px; cursor: default; }}
    .pm-default {{ color: var(--text-2); }}
    .pm-none {{ color: var(--text-3); opacity: 0.6; font-size: 13px; }}
    .pm-blocked {{ color: var(--danger); }}
    .pm-special {{ padding: 0 6px; border-radius: var(--radius-sm); background: rgb(var(--ok-rgb) / 0.16); color: var(--ok); font-weight: 600; white-space: nowrap; }}
    /* 권한 현황 요약 보기(계정 기준 / 문서 기준): 한 줄 = 계정 하나(문서 하나). 위 두 표와 같은 압축 규칙(여백 6~8px, 보조 글자 11~11.5px)을 쓴다. */
    .perm-views {{ display: inline-flex; gap: 4px; margin: 0 0 12px; padding: 3px; background: var(--sunken); border: 1px solid var(--line-soft); border-radius: var(--radius-sm); }}
    .perm-views a {{ padding: 5px 14px; font-size: 12.5px; color: var(--text-2); border-radius: 6px; text-decoration: none; }}
    .perm-views a:hover {{ color: var(--text); }}
    .perm-views a[aria-current="page"] {{ background: var(--raised); color: var(--text); font-weight: 600; }}
    .perm-chip-sep {{ width: 1px; align-self: stretch; margin: 2px 4px; background: var(--line); }}
    #perm-status {{ overflow-anchor: none; }}
    .tbl-perm-acct, .tbl-perm-doc {{ width: 100%; }}
    .tbl-perm-acct th, .tbl-perm-doc th {{ padding: 8px 10px; }}
    .tbl-perm-acct td, .tbl-perm-doc td {{ padding: 6px 10px; height: 40px; line-height: 1.3; }}
    .tbl-perm-acct .badge, .tbl-perm-doc .badge {{ padding: 1px 8px 1px 7px; font-size: 11px; line-height: 18px; }}
    .tbl-perm-acct .perm-act, .tbl-perm-doc .perm-act {{ width: 88px; text-align: right; }}
    .perm-n {{ font-variant-numeric: tabular-nums; }}
    .perm-ok {{ color: var(--ok); font-weight: 600; }}
    .perm-warn {{ margin-left: 8px; font-size: 11.5px; font-weight: 600; color: var(--warn); }}
    .perm-soon {{ color: var(--warn); font-weight: 500; }}
    tr.perm-sel > td {{ background: rgb(var(--accent-rgb) / 0.08); }}
    #perm-selection {{ scroll-margin-top: 16px; }}
    .perm-hint {{ margin-top: 10px; font-size: 11.5px; color: var(--text-3); }}
    .perm-detail-row > td {{ height: auto; padding: 0 0 8px; }}
    .perm-detail {{ padding: 10px 12px; border: 1px solid var(--line-soft); border-radius: var(--radius); background: var(--sunken); overflow-wrap: anywhere; }}
    .perm-detail-cols {{ display: grid; grid-template-columns: minmax(0, var(--split-main)) repeat(2, minmax(0, 1fr)); gap: 16px; }}
    @media (max-width: 1120px) {{ .perm-detail-cols {{ grid-template-columns: 1fr; gap: 12px; }} }}
    .pd-title {{ margin-bottom: 4px; font-size: 12px; font-weight: 600; color: var(--text-2); }}
    .pd-n {{ margin-left: 4px; font-size: 11.5px; font-weight: 500; color: var(--text-3); font-variant-numeric: tabular-nums; }}
    .pd-n-ok {{ color: var(--ok); }}
    .pd-line {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 6px 12px; padding: 5px 0; border-top: 1px solid var(--line-soft); }}
    .pd-info {{ min-width: 0; }}
    .pd-main {{ font-size: 13px; color: var(--text); }}
    .pd-sub, .pd-meta {{ font-size: 11.5px; color: var(--text-3); font-weight: 400; }}
    .pd-sub {{ margin-top: 2px; }}
    .pd-plain {{ padding: 3px 0; border-top: 1px solid var(--line-soft); font-size: 12.5px; color: var(--text); }}
    .pd-empty {{ padding: 3px 0; border-top: 1px solid var(--line-soft); font-size: 12px; color: var(--text-3); }}
    .perm-detail .action-reason-input {{ width: 150px; height: 28px; min-height: 28px; font-size: 11.5px; }}
    .perm-detail .action-btn-sm {{ height: 28px; min-height: 28px; font-size: 11.5px; }}
    button.filter-chip {{ display: inline-flex; align-items: center; gap: 6px; border-radius: var(--radius-sm); padding: 5px 11px; min-height: 30px; font-size: 12.5px; }}
    .chip-dot {{ width: 7px; height: 7px; border-radius: 50%; display: inline-block; flex-shrink: 0; }}
    .chip-cnt {{ font-size: 11.5px; color: var(--text-3); font-variant-numeric: tabular-nums; margin-left: 1px; }}
    button.filter-chip.active .chip-cnt {{ color: var(--text); font-weight: 600; }}
    .stream-foot-note {{
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;
      margin-top: 14px; padding: 9px 12px; border-radius: var(--radius-sm);
      background: var(--sunken); border: 1px solid var(--line-soft);
      font-size: 12px; color: var(--text-3);
    }}
    .rbar-ok {{ background: var(--ok); }}
    .rbar-top .d.ok {{ background: var(--ok); }}
    .pq-dot.is-closed {{ background: var(--text-3); }}
    .hitem.ok .hdot {{ background: var(--ok); }} .hitem.ok .hstate {{ color: var(--text-2); }}
    b, strong {{ font-weight: 600; }}
    .ingest-flag {{ display: inline-block; margin-left: 6px; padding: 0 6px; border-radius: 4px; font-size: 12px; font-weight: 600; line-height: 18px; color: var(--warn); background: rgb(var(--warn-rgb) / 0.14); }}
    .log-tbl th {{ padding: 9px 12px; }}
    .log-tbl td {{ padding: 8px 12px; line-height: 1.4; }}
    .log-tbl td:nth-child(-n+3) {{ white-space: nowrap; }}
    .log-tbl td .cell-sub {{ display: block; margin: 2px 0 0; font-size: 12px; line-height: 1.3; color: var(--text-3); font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; }}
    .log-tbl .badge {{ padding: 1px 8px; font-size: 12px; }}
    .log-tbl tbody tr:nth-child(even) {{ background: rgb(var(--text-rgb) / 0.02); }}
    .tbl-control {{ table-layout: fixed; width: 100%; }}
    .tbl-control th:nth-child(1), .tbl-control td:nth-child(1) {{ width: 118px; overflow: hidden; }}
    .tbl-control th:nth-child(3), .tbl-control td:nth-child(3) {{ width: 234px; text-align: right; }}
    .tbl-control td:nth-child(2) {{ overflow: hidden; }}
    .tbl-control th {{ padding: 8px 10px; font-size: 12px; font-weight: 600; color: var(--text-3); }}
    .tbl-control tbody td {{ height: 66px; padding: 10px; line-height: 1.35; vertical-align: middle; }}
    .tbl-control tbody td:first-child .badge {{ height: 22px; line-height: 16px; }}
    .tbl-control .ctrl-primary {{ display: flex; align-items: baseline; gap: 6px; height: 22px; line-height: 22px; white-space: nowrap; overflow: hidden; }}
    .tbl-control td .cell-sub {{ font-size: 11px !important; line-height: 15px; height: 15px; margin-top: 4px; font-weight: 400; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
    .tbl-control td .cell-sub .muted {{ font-size: 11px !important; }}
    .tbl-control td:nth-child(3) .action-reason-input {{ height: 30px; min-height: 30px; padding: 3px 7px; font-size: 12px; }}
    .tbl-control td:nth-child(3) .action-btn-sm,
    .tbl-control td:nth-child(3) button,
    .tbl-control td:nth-child(3) a.btn-ghost {{ height: 30px; min-height: 30px; padding: 4px 10px; font-size: 12px; line-height: 1; }}
    .tbl-control td:nth-child(3) input[type="number"] {{ height: 30px; min-height: 30px; padding: 4px 6px; font-size: 13px; font-variant-numeric: tabular-nums; text-align: center; }}
    .ip-control-panel {{ container-type: inline-size; }}
    .ip-control-panel .tbl-control :is(th,td):nth-child(3) {{ width: 254px; }}
    .ip-action-fields {{ display: inline-grid; grid-template-columns: minmax(0, 1fr) 88px; align-items: center; gap: 8px; width: 234px; max-width: 100%; }}
    .ip-action-fields .action-reason-input {{ width: 100%; min-width: 0; }}
    @supports (field-sizing: content) {{
      .ip-action-fields .action-reason-input {{
        field-sizing: content; justify-self: end; width: auto; min-width: 3em; max-width: 100%;
      }}
    }}
    .ip-block-period {{ display: inline-flex; align-items: center; justify-self: end; }}
    .ip-block-period input[name="block_duration"] {{ width: 70px; border-radius: var(--radius-sm) 0 0 var(--radius-sm); }}
    .ip-block-period select {{ height: 30px; min-height: 30px; margin-left: -1px; padding: 2px 5px; border-radius: 0 var(--radius-sm) var(--radius-sm) 0; font-size: 12px; }}
    .ip-block-period :focus {{ position: relative; z-index: 1; }}
    @container (max-width: 540px) {{
      .ip-control-panel .tbl-control tr {{ display: grid; grid-template-columns: 118px minmax(0, 1fr); }}
      .ip-control-panel .tbl-control :is(th,td):nth-child(n) {{ width: auto; height: auto; }}
      .ip-control-panel .tbl-control th:nth-child(3) {{ position: absolute; clip-path: inset(100%); }}
      .ip-control-panel .tbl-control td:nth-child(3) {{ grid-column: 1 / -1; padding-top: 0; }}
      .ip-control-panel .tbl-control tbody td:not(:last-child) {{ border-bottom: 0; }}
    }}
    .tbl-incidents-queue th {{ padding: 9px 12px; font-size: 12px; font-weight: 600; color: var(--text-3); }}
    .tbl-incidents-queue td {{ padding: 8px 12px !important; line-height: 1.4 !important; }}
    .tbl-incidents-queue .badge {{ padding: 1px 8px; font-size: 12px; }}
    .tbl-incidents-queue .cell-title {{ font-size: 13px !important; font-weight: 500 !important; line-height: 1.4; }}
    .tbl-incidents-queue td:nth-child(4) {{ font-size: 13px; font-weight: 500; color: var(--text); line-height: 1.4; }}
    .tbl-incidents-queue td:nth-child(4) > code.ip {{ font-size: 12.5px !important; font-weight: 500 !important; }}
    .tbl-incidents-queue td .cell-sub {{ margin: 2px 0 0 !important; font-size: 12px !important; font-weight: 400 !important; line-height: 1.3 !important; color: var(--text-3); }}
    .tbl-incidents-queue td:nth-child(4) .cell-sub *, .tbl-incidents-queue td:nth-child(4) .cell-sub code {{ font-size: 12px !important; font-weight: 400 !important; }}
    .duration-presets {{ display: inline-flex; align-items: center; gap: 4px; flex-wrap: wrap; }}
    button.dur-preset-btn {{
      background: transparent; color: var(--text-2);
      border: 1px solid var(--line); border-radius: var(--radius-sm);
      padding: 3px 8px; min-height: 26px; font-size: 12px; font-weight: 500;
    }}
    @media (hover: hover) {{ button.dur-preset-btn:hover:not(:disabled) {{ background: rgb(var(--accent-rgb) / 0.14); color: var(--text); border-color: rgb(var(--accent-rgb) / 0.45); filter: none; }} }}
    button.dur-preset-btn.is-active {{ background: rgb(var(--accent-rgb) / 0.16); color: var(--accent); border-color: rgb(var(--accent-rgb) / 0.5); font-weight: 600; }}
    .panel-actions {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .panel:has(> table.log-tbl) {{ overflow-x: auto; }}
    .log-tbl td:nth-child(4) {{ white-space: normal; overflow-wrap: break-word; }}
    .log-tbl td:nth-child(4) code, .log-tbl td:nth-child(4) .flow, .log-tbl td:nth-child(4) .ev-chip {{ white-space: nowrap; word-break: keep-all; overflow-wrap: normal; }}
    .log-tbl td:nth-child(4) {{ min-width: 0; width: 100%; }}
    .run-badge {{ display: inline-block; margin-left: 8px; padding: 0 7px; border-radius: 999px; font-size: 12px; font-weight: 600; line-height: 18px; background: rgb(var(--warn-rgb) / 0.16); color: var(--warn); }}
    .foot {{ margin-top: 36px; padding-top: 16px; border-top: 1px solid var(--line-soft); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px 20px; font-size: 12px; color: var(--text-3); }}
    .foot a {{ color: var(--text-2); }}
    body.bare .foot {{ display: none; }}
    @media (prefers-reduced-motion: reduce) {{
      *, *::before, *::after {{ animation: none !important; transition: none !important; }}
    }}

    /* ===== 관제 업무 테마 (2026-11-24) =====
       구조는 통합보안관제 그대로, 색은 역할별로 나눠 계산으로 검증한 값만 쓴다.
       - 출처(범주색): ERP 파랑 · Gateway 청록 · Caddy 연보라. 빨강·주황·노랑은 상태 전용이라 출처에 쓰지 않는다.
         dataviz 검증(전 쌍): 다크 색각 이상 ΔE 12.4 · 정상 18.2, 라이트 색각 이상 16.0 · 정상 21.2. 그래프·도넛·카드·표가 같은 변수를 쓴다.
       - 상태색(고정): 정상 · 주의 · 심각 · 위험. 출처 색과 다른 단계이며 항상 글자·아이콘과 함께 쓴다.
       - 심각도(순서): 위험 > 심각 > 주의 > 낮음·정보(회색). 색이 많아지지 않게 낮은 단계는 무채색.
       - 강조: 무채색. 화면의 색은 데이터와 상태에만 쓴다.
       - 글자는 상태색이 아닌 글자색을 쓰고, 상태 글자색은 배경 대비 4.5:1 이상(다크 위험 5.4 · 정상 5.2). */
    :root {{
      --bg: #22262c; --sunken: #1c2025; --surface: #2b3037; --raised: #333943;
      --line: #4b5460; --line-soft: #3a414a;
      --text: #d8dee8; --text-2: #b3bcc9; --text-3: #98a3b2;
      --accent: #f0efec; --on-accent: #1c2025;
      --brand-mark: #bfd48e;
      --ok: #48ba48; --danger: #eb8888; --warn: #fab219;
      --source-erp: #70a8ec; --source-caddy: #b9a7f2; --source-gateway: #52b694;
      --source-waf: #dda9d0;
      --text-rgb: 216 222 232; --sunken-rgb: 28 32 37; --surface-rgb: 43 48 55;
      --accent-rgb: 240 239 236; --ok-rgb: 72 186 72; --danger-rgb: 235 136 136; --warn-rgb: 250 178 25;
      --side-bg: #1b1f24; --side-line: #3a414a;
      --shadow: none; --overlay: rgb(8 8 8 / 0.65);
      --radius: 6px; --radius-sm: 4px;
      --sev-critical: #ff3b3b; --sev-high: #ff5252; --sev-medium: #fab219; --sev-low: #a6a5a0; --sev-info: #a6a5a0;
    }}
    :root[data-theme="light"] {{
      --bg: #f4f4f2; --sunken: #efefec; --surface: #fcfcfb; --raised: #f6f6f4;
      --line: #e1e0d9; --line-soft: #ebeae5;
      --text: #0b0b0b; --text-2: #52514e; --text-3: #6b6a65;
      --accent: #0b0b0b; --on-accent: #fcfcfb; --brand-mark: #587a2a;
      --ok: #006300; --danger: #c42b2b; --warn: #8a5a00;
      --source-erp: #256abf; --source-caddy: #a993ec; --source-gateway: #1a9e6e;
      --source-waf: #96396e;
      --text-rgb: 11 11 11; --accent-rgb: 11 11 11; --ok-rgb: 0 99 0; --danger-rgb: 196 43 43; --warn-rgb: 138 90 0;
      --side-bg: #fcfcfb; --side-line: #e1e0d9;
      --shadow: none;
      --sev-critical: #b91c1c; --sev-high: #dc2626; --sev-medium: #946200; --sev-low: #6b6a65; --sev-info: #6b6a65;
      --source-caddy: #6a4fc2; --source-gateway: #0d7a55;
    }}
    /* 알약 모양 대신 각진 꼬리표 */
    .badge, a.range-chip, .run-badge, .request-status, .pop-badge {{ border-radius: 4px !important; }}
    .nav-link {{ border-radius: 4px; min-height: 34px; }}
    .nav-link.active {{ background: rgb(var(--text-rgb) / 0.08); box-shadow: inset 2px 0 0 var(--text); color: var(--text); }}
    /* 밀도: 업무 화면답게 여백을 줄이고 숫자는 또렷하게 */
    .page-head {{ margin: 0 0 16px; }}
    .page-head h1 {{ font-size: 20px; font-weight: 600; letter-spacing: -0.02em; }}
    .eyebrow {{ font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; }}
    .panel {{ padding: 16px 18px; margin-bottom: 16px; }}
    .panel h2 {{ font-size: 14px; }}
    .panel-header {{ margin-bottom: 12px; }}
    .metrics {{ margin-bottom: 16px; }}
    .metric {{ padding: 14px 18px; }}
    .metric-label {{ font-size: 12px; color: var(--text-3); }}
    .metric-val {{ font-size: 28px; }}
    .metrics {{ grid-template-columns: repeat(4, minmax(0, 1fr)); }}
    .metric:focus-visible {{ outline: 2px solid var(--accent); outline-offset: -3px; }}
    .metric.is-primary {{ background: rgb(var(--danger-rgb) / 0.045); }}
    .metric.is-primary .metric-label {{ color: var(--text-2); font-weight: 600; }}
    @media (max-width: 1120px) {{ .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} .metric:nth-child(odd) {{ border-left: none; }} .metric:nth-child(n+3) {{ border-top: 1px solid var(--line); }} }}
    @media (max-width: 520px) {{ .metrics {{ grid-template-columns: 1fr; }} .metric {{ border-left: none; border-top: 1px solid var(--line); }} .metric:first-child {{ border-top: none; }} }}
    .grid-2col-eq, .pq-split, .grid-2col {{ gap: 16px; margin-bottom: 16px; }}
    @media (min-width: 1121px) {{ .grid-2col-eq, .grid-2col {{ grid-template-columns: minmax(0, var(--split-main)) minmax(0, 1fr); }} }}
    .grid-2col-half {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; margin-bottom: 20px; align-items: stretch; }}
    @media (max-width: 1120px) {{ .grid-2col-half {{ grid-template-columns: 1fr; }} }}
    .overview-login-grid {{ display: grid; grid-template-columns: minmax(0, var(--split-main)) minmax(0, 1fr); gap: 16px; margin-bottom: 16px; align-items: stretch; }}
    .overview-login-grid > .panel {{ min-width: 0; margin-bottom: 0; }}
    #login-failure-ranking .topn-grid {{ gap: 12px; }}
    #login-failure-ranking .topn-row {{ grid-template-columns: minmax(0, 1.8fr) minmax(30px, 0.65fr) auto; gap: 6px; }}
    #login-failure-ranking .topn-row a {{ display: block; min-width: 0; overflow: hidden; text-overflow: ellipsis; }}
    @media (max-width: 1120px) {{ .overview-login-grid {{ grid-template-columns: 1fr; }} }}
    @media (max-width: 600px) {{ #login-failures .lf-wrap {{ overflow-x: auto; }} #login-failures .lf-svg {{ min-width: 560px; }} }}
    th {{ font-size: 13px; letter-spacing: 0.02em; background: rgb(var(--text-rgb) / 0.025); }}
    .tbl-incidents td {{ padding-top: 10px; padding-bottom: 10px; }}
    .pq-split .tbl-incidents td {{ padding-top: 7px; padding-bottom: 7px; line-height: 1.35; }}
    .pq-split .tbl-incidents .cell-title, .pq-split .pq-row b {{ font-size: 14px; font-weight: 600; font-style: normal; letter-spacing: -0.065px; line-height: 21px; }}
    .pq-split .tbl-incidents .cell-sub, .pq-split .tbl-incidents td:last-child {{ margin-top: 2px; font-size: 12px; font-weight: 400; }}
    .pq-split .tbl-incidents td:last-child .rel {{ font-size: 12px; }}
    .pq-split .tbl-incidents tr[data-overview-incident] {{ cursor: pointer; }}
    .pq-split .tbl-incidents tr[data-overview-incident]:focus-visible {{ outline: 2px solid var(--accent); outline-offset: -2px; }}
    .pq-split .pq-item {{ padding-top: 7px; padding-bottom: 7px; }}
    .overview-pop-table th {{ padding: 7px 10px; }}
    .overview-pop-table td {{ padding: 6px 10px; line-height: 1.35; }}
    .overview-pop-table .cell-sub {{ margin-top: 2px; line-height: 1.3; }}
    .overview-history td {{ padding: 7px 10px; line-height: 1.35; }}
    .overview-history .cell-sub {{ margin-top: 1px; }}
    #active-blocks-overview td {{ padding: 6px 8px; line-height: 1.3; }}
    #active-blocks-overview .cell-sub {{ margin-top: 1px; line-height: 1.25; }}
    #active-blocks-overview button.btn-emerald {{ padding: 5px 9px; }}
    /* 심각도: 색 + 동그라미 + 글자 (색만으로 구분하지 않음) */
    .sev {{ display: inline-flex; align-items: center; gap: 6px; font-weight: 600; font-size: 12px; color: var(--text-2); white-space: nowrap; }}
    .sev::before {{ content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--sev-c, var(--sev-info)); }}
    .sev-critical {{ --sev-c: var(--sev-critical); color: var(--sev-critical); font-weight: 700; }}
    .sev-high {{ --sev-c: var(--sev-high); color: var(--sev-high); font-weight: 700; }}
    .sev-medium {{ --sev-c: var(--sev-medium); }} .sev-low {{ --sev-c: var(--sev-low); }} .sev-info {{ --sev-c: var(--sev-info); }}
    tr.sev-row > td:first-child {{ box-shadow: inset 3px 0 0 var(--sev-c, transparent); }}
    /* 해결된 사건(차단 해제됨): 바만 초록. 심각도 글자("높음")는 .sev 쪽 변수를 쓰므로 그대로 둔다. */
    tr.sev-row.sev-resolved {{ --sev-c: var(--ok); }}
  </style>
  <script>
  function toggleTheme() {{
    var next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    try {{ localStorage.setItem("soc-theme", next); }} catch (e) {{}}
  }}
  function beginPracticeReset(event, form) {{
    event.preventDefault();
    var typed = prompt("관제 로그·사건·승인 이력을 백업 없이 초기화하고 ERP 계정 잠금·로그인 실패 횟수를 리셋합니다. 원본 로그 파일과 ERP 계정은 유지됩니다. 계속하려면 '초기화'를 입력하세요.");
    if (typed === null || typed.trim() !== "초기화") return false;
    var button = form.querySelector("button");
    var status = form.querySelector(".practice-reset-status");
    button.disabled = true;
    button.textContent = "초기화 중…";
    status.textContent = "관제 기록과 ERP 로그인 상태를 초기화하고 있습니다.";
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
    var activePermFilter = "all";
    var searchTermSoc = "";
    var autoRefreshMs = {refresh_ms};
    var autoRefreshLabel = "{int(refresh_seconds) if refresh_seconds else 0}초 자동 동기화";
    function isAutoRefreshPaused() {{
      var sb = document.getElementById("socSearchBox");
      var modal = document.getElementById("holoModalBackdrop");
      var searching = sb && (document.activeElement === sb || (sb.value || "").trim().length > 0);
      var filteringIncidents = document.querySelector(".incident-filters:focus-within, main.content form:focus-within");
      var modalOpen = (modal && modal.classList.contains("open")) || document.querySelector(".request-card[open]");
      var scrolled = (window.scrollY || document.documentElement.scrollTop || 0) > 120;
      var manual = false;
      try {{ manual = sessionStorage.getItem("soc-refresh-paused") === "1"; }} catch (e) {{}}
      return Boolean(manual || searching || filteringIncidents || modalOpen || scrolled || window.__bkHover || window.__eventPeriodLoading || window.__permStatusLoading);
    }}
    window.addEventListener("scroll", function() {{ updateAutoRefreshState(); }}, {{ passive: true }});
    document.addEventListener("click", function(event) {{
      var row = event.target.closest("#holoModalBody tr[data-incident-row]");
      if (!row || event.target.closest("a, button, input, select, textarea, label")) return;
      row.querySelector("a[data-incident-detail]").click();
    }});
    document.addEventListener("click", function(event) {{
      var row = event.target.closest("tr[data-overview-incident]");
      if (row && !event.target.closest("a, button, input, select, textarea, label"))
        window.location.href = row.dataset.incidentHref;
    }});
    document.addEventListener("keydown", function(event) {{
      var row = event.target.closest("tr[data-overview-incident]");
      if (row && event.target === row && (event.key === "Enter" || event.key === " ")) {{
        event.preventDefault();
        window.location.href = row.dataset.incidentHref;
      }}
    }});
    document.addEventListener("submit", function(event) {{
      var form = event.target;
      if (!form.matches("form[action^='/incidents/'][action$='/approve']")) return;
      if (form.dataset.approvalSubmitting) {{
        event.preventDefault();
        return;
      }}
      form.dataset.approvalSubmitting = "true";
      if (event.submitter) event.submitter.setAttribute("aria-disabled", "true");
    }});
    window.addEventListener("pageshow", function() {{
      document.querySelectorAll("form[data-approval-submitting]").forEach(function(form) {{
        delete form.dataset.approvalSubmitting;
        form.querySelector("[aria-disabled='true']")?.removeAttribute("aria-disabled");
      }});
    }});
    // 하루(1,440분)를 넘는 IP 차단은 실수로 길게 넣었을 수 있으니 한 번 더 확인한다.
    function confirmLongBlock(form) {{
      var m = parseInt(form.duration_minutes.value, 10);
      if (!(m > 1440)) return true;
      var days = Math.round(m / 1440 * 10) / 10;
      return window.confirm("정말 " + days + "일(" + m.toLocaleString() + "분) 동안 이 단말을 차단할까요?\\n차단은 해제하기 전까지 접속이 막힙니다.");
    }}
    function toggleManualRefreshPause() {{
      try {{
        if (sessionStorage.getItem("soc-refresh-paused") === "1") sessionStorage.removeItem("soc-refresh-paused");
        else sessionStorage.setItem("soc-refresh-paused", "1");
      }} catch (e) {{}}
      updateAutoRefreshState();
    }}
    function updateAutoRefreshState() {{
      if (!autoRefreshMs) return;
      var pill = document.getElementById("socSyncPill");
      if (!pill) return;
      if (!pill.__bound) {{
        pill.__bound = true;
        pill.addEventListener("click", toggleManualRefreshPause);
        pill.addEventListener("keydown", function(e) {{ if (e.key === "Enter" || e.key === " ") {{ e.preventDefault(); toggleManualRefreshPause(); }} }});
      }}
      var manualPaused = false;
      try {{ manualPaused = sessionStorage.getItem("soc-refresh-paused") === "1"; }} catch (e) {{}}
      if (manualPaused) {{
        pill.innerHTML = '<span class="pulse-dot" style="background:var(--warn);"></span>자동 갱신 멈춤 · 눌러서 다시 시작';
        return;
      }}
      if (isAutoRefreshPaused()) {{
        pill.innerHTML = '<span class="pulse-dot" style="background:var(--warn);"></span>' + (window.__bkHover ? '차트 확인 중 · 일시정지' : ((window.scrollY || document.documentElement.scrollTop || 0) > 120 ? '아래로 내려서 일시정지' : '검색 중 · 일시정지'));
      }} else {{
        pill.innerHTML = '<span class="pulse-dot"></span>' + autoRefreshLabel;
      }}
    }}
    function applySocTableFilters(root = document) {{
      var rows = root.querySelectorAll("table tbody tr:not(.perm-detail-row), .request-card");
      var shown = 0;
      var total = 0;
      var permShown = 0;
      var permTotal = 0;
      for (var i = 0; i < rows.length; i++) {{
        var r = rows[i];
        var src = r.getAttribute("data-source");
        var permTags = r.getAttribute("data-perm-tags");
        if (src) total++;
        var okChip = true;
        if (permTags) {{
          permTotal++;
          okChip = activePermFilter === "all" || permTags.split(" ").includes(activePermFilter);
        }} else if (activeEventChip && activeEventChip !== "all" && src) {{
          if (activeEventChip === "anomaly") {{
            okChip = r.getAttribute("data-anomaly") === "1";
          }} else if (activeEventChip === "flow") {{
            okChip = !!r.getAttribute("data-flow");
          }} else {{
            okChip = src.split(" ").includes(activeEventChip);
          }}
        }}
        var txt = ((r.matches(".request-card") ? r.textContent : r.innerText) || "").toLowerCase();
        var okSearch = (!searchTermSoc || txt.indexOf(searchTermSoc) !== -1);
        var visible = okChip && okSearch;
        r.style.display = visible ? "" : "none";
        if (visible && src) shown++;
        if (visible && permTags) permShown++;
      }}
      syncPermDetailVisibility();
      var cntEl = root.querySelector("#eventsFilterCount");
      if (cntEl && total > 0) {{
        cntEl.innerText = "표시: " + shown + " / " + total + "건";
      }}
      var permCount = root.querySelector("#permMatrixFilterCount");
      if (permCount) permCount.innerText = "표시: " + permShown + " / " + permTotal + "개 계정";
    }}
    function toggleAllEventCards(btn) {{
      var cards = document.querySelectorAll(".request-card");
      var anyClosed = false;
      for (var i = 0; i < cards.length; i++) {{
        if (cards[i].style.display !== "none" && !cards[i].open) {{
          anyClosed = true;
          break;
        }}
      }}
      for (var j = 0; j < cards.length; j++) {{
        if (cards[j].style.display !== "none") {{
          cards[j].open = anyClosed;
        }}
      }}
      if (btn) {{
        btn.innerText = anyClosed ? "모두 접기" : "모두 펼치기";
        btn.setAttribute("aria-pressed", anyClosed ? "true" : "false");
      }}
      updateAutoRefreshState();
    }}
    function syncPermDetailVisibility() {{
      var selected = document.getElementById("perm-selection");
      if (selected) selected.nextElementSibling.hidden = selected.style.display === "none";
    }}
    function setPermMatrixFilter(mode) {{
      var panel = document.getElementById("perm-status");
      if (!panel) return;
      activePermFilter = mode || "all";
      panel.querySelectorAll("button[data-perm-filter]").forEach(function(button) {{
        button.classList.toggle("active", button.getAttribute("data-perm-filter") === activePermFilter);
      }});
      applySocTableFilters(panel);
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
      var btns = document.querySelectorAll("button.filter-chip[data-filter]");
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
      if (document.querySelector(".filter-chip-bar button[data-filter]")) {{
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
    let holoReturnFocus = null;
    function openHoloModal(title, badgeText, bodyHtml) {{
      var bd = document.getElementById("holoModalBackdrop");
      if (!bd) return;
      if (!bd.classList.contains("open")) holoReturnFocus = document.activeElement;
      document.getElementById("holoModalTitle").innerText = title || "상세 정보";
      document.getElementById("holoModalBadge").innerText = badgeText || "상세";
      document.getElementById("holoModalBody").innerHTML = bodyHtml || "";
      bd.classList.add("open");
      bd.querySelector(".pop-close").focus();
    }}
    function openHoloTemplate(tplId, title, badgeText) {{
      var tpl = document.getElementById(tplId);
      if (!tpl) return;
      openHoloModal(title, badgeText, tpl.innerHTML);
    }}
    function closeHoloModal() {{
      var bd = document.getElementById("holoModalBackdrop");
      if (!bd || !bd.classList.contains("open")) return;
      bd.classList.remove("open");
      if (holoReturnFocus?.isConnected) holoReturnFocus.focus();
      holoReturnFocus = null;
    }}
    window.addEventListener("keydown", function(e) {{
      if (e.key === "Escape") closeHoloModal();
      var bd = document.getElementById("holoModalBackdrop");
      if (e.key !== "Tab" || !bd?.classList.contains("open")) return;
      var items = [...bd.querySelectorAll('button, a[href], input, select, textarea, summary, [tabindex]')]
        .filter(el => el.tabIndex >= 0 && !el.disabled && el.getClientRects().length);
      var first = items[0], last = items[items.length - 1];
      if (!bd.contains(document.activeElement) ||
          (e.shiftKey ? document.activeElement === first : document.activeElement === last)) {{
        e.preventDefault();
        (e.shiftKey ? last : first)?.focus();
      }}
    }});
    function openShieldBriefing() {{
      openHoloModal(
        "3계층 방어 구조",
        "SIEM · SOAR",
        "<div class='pop-stats three'>" +
        "<div class='pop-stat'><div class='k'><i class='d source-gateway'></i>1. Gateway · 방화벽</div>" +
        "<div class='note'>직접 우회 접근(<code>POLICY-CLIENT-CADDY-ONLY</code>)을 차단하고, 승인된 사건에는 <code>APR-*</code> DROP 규칙을 집행합니다.</div></div>" +
        "<div class='pop-stat'><div class='k'><i class='d source-caddy'></i>2. Caddy · TLS 프록시</div>" +
        "<div class='note'>HTTPS를 종단하고 고유 <code>request_id</code>를 부여해 ERP 인증 이벤트와 웹 요청을 1:1로 상관 분석합니다.</div></div>" +
        "<div class='pop-stat'><div class='k'><i class='d source-erp'></i>3. ERP · 탐지 엔진</div>" +
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
      <div class="side-top">
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
          <div class="login-logo">{_svg_icon("shield", "var(--brand-mark)", 22)}</div>
          <div>
            <h1>Sentinel</h1>
            <div class="sub">SIEM · SOAR 보안관제</div>
          </div>
        </div>
        {err_html}
        <form method="post" action="/login">
          <label class="field"><span>담당자 아이디</span>
            <input type="text" name="username" required autocomplete="username" autofocus placeholder="아이디" /></label>
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
            f'<span style="color:var(--text);font-weight:500;">{kst_str}</span> '
            f'<span style="color:var(--text-2);font-size:12px;">KST{utc_part}</span>'
            f"</span>"
        )
    except Exception:
        return f"<code>{html.escape(raw)}</code>"


def _fmt_status(status: str, eligible: bool | None = None) -> str:
    # 차단 승인이 불가능한 조사용 사건에는 '승인 필요'를 쓰지 않는다(없는 버튼을 찾게 만든다).
    labels = {
        "open": ("b-open", "alert", "var(--warn)" if eligible is False else "var(--danger)",
                 "확인 필요 · 조사용 (open)" if eligible is False else "확인·승인 필요 (open)"),
        "blocked": ("b-blocked", "stop", "var(--danger)", "차단 적용 중 (blocked)"),
        "applied": ("b-applied", "shield_off", "var(--danger)", "방화벽 차단 중 (applied)"),
        "released": ("b-released", "check", "var(--ok)", "차단 해제됨 (released)"),
        "approved": ("b-approved", "check", "var(--accent)", "승인됨 (approved)"),
        "expired": ("b-expired", "warn", "var(--ok)", "만료됨 (expired)"),
        "pending": ("b-warn", "warn", "var(--warn)", "승인 대기 (pending)"),
        "unknown": ("b-warn", "warn", "var(--warn)", "결과 미확인 (unknown)"),
        "rejected": ("b-blocked", "stop", "var(--danger)", "거부됨 (rejected)"),
        "closed": ("b-closed", "check", "var(--text-3)", "종료 (closed)"),
    }
    entry = labels.get(status)
    if entry is None:
        return f'<span class="badge b-{html.escape(status)}">{html.escape(status)}</span>'
    cls, icon, col, text = entry
    text = re.sub(r"\s*\([^)]*\)\s*$", "", text)
    return f'<span class="badge {cls}" title="{html.escape(status)}">{_svg_icon(icon, col, 12)} {text}</span>'


def _fmt_event_type(ev_type: str, outcome: str | None = None, *, show_code: bool = True) -> str:
    """이벤트 종류: 한글 라벨이 주, 로그 코드는 아래 보조줄(검색과 감사에 쓰이므로 남긴다)."""
    labels = {
        "login_success": ("로그인 성공", "good"),
        "login_failed": ("로그인 실패", "bad"),
        "login_source_denied": ("비인가 IP 로그인 거부", "bad"),
        "login_blocked": ("잠긴 계정 로그인 거부", "bad"),
        "account_locked": ("ERP 계정 잠금", "bad"),
        "account_unlocked": ("ERP 계정 잠금 해제", "good"),
        "doc_access_requested": ("자료실 문서 열람 요청", "info"),
        "doc_access_approved": ("자료실 문서 열람 승인", "good"),
        "doc_access_rejected": ("자료실 문서 열람 반려", "bad"),
        "doc_permission_granted": ("자료실 문서 특별 권한 부여", "good"),
        "doc_permission_revoked": ("자료실 문서 특별 권한 회수", ""),
        "account_permissions_revoked": ("퇴사 · 계정 전체 권한 회수", "bad"),
        "account_permissions_restored": ("계정 권한 복구 (재직 전환)", "good"),
        "logout": ("로그아웃", ""),
        "fw_allow": ("통과 · 허용", "good"),
        "fw_deny": ("방화벽 차단", "bad"),
        "waf_detected": ("WAF 탐지", "warn"),
        "waf_blocked": ("WAF 차단", "bad"),
    }
    if ev_type == "http_request":
        label, tone = "웹 요청", ("bad" if outcome == "failure" else "good" if outcome == "success" else "")
    elif ev_type == "document_read":
        label, tone = ("문서 열람 거부", "bad") if outcome == "failure" else ("문서 열람", "good")
    elif ev_type in labels:
        label, tone = labels[ev_type]
    else:
        label, tone = html.escape(ev_type), ""
    code = f'<div class="cell-sub">{html.escape(ev_type)}</div>' if show_code else ""
    return f'<span class="ev-act {tone}">{label}</span>{code}'


def _fmt_log_time(ts_val: Any) -> str:
    """로그 표 전용 시각: 'MM-DD HH:MM:SS'(KST)만 보여 주고, 연도·UTC 원본은 마우스를 올리면 보인다."""
    dt = _parse_utc(ts_val)
    if dt is None:
        return '<span class="lt muted">-</span>'
    kst = dt.astimezone(timezone(timedelta(hours=9)))
    full = kst.strftime("%Y-%m-%d %H:%M:%S") + " KST · " + str(ts_val)
    return f'<time class="lt" datetime="{html.escape(str(ts_val))}" title="{html.escape(full)}">{kst.strftime("%m-%d %H:%M:%S")}</time>'


def _raw_cell(ev: dict[str, Any]) -> str:
    """원본 추적 칸: raw_id 복사 버튼 + 실시간이 아닌 수집(재현·가상)일 때만 표시."""
    mode = str(ev.get("ingest_mode") or "")
    flag = "" if mode == "live" else f'<span class="ingest-flag">{"재현" if mode == "replay" else "가상" if mode == "synthetic" else html.escape(mode or "미상")}</span>'
    return _copy_id_chip(ev["raw_id"]) + flag


def _collapse_runs(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """연속으로 똑같은 로그(같은 출처·종류·내용)는 한 줄로 합치고 횟수를 붙인다. 화면 표시만 줄이며 원본은 그대로다."""
    out: list[dict[str, Any]] = []
    last_key = None
    for ev in events:
        key = (ev.get("source"), ev.get("event_type"), ev.get("outcome"), ev.get("status_code"),
               ev.get("rule_id"), _event_line(ev, no_action=True))
        if out and key == last_key:
            out[-1]["_run"] += 1
            out[-1]["_run_from"] = ev.get("event_ts_utc")
        else:
            out.append({**ev, "_run": 1, "_run_from": ev.get("event_ts_utc")})
            last_key = key
    return out


def _run_badge(ev: dict[str, Any]) -> str:
    n = ev.get("_run", 1)
    if n <= 1:
        return ""
    newest, oldest = _parse_utc(ev.get("event_ts_utc")), _parse_utc(ev.get("_run_from"))
    span = ""
    if newest and oldest:
        span = " · " + (_fmt_dur((newest - oldest).total_seconds()) if newest > oldest else "1초 미만")
    return (f'<span class="run-badge" title="같은 로그 {n}건이 연속 발생 · 가장 오래된 시각 '
            f'{html.escape(str(ev.get("_run_from") or ""))}">×{n}{span}</span>')


def _fmt_ingest_mode(mode: str) -> str:
    if mode == "live":
        return '<span class="badge b-ok">실시간 (live)</span>'
    if mode == "replay":
        return '<span class="badge b-warn">재현 (replay)</span>'
    if mode == "synthetic":
        return '<span class="badge b-warn">가상 (synthetic)</span>'
    return f'<span class="badge b-warn">{html.escape(mode)}</span>'


def _fmt_source_badge(source: str) -> str:
    labels = {"erp": "ERP", "gateway": "Gateway", "caddy": "Caddy", "waf": "WAF"}
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
            return f'<span style="color:var(--text-3);font-size:12px;">{esc(prefix)} -</span>'
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


_ERP_USER_DIRECTORY: dict[str, tuple[str, str]] = {
    "alice": ("행정", "사원"),
    "bob": ("행정", "팀장"),
    "carol": ("보안", "사원"),
    "dave": ("인사", "팀장"),
    "erin": ("인사", "사원"),
    "frank": ("보안", "팀장"),
}
_ERP_DEPT_KO: dict[str, str] = {"영업": "행정"}
_ERP_ROLE_KO: dict[str, str] = {"member": "사원", "manager": "팀장", "admin": "관리자"}


def _fmt_user_badge(
    username: str | None,
    dept: str | None = None,
    role: str | None = None,
    *,
    prominent: bool = False,
    compact: bool = False,
) -> str:
    """ERP 계정명과 함께 부서·직급 정보를 표시한다. compact는 prominent의 작은 크기(행 높이를 줄여야 하는 표용)."""
    raw = str(username or "").strip()
    if not raw or raw == "-":
        return '<span class="muted">-</span>'
    known = _ERP_USER_DIRECTORY.get(raw.lower())
    dept_raw = str(dept or (known[0] if known else "")).strip()
    dept_v = _ERP_DEPT_KO.get(dept_raw, dept_raw)
    role_raw = str(role or (known[1] if known else "")).strip()
    role_v = _ERP_ROLE_KO.get(role_raw.lower(), role_raw)
    meta = " · ".join(p for p in (dept_v, role_v) if p)
    base = _pv(raw)
    if prominent:
        name_px, meta_px = ("13.5px", "12px") if compact else ("15px", "14px")
        base_html = f'<span style="font-size:{name_px};font-weight:600;color:var(--text);">{base}</span>'
        if not meta:
            return base_html
        return f'{base_html} <span style="font-size:{meta_px};font-weight:500;color:var(--text-2);white-space:nowrap;">({html.escape(meta)})</span>'
    if not meta:
        return base
    return f'{base} <span class="muted" style="font-size:12px;white-space:nowrap;">({html.escape(meta)})</span>'


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


def _case_time_panel(inc: IncidentView) -> str:
    contexts, priority = case_time_context(inc)
    if not contexts:
        return ""
    policies = " · ".join(sorted({c["policy_id"] for c in contexts}))
    stamps = " · ".join(sorted({c["local_time"] for c in contexts}))
    exceptions = sum(bool(c.get("exception")) for c in contexts)
    reevaluated = sum(bool(c.get("historical_reevaluation")) for c in contexts)
    return ('<section class="panel"><h2>심야 · 휴일 접속 근거</h2>'
            f'<p>이 사건의 로그인 시도 중 {len(contexts)}건 · 승인 예외 {exceptions}건'
            + (' · 동일 심각도 사건보다 우선 확인' if priority else ' · 시간 정보 참고용') + '</p>'
            '<div class="panel-sub">KST 기준 심야 23:00–07:00 · 주말 및 등록 휴무일. 실패 횟수와 차단 권한은 기존 규칙을 따릅니다.</div>'
            f'<details><summary>판단 시각 · 정책 확인</summary><p>{html.escape(stamps)}</p><p>정책 {html.escape(policies)}</p>'
            f'<p>기존 기록의 현재 정책 재평가 {reevaluated}건 · 나머지는 수집 당시 정책</p></details></section>')


def _time_badge(event: Any) -> str:
    context = event_time_context(event)
    if not context.get("outside"):
        return ""
    labels = (["심야"] if context.get("night") else []) + (["휴일"] if context.get("weekend") or context.get("holiday") else [])
    label = " · ".join(labels) + (" · 승인 예외" if context.get("exception") else "")
    basis = "현재 정책으로 재평가" if context.get("historical_reevaluation") else "수집 당시 정책"
    return (f'<span class="badge" style="color:var(--text-2);border:1px solid var(--line);background:var(--raised);" '
            f'title="{html.escape(basis + ": " + context["policy_id"] + " · " + context["local_time"], quote=True)}">{label}</span>')


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
        if et in ("waf_detected", "waf_blocked"):
            is_blk = et == "waf_blocked"
            rule_raw = str(ev.get("rule_id") or "-").strip() or "-"
            parts = [
                act("WAF 차단" if is_blk else "WAF 탐지", "bad" if is_blk else "warn"),
                chip(cip),
                chip(f"규칙 {rule_raw}", "bad" if is_blk else ""),
            ]
        else:
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

  function linearPath(p) {
    var d = "M" + p[0][0] + "," + p[0][1];
    for (var i = 1; i < p.length; i++) d += "L" + p[i][0] + "," + p[i][1];
    return d;
  }
  /* ================= 면적 차트 ================= */
  function initArea(root) {
    var data = JSON.parse(root.getAttribute("data-chart"));
    var rows = data.rows, series = data.series, n = rows.length;
    var hidden = {};
    var H = data.height || 240, M = { l: 38, r: 16, t: 14, b: 30 };
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
    var zoomFrame = 0;

    function X(i) { return n === 1 ? M.l + iw / 2 : M.l + (i * iw) / (n - 1); }
    function Y(v) { return M.t + ih - (v / ymax) * ih; }

    function draw(animate, previous) {
      cancelAnimationFrame(zoomFrame);
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
      (data.nightBands || []).forEach(function (band) {
        el("rect", {x:M.l+band[0]*iw,y:M.t,width:(band[1]-band[0])*iw,height:ih,
          fill:"rgb(var(--accent-rgb) / 0.09)","pointer-events":"none","aria-label":"심야 23시~07시"},svg);
      });

      var defs = el("defs", {}, svg);
      series.forEach(function (s) {
        var g = el("linearGradient", { id: uid + "f" + s.key, x1: "0", x2: "0", y1: "0", y2: "1" }, defs);
        el("stop", { offset: "0%", style: "stop-color:" + s.color + ";stop-opacity:0.18" }, g);
        el("stop", { offset: "100%", style: "stop-color:" + s.color + ";stop-opacity:0" }, g);
      });
      var cg = el("linearGradient", { id: uid + "x", gradientUnits: "userSpaceOnUse", x1: "0", x2: "0", y1: M.t, y2: M.t + ih }, defs);
      [[0, 0], [0.12, 1], [0.88, 1], [1, 0]].forEach(function (st) {
        el("stop", { offset: st[0], style: "stop-color:var(--text-3);stop-opacity:" + st[1] }, cg);
      });
      var clip = el("clipPath", { id: uid + "c" }, defs);
      var clipRect = el("rect", { x: 0, y: 0, width: animate ? 0 : W + 2, height: H }, clip);

      // 기준선과 중간·최대 눈금만 표시한다.
      for (var k = 0; k <= 4; k += 2) {
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
      var paths = [];
      visible.forEach(function (s) {
        var pts = rows.map(function (r, i) { return [xs[i], Y(r[s.key] || 0)]; });
        var line = linearPath(pts);
        function areaPath(points, contour) {
          return contour + "L" + points[points.length - 1][0] + "," + (M.t + ih)
            + "L" + points[0][0] + "," + (M.t + ih) + "Z";
        }
        var fill = el("path", { d: areaPath(pts, line), fill: "url(#" + uid + "f" + s.key + ")" }, layer);
        var stroke = el("path", { d: line, fill: "none", stroke: s.color, "stroke-width": 1.5, "stroke-linecap": "butt", "stroke-linejoin": "miter" }, layer);
        if (previous) {
          var from = rows.map(function (row) {
            var center = (row.start + row.end) / 2;
            var i = previous.rows.findIndex(function (item) { return item.start <= center && center < item.end; });
            var position = (center - previous.start) / (previous.end - previous.start);
            var value = i < 0 ? 0 : (previous.rows[i][s.key] || 0);
            return [M.l + Math.max(0, Math.min(1, position)) * iw, M.t + ih * (1 - value / previous.ymax)];
          });
          paths.push({from: from, to: pts, update: function (points) {
            var contour = linearPath(points);
            fill.setAttribute("d", areaPath(points, contour));
            stroke.setAttribute("d", contour);
          }});
        }
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

      if (paths.length) {
        var start = performance.now();
        (function zoom(ts) {
          var progress = Math.min(1, (ts - start) / 360);
          var eased = 1 - Math.pow(1 - progress, 3);
          paths.forEach(function (path) {
            path.update(path.to.map(function (point, index) {
              var old = path.from[index];
              return [old[0] + (point[0] - old[0]) * eased, old[1] + (point[1] - old[1]) * eased];
            }));
          });
          if (progress < 1) zoomFrame = requestAnimationFrame(zoom);
        })(start);
      }

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
      var html = '<div class="t">' + r.t + (r.span ? ' <span style="font-weight:400;color:var(--text-3);font-size:12px;">(' + r.span + ')</span>' : '') + "</div>";
      visible.forEach(function (s) {
        var v = r[s.key] || 0; total += v;
        html += '<div class="r"><i style="background:' + s.color + '"></i>' + s.label + "<b>" + v + "건</b></div>";
      });
      if (visible.length > 1) html += '<div class="r sum">합계<b>' + total + "건</b></div>";
      if (r.href) html += '<div class="r" style="margin-top:4px;color:var(--accent);font-size:12px;font-weight:600;">클릭하여 상세 로그 보기 →</div>';
      tip.innerHTML = html;
      tip.style.opacity = 1;
    }

    var animate = !reduce && !recentlyAnimated(animKey);
    draw(animate);
    if (animate) markAnimated(animKey);
    var panel = root.closest("#event-trend");
    if (panel) {
      var periodRequest;
      panel.addEventListener("click", async function (event) {
        var link = event.target.closest(".chart-periods .range-chip");
        if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        if (periodRequest) periodRequest.abort();
        if (link.hasAttribute("aria-current")) return;
        var request = new AbortController();
        periodRequest = request;
        window.__eventPeriodLoading = true;
        try {
          var response = await fetch(link.href, {signal: request.signal});
          if (!response.ok) throw Error("period response");
          var page = new DOMParser().parseFromString(await response.text(), "text/html");
          var incoming = page.getElementById(root.id);
          var subtitle = page.getElementById("event-trend-subtitle");
          if (!incoming || !subtitle) throw Error("period content");
          if (request.signal.aborted) return;
          var selected = new URL(link.href);
          var previous = {rows: rows, start: rows[0].start, end: rows[n - 1].end, ymax: ymax};
          var incomingData = JSON.parse(incoming.getAttribute("data-chart"));
          rows = incomingData.rows;
          data.nightBands = incomingData.nightBands || [];
          n = rows.length;
          root.setAttribute("data-chart", incoming.getAttribute("data-chart"));
          panel.querySelector("#event-trend-subtitle").textContent = subtitle.textContent;
          panel.querySelectorAll(".chart-periods .range-chip").forEach(function (tab) {
            tab.classList.toggle("active", tab === link);
            if (tab === link) tab.setAttribute("aria-current", "true");
            else tab.removeAttribute("aria-current");
          });
          document.querySelectorAll("#login-failures .chart-periods .range-chip").forEach(function (tab) {
            var url = new URL(tab.href);
            url.searchParams.set("et", selected.searchParams.get("et"));
            tab.href = url;
          });
          history.replaceState(history.state, "", selected);
          hide();
          draw(false, reduce ? null : previous);
          panel.querySelector("[role=status]").hidden = true;
        } catch (error) {
          if (request.signal.aborted) return;
          var status = panel.querySelector("[role=status]");
          status.textContent = "\uc9d1\uacc4 \ub2e8\uc704\ub97c \ubc14\uafb8\uc9c0 \ubabb\ud588\uc2b5\ub2c8\ub2e4. \ub2e4\uc2dc \uc2dc\ub3c4\ud574 \uc8fc\uc138\uc694.";
          status.hidden = false;
        } finally {
          if (periodRequest === request) {
            periodRequest = null;
            window.__eventPeriodLoading = false;
          }
        }
      });
    }
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
    {"key": "erp", "label": "ERP", "color": "var(--source-erp)"},
    {"key": "caddy", "label": "Caddy", "color": "var(--source-caddy)"},
    {"key": "waf", "label": "WAF", "color": "var(--source-waf)"},
    {"key": "gateway", "label": "Gateway", "color": "var(--source-gateway)"},
]


_EVENT_TREND_TABS = {
    "hourly": "시간별",
    "daily": "일별",
    "weekly": "주별",
    "monthly": "월별",
    "suspect": "실패·의심",
}


# 화면이 인라인 스크립트·스타일을 쓰므로 script-src/style-src는 제한하지 않고, 틀 삽입·폼 전송처·플러그인만 막는다.
_SECURITY_HEADERS = (
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    # no-referrer는 브라우저에서 동일 출처 POST 폼 전송 시에도 Origin: null을 보내 _verify_origin을 막으므로 same-origin을 쓴다.
    ("Referrer-Policy", "same-origin"),
    ("Cache-Control", "no-store"),
    ("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"),
)

_FONT_PATH = Path(__file__).resolve().parent / "static" / "fonts" / "PretendardVariable.woff2"
_font_cache: list[bytes | None] = []


def _font_bytes() -> bytes | None:
    """자체 제공 글꼴(woff2). 형식이 맞지 않거나 없으면 None을 돌려 404로 답한다."""
    if not _font_cache:
        try:
            data = _FONT_PATH.read_bytes()
        except OSError:
            data = b""
        _font_cache.append(data if data[:4] == b"wOF2" else None)
    return _font_cache[0]


# 브라우저가 알아서 보내는 정상 요청: 로그인 전 세션 확인(401)과 아이콘 요청(404)은 이상으로 세지 않는다.
_ROUTINE_BROWSER_PROBES = {("/favicon.ico", 404), ("/api/session", 401)}


def _is_suspect_event(source: str, event_type: str, outcome: str, status_code: int | None,
                      http_path: str | None = None) -> bool:
    """실패·거부·차단·HTTP 오류 등 보안상 의심 이벤트 여부를 판정한다."""
    if source == "erp":
        return event_type == "login_failed" or outcome in {"failure", "denied"} or "denied" in event_type
    if source == "gateway":
        return event_type == "fw_deny" or outcome in {"failure", "denied", "deny", "drop"}
    if source == "caddy":
        if event_type in {"waf_detected", "waf_blocked"}:
            return True
        if status_code is not None and (str(http_path or "").split("?", 1)[0], int(status_code)) in _ROUTINE_BROWSER_PROBES:
            return False
        return (status_code is not None and int(status_code) >= 400) or outcome == "failure"
    return False


def _bk_area_chart(
    store: DashboardStore | DbDashboardStore,
    tab: str,
    now_utc: datetime | None = None,
) -> tuple[str, str]:
    """선택한 한국시간 구간에 맞춰 이벤트를 출처별로 집계한다."""
    from bisect import bisect_right

    period = "hourly" if tab == "suspect" else tab
    period, edges = _login_window(period, now_utc)
    sources = tuple(series["key"] for series in _BK_SERIES)
    formats = {"hourly": "%H:%M", "daily": "%m-%d", "weekly": "%m-%d", "monthly": "%Y-%m"}
    rows = [
        {"t": edge.strftime(formats[period]), "span": f"{edge:%m-%d %H:%M} ~ {edges[i + 1]:%m-%d %H:%M}",
         "start": edge.timestamp(),
         "end": edges[i + 1].timestamp(), **dict.fromkeys(sources, 0)}
        for i, edge in enumerate(edges[:-1])
    ]
    try:
        events = store.get_trend_events(edges[0].astimezone(timezone.utc))
    except Exception:
        events = []
    for stamp, source, event_type, outcome, status, http_path in events:
        if source not in {"erp", "caddy", "gateway"} or (tab == "suspect" and not _is_suspect_event(source, event_type, outcome, status, http_path)):
            continue
        series_key = "waf" if source == "caddy" and event_type in {"waf_detected", "waf_blocked"} else source
        index = bisect_right(edges, stamp) - 1
        if 0 <= index < len(rows):
            rows[index][series_key] += 1
    for i, row in enumerate(rows):
        if any(row[source] for source in sources):
            start_utc = edges[i].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            end_utc = edges[i + 1].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            row["href"] = f"/events?from={start_utc}&to={end_utc}" + ("&anomaly=1" if tab == "suspect" else "")
    count = sum(row[source] for row in rows for source in sources)
    label = _LOGIN_RANGES[period][1] if tab != "suspect" else _EVENT_TREND_TABS[tab]
    subtitle = f"{label} · 한국시간 · {count:,}건 · 음영: 심야 23:00–07:00 · WAF 판정은 Caddy에서 분리"
    payload = {"rows": rows, "series": _BK_SERIES, "nightBands": night_bands(edges[0], edges[-2])}
    return f'<div class="bk-chart" id="bk-area-events" data-chart="{_bk_json_attr(payload)}"></div>', subtitle


def _bk_donut(stats_map: dict[str, dict[str, Any]]) -> str:
    def cnt(key: str) -> int:
        return int(stats_map.get(key, {}).get("count", 0))

    items = [
        {"label": "ERP", "value": cnt("erp"), "color": "var(--source-erp)"},
        {"label": "Caddy", "value": cnt("caddy"), "color": "var(--source-caddy)"},
        {"label": "Gateway", "value": cnt("gateway"), "color": "var(--source-gateway)"},
    ]
    return f'<div class="bk-donut" id="bk-donut-src" data-donut="{_bk_json_attr({"items": items})}"></div>'


def _render_incident_timeline(inc: IncidentView) -> str:
    entries = [
        (ev.event_ts_utc, _fmt_source_badge(ev.source), _fmt_event_type(ev.event_type, ev.outcome))
        for ev in inc.evidence_events
    ]
    entries.append((inc.created_at_utc, "관제", "사건 등록"))
    entries.extend(
        (approval.approved_at_utc, "조치 승인", html.escape(approval.approved_by))
        for approval in inc.approvals
    )
    rows = "".join(
        f"<tr><td class='nowrap'>{_fmt_ts(stamp)}</td><td>{source}</td><td>{description}</td></tr>"
        for stamp, source, description in sorted(
            entries, key=lambda entry: _parse_utc(entry[0]) or datetime.min.replace(tzinfo=timezone.utc)
        )
    )
    return f"""
    <div class="panel">
      <div class="panel-header"><h2>사건 타임라인</h2></div>
      <table>
        <thead><tr><th>시각</th><th>출처</th><th>내용</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
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


def _health_strip(stats_map: dict[str, dict[str, Any]], waf_stats: dict[str, Any] | None = None) -> str:
    """수집 상태(맹점 감시): 마지막 수신이 10분 넘게 없으면 지연."""
    now_utc = datetime.now(timezone.utc)
    items = []
    sources = (("erp", "ERP", "var(--source-erp)"), ("gateway", "Gateway", "var(--source-gateway)"),
               ("caddy", "Caddy", "var(--source-caddy)"))
    if waf_stats is not None:
        sources += (("waf", "WAF", "var(--source-waf)"),)
    for key, name, color in sources:
        st = waf_stats if key == "waf" else stats_map.get(key)
        cnt = int(st["count"]) if st else 0
        last = st["last_received_utc"] if st else None
        last_dt = _parse_utc(last)
        if key == "waf":
            state, label = ("ok", "판정 기록 있음") if cnt else ("wait", "판정 기록 없음")
        elif not cnt or last_dt is None:
            state, label = "wait", "수집 대기"
        elif (now_utc - last_dt).total_seconds() > 600:
            state, label = "stale", "수신 지연"
        else:
            state, label = "ok", "정상"
        items.append(
            f'<a class="hitem {state}" href="/logs/{key}">'
            f'<span class="hname"><i style="background:{color}"></i>{name}</span>'
            f'<span class="hstate">{label}</span>'
            f'<span class="hmeta">{cnt:,}건 · 마지막 수신 {_rel_time(last)}</span></a>'
        )
    return f'<div class="health" aria-label="로그 수집 상태">{"".join(items)}</div>'


# 수집 공백 판정 기준. 화면 문구가 아니라 계산 규칙이며, 값은 snapshot["ingest"]에도 함께 남긴다.
INGEST_MIN_GAP_HOURS = 3        # 이 시간 이상 연속으로 한 건도 못 받았으면 'gap'(공백 의심)
INGEST_SPARSE_ACTIVE_RATIO = 0.25  # 이벤트가 있는 시간이 이 비율 미만이면 'sparse'(원래 뜸한 출처)
INGEST_SPARSE_STALL_HOURS = 24  # 뜸한 출처라도 기간이 진행 중인데 이만큼 연속으로 조용하면 'gap'(수신 중단 의심)


def last_tail_silent(counts, obs_from, obs_to):
    """관측 구간 끝에서 연속으로 0건인 시간 수. 관측 구간에 기록이 하나도 없으면 구간 전체 길이."""
    tail = 0
    for i in range(obs_to - 1, obs_from - 1, -1):
        if counts[i] > 0:
            break
        tail += 1
    return tail


def _ingest_source(key, label, hour_counts, first_event, start, end, now, bucket_hours):
    """한 출처의 수집 공백 요약. start/end는 보고 기간(end 미포함), 모두 tz-aware.

    경계 판단(코드로 고정한 규칙):
    1) 수집 시작 전: 이 출처의 첫 이벤트가 기간 중간이면, 그 이전 칸은 '공백'이 아니라 '범위 밖'(None)이다.
       첫 이벤트가 기간 이전부터 있었다면 기간 첫 칸부터 평가한다.
    2) 기간 진행 중: 지금 시각이 속한 시간 칸(아직 덜 찬 칸)과 그 뒤 미래 칸은 평가하지 않는다(None).
       단, 시계 오차로 미래 시각의 이벤트가 이미 있으면 그 칸은 값을 보여 준다.
    3) 이벤트가 0건인 출처는 '공백'으로 단정하지 않고 state='no_data'로 둔다. 원래 트래픽이 없는 것인지
       수집이 끊긴 것인지 이 데이터만으로는 구분할 수 없기 때문이다(가짜 수치 금지).
       이전 기록이 있었는지만 had_prior_data로 알려 준다.
    4) 이벤트가 있어도 활동한 시간 비율이 낮은 출처(예: WAF)는 무수신이 평소 모습이므로
       'sparse'로 표기하고 공백 의심으로 올리지 않는다. 최장 무수신 수치는 그대로 준다.
    공백 길이는 표시 칸(bucket_hours)과 무관하게 항상 1시간 단위로 계산한다.
    """
    hour = timedelta(hours=1)
    n = int((end - start) / hour)
    counts = [0] * n
    for key_h, c in hour_counts:
        i = int((datetime.strptime(key_h, "%Y-%m-%dT%H").replace(tzinfo=timezone.utc) - start) / hour)
        if 0 <= i < n:
            counts[i] += c
    total = sum(counts)

    first_dt = _parse_utc(first_event) if first_event else None
    had_prior = first_dt is not None and first_dt < start
    if first_dt is None or first_dt >= end:
        obs_from = n  # 기간 안에 평가할 칸이 없다
    else:
        obs_from = max(0, int((first_dt - start) // hour))
    obs_to = n if now >= end else max(0, min(n, int((now - start) // hour)))  # 덜 찬 현재 칸은 제외

    hourly = [c if (obs_from <= i < obs_to or c > 0) else None for i, c in enumerate(counts)]
    evaluated = max(0, obs_to - obs_from)
    active = sum(1 for i in range(obs_from, obs_to) if counts[i] > 0)

    gap_len = gap_from = 0
    run = run_from = 0
    for i in range(obs_from, obs_to):
        if counts[i] == 0:
            if run == 0:
                run_from = i
            run += 1
            if run > gap_len:
                gap_len, gap_from = run, run_from
        else:
            run = 0

    def kst_iso(idx):
        return (start + idx * hour).astimezone(KST).isoformat()

    buckets = []
    for b in range(0, n, bucket_hours):
        chunk = hourly[b:b + bucket_hours]
        seen = [c for c in chunk if c is not None]
        if not seen or (len(seen) < len(chunk) and sum(seen) == 0):
            buckets.append(None)  # 덜 관측된 칸의 0은 공백이 아니므로 값 없음으로 둔다
        else:
            buckets.append(sum(seen))

    if total == 0:
        state, gap_len = "no_data", None
    elif evaluated and active / evaluated < INGEST_SPARSE_ACTIVE_RATIO:
        state = "sparse"
        # 뜸한 출처는 평소 무수신이 길어 공백 판정을 못 한다. 대신 지금 진행 중인 기간의 끝에서 오래 조용하면 올린다.
        if now < end and last_tail_silent(counts, obs_from, obs_to) >= INGEST_SPARSE_STALL_HOURS:
            state = "gap"
    elif gap_len >= INGEST_MIN_GAP_HOURS:
        state = "gap"
    else:
        state = "ok"
    has_gap = gap_len is not None and gap_len > 0
    # 실무자가 가장 먼저 묻는 것: 마지막으로 받은 게 언제고, 그 뒤로 몇 시간째 조용한가(시간 단위).
    last_i = max((i for i in range(obs_from, obs_to) if counts[i] > 0), default=None)
    tail_silent = (obs_to - 1 - last_i) if last_i is not None else None
    return {
        "key": key, "label": label, "total": total, "buckets": buckets,
        "max_gap_hours": gap_len,
        "gap_start_kst": kst_iso(gap_from) if has_gap else None,
        "gap_end_kst": kst_iso(gap_from + gap_len) if has_gap else None,
        "gap_ongoing": bool(has_gap and gap_from + gap_len == obs_to and now < end),
        "state": state,
        "observed_from_kst": kst_iso(obs_from) if evaluated else None,
        "had_prior_data": had_prior,
        "evaluated_hours": evaluated, "active_hours": active,
        "last_active_kst": kst_iso(last_i) if last_i is not None else None,
        "tail_silent_hours": tail_silent,
    }


def _ingest_snapshot(store, start, end, kind, now):
    """보고 기간의 출처별 수집 공백. 출처 분리는 snapshot["sources"]와 같은 규칙(WAF는 caddy에서 분리)."""
    waf_types = ("waf_detected", "waf_blocked")
    specs = (
        ("erp", "ERP", {"source": "erp"}),
        ("gateway", "게이트웨이", {"source": "gateway"}),
        ("caddy", "웹 프록시(WAF 제외)", {"source": "caddy", "exclude_event_types": waf_types}),
        ("waf", "WAF 판정", {"source": "caddy", "event_types": waf_types}),
    )
    bucket_hours = 1 if kind == "weekly" else 6
    sources = []
    for key, label, flt in specs:
        hours = store.get_event_hours(since_utc=start, until_utc=end, ingest_mode="live", **flt)
        first = store.get_first_event_utc(until_utc=end, ingest_mode="live", **flt)
        sources.append(_ingest_source(key, label, hours, first, start.astimezone(timezone.utc),
                                      end.astimezone(timezone.utc), now, bucket_hours))
    obs_to = min(end, now.replace(minute=0, second=0, microsecond=0))
    return {
        "bucket_hours": bucket_hours,
        "period_start_kst": start.astimezone(KST).isoformat(),
        "period_end_kst": end.astimezone(KST).isoformat(),
        "period_open": now < end,
        "observed_to_kst": max(start, obs_to).astimezone(KST).isoformat(),
        "min_gap_hours": INGEST_MIN_GAP_HOURS,
        "sparse_active_ratio": INGEST_SPARSE_ACTIVE_RATIO,
        "sources": sources,
    }


EXTRA_EVENT_LIMIT = 100000  # list_recent_events 상한. 이 수에 닿으면 잘렸을 수 있어 '집계 불가'로 표시한다.


def _extra_metrics(store, start, end):
    """2순위 지표. 이미 수집된 정규화 이벤트만 센다. 못 센 항목은 state="unknown"으로 남겨 0과 구분한다."""
    def fetch(source, types):
        rows = store.list_recent_events(limit=EXTRA_EVENT_LIMIT, source=source, event_types=types,
                                        since_utc=start, until_utc=end, ingest_mode="live")
        return rows, len(rows) >= EXTRA_EVENT_LIMIT

    out = {}
    # 1) WAF 유형별. CRS 941xxx=XSS, 942xxx=SQL 인젝션(변환기가 이 범위만 통과시킨다), 그 밖 규칙은 별도 이름 그대로.
    rows, cut = fetch("caddy", ("waf_detected", "waf_blocked"))
    families = {}
    for row in rows:
        rule = str(row.get("rule_id") or "")
        parts = [part.strip() for part in rule.split(",") if part.strip()]
        name = ("SQL 인젝션 유형(942)" if any(x.startswith("942") for x in parts)
                else "XSS 유형(941)" if any(x.startswith("941") for x in parts)
                else rule or "규칙 미상")
        families[name] = families.get(name, 0) + 1
    out["waf"] = {"state": "unknown" if cut else "ok", "total": len(rows),
                  "detected": sum(1 for r in rows if r["event_type"] == "waf_detected"),
                  "blocked": sum(1 for r in rows if r["event_type"] == "waf_blocked"), "families": families}
    # 2) ERP 문서 열람 결과. 403(권한 없음)과 404(없는 문서)는 의미가 달라 나눈다.
    rows, cut = fetch("erp", ("document_read",))
    codes = {"ok": 0, "unauth": 0, "forbidden": 0, "missing": 0, "other": 0}
    for row in rows:
        code = row.get("status_code")
        codes["ok" if code == 200 else "unauth" if code == 401 else "forbidden" if code == 403
              else "missing" if code == 404 else "other"] += 1
    out["doc_read"] = dict(codes, state="unknown" if cut else "ok", total=len(rows))
    # 3) 재발: 같은 IP·계정의 로그인 실패가 서로 다른 2일 이상에 나타남(KST 날짜 기준).
    rows, cut = fetch("erp", ("login_failed",))
    days = {"ip": {}, "account": {}}
    for row in rows:
        stamp = _parse_utc(row.get("event_ts_utc"))
        if stamp is None:
            continue
        day = stamp.astimezone(KST).date().isoformat()
        for kind_key, value in (("ip", row.get("client_ip")), ("account", row.get("username"))):
            if value:
                days[kind_key].setdefault(value, set()).add(day)
    out["recur"] = {"state": "unknown" if cut else "ok", "failed_total": len(rows),
                    "ips": sum(1 for d in days["ip"].values() if len(d) >= 2),
                    "accounts": sum(1 for d in days["account"].values() if len(d) >= 2)}
    return out


def _report_snapshot(store, day, kind, now=None):
    snapshot = weekly_snapshot(store.list_incidents(), day, _parse_utc, AUTO_ACCOUNT_LOCK_RULE_ID,
                               lambda approvals: _block_effects(store, approvals), kind=kind)
    start = datetime(day.year, day.month, day.day, tzinfo=KST)
    end_day = period_end(day, kind)
    end = datetime(end_day.year, end_day.month, end_day.day, tzinfo=KST)
    def count(source, event_types=None):
        return store.count_recent_events(source=source, event_types=event_types, since_utc=start, until_utc=end,
                                         ingest_mode="live")

    # WAF 판정은 source="caddy"로 들어온다. 분리하지 않으면 "웹 프록시" 수치가 WAF를 품어
    # 보고서에 WAF가 한 번도 드러나지 않는다(화면 왼쪽 메뉴·수집 상태 띠는 WAF를 별도 출처로 센다).
    waf = count("caddy", ("waf_detected", "waf_blocked"))
    snapshot["sources"] = {"ERP": count("erp"), "게이트웨이": count("gateway"),
                           "웹 프록시(WAF 제외)": count("caddy") - waf, "WAF 판정": waf}
    if hasattr(store, "list_recent_events"):  # 키가 없으면 옛 확정본과 같은 취급이다
        snapshot["extra"] = _extra_metrics(store, start, end)
    # 수집 공백. 시간 단위 조회가 없는 저장소(옛 대역 등)에서는 키를 만들지 않는다.
    # 키가 없는 옛 확정본과 같은 취급이라 화면은 .get("ingest")로 방어하면 된다.
    if hasattr(store, "get_event_hours") and hasattr(store, "get_first_event_utc"):
        snapshot["ingest"] = _ingest_snapshot(store, start, end, kind, now or datetime.now(timezone.utc))
    return snapshot


def _incident_response_status(inc: IncidentView) -> str:
    if any(alert.rule_id == AUTO_ACCOUNT_LOCK_RULE_ID for alert in inc.alerts):
        return '<span class="badge b-applied">계정 자동 잠금 기록</span>'
    if inc.status == "open" and inc.block_rule_eligible and inc.live_and_trusted_eligible:
        return '<span class="badge b-open">IP 차단 승인 대기</span>'
    return _fmt_status(inc.status, inc.block_rule_eligible)


def _block_effects(store: Any, approvals: list[Any]) -> dict[str, dict[str, Any]]:
    """승인 차단별 효과. 새 기록을 만들지 않고 이미 수집된 로그를 승인 ID로 묶어 센다.

    - attempts: 차단 규칙(APR)이 막고 기록한 접속 시도 수. 같은 연결(출발지 포트)의 재전송은 한 번으로 센다.
    - success: 조회한 ERP 로그 중 차단 기간에 같은 IP에서 로그인에 성공한 수.
    """
    blocks = [
        ap for ap in approvals
        if ap.action_type == "block" and ap.status in {"applied", "released", "expired"}
    ]
    if not blocks:
        return {}
    def events(source, event_type, start, end):
        page_size = 500
        offset = 0
        while True:
            page = store.list_recent_events(
                limit=page_size, offset=offset, source=source, event_types=(event_type,),
                since_utc=start, until_utc=end,
            )
            yield from page
            if len(page) < page_size:
                return
            offset += len(page)
    now = datetime.now(timezone.utc)
    out: dict[str, dict[str, Any]] = {}
    for ap in blocks:
        start = _parse_utc(ap.approved_at_utc)
        gr = ap.gateway_response if isinstance(ap.gateway_response, dict) else {}
        ends = [d for d in (_parse_utc(gr.get("released_at_utc")), _parse_utc(ap.expires_at_utc), now) if d is not None]
        end = min(ends) if ends else now
        if start is None or end <= start or (ap.status == "applied" and gr.get("rule_present") is False):
            continue
        try:
            gw = list(events("gateway", "fw_deny", start, end))
            erp_ok = list(events("erp", "login_success", start, end))
        except Exception:
            continue
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
        return '<span class="muted">집계 없음</span>'
    tone = "muted" if eff["success"] == 0 else "bad"
    tip = "게이트웨이 차단 규칙이 막고 기록한 접속 시도입니다. 같은 연결(출발지 포트)의 재전송은 한 번으로 셉니다."
    return (
        f'<span title="{tip}"><b>{eff["attempts"]}건</b> 막음</span>'
        f' <span class="cell-sub {tone}" title="조회 로그 내 로그인 성공">· 성공 {eff["success"]}건</span>'
    )


def _block_scope_note(ip: Any) -> str:
    """승인 전에 무엇이 막히는지 분명히 알려 준다(계정이 아니라 IP 단위 조치)."""
    if not ip:
        return ""
    return (
        f'<div class="pop-note" style="margin:12px 0 0;">승인하면 <b>{html.escape(str(ip))}</b> (IP)에서 오는 '
        f"<b>모든 계정</b>의 접속이 입력한 시간 동안 게이트웨이에서 차단됩니다. 계정(예: alice)은 잠기지 않고, "
        f"다른 IP의 접속에는 영향이 없습니다.</div>"
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
    if gr.get("error") == "target_not_allowed":
        note = '<div class="cell-sub bad">게이트웨이 차단 허용 목록에 없는 IP입니다. 차단이 적용되지 않았습니다.</div>'
    elif gr.get("error"):
        note = f'<div class="cell-sub bad">{esc(str(gr.get("message") or gr.get("error")))}</div>'
    elif ap.status == "applied" and "rule_present" in gr:
        note = (
            '<div class="cell-sub ok">차단 규칙 적용 확인</div>'
            if gr.get("rule_present")
            else '<div class="cell-sub warn">차단 규칙 미확인</div>'
        )
    elif ap.status == "released" and gr.get("released_at_utc"):
        note = f'<div class="cell-sub">해제 {_rel_time(gr.get("released_at_utc"))}</div>'
    if is_block and ap.status == "rejected":
        note += '<div class="cell-sub">차단 미적용</div>'
    elif is_block and ap.status in {"pending", "unknown", "apply_failed"}:
        note += '<div class="cell-sub">차단 적용 확인 필요</div>'
    elif is_block and effect is not None:
        note += f'<div class="cell-sub">차단 중 막은 접속 시도 <b>{effect["attempts"]}건</b></div>'
        if effect["success"]:
            note += f'<div class="cell-sub bad">차단 중 로그인 성공 {effect["success"]}건</div>'
    elif is_block and ap.status in {"applied", "released", "expired"}:
        note += '<div class="cell-sub">차단 효과 집계 없음</div>'
    expiry = (
        "—" if ap.status == "rejected"
        else _remaining(ap.expires_at_utc) if ap.status == "applied"
        else _fmt_ts(ap.expires_at_utc, include_utc=False)
    )
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


_LOGIN_RANGES = {
    "hourly": ("시간별", "최근 24시간", 24),
    "daily": ("일별", "최근 14일", 14),
    "weekly": ("주별", "최근 8주", 8),
    "monthly": ("월별", "최근 12개월", 12),
}
_LOGIN_CHART_KST = timezone(timedelta(hours=9))


def _login_window(range_key: str, now_utc: datetime | None = None) -> tuple[str, list[datetime]]:
    """Return inclusive bucket starts and the exclusive end in KST."""
    if range_key not in _LOGIN_RANGES:
        range_key = "hourly"
    count = _LOGIN_RANGES[range_key][2]
    now = (now_utc or datetime.now(timezone.utc)).astimezone(_LOGIN_CHART_KST)
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if range_key == "monthly":
        month = now.year * 12 + now.month - 1
        return range_key, [
            day.replace(year=idx // 12, month=idx % 12 + 1, day=1)
            for idx in range(month - count + 1, month + 2)
        ]
    current, step = {
        "hourly": (now.replace(minute=0, second=0, microsecond=0), timedelta(hours=1)),
        "daily": (day, timedelta(days=1)),
        "weekly": (day - timedelta(days=day.weekday()), timedelta(weeks=1)),
    }[range_key]
    return range_key, [current + step * offset for offset in range(1 - count, 2)]


def _login_failure_panel(
    store: DashboardStore | DbDashboardStore,
    range_key: str,
    events: list[tuple[datetime, str, str, str]] | None = None,
    event_tab: str = "hourly",
    boundaries: list[datetime] | None = None,
    incidents: list[IncidentView] | None = None,
) -> str:
    """Show ERP login failures over the selected calendar buckets."""
    from bisect import bisect_right

    if boundaries is None:
        range_key, boundaries = _login_window(range_key)
    n = len(boundaries) - 1
    range_label = _LOGIN_RANGES[range_key][1]
    if events is None:
        try:
            events = store.get_login_events(boundaries[0])
        except Exception:
            events = []
    fails = [0] * n
    oks = [0] * n
    for dt, ev_type, *_rest in events:
        i = bisect_right(boundaries, dt) - 1
        if 0 <= i < n:
            if ev_type == "login_failed":
                fails[i] += 1
            else:
                oks[i] += 1
    total_fail, total_ok = sum(fails), sum(oks)
    recent_alerts = [
        (incident, alert)
        for incident in (incidents or [])
        for alert in incident.alerts
        if alert.rule_id == LOGIN_FAILURE_RULE_ID
        and boundaries[0] <= _parse_utc(alert.window_end_utc) < boundaries[-1]
    ]
    latest = max(recent_alerts, key=lambda pair: pair[1].window_end_utc, default=None)
    incident_note = (
        f'<div class="panel-sub">최근 반복 로그인 사건 · 5분 동안 실패 '
        f'<b>{latest[1].failure_count}회</b> · '
        f'<a href="/incidents/{html.escape(latest[0].incident_id)}">사건 보기</a></div>'
        if latest else ""
    )

    w, h = 560, 150
    ml, mr, mt, mb = 34, 18, 14, 26
    pw, ph = w - ml - mr, h - mt - mb
    ymax = max(DEFAULT_THRESHOLD + 1, max(fails))
    slot = pw / n
    bw = min(32.0, slot * 0.56)

    def y_of(v: float) -> float:
        return mt + ph - (v / ymax) * ph

    tick_format = {"hourly": "%H:%M", "daily": "%m-%d", "weekly": "%m-%d", "monthly": "%Y-%m"}[range_key]

    parts: list[str] = []
    for a, b in night_bands(boundaries[0], boundaries[-1]):
        parts.append(f'<rect x="{ml + a * pw:.2f}" y="{mt}" width="{(b-a)*pw:.2f}" height="{ph}" fill="rgb(var(--accent-rgb) / 0.09)" pointer-events="none"><title>심야 23:00–07:00 KST</title></rect>')
    for tick in sorted({0, ymax // 2, ymax}):
        parts.append(
            f'<line x1="{ml}" x2="{w - mr}" y1="{y_of(tick):.1f}" y2="{y_of(tick):.1f}" stroke="var(--line-soft)" stroke-width="1"/>'
            f'<text x="{ml - 6}" y="{y_of(tick) + 4:.1f}" text-anchor="end" font-size="11" style="fill:var(--text-2)">{tick}</text>'
        )
    step = max(1, (n + 5) // 6)
    x_indices = list(range(0, n, step))
    if (n - 1) not in x_indices and (n - 1 - x_indices[-1]) >= max(2, step // 2):
        x_indices.append(n - 1)
    for i in x_indices:
        parts.append(
            f'<text x="{ml + i * slot + slot / 2:.1f}" y="{h - 7}" text-anchor="middle" font-size="11" style="fill:var(--text-2)">{boundaries[i].strftime(tick_format)}</text>'
        )
    for i in range(n):
        x = ml + i * slot
        bar_h = (fails[i] / ymax) * ph
        title_rng = f"{boundaries[i]:%m-%d %H:%M} ~ {boundaries[i + 1]:%m-%d %H:%M} KST"
        href_str = ""
        if fails[i] + oks[i] > 0:
            b_start = boundaries[i].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            b_end = boundaries[i + 1].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            href_str = f"/events?from={b_start}&to={b_end}"
        bar = (
            f'<rect class="lf-bar" x="{x + (slot - bw) / 2:.1f}" y="{mt + ph - bar_h:.1f}" width="{bw:.1f}" height="{bar_h:.1f}" rx="1.5" fill="var(--danger)"/>'
            if fails[i] > 0
            else ""
        )
        cur_style = ' style="cursor:pointer"' if href_str else ""
        parts.append(
            f'<g class="lf-col"{cur_style} data-title="{html.escape(title_rng)}" '
            f'data-start="{int(boundaries[i].timestamp())}" data-end="{int(boundaries[i + 1].timestamp())}" '
            f'data-fail="{fails[i]}" data-ok="{oks[i]}" '
            f'data-href="{html.escape(href_str)}">'
            f'<rect class="lf-hit" x="{x:.1f}" y="{mt}" width="{slot:.1f}" height="{ph}"/>{bar}</g>'
        )
    threshold_y = y_of(DEFAULT_THRESHOLD)
    parts.append(
        f'<g class="lf-threshold">'
        f'<title>탐지 기준 {DEFAULT_THRESHOLD}회 / 5분. 막대는 선택한 구간의 전체 합계입니다.</title>'
        f'<line x1="{ml}" x2="{w - mr}" y1="{threshold_y:.1f}" y2="{threshold_y:.1f}" '
        'stroke="var(--warn)" stroke-width="1.5" stroke-dasharray="5 4" pointer-events="none"/>'
        f'<line x1="{ml}" x2="{w - mr}" y1="{threshold_y:.1f}" y2="{threshold_y:.1f}" '
        'stroke="transparent" stroke-width="9" pointer-events="stroke"/></g>'
    )
    if total_fail == 0 and total_ok == 0:
        parts.append(
            f'<text x="{ml + pw / 2:.1f}" y="{mt + ph / 2 + 22:.1f}" text-anchor="middle" font-size="13" style="fill:var(--text-2)">이 구간에 로그인 기록이 없습니다</text>'
        )
    aria = f"{range_label} 로그인 실패 {total_fail}건, 성공 {total_ok}건"
    et_safe = event_tab if event_tab in _EVENT_TREND_TABS else "hourly"
    chip_items = []
    for key, lab in _LOGIN_RANGES.items():
        is_cur = key == range_key
        chip_items.append(
            f'<a class="range-chip{" active" if is_cur else ""}" href="/?lf={key}&et={et_safe}"'
            + (' aria-current="true"' if is_cur else "")
            + f'>{lab[0]}</a>'
        )
    chips = "".join(chip_items)
    return f"""
    <div class="panel" id="login-failures" style="scroll-margin-top:20px;">
      <div class="panel-header">
        <div>
          <h2>로그인 실패 추이</h2>
          <div class="panel-sub" id="login-trend-subtitle">{html.escape(range_label)} · 한국시간 · 실패 {total_fail}건 · 성공 {total_ok}건</div>
        </div>
      </div>
      <nav class="chart-periods" aria-label="로그인 실패 집계 단위">{chips}</nav>
      {incident_note}
      <div class="panel-sub" id="login-range-status" role="status" hidden></div>
      <div class="lf-wrap" style="position:relative;">
        <svg class="lf-svg" viewBox="0 0 {w} {h}" role="img" aria-label="{html.escape(aria)}" style="width:100%;height:auto;max-height:230px;display:block;">{"".join(parts)}</svg>
        <div class="bk-tip" id="lfTip" style="opacity:0;"></div>
      </div>
      <script>(function(){{
        function bindChart(panel){{
        var wrap=panel.querySelector(".lf-wrap"),tip=panel.querySelector("#lfTip");
        if(!wrap||!tip)return;
        wrap.querySelectorAll(".lf-col").forEach(function(col){{
          col.addEventListener("pointerenter",function(e){{
            var t=col.getAttribute("data-title")||"",
                f=col.getAttribute("data-fail")||"0",ok=col.getAttribute("data-ok")||"0",
                hr=col.getAttribute("data-href")||"";
            var h='<div class="t">'+t+'</div>';
            h+='<div class="r"><i style="background:var(--danger)"></i>실패<b>'+f+'건</b></div>';
            h+='<div class="r"><i style="background:var(--ok)"></i>성공<b>'+ok+'건</b></div>';
            if(hr)h+='<div class="r" style="margin-top:4px;color:var(--accent);font-size:12px;font-weight:600;">클릭하여 상세 로그 보기 →</div>';
            tip.innerHTML=h;tip.style.opacity="1";
            var wr=wrap.getBoundingClientRect(),cx=e.clientX-wr.left+wrap.scrollLeft;
            tip.style.left=Math.max(wrap.scrollLeft+110,Math.min(wrap.scrollLeft+wrap.clientWidth-110,cx))+"px";
            tip.style.top="8px";
            tip.style.transform="translateX(-50%)";
          }});
          col.addEventListener("pointermove",function(e){{
            var wr=wrap.getBoundingClientRect(),cx=e.clientX-wr.left+wrap.scrollLeft;
            tip.style.left=Math.max(wrap.scrollLeft+110,Math.min(wrap.scrollLeft+wrap.clientWidth-110,cx))+"px";
          }});
          col.addEventListener("click",function(){{
            var hr=col.getAttribute("data-href");
            if(hr)window.location.href=hr;
          }});
        }});
        wrap.onpointerleave=function(){{tip.style.opacity="0";}};
        wrap.querySelector(".lf-threshold").addEventListener("pointerenter",function(){{tip.style.opacity="0";}});
        }}
        var panel=document.getElementById("login-failures"), pending, zoomFrame;
        if(!panel)return;
        function updateBars(incoming){{
          var svg=panel.querySelector(".lf-svg");
          var old=Array.from(svg.querySelectorAll(".lf-col")).map(function(col){{
            var bar=col.querySelector(".lf-bar"), hit=col.querySelector(".lf-hit");
            return {{start:+col.dataset.start,end:+col.dataset.end,x:+hit.getAttribute("x"),w:+hit.getAttribute("width"),
              height:bar ? +bar.getAttribute("height") : 0}};
          }});
          cancelAnimationFrame(zoomFrame);
          svg.setAttribute("aria-label",incoming.getAttribute("aria-label"));
          svg.replaceChildren(...incoming.childNodes);
          panel.querySelector("#lfTip").style.opacity="0";
          if(!old.length||window.matchMedia("(prefers-reduced-motion: reduce)").matches)return;
          var first=old[0],last=old[old.length-1];
          var chartWidth=last.x+last.w-first.x;
          var bars=Array.from(svg.querySelectorAll(".lf-bar")).map(function(bar){{
            var col=bar.parentElement, center=(+col.dataset.start + +col.dataset.end)/2;
            var match=old.find(function(item){{return item.start<=center&&center<item.end;}});
            var ratio=(center-first.start)/(last.end-first.start);
            var fromCenter=first.x+Math.max(0,Math.min(1,ratio))*chartWidth;
            var width=+bar.getAttribute("width"), height=+bar.getAttribute("height");
            return {{bar:bar, x:+bar.getAttribute("x"), width:width, height:height,
              baseline:+bar.getAttribute("y")+height, fromCenter:fromCenter,
              fromWidth:match ? Math.min(width,match.w*0.56) : 0, fromHeight:match ? match.height : 0}};
          }});
          if(!bars.length)return;
          var start=performance.now();
          function frame(now){{
            var p=Math.min(1,(now-start)/340), amount=1-Math.pow(1-p,3);
            bars.forEach(function(item){{
              var width=item.fromWidth+(item.width-item.fromWidth)*amount;
              var height=item.fromHeight+(item.height-item.fromHeight)*amount;
              var center=item.fromCenter+(item.x+item.width/2-item.fromCenter)*amount;
              item.bar.setAttribute("x",center-width/2);
              item.bar.setAttribute("width",width);
              item.bar.setAttribute("y",item.baseline-height);
              item.bar.setAttribute("height",height);
            }});
            if(p<1)zoomFrame=requestAnimationFrame(frame);
          }}
          frame(start);
        }}
        bindChart(panel);
        document.addEventListener("click",async function(e){{
          var link=e.target.closest("#login-failures .range-chip");
          if(!link||e.button!==0||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey)return;
          e.preventDefault();
          if(pending)pending.abort();
          if(link.hasAttribute("aria-current"))return;
          var request=new AbortController();
          pending=request;
          try{{
            var response=await fetch(link.href,{{signal:request.signal}});
            if(!response.ok)throw Error("range response");
            var page=new DOMParser().parseFromString(await response.text(),"text/html");
            var next=page.getElementById("login-failures");
            var ranking=page.getElementById("login-failure-ranking");
            if(!next||!ranking)throw Error("range content");
            if(request.signal.aborted)return;
            var scrollY=window.scrollY;
            updateBars(next.querySelector(".lf-svg"));
            panel.querySelector("#login-trend-subtitle").textContent=next.querySelector("#login-trend-subtitle").textContent;
            panel.querySelector("#login-range-status").hidden=true;
            panel.querySelectorAll(".chart-periods .range-chip").forEach(function(tab){{
              tab.classList.toggle("active",tab===link);
              if(tab===link)tab.setAttribute("aria-current","true");
              else tab.removeAttribute("aria-current");
            }});
            document.getElementById("login-failure-ranking").replaceWith(ranking);
            bindChart(panel);
            document.querySelectorAll("#event-trend .range-chip").forEach(function(chip){{
              var url=new URL(chip.href);
              url.searchParams.set("lf",new URL(link.href).searchParams.get("lf"));
              chip.href=url.href;
            }});
            history.replaceState(history.state,"",link.href);
            if(window.scrollY!==scrollY)window.scrollTo({{top:scrollY,behavior:"instant"}});
          }}catch(error){{
            if(request.signal.aborted)return;
            var status=panel.querySelector("#login-range-status");
            status.hidden=false;
            status.textContent="집계 단위를 바꾸지 못했습니다. 다시 눌러 주세요.";
          }}finally{{
            if(pending===request)pending=null;
          }}
        }});
      }})();</script>
    </div>
    """


_INCIDENT_TYPES = {
    "account": "계정 잠금",
    "ip": "IP 차단",
    "access": "ERP 접속 정책 거부",
    "review": "탐지 검토",
}
_INCIDENT_SEVERITIES = {"critical": "긴급", "high": "높음", "medium": "중간", "low": "낮음", "info": "정보"}
_INCIDENT_STATUSES = {"open": "미처리", "blocked": "차단 중", "released": "해제됨", "closed": "종료"}


def _incident_type(inc: IncidentView) -> str:
    if inc.is_login_source_denial:
        return "access"
    if inc.has_account_lock_rule or any(a.rule_id == AUTO_ACCOUNT_LOCK_RULE_ID for a in inc.alerts):
        return "account"
    if inc.block_rule_eligible:
        return "ip"
    return "review"


def _incident_severity(inc: IncidentView) -> str:
    levels = list(_INCIDENT_SEVERITIES)
    return next((level for level in levels if any(a.severity == level for a in inc.alerts)), "")


def _prioritize_incidents(incidents: list[IncidentView]) -> list[IncidentView]:
    newest_first = sorted(incidents, key=lambda inc: _parse_utc(inc.created_at_utc)
                          or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    severity_rank = {level: rank for rank, level in enumerate(_INCIDENT_SEVERITIES)}
    return sorted(newest_first, key=lambda inc: (
        inc.status != "open",
        severity_rank.get(_incident_severity(inc), len(severity_rank)),
        not case_time_context(inc)[1],
        _incident_type(inc) == "access",
    ))


def _incident_filter(name: str, label: str, options: dict[str, str], selected: str) -> str:
    choices = "".join(
        f'<option value="{key}"{" selected" if key == selected else ""}>{value}</option>'
        for key, value in options.items()
    )
    return f'<label>{label} <select name="{name}"><option value="">전체</option>{choices}</select></label>'


def _incident_queue_content(
    incidents: list[IncidentView],
    *,
    overview: bool = False,
    status: str = "",
    severity: str = "",
    incident_type: str = "",
) -> str:
    esc = html.escape
    ordered = _prioritize_incidents(incidents)
    if overview:
        pending = [inc for inc in ordered if inc.status == "open"]
        visible = pending[:3]
        heading = "우선 확인할 사건"
        summary = f"미처리 {len(pending)}건 · {len(visible)}건 표시"
        controls = ""
        link = '<a class="btn-ghost" href="/incidents">전체 사건 보기 →</a>'
        empty = "미처리 사건이 없습니다."
    else:
        visible = [
            inc for inc in ordered
            if (not status or inc.status == status)
            and (not severity or _incident_severity(inc) == severity)
            and (not incident_type or _incident_type(inc) == incident_type)
        ]
        heading = "사건 대기열"
        summary = f"전체 {len(incidents)}건 · {len(visible)}건 표시"
        link = ""
        empty = "조건에 맞는 사건이 없습니다." if status or severity or incident_type else "탐지된 보안 사건이 없습니다."
        controls = f"""
        <form method="get" action="/incidents" class="incident-filters">
          {_incident_filter("status", "상태", _INCIDENT_STATUSES, status)}
          {_incident_filter("severity", "심각도", _INCIDENT_SEVERITIES, severity)}
          {_incident_filter("type", "유형", _INCIDENT_TYPES, incident_type)}
          <button type="submit" class="btn-ghost">적용</button>
          <a href="/incidents" class="btn-ghost">초기화</a>
        </form>
        """
    rows = []
    for inc in visible:
        user = _fmt_user_badge(inc.username) if inc.username else ""
        target = f"<code class='ip'>{esc(inc.target_ip)}</code>" if inc.target_ip else "여러 출발지"
        level = _INCIDENT_SEVERITIES.get(_incident_severity(inc), "미지정")
        kind = _incident_type(inc)
        response = _INCIDENT_TYPES[kind]
        if any(alert.rule_id == AUTO_ACCOUNT_LOCK_RULE_ID for alert in inc.alerts):
            response = "계정 잠금 · 자동"
        elif kind == "ip":
            response = "IP 차단 · 보안팀 승인"
        elif kind == "account":
            response = "계정 잠금 전 관찰 · 자동 기준 5회"
        elif kind == "access":
            response = "비인가 IP 자동 차단 · 보안팀 임시 해제 가능"
        sev_key = _incident_severity(inc) or "info"
        status_cell = (
            f'<span class="badge b-applied" title="open">{_svg_icon("shield_off", "var(--danger)", 12)} 자동 차단 중</span>'
            if inc.is_login_source_denial and inc.status == "open"
            else _incident_response_status(inc)
        )
        row_attrs = (
            f" data-overview-incident data-incident-href='/incidents/{esc(inc.incident_id, quote=True)}'"
            f" tabindex='0' aria-label='사건 상세: {esc(_title_parts(inc.title)[0], quote=True)}'"
            if overview else ""
        )
        # '차단 해제됨'으로 표시되는 사건은 심각도가 높아도 이미 해결됐으므로 왼쪽 바만 초록색으로 둔다.
        # 계정 자동 잠금 사건은 상태 칸이 '계정 자동 잠금 기록'이라 해결 표시 대상이 아니다.
        resolved = inc.status == "released" and not any(
            alert.rule_id == AUTO_ACCOUNT_LOCK_RULE_ID for alert in inc.alerts
        )
        rows.append(
            f"<tr class='sev-row sev-{sev_key}{' sev-resolved' if resolved else ''}'{row_attrs}>"
            f"<td>{status_cell}</td><td><span class='sev sev-{sev_key}'>{level}</span></td>"
            f"<td><a class='cell-title' href='/incidents/{esc(inc.incident_id)}'>{esc(_title_parts(inc.title)[0])}</a>"
            f"<div class='cell-sub'>{response}{' · 심야·휴일 우선 확인' if case_time_context(inc)[1] else ''}</div></td>"
            f"<td>{target}<div class='cell-sub'>{user}</div></td>"
            f"<td class='nowrap'>{_rel_time(inc.created_at_utc)}</td></tr>"
        )
    table_body = "".join(rows) or f"<tr><td colspan='5' class='empty'>{empty}</td></tr>"
    table_cls = "tbl-incidents" if overview else "tbl-incidents tbl-incidents-queue"
    panel = f"""
    <div class="panel" id="incidents">
      <div class="panel-header">
        <div><h2>{heading}</h2><div class="panel-sub">{summary}</div></div>
        {link}
      </div>
      {controls}
      <table class="{table_cls}">
        <thead><tr><th>상태</th><th>심각도</th><th>사건 · 유형</th><th>출발지 · 계정</th><th>경과</th></tr></thead>
        <tbody>{table_body}</tbody>
      </table>
    </div>
    """
    if not overview:
        return panel
    # 개요: 마우스를 올리면 왼쪽 카드가 줄어들며 오른쪽에 최근 처리한 사건 5건이 나타난다.
    recent = [inc for inc in ordered if inc.status != "open"]
    recent.sort(key=lambda inc: _parse_utc(inc.created_at_utc) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    state_ko = {"blocked": "차단 중", "released": "해제됨", "closed": "종료"}
    def _item(inc):
        tone = {"blocked": "is-danger", "released": "is-released", "closed": "is-closed"}.get(inc.status, "is-closed")
        who = " · ".join(x for x in (inc.target_ip or "여러 출발지", inc.username or "") if x)
        return (
            f"<li><a class='pq-item' href='/incidents/{esc(inc.incident_id)}'><span class='pq-dot {tone}' aria-hidden='true'></span>"
            f"<span class='pq-row'><b>{esc(_title_parts(inc.title)[0])}</b><span class='pq-time'>{_rel_time(inc.created_at_utc)}</span></span>"
            f"<span class='pq-meta'><span class='pq-state'>{state_ko.get(inc.status, esc(inc.status))}</span> · "
            f"{_INCIDENT_TYPES[_incident_type(inc)]} · {esc(who)}</span></a></li>"
        )
    items = ("<ul class='pq-list'>" + "".join(_item(inc) for inc in recent[:5]) + "</ul>") if recent         else "<div class='pq-empty'>처리한 사건이 아직 없습니다.</div>"
    return f"""
    <div class="pq-split">
      {panel}
      <aside class="pq-side" aria-label="최근 처리한 사건"><div class="panel">
        <div class="panel-header"><div><h2>최근 처리한 사건</h2><div class="panel-sub">최근 {min(5, len(recent))}건</div></div></div>
        {items}
      </div></aside>
    </div>
    """


def _render_x_login_access_row(
    cases: list[IncidentView],
    login_access_client: LoginAccessClient | None,
    *,
    can_approve: bool,
    can_release: bool,
    csrf_hidden: str,
) -> str:
    esc = html.escape
    live_cases = {case.incident_id: case for case in cases if case.login_access_event is not None}
    ref_inc = next(iter(live_cases.values()), cases[0])
    access_state = None
    event = ref_inc.login_access_event
    if login_access_client is not None and event is not None:
        try:
            access_state = login_access_client.lookup_account_access(event)
        except LoginAccessError:
            pass

    status = access_state["status"] if access_state else None
    row_class, badge_class = "row-locked", "b-locked"
    detail = "X에서 새 로그인 거부"
    action = ""
    if access_state and status == "active":
        row_class, badge_class = "row-allow", "b-allow"
        label = "임시 허용 중"
        detail = _remaining(access_state.get("expires_at"))
        # 가장 최근 요청을 조회했더라도 취소는 실제 승인에 연결된 사건으로 보낸다.
        grant_case = live_cases.get(access_state.get("incident_id"))
        if grant_case is None:
            action = '<span class="muted">승인한 사건을 확인할 수 없습니다.</span>'
        else:
            ref_inc = grant_case
            disabled = "" if can_release else "disabled title='취소 권한이 필요합니다'"
            action = (
                f'<form method="post" action="/incidents/{esc(ref_inc.incident_id)}/revoke-login" class="action-inline-form">'
                f'{csrf_hidden}<input type="hidden" name="next" value="/incidents" />'
                f'<button type="submit" class="action-btn-sm" {disabled}>승인 취소</button></form>'
            )
    elif status in ("pending", "revoked"):
        label = "승인 대기" if status == "pending" else "승인 취소됨"
        disabled = "" if can_approve else "disabled title='승인 권한이 필요합니다'"
        action = (
            f'<form method="post" action="/incidents/{esc(ref_inc.incident_id)}/grant-login" class="ip-action-fields">'
            f'{csrf_hidden}<input type="hidden" name="next" value="/incidents" />'
            f'<input name="reason" type="text" value="단말 X 임시 접속 허용" maxlength="200" required class="action-reason-input" aria-label="임시 승인 사유" />'
            f'<button type="submit" class="btn-emerald action-btn-sm" {disabled}>5분 임시 승인</button></form>'
        )
    elif status == "expired":
        label = "승인 기간 만료"
    else:
        row_class, badge_class = "", "b-suspect"
        label = "승인 상태 확인 필요" if event else "기록 확인용"
        detail = "임시 승인 대상"

    if not action:
        action = f'<a class="btn-ghost" href="/incidents/{esc(ref_inc.incident_id)}">상세 →</a>'
    user_inline = f"{_fmt_user_badge(ref_inc.username)} · " if ref_inc.username else ""
    return (
        f"<tr class='{row_class}'>"
        f"<td><span class='badge {badge_class}'>{label}</span><div class='cell-sub'>{detail}</div></td>"
        f"<td><div class='ctrl-primary'>"
        f"<code class='ip' style='font-size:14.5px;'>{esc(ref_inc.target_ip)}</code>"
        f"<span class='muted' style='font-size:12px;font-weight:500;'>(단말 X)</span></div>"
        f"<div class='cell-sub' style='color:var(--text-3);'>"
        f"{user_inline}<a href='/incidents/{esc(ref_inc.incident_id)}' style='color:var(--text-3);text-decoration:underline;text-underline-offset:2px;'>{esc(ref_inc.incident_id)}</a> · 관련 {len(cases)}건</div></td>"
        f"<td class='nowrap'>{action}</td></tr>"
    )


def _ip_block_minutes(form: dict[str, list[str]]) -> int:
    if "block_unit" not in form and "block_duration" not in form:
        # 사건 상세와 기존 호출은 분 단위로 제출한다.
        return int(form.get("duration_minutes", ["10"])[0])

    unit = form.get("block_unit", [""])[0]
    if unit not in ("minutes", "hours"):
        raise ValueError("차단 시간 단위를 선택해 주세요.")
    in_hours = unit == "hours"
    factor = 60 if in_hours else 1
    maximum = MAX_BLOCK_MINUTES // factor
    raw = form.get("block_duration", [""])[0].strip()
    if not (raw.isdecimal() and len(raw) <= 5 and 1 <= int(raw) <= maximum):
        label = "시간" if in_hours else "분"
        raise ValueError(f"차단 기간은 1~{maximum:,}{label} 사이의 정수로 입력해 주세요.")
    return int(raw) * factor


def _render_incidents_control_panels(
    incidents: list[IncidentView],
    *,
    current_user: str | None = None,
    auth_enabled: bool = False,
    csrf_token: str = "",
    login_access_client: LoginAccessClient | None = None,
) -> str:
    """사건 페이지 상단 2단 조치 패널: 좌측 IP 차단·해제, 우측 ERP 계정 잠금·해제."""
    esc = html.escape
    can_approve = (not auth_enabled) or (bool(current_user) and role_can(current_user, "approve"))
    can_release = (not auth_enabled) or (bool(current_user) and role_can(current_user, "release"))
    csrf_hidden = f'<input type="hidden" name="csrf_token" value="{esc(csrf_token)}" />' if csrf_token else ""
    actor_field = "" if auth_enabled else '<input type="hidden" name="approved_by" value="soc-operator" />'

    # 방화벽은 단말 IP별로, X의 ERP 로그인 승인은 계정별로 표시한다.
    ip_cases: dict[str, list[IncidentView]] = {}
    x_cases: dict[str, list[IncidentView]] = {}
    for inc in _prioritize_incidents(incidents):
        if not inc.target_ip:
            continue
        if inc.target_ip == X_LOGIN_IP:
            if inc.is_login_source_denial:
                x_cases.setdefault(inc.username, []).append(inc)
            continue
        has_active_ap = any(ap.status == "applied" for ap in inc.approvals)
        if inc.block_rule_eligible or has_active_ap:
            ip_cases.setdefault(inc.target_ip, []).append(inc)

    ip_rows: list[str] = []
    for ip_addr, cases in ip_cases.items():
        active_for_ip = [
            (case, approval)
            for case in cases
            for approval in case.approvals
            if approval.action_type == "block" and approval.status == "applied"
        ]
        blocked_inc = next(
            (c for c in cases if any(ap.action_type == "block" and ap.status == "applied" for ap in c.approvals)),
            None,
        )
        if blocked_inc is not None:
            ip_row_cls = " class='row-locked'"
            ap = next(ap for ap in reversed(blocked_inc.approvals) if ap.status == "applied")
            dis = "" if can_release else "disabled title='해제 권한이 없는 계정입니다'"
            rem = _remaining(ap.expires_at_utc)
            active_suffix = (
                f" · 활성 승인 {len(active_for_ip)}건(현재 승인만 해제)"
                if len(active_for_ip) > 1
                else f" · 활성 승인 {len(active_for_ip)}건"
            )
            state_badge = f'<span class="badge b-locked">차단 중</span><div class="cell-sub" style="color:var(--sev-high);font-weight:500;">{rem}</div>'
            btn_html = (
                f'<form method="post" action="/incidents/{esc(blocked_inc.incident_id)}/release" class="action-inline-form">{release_fields()}'
                f'{csrf_hidden}<input type="hidden" name="approval_id" value="{esc(ap.approval_id)}" />'
                f'<input type="hidden" name="next" value="/incidents" />'
                f'<button type="submit" class="btn-emerald action-btn-sm" {dis}>차단 해제</button></form>'
            )
            ref_inc = blocked_inc
        else:
            ip_row_cls = " class='row-allow'"
            eligible_inc = next((c for c in cases if _can_approve_incident(c, True)), cases[0])
            can_act = _can_approve_incident(eligible_inc, True)
            state_badge = '<span class="badge b-allow">허용 중</span><div class="cell-sub" style="color:var(--ok);font-weight:500;">방화벽 미차단</div>'
            if can_act:
                dis = "" if can_approve else "disabled title='승인 권한이 없는 계정입니다'"
                btn_html = (
                    f'<form method="post" action="/incidents/{esc(eligible_inc.incident_id)}/approve" class="ip-action-fields" onsubmit="return confirmLongBlock(this)">'
                    f'{csrf_hidden}{actor_field}'
                    f'<input type="hidden" name="next" value="/incidents" />'
                    f'<span class="ip-block-period"><input name="block_duration" type="number" value="10" min="1" max="{MAX_BLOCK_MINUTES}" '
                    f'step="1" required aria-label="IP 차단 기간" {dis} />'
                    f'<select name="block_unit" aria-label="IP 차단 기간 단위" {dis} '
                    f'onchange="this.form.elements.block_duration.max=this.selectedOptions[0].dataset.max">'
                    f'<option value="minutes" data-max="{MAX_BLOCK_MINUTES}">분</option>'
                    f'<option value="hours" data-max="{MAX_BLOCK_MINUTES // 60}">시간</option></select></span>'
                    f'<button type="submit" class="action-btn-sm" {dis}>IP 차단</button></form>'
                )
            else:
                btn_html = '<span class="muted" style="font-size:12px;">대기</span>'
            ref_inc = eligible_inc
            active_suffix = ""
        ip_rows.append(
            f"<tr{ip_row_cls}>"
            f"<td>{state_badge}</td>"
            f"<td><div class='ctrl-primary'><code class='ip' style='font-size:14.5px;'>{esc(ip_addr)}</code></div>"
            f"<div class='cell-sub' style='color:var(--text-3);'><a href='/incidents/{esc(ref_inc.incident_id)}' style='color:var(--text-3);text-decoration:underline;text-underline-offset:2px;'>{esc(ref_inc.incident_id)}</a> · 관련 {len(cases)}건{active_suffix}</div></td>"
            f"<td class='nowrap'>{btn_html}</td>"
            f"</tr>"
        )
    for cases in x_cases.values():
        ip_rows.append(_render_x_login_access_row(
            cases, login_access_client,
            can_approve=bool(can_approve and current_user and csrf_token),
            can_release=bool(can_release and current_user and csrf_token),
            csrf_hidden=csrf_hidden,
        ))
    ip_tbody = "".join(ip_rows) or "<tr><td colspan='3' class='empty'>차단 대상 단말 IP 사건이 없습니다.</td></tr>"

    # 2) 계정 단위 최신 사건 정리 (계정 관찰·자동잠금 사건 대상)
    acc_cases: dict[str, list[IncidentView]] = {}
    for inc in _prioritize_incidents(incidents):
        acct = inc.lockable_account or (inc.username if _incident_type(inc) == "account" else None)
        if acct:
            acc_cases.setdefault(acct, []).append(inc)

    acc_rows: list[str] = []
    for acct, cases in acc_cases.items():
        ref_inc = cases[0]
        lock_state: dict[str, Any] | None = None
        lookup_err = ""
        if login_access_client is not None:
            # 같은 계정에 이미 만료·해제된 과거 사건이 있더라도, 현재 잠금 중(active)이거나 새로 발생한 미조치 사건(available)을 우선 찾는다.
            lockable_candidates = [c for c in cases if c.lockable_account]
            chosen_inc = None
            chosen_state = None
            for cand in lockable_candidates[:6]:
                try:
                    st = login_access_client.lookup_account_lock(cand.incident_id, acct)
                except LoginAccessError as exc:
                    lookup_err = str(exc)
                    st = None
                if st is None:
                    continue
                if st.get("status") == "active":
                    chosen_inc, chosen_state = cand, st
                    break
                if st.get("status") == "available" and chosen_state is None:
                    chosen_inc, chosen_state = cand, st
            if chosen_inc is not None and chosen_state is not None:
                ref_inc, lock_state = chosen_inc, chosen_state
            elif lockable_candidates and not lookup_err:
                # 모든 사건의 잠금이 이미 만료(expired)되었거나 해제 완료(unlocked)된 경우 상단 조치 패널에 쌓이지 않게 제외한다.
                continue

        status_val = lock_state["status"] if lock_state else None
        row_cls = ""
        if lock_state and status_val == "active":
            row_cls = " class='row-locked'"
            exp_txt = _remaining(lock_state.get("expires_at"))
            state_badge = f'<span class="badge b-locked">계정 잠금 중</span><div class="cell-sub" style="color:var(--sev-high);font-weight:500;">{exp_txt}</div>'
            # 같은 계정의 다른 사건을 조회해도 ERP는 실제로 잠금을 시작한 사건 번호를 돌려준다.
            lock_incident_id = lock_state.get("incident_id")
            lock_inc = next(
                (case for case in cases if case.incident_id == lock_incident_id and case.lockable_account == acct),
                None,
            )
            if lock_inc is None:
                act_html = '<span class="muted" style="font-size:12px;">잠금을 시작한 사건을 확인할 수 없습니다.</span>'
            else:
                ref_inc = lock_inc
                dis = "" if (can_release and current_user and csrf_token) else "disabled title='해제 권한이 필요합니다'"
                act_html = (
                    f'<form method="post" action="/incidents/{esc(ref_inc.incident_id)}/unlock-account" class="action-inline-form">'
                    f'{csrf_hidden}<input type="hidden" name="next" value="/incidents" />'
                    f'<input name="reason" type="text" value="보안팀 검토 후 해제" maxlength="200" required class="action-reason-input" style="width:116px;" aria-label="잠금 해제 사유" />'
                    f'<button type="submit" class="btn-emerald action-btn-sm" {dis}>잠금 해제</button></form>'
                )
        elif status_val == "available":
            row_cls = " class='row-suspect'"
            state_badge = '<span class="badge b-suspect">의심 · 조치 필요</span><div class="cell-sub" style="color:var(--warn);font-weight:500;">미잠금 · 로그인 가능</div>'
            dis = "" if (can_approve and current_user and csrf_token) else "disabled title='잠금 권한이 필요합니다'"
            act_html = (
                f'<form method="post" action="/incidents/{esc(ref_inc.incident_id)}/lock-account" class="action-inline-form">'
                f'{csrf_hidden}<input type="hidden" name="next" value="/incidents" />'
                f'<input name="reason" type="text" value="의심 계정 수동 잠금" maxlength="200" required class="action-reason-input" style="width:76px;" aria-label="계정 잠금 사유" />'
                f'<input name="duration" type="number" value="10" min="1" max="{MAX_ACCOUNT_LOCK_MINUTES}" required style="width:68px;" aria-label="계정 잠금 시간(분, 최대 24시간)" />'
                f'<button type="submit" class="action-btn-sm" {dis}>분 잠금</button></form>'
            )
        else:
            row_cls = " class='row-suspect'"
            note_txt = "연동 오류" if lookup_err else "의심 · 확인 필요"
            state_badge = f'<span class="badge b-suspect">{note_txt}</span><div class="cell-sub">상세에서 확인</div>'
            act_html = f'<a class="btn-ghost" href="/incidents/{esc(ref_inc.incident_id)}">상세 →</a>'

        acc_rows.append(
            f"<tr{row_cls}>"
            f"<td>{state_badge}</td>"
            f"<td><div class='ctrl-primary'>{_fmt_user_badge(acct, prominent=True)}</div>"
            f"<div class='cell-sub' style='color:var(--text-3);'><a href='/incidents/{esc(ref_inc.incident_id)}' style='color:var(--text-3);text-decoration:underline;text-underline-offset:2px;'>{esc(ref_inc.incident_id)}</a> · 관련 {len(cases)}건</div></td>"
            f"<td class='nowrap'>{act_html}</td>"
            f"</tr>"
        )
    acc_tbody = "".join(acc_rows) or "<tr><td colspan='3' class='empty'>현재 잠금 중이거나 조치가 필요한 ERP 계정이 없습니다.</td></tr>"

    return f"""
    <div class="grid-2col-half">
      <div class="panel ip-control-panel" style="margin-bottom:0;height:100%;">
        <div class="panel-header">
          <div>
            <h2>IP 차단 · 해제</h2>
            <div class="panel-sub">단말 IP의 차단 기간은 1~{MAX_BLOCK_MINUTES:,}분 또는 1~{MAX_BLOCK_MINUTES // 60:,}시간(최대 30일)입니다. 사건 상세에서 자주 쓰는 기간을 바로 선택할 수 있습니다. X 단말은 ERP에서 기본 거부되며 계정별로 5분간 승인합니다.</div>
          </div>
          <span class="badge b-replay">{len(ip_cases) + bool(x_cases)}개 IP</span>
        </div>
        <table class="tbl-control">
          <thead><tr><th>상태</th><th>대상 IP · 최근 사건</th><th>조치</th></tr></thead>
          <tbody>{ip_tbody}</tbody>
        </table>
      </div>

      <div class="panel" style="margin-bottom:0;height:100%;">
        <div class="panel-header">
          <div>
            <h2>계정 잠금 · 해제</h2>
            <div class="panel-sub">IP를 바꿔 가며 계정을 노릴 때 모든 단말에서 ERP 로그인을 1~{MAX_ACCOUNT_LOCK_MINUTES:,}분(최대 24시간) 잠그거나 해제합니다.</div>
          </div>
          <span class="badge b-replay">{len(acc_rows)}개 계정</span>
        </div>
        <table class="tbl-control">
          <thead><tr><th>상태</th><th>대상 계정 · 최근 사건</th><th>조치</th></tr></thead>
          <tbody>{acc_tbody}</tbody>
        </table>
      </div>
    </div>
    """


def render_incident_queue(
    store: DashboardStore | DbDashboardStore,
    current_user: str | None = None,
    auth_enabled: bool = False,
    csrf_token: str = "",
    *,
    status: str = "",
    severity: str = "",
    incident_type: str = "",
    login_access_client: LoginAccessClient | None = None,
    error_message: str | None = None,
) -> bytes:
    incidents = store.list_incidents()
    err_html = (
        f'<div class="alert-banner is-error" role="alert"><span>{html.escape(error_message)}</span></div>'
        if error_message
        else ""
    )
    panels = _render_incidents_control_panels(
        incidents,
        current_user=current_user,
        auth_enabled=auth_enabled,
        csrf_token=csrf_token,
        login_access_client=login_access_client,
    )
    head_html = _page_head(
        "탐지 · 대응",
        "사건",
        "탐지된 보안 사건에 대해 게이트웨이 IP 차단·해제와 ERP 계정 잠금·임시 접속 승인을 집행합니다.",
    )
    body = head_html + err_html + panels + _incident_queue_content(
        incidents,
        status=status if status in _INCIDENT_STATUSES else "",
        severity=severity if severity in _INCIDENT_SEVERITIES else "",
        incident_type=incident_type if incident_type in _INCIDENT_TYPES else "",
    )
    return _page_shell("관제 대시보드 · 사건", body, current_user=current_user, auth_enabled=auth_enabled,
                       refresh_seconds=5, active_path="/incidents", csrf_token=csrf_token)


_DEFAULT_ERP_DOCUMENTS: tuple[dict[str, str | None], ...] = (
    {"id": "19f7c61e-6f1c-5b31-8b9f-735689b1031e", "title": "포털 이용 안내", "department": None, "level": "public"},
    {"id": "8e35b3a6-47cb-5081-9431-51f4040736f0", "title": "정보 보호 기본 수칙", "department": None, "level": "public"},
    {"id": "e185b0be-5d68-544e-83f9-3e7272625836", "title": "문서 등급 분류 기준", "department": None, "level": "public"},
    {"id": "38800150-3588-5891-9b8e-35c0a1a5f54c", "title": "영업 업무 절차 안내", "department": "영업", "level": "dept"},
    {"id": "c7557a93-7c52-5596-9651-6d712d458827", "title": "영업팀 거래처 응대 지침", "department": "영업", "level": "secret"},
    {"id": "82942466-9254-5654-8155-96182c788a25", "title": "인사 업무 절차 안내", "department": "인사", "level": "dept"},
    {"id": "77a3f51e-3625-5458-9214-441c1317226d", "title": "급여 지급 규정", "department": "인사", "level": "secret"},
    {"id": "a7284572-358a-5781-8c80-361634147122", "title": "인사 평가 기준", "department": "인사", "level": "secret"},
    {"id": "1e256173-744a-5826-9651-664245318499", "title": "보안 업무 절차 안내", "department": "보안", "level": "dept"},
    {"id": "5939431c-2358-5974-9602-879283118824", "title": "계정 발급 및 회수 절차", "department": "보안", "level": "secret"},
)
_DOC_LEVEL_KO: dict[str, str] = {"public": "일반", "dept": "부서", "secret": "기밀"}


def _default_can_read_doc(user_dept: str, user_role: str, doc_dept: str | None, doc_level: str) -> bool:
    if doc_level == "public":
        return True
    norm_u = _ERP_DEPT_KO.get(user_dept, user_dept)
    norm_d = _ERP_DEPT_KO.get(doc_dept or "", doc_dept or "")
    if norm_u != norm_d:
        return False
    if doc_level == "dept":
        return True
    if doc_level == "secret":
        return user_role in ("manager", "팀장")
    return False


# 특별 권한 부여 목록의 한 쪽 크기. 같은 계정·문서 조합은 한 번만 부여되고 최대 24시간 뒤 회수되므로 평소에는 한 쪽으로 끝난다.
_PERM_GRANT_PAGE_SIZE = 8


def render_permissions_page(
    current_user: str | None = None,
    auth_enabled: bool = False,
    csrf_token: str = "",
    *,
    login_access_client: LoginAccessClient | None = None,
    error_message: str | None = None,
    notice_message: str | None = None,
    grant_page: int = 1,
    view: str = "account",
    acct: str = "",
    doc: str = "",
) -> bytes:
    """권한 부여 카테고리: (1) 타 부서·기밀 문서 개별 권한 부여·회수 (2) 퇴사 계정 전체 권한 회수·복구 (3) 계정별 문서 권한 현황.

    부여 목록은 _PERM_GRANT_PAGE_SIZE건씩 쪽으로 나눠 보여 준다(grant_page, 1부터)."""
    esc = html.escape
    can_approve = (not auth_enabled) or (bool(current_user) and role_can(current_user, "approve"))
    can_release = (not auth_enabled) or (bool(current_user) and role_can(current_user, "release"))
    csrf_hidden = f'<input type="hidden" name="csrf_token" value="{esc(csrf_token)}" />' if csrf_token else ""

    overview: dict[str, Any] | None = None
    fetch_err = ""
    if login_access_client is not None:
        try:
            overview = login_access_client.fetch_permissions()
        except LoginAccessError as exc:
            fetch_err = str(exc)

    if overview and isinstance(overview.get("users"), list) and overview["users"]:
        users_list = overview["users"]
    else:
        users_list = [
            {
                "username": uname,
                "department": dept,
                "role": "manager" if role_ko == "팀장" else "member",
                "account_status": "active",
                "revoked_by": None,
                "revoke_reason": None,
                "revoked_at": None,
            }
            for uname, (dept, role_ko) in _ERP_USER_DIRECTORY.items()
        ]

    if overview and isinstance(overview.get("documents"), list) and overview["documents"]:
        docs_list = overview["documents"]
    else:
        docs_list = [dict(d) for d in _DEFAULT_ERP_DOCUMENTS]

    grants_list: list[dict[str, Any]] = (
        overview["grants"] if (overview and isinstance(overview.get("grants"), list)) else []
    )
    active_grants = [g for g in grants_list if g.get("status") == "active"]
    active_grant_by_pair: dict[tuple[str, str], dict[str, Any]] = {
        (str(g.get("username")), str(g.get("document_id"))): g for g in active_grants
    }
    active_grant_pairs = set(active_grant_by_pair)

    err_banner = ""
    if error_message or fetch_err:
        msg = error_message or fetch_err
        err_banner = f'<div class="alert-banner is-error" role="alert"><span>{esc(msg)}</span></div>'
    notice_banner = ""
    if notice_message:
        notice_banner = f'<div class="alert-banner is-ok" role="status"><span>{esc(notice_message)}</span></div>'

    # 1) 좌측 패널: 자료실 문서 특별 권한 부여 · 회수
    user_options: list[str] = []
    user_access_map: dict[str, dict[str, str]] = {}
    user_meta_map: dict[str, dict[str, Any]] = {}
    for u in users_list:
        uname = str(u.get("username") or "")
        udept = _ERP_DEPT_KO.get(str(u.get("department") or ""), str(u.get("department") or ""))
        urole_raw = str(u.get("role") or "")
        urole_ko = _ERP_ROLE_KO.get(urole_raw.lower(), urole_raw)
        is_rev = u.get("account_status") == "revoked"
        status_suffix = " — 퇴사(권한 회수됨)" if is_rev else ""
        dis_opt = " disabled" if is_rev else ""
        user_options.append(
            f'<option value="{esc(uname)}"{dis_opt}>{esc(uname)} ({esc(udept)} · {esc(urole_ko)}){status_suffix}</option>'
        )
        doc_states: dict[str, str] = {}
        default_cnt = 0
        granted_cnt = 0
        selectable_cnt = 0
        for d in docs_list:
            did = str(d.get("id") or "")
            ddept = str(d.get("department") or "")
            dlevel = str(d.get("level") or "public")
            if _default_can_read_doc(udept, urole_raw, ddept, dlevel):
                doc_states[did] = "default"
                default_cnt += 1
            elif (uname, did) in active_grant_pairs:
                doc_states[did] = "granted"
                granted_cnt += 1
            else:
                doc_states[did] = "restricted"
                if dlevel != "public":
                    selectable_cnt += 1
        user_access_map[uname] = doc_states
        user_meta_map[uname] = {
            "dept": udept,
            "role": urole_ko,
            "default_cnt": default_cnt,
            "granted_cnt": granted_cnt,
            "selectable_cnt": selectable_cnt,
        }

    doc_options: list[str] = []
    restricted_doc_cnt = 0
    for d in docs_list:
        dlevel = str(d.get("level") or "public")
        if dlevel == "public":
            continue
        restricted_doc_cnt += 1
        did = str(d.get("id") or "")
        dtitle = str(d.get("title") or "")
        ddept_raw = str(d.get("department") or "")
        ddept_ko = _ERP_DEPT_KO.get(ddept_raw, ddept_raw) or "공통"
        dlevel_ko = _DOC_LEVEL_KO.get(dlevel, dlevel)
        doc_options.append(
            f'<option value="{esc(did)}" data-base-label="{esc(f"{dtitle} ({ddept_ko} · {dlevel_ko})")}">'
            f'{esc(dtitle)} ({esc(ddept_ko)} · {esc(dlevel_ko)})</option>'
        )

    dis_grant = "" if (can_approve and login_access_client is not None) else "disabled title='승인 권한 또는 ERP 연동이 필요합니다'"
    dis_revoke = "" if (can_release and login_access_client is not None) else "disabled title='해제 권한 또는 ERP 연동이 필요합니다'"

    # 부여가 많아져도 화면이 끝없이 길어지지 않도록 쪽으로 나눈다. 쪽 번호는 주소(?gp=)에 두어 자동 새로고침 뒤에도 유지된다.
    grant_total = len(active_grants)
    grant_pages = max(1, -(-grant_total // _PERM_GRANT_PAGE_SIZE))
    grant_page = min(max(1, int(grant_page)), grant_pages)
    grant_start = (grant_page - 1) * _PERM_GRANT_PAGE_SIZE

    grant_rows: list[str] = []
    for g in active_grants[grant_start:grant_start + _PERM_GRANT_PAGE_SIZE]:
        guname = str(g.get("username") or "")
        gdid = str(g.get("document_id") or "")
        gdtitle = str(g.get("document_title") or "")
        gddept = _ERP_DEPT_KO.get(str(g.get("doc_department") or ""), str(g.get("doc_department") or ""))
        gdlevel_raw = str(g.get("doc_level") or "")
        gdlevel = _DOC_LEVEL_KO.get(gdlevel_raw, gdlevel_raw)
        greason = str(g.get("reason") or "")
        gby = str(g.get("granted_by") or "")
        gexp_txt = _remaining(g.get("expires_at"), plain=True) if g.get("expires_at") else "상시 유지"
        lv_cls = "b-warn" if gdlevel_raw == "secret" else "b-replay"
        g_known = _ERP_USER_DIRECTORY.get(guname.lower())
        g_user_dept = _ERP_DEPT_KO.get(str(g.get("department") or (g_known[0] if g_known else "")), str(g.get("department") or (g_known[0] if g_known else "")))
        g_user_role = _ERP_ROLE_KO.get(str(g.get("role") or (g_known[1] if g_known else "")).lower(), str(g.get("role") or (g_known[1] if g_known else "")))
        g_user_meta = " · ".join(p for p in (g_user_dept, g_user_role) if p)
        grant_rows.append(
            f"<tr data-source='grant {esc(guname)}'>"
            f"<td><span style='font-size:13.5px;font-weight:600;color:var(--text);'>{_pv(guname)}</span>"
            + (f"<div class='cell-sub'>{esc(g_user_meta)}</div>" if g_user_meta else "")
            + f"</td>"
            f"<td>"
            f"<div style='display:flex;align-items:center;gap:6px;flex-wrap:wrap;'>"
            f"<span class='cell-title'>{esc(gdtitle)}</span>"
            f"<span class='badge {lv_cls}'>{esc(gddept)} · {esc(gdlevel)}</span>"
            f"<span class='badge b-allow'>자동 회수까지 {esc(gexp_txt)}</span>"
            f"</div>"
            f"<div class='cell-sub'>사유: {esc(greason)} · 승인자: <b>{esc(gby)}</b></div>"
            f"</td>"
            f"<td class='nowrap'>"
            f"<form method='post' action='/permissions/action' class='action-inline-form'>"
            f"{csrf_hidden}<input type='hidden' name='action' value='revoke_doc' />"
            f"<input type='hidden' name='gp' value='{grant_page}' />"
            f"<input type='hidden' name='username' value='{esc(guname)}' />"
            f"<input type='hidden' name='document_id' value='{esc(gdid)}' />"
            f"<input name='reason' type='text' value='업무 협조 종료 · 권한 회수' maxlength='200' required class='action-reason-input' aria-label='권한 회수 사유' />"
            f"<button type='submit' class='btn-warn-outline action-btn-sm' {dis_revoke}>권한 회수</button>"
            f"</form></td></tr>"
        )
    grant_tbody = (
        "".join(grant_rows)
        or "<tr><td colspan='3' class='empty'>현재 타 부서·기밀 문서에 추가로 부여된 특별 권한이 없습니다. 위 입력란에서 계정과 문서를 골라 임시 열람 권한을 부여할 수 있습니다.</td></tr>"
    )
    # 쪽이 하나뿐이면(8건 이하) 쪽 이동 줄을 만들지 않아 평소 화면은 그대로다.
    grant_end = min(grant_start + _PERM_GRANT_PAGE_SIZE, grant_total)
    grant_pager = (
        f'<div class="perm-grant-pager"><span class="muted">총 <b>{grant_total:,}</b>건 · {grant_start + 1:,}–{grant_end:,}건</span>'
        + _event_pagination(grant_page, grant_pages, base="/permissions", param="gp", label="특별 권한 부여 목록 페이지")
        + "</div>"
        if grant_pages > 1 else ""
    )

    pending_requests = overview.get("requests", []) if overview else []
    request_rows = []
    for req in pending_requests:
        request_id = int(req["id"])
        request_dept = str(req.get("doc_department") or "")
        request_level = str(req.get("doc_level") or "")
        duration = int(req["duration_minutes"])
        duration_label = f"{duration // 60}시간" if duration % 60 == 0 else f"{duration}분"
        tag = "b-warn" if request_level == "secret" else "b-replay"
        # ISO 타임스탬프는 다른 관제 표와 같은 한국 시간 표기를 사용한다.
        created = datetime.fromisoformat(req["created_at"]).astimezone(KST).strftime("%m-%d %H:%M")
        request_rows.append(
            f"<tr><td><span class='cell-title'>{esc(req['username'])}</span>"
            f"<div class='cell-sub'>{esc(created)}</div></td>"
            f"<td><span class='cell-title'>{esc(req['document_title'])}</span> "
            f"<span class='badge {tag}'>{esc(_ERP_DEPT_KO.get(request_dept, request_dept))} · "
            f"{esc(_DOC_LEVEL_KO.get(request_level, request_level))}</span>"
            f"<div class='cell-sub' style='overflow-wrap:anywhere;'>"
            f"{esc(duration_label)} 요청 · {esc(req['reason'])}</div></td>"
            f"<td class='nowrap'><form method='post' action='/permissions/action' class='action-inline-form'>"
            f"{csrf_hidden}<input type='hidden' name='access_request_id' value='{request_id}' />"
            f"<button type='submit' name='action' value='approve_doc_request' class='secondary action-btn-sm' {dis_grant}>승인</button>"
            f"<button type='submit' name='action' value='reject_doc_request' class='btn-warn-outline action-btn-sm' {dis_grant}>반려</button>"
            f"</form></td></tr>"
        )
    request_tbody = "".join(request_rows) or (
        "<tr><td colspan='3' class='empty'>"
        + ("열람 요청을 확인할 수 없습니다." if overview is None else "승인 대기 중인 열람 요청이 없습니다.")
        + "</td></tr>"
    )

    # 2) 우측 패널: 퇴사 · 계정 전체 권한 회수 (영구 차단) 및 복구
    account_rows: list[str] = []
    matrix_rows: list[str] = []
    dept_counts: dict[str, int] = {"행정": 0, "인사": 0, "보안": 0}
    granted_user_cnt = 0
    # 3) 하단 권한 격자의 열 = 문서. 부서별로 묶고(공통 먼저), 묶음 안에서는 일반 → 부서 → 기밀 순서로 둔다.
    #    문서의 부서는 열 묶음 제목에 한 번, 기밀 여부는 문서 제목 아래에 한 번만 적는다(칸마다 되풀이하지 않는다).
    level_rank = {"public": 0, "dept": 1, "secret": 2}
    grid_docs: list[dict[str, Any]] = []
    for idx, d in enumerate(docs_list):
        g_dept_raw = str(d.get("department") or "")
        grid_docs.append({
            "id": str(d.get("id") or ""), "title": str(d.get("title") or ""), "dept_raw": g_dept_raw,
            "dept": _ERP_DEPT_KO.get(g_dept_raw, g_dept_raw) or "공통",
            "level": str(d.get("level") or "public"), "idx": idx,
        })
    group_order: list[str] = ["공통"] if any(g["dept"] == "공통" for g in grid_docs) else []
    for g in grid_docs:
        if g["dept"] not in group_order:
            group_order.append(g["dept"])
    grid_docs.sort(key=lambda g: (group_order.index(g["dept"]), level_rank.get(g["level"], 9), g["idx"]))
    for i, g in enumerate(grid_docs):
        g["group_start"] = i == 0 or grid_docs[i - 1]["dept"] != g["dept"]
    # '특별 권한 보유' 필터 버튼의 숫자 = 그 필터로 실제로 남는 행 수(초록 칸이 하나라도 있는 계정).
    grid_special_users = 0
    grid_secret_users = 0   # 부서 밖 기밀 문서를 특별 부여로 열람 중인 계정 수
    grid_soon_users = 0     # 1시간 안에 만료되는 특별 부여가 있는 계정 수
    now_utc = datetime.now(timezone.utc)
    acct_data: list[dict[str, Any]] = []  # 계정 기준·문서 기준 보기가 함께 쓰는 계정별 요약
    for u in users_list:
        uname = str(u.get("username") or "")
        udept = _ERP_DEPT_KO.get(str(u.get("department") or ""), str(u.get("department") or ""))
        dept_counts[udept] = dept_counts.get(udept, 0) + 1
        urole_raw = str(u.get("role") or "")
        is_rev = u.get("account_status") == "revoked"
        user_active_grants = [g for g in active_grants if str(g.get("username")) == uname]
        if user_active_grants:
            granted_user_cnt += 1

        if is_rev:
            retire_row_cls = " class='row-locked'"
            rev_reason = str(u.get("revoke_reason") or "퇴사 처리")
            rev_by = str(u.get("revoked_by") or "soc-operator")
            state_badge = '<span class="badge b-locked">퇴사 · 전면 차단</span><div class="cell-sub" style="white-space:nowrap;color:var(--sev-high);font-weight:500;">로그인·열람 불가</div>'
            sub_info = f"회수 사유: {esc(rev_reason)} · 처리자: {esc(rev_by)}"
            act_form = (
                f"<form method='post' action='/permissions/action' class='action-inline-form'>"
                f"{csrf_hidden}<input type='hidden' name='action' value='restore_account' />"
                f"<input type='hidden' name='username' value='{esc(uname)}' />"
                f"<input name='reason' type='text' value='재직 · 기본 권한 복구' maxlength='200' required class='action-reason-input' aria-label='권한 복구 사유' />"
                f"<button type='submit' class='btn-emerald action-btn-sm' style='min-width:96px;' {dis_revoke}>권한 복구</button></form>"
            )
        else:
            retire_row_cls = ""
            state_sub = (
                f'<div class="cell-sub" style="white-space:nowrap;color:var(--ok);font-weight:500;">특별 권한 {len(user_active_grants)}건</div>'
                if user_active_grants
                else '<div class="cell-sub" style="white-space:nowrap;">기본 권한 활성</div>'
            )
            state_badge = f'<span class="badge b-allow">재직 · 정상</span>{state_sub}'
            scope_txt = "부서 + 기밀 문서" if urole_raw == "manager" else "부서 일반 문서"
            sub_info = f"기본 범위: 공통 일반 + {esc(udept)} ({scope_txt})"
            act_form = (
                f"<form method='post' action='/permissions/action' class='action-inline-form'>"
                f"{csrf_hidden}<input type='hidden' name='action' value='retire_account' />"
                f"<input type='hidden' name='username' value='{esc(uname)}' />"
                f"<input name='reason' type='text' value='퇴사 · 전체 권한 회수' maxlength='200' required class='action-reason-input' aria-label='퇴사 회수 사유' />"
                f"<button type='submit' class='btn-danger-outline action-btn-sm' style='min-width:92px;' {dis_grant}>퇴사 · 전면 회수</button></form>"
            )

        account_rows.append(
            f"<tr{retire_row_cls} data-source='account {esc(uname)} {esc(udept)}'>"
            f"<td>{state_badge}</td>"
            f"<td>{_fmt_user_badge(uname, udept, urole_raw, prominent=True, compact=True)}"
            f"<div class='cell-sub'>{sub_info}</div></td>"
            f"<td class='nowrap'>{act_form}</td>"
            f"</tr>"
        )

        # 3) 하단 권한 격자 행: 한 계정 = 한 행, 한 문서 = 한 칸. 칸에는 기호만 두고 자세한 내용은 마우스를 올렸을 때(title) 보여 준다.
        cells: list[str] = []
        special_cnt = 0
        base_list: list[dict[str, Any]] = []
        limited_list: list[dict[str, Any]] = []
        special_list: list[tuple[dict[str, Any], dict[str, Any]]] = []
        secret_special = soon_special = 0
        soonest: datetime | None = None
        for g in grid_docs:
            gs = " pm-gs" if g["group_start"] else ""
            label = f'{g["title"]} · {g["dept"]} · {_DOC_LEVEL_KO.get(g["level"], g["level"])}'
            if is_rev:
                limited_list.append(g)
                mark = f'<span class="pm-mark pm-blocked" title="{esc(label)} — 퇴사로 차단">✕</span>'
            elif _default_can_read_doc(udept, urole_raw, g["dept_raw"], g["level"]):
                base_list.append(g)
                mark = f'<span class="pm-mark pm-default" title="{esc(label)} — 기본 열람">●</span>'
            elif (uname, g["id"]) in active_grant_pairs:
                special_cnt += 1
                g_rec = active_grant_by_pair.get((uname, g["id"]), {})
                special_list.append((g, g_rec))
                exp_dt = _parse_utc(g_rec.get("expires_at"))
                if g["level"] == "secret":
                    secret_special += 1
                if exp_dt is not None:
                    soonest = exp_dt if soonest is None or exp_dt < soonest else soonest
                    if (exp_dt - now_utc).total_seconds() <= 3600:
                        soon_special += 1
                rem = _remaining(g_rec.get("expires_at"), plain=True) if g_rec.get("expires_at") else "상시 유지"
                why = f' · 사유: {g_rec.get("reason")}' if g_rec.get("reason") else ""
                who = f' · 승인자: {g_rec.get("granted_by")}' if g_rec.get("granted_by") else ""
                mark = (f'<span class="pm-mark pm-special" title="{esc(label)} — 특별 부여 · {esc(rem)}{esc(why)}{esc(who)}">'
                        f'{esc(rem.replace(" 남음", ""))}</span>')
            else:
                limited_list.append(g)
                mark = f'<span class="pm-mark pm-none" title="{esc(label)} — 열람 제한">·</span>'
            cells.append(f'<td class="pm-cell{gs}">{mark}</td>')

        if is_rev:
            status = '<span class="pm-status is-bad">퇴사 · 로그인·열람 불가</span>'
        elif special_cnt:
            status = f'<span class="pm-status is-ok">재직 · 특별 권한 {special_cnt}건</span>'
        else:
            status = '<span class="pm-status">재직 · 기본 권한</span>'
        perm_tags = (["all", udept, "revoked" if is_rev else "active"] + (["granted"] if special_cnt else [])
                     + (["secret"] if secret_special else []) + (["soon"] if soon_special else []))
        grid_special_users += 1 if special_cnt else 0
        grid_secret_users += 1 if secret_special else 0
        grid_soon_users += 1 if soon_special else 0
        acct_data.append({
            "uname": uname, "udept": udept, "urole": urole_raw, "is_rev": is_rev, "base": base_list, "limited": limited_list,
            "special": special_list, "secret": secret_special, "soon": soon_special, "soonest": soonest, "tags": perm_tags,
        })
        matrix_rows.append(
            f"<tr{' class=\"row-locked\"' if is_rev else ''} data-source='matrix {esc(uname)} {esc(udept)}' data-perm-tags='{esc(' '.join(perm_tags))}'>"
            f"<td class='pm-acct'>{_fmt_user_badge(uname, udept, urole_raw, prominent=True, compact=True)}<div class='pm-sub'>{status}</div></td>"
            + "".join(cells) + "</tr>"
        )

    # 격자 머리말: 1줄 = 부서 묶음, 2줄 = 문서 제목(기밀 문서는 제목 아래에 '기밀').
    group_heads: list[str] = []
    doc_heads: list[str] = []
    for g in grid_docs:
        gs = " pm-gs" if g["group_start"] else ""
        if g["group_start"]:
            span = sum(1 for x in grid_docs if x["dept"] == g["dept"])
            group_heads.append(f'<th class="pm-group{gs}" colspan="{span}" scope="colgroup">{esc(g["dept"])}</th>')
        lvl = _DOC_LEVEL_KO.get(g["level"], g["level"])
        secret_tag = '<span class="pm-secret">기밀</span>' if g["level"] == "secret" else ""
        doc_heads.append(
            f'<th class="pm-doc{gs}" scope="col" title="{esc(g["title"])} · {esc(g["dept"])} · {esc(lvl)}">{esc(g["title"])}{secret_tag}</th>'
        )

    revoked_cnt = sum(1 for u in users_list if u.get("account_status") == "revoked")
    active_user_cnt = len(users_list) - revoked_cnt
    access_json = json.dumps(user_access_map, ensure_ascii=False)
    meta_json = json.dumps(user_meta_map, ensure_ascii=False)

    head_html = _page_head(
        "접근 제어 · 권한 관리",
        "권한 부여",
        "ERP 자료실의 타 부서·기밀 문서 열람 권한을 개별 부여·회수하거나, 퇴사 계정의 모든 권한과 세션을 일괄 차단합니다.",
    )
    metrics_html = _stat_strip([
        ("관리 대상 계정", f"{len(users_list)}명", f"재직 {active_user_cnt}명 · 퇴사 차단 {revoked_cnt}명", ""),
        ("활성 특별 권한", f"{len(active_grants)}건", f"부여 계정 {granted_user_cnt}명 · 만료 시 자동 회수", "is-accent" if active_grants else ""),
        ("퇴사 · 전면 차단", f"{revoked_cnt}명", "ERP 로그인 · 문서 열람 즉시 차단", "is-danger" if revoked_cnt else ""),
        ("보호 문서 (부서·기밀)", f"{restricted_doc_cnt}건", f"전체 자료실 문서 {len(docs_list)}건 중", ""),
    ])

    # 4) 하단 권한 현황: 요약·예외를 먼저, 문서 이름 나열은 뒤로. 보기는 계정 기준 / 문서 기준 / 격자 비교 세 가지이고,
    #    상세는 선택한 행 바로 아래에 연다. 선택은 주소에 두어 자동 새로고침 뒤에도 유지한다.
    view = view if view in ("account", "doc", "grid") else "account"
    sel_acct = acct if acct in {a["uname"] for a in acct_data} else ""
    sel_doc = doc if doc in {g["id"] for g in grid_docs} else ""

    def pv_url(view_name: str, *, anchor: str = "perm-status", **extra: str) -> str:
        params = {"view": view_name, **{k: v for k, v in extra.items() if v}}
        if grant_page > 1:
            params["gp"] = str(grant_page)
        return esc("/permissions?" + urllib.parse.urlencode(params) + "#" + anchor, quote=True)

    def detail_link(view_name: str, selected: bool, key: str, value: str) -> str:
        row_key = f'data-perm-detail="{esc(value)}"'
        if selected:
            return (f'<a class="btn-ghost action-btn-sm" href="{pv_url(view_name)}" '
                    f'aria-expanded="true" aria-controls="perm-detail" {row_key}>닫기</a>')
        href = pv_url(view_name, anchor="perm-selection", **{key: value})
        return f'<a class="btn-ghost action-btn-sm" href="{href}" aria-expanded="false" {row_key}>상세 ›</a>'

    def doc_meta(g: dict[str, Any]) -> str:
        return f'{g["dept"]} · {_DOC_LEVEL_KO.get(g["level"], g["level"])}'

    def rem_txt(rec: dict[str, Any]) -> str:
        return _remaining(rec.get("expires_at"), plain=True) if rec.get("expires_at") else "상시 유지"

    def expiry_cell(dt: datetime | None) -> str:
        if dt is None:
            return '<span class="muted">—</span>'
        soon_cls = ' class="perm-soon"' if (dt - now_utc).total_seconds() <= 3600 else ""
        return f"<span{soon_cls}>{esc(_remaining(dt.isoformat(), plain=True))}</span>"

    def revoke_form(guname: str, gdid: str) -> str:
        ctx = ""
        if view == "account" and sel_acct:
            ctx = f"<input type='hidden' name='acct' value='{esc(sel_acct)}' />"
        elif view == "doc" and sel_doc:
            ctx = f"<input type='hidden' name='doc' value='{esc(sel_doc)}' />"
        return (
            "<form method='post' action='/permissions/action' class='action-inline-form'>"
            f"{csrf_hidden}<input type='hidden' name='action' value='revoke_doc' />"
            f"<input type='hidden' name='gp' value='{grant_page}' /><input type='hidden' name='view' value='{view}' />{ctx}"
            f"<input type='hidden' name='username' value='{esc(guname)}' /><input type='hidden' name='document_id' value='{esc(gdid)}' />"
            "<input name='reason' type='text' value='업무 협조 종료 · 권한 회수' maxlength='200' required class='action-reason-input' aria-label='권한 회수 사유' />"
            f"<button type='submit' class='btn-warn-outline action-btn-sm' {dis_revoke}>권한 회수</button></form>"
        )

    def grant_line(a: dict[str, Any], g: dict[str, Any], rec: dict[str, Any], who: str) -> str:
        """특별 부여 한 건: 무엇을(문서) · 언제까지 · 왜 · 누가 승인 + 회수 버튼."""
        return (
            f'<div class="pd-line"><div class="pd-info"><div class="pd-main">{who}</div>'
            f'<div class="pd-sub">{esc(rem_txt(rec))} · 사유: {esc(str(rec.get("reason") or "-"))} · 승인자: {esc(str(rec.get("granted_by") or "-"))}</div></div>'
            f"{revoke_form(a['uname'], g['id'])}</div>"
        )

    def plain_list(items: list[str], empty: str) -> str:
        return "".join(f'<div class="pd-plain">{x}</div>' for x in items) or f'<div class="pd-empty">{empty}</div>'

    def detail_cols(special_html: str, special_n: int, base_html: str, base_n: int, limit_html: str, limit_n: int) -> str:
        return (
            '<div class="perm-detail-cols">'
            f'<div><div class="pd-title">특별 부여 <span class="pd-n pd-n-ok">{special_n}</span></div>{special_html}</div>'
            f'<div><div class="pd-title">기본 열람 <span class="pd-n">{base_n}</span></div>{base_html}</div>'
            f'<div><div class="pd-title">열람 제한 <span class="pd-n">{limit_n}</span></div>{limit_html}</div>'
            "</div>"
        )

    def status_badge(a: dict[str, Any]) -> str:
        return '<span class="badge b-locked">퇴사 · 차단</span>' if a["is_rev"] else '<span class="badge b-allow">재직</span>'

    def detail_row(label: str, columns: str) -> str:
        return (
            '<tr class="perm-detail-row"><td colspan="7">'
            f'<div class="perm-detail" id="perm-detail" role="region" aria-label="{esc(label)}">'
            f'{columns}</div></td></tr>'
        )

    filter_bar = ""
    if view in ("account", "grid"):
        def chip(mode: str, label: str, count: int, dot: str = "", tip: str = "") -> str:
            dot_html = f'<i class="chip-dot" style="background:var({dot})"></i>' if dot else ""
            title_attr = f' title="{esc(tip)}"' if tip else ""
            active = " active" if mode == "all" else ""
            return (f'<button type="button" class="filter-chip{active}" data-perm-filter="{esc(mode)}"{title_attr} '
                    f"onclick=\"setPermMatrixFilter('{esc(mode)}')\">{dot_html}{label} <span class=\"chip-cnt\">{count}</span></button>")
        filter_bar = (
            '<div class="filter-chip-bar perm-matrix-filters" role="toolbar" aria-label="예외·부서·상태 필터">'
            + chip("all", "전체", len(users_list))
            + chip("granted", "특별 권한 보유", grid_special_users, "--ok", "특별 부여로 부서 밖 문서를 열람 중인 계정")
            + chip("secret", "기밀 예외", grid_secret_users, "--warn", "부서 밖 기밀 문서를 특별 부여로 열람 중인 계정")
            + chip("soon", "1시간 내 만료", grid_soon_users, "--warn", "특별 부여가 1시간 안에 만료되는 계정")
            + chip("revoked", "퇴사 · 차단", revoked_cnt, "--danger")
            + '<span class="perm-chip-sep" aria-hidden="true"></span>'
            + "".join(chip(d_name, d_name, dept_counts.get(d_name, 0)) for d_name in ("행정", "인사", "보안"))
            + f'<span id="permMatrixFilterCount" class="muted" style="margin-left:auto;font-size:12.5px;">표시: {len(users_list)} / {len(users_list)}개 계정</span>'
            "</div>"
        )

    if view == "account":
        ordered = sorted(enumerate(acct_data), key=lambda t: (-t[1]["secret"], -len(t[1]["special"]), t[0]))
        rows_html = []
        for _, a in ordered:
            sel = a["uname"] == sel_acct
            n_sp = len(a["special"])
            sp_cell = '<span class="muted">—</span>' if not n_sp else (
                f'<span class="perm-ok perm-n">{n_sp}건</span>' + (f'<span class="perm-warn">기밀 {a["secret"]}</span>' if a["secret"] else "")
            )
            link = detail_link("account", sel, "acct", a["uname"])
            cls = " ".join(c for c in ("row-locked" if a["is_rev"] else "", "perm-sel" if sel else "") if c)
            cls_attr = f' class="{cls}"' if cls else ""
            selected_id = ' id="perm-selection"' if sel else ""
            rows_html.append(
                f"<tr{cls_attr}{selected_id} data-source='matrix {esc(a['uname'])} {esc(a['udept'])}' data-perm-tags='{esc(' '.join(a['tags']))}'>"
                f"<td>{_fmt_user_badge(a['uname'], a['udept'], a['urole'], prominent=True, compact=True)}</td>"
                f"<td>{status_badge(a)}</td><td class='perm-n'>{len(a['base'])}건</td><td>{sp_cell}</td>"
                f"<td>{expiry_cell(a['soonest'])}</td><td class='perm-n'>{len(a['limited'])}건</td><td class='perm-act'>{link}</td></tr>"
            )
            if sel:
                sp_html = "".join(
                    grant_line(a, g, rec, f'<b>{esc(g["title"])}</b> <span class="pd-meta">{esc(doc_meta(g))}</span>')
                    for g, rec in a["special"]
                ) or '<div class="pd-empty">부여된 특별 문서 없음</div>'
                fmt = lambda g: f'{esc(g["title"])} <span class="pd-meta">{esc(doc_meta(g))}</span>'
                rows_html.append(detail_row(f"{a['uname']} 문서 열람 상세", detail_cols(
                    sp_html, n_sp, plain_list([fmt(g) for g in a["base"]], "없음"), len(a["base"]),
                    plain_list([fmt(g) for g in a["limited"]], "없음"), len(a["limited"]),
                )))
        status_body = (
            '<table class="tbl-perm-acct"><thead><tr><th>계정</th><th>상태</th><th>기본 열람</th><th>특별 부여</th>'
            '<th>가장 빠른 만료</th><th>열람 제한</th><th></th></tr></thead>'
            f'<tbody>{"".join(rows_html)}</tbody></table>'
        )
        if not sel_acct:
            status_body += '<div class="perm-hint">‘상세’를 누르면 해당 계정 바로 아래에 문서와 특별 부여 사유가 펼쳐집니다.</div>'
        status_sub = "계정마다 한 줄로 요약합니다. 특별 부여·기밀 예외가 많은 계정이 위에 나옵니다."
        status_badge_txt = f"총 {len(users_list)}개 계정"
    elif view == "doc":
        doc_data = []
        for g in grid_docs:
            readers = [a for a in acct_data if any(x["id"] == g["id"] for x in a["base"])]
            specials = [(a, rec) for a in acct_data for (gg, rec) in a["special"] if gg["id"] == g["id"]]
            limited = [a for a in acct_data if any(x["id"] == g["id"] for x in a["limited"])]
            exps = [e for e in (_parse_utc(rec.get("expires_at")) for _, rec in specials) if e is not None]
            doc_data.append({"g": g, "readers": readers, "specials": specials, "limited": limited, "soonest": min(exps) if exps else None})
        doc_data.sort(key=lambda d_: (-len(d_["specials"]), -level_rank.get(d_["g"]["level"], 0), d_["g"]["idx"]))
        rows_html = []
        for d_ in doc_data:
            g = d_["g"]
            sel = g["id"] == sel_doc
            sp_cell = f'<span class="perm-ok perm-n">{len(d_["specials"])}명</span>' if d_["specials"] else '<span class="muted">—</span>'
            lvl_html = (f'<span class="perm-warn" style="margin-left:0;">{esc(_DOC_LEVEL_KO.get(g["level"], g["level"]))}</span>'
                        if g["level"] == "secret" else esc(_DOC_LEVEL_KO.get(g["level"], g["level"])))
            link = detail_link("doc", sel, "doc", g["id"])
            selected_attrs = ' class="perm-sel" id="perm-selection"' if sel else ""
            rows_html.append(
                f"<tr{selected_attrs} data-source='doc {esc(g['title'])}'>"
                f"<td><b>{esc(g['title'])}</b></td><td>{esc(g['dept'])}</td><td>{lvl_html}</td>"
                f"<td class='perm-n'>{len(d_['readers'])}명</td><td>{sp_cell}</td><td>{expiry_cell(d_['soonest'])}</td>"
                f"<td class='perm-act'>{link}</td></tr>"
            )
            if sel:
                who = lambda a: _fmt_user_badge(a["uname"], a["udept"], a["urole"])
                sp_html = "".join(grant_line(a, g, rec, who(a)) for a, rec in d_["specials"]) or '<div class="pd-empty">부여된 계정 없음</div>'
                lim_items = [who(a) + (' <span class="pd-meta">퇴사 · 차단</span>' if a["is_rev"] else "") for a in d_["limited"]]
                rows_html.append(detail_row(f"{g['title']} 열람 가능 계정 상세", detail_cols(
                    sp_html, len(d_["specials"]), plain_list([who(a) for a in d_["readers"]], "없음"), len(d_["readers"]),
                    plain_list(lim_items, "없음"), len(d_["limited"]),
                )))
        status_body = (
            '<table class="tbl-perm-doc"><thead><tr><th>문서</th><th>부서</th><th>등급</th><th>기본 열람</th><th>특별 부여</th>'
            '<th>가장 빠른 만료</th><th></th></tr></thead>'
            f'<tbody>{"".join(rows_html)}</tbody></table>'
        )
        if not sel_doc:
            status_body += '<div class="perm-hint">‘상세’를 누르면 해당 문서 바로 아래에 열람 가능 계정과 특별 부여 사유가 펼쳐집니다.</div>'
        status_sub = "문서마다 한 줄로 요약합니다. 특별 부여가 있는 문서가 위에 나옵니다."
        status_badge_txt = f"총 {len(grid_docs)}개 문서"
    else:
        status_body = (
            '<div class="pm-legend" aria-label="기호 설명">'
            '<span><span class="pm-mark pm-default">●</span>기본 열람</span>'
            '<span><span class="pm-mark pm-special">58분</span>특별 부여 (남은 시간)</span>'
            '<span><span class="pm-mark pm-none">·</span>열람 제한</span>'
            '<span><span class="pm-mark pm-blocked">✕</span>퇴사로 차단</span></div>'
            '<div class="pm-scroll"><table class="tbl-perm-grid"><thead>'
            f'<tr><th class="pm-acct-h" rowspan="2" scope="col">계정</th>{"".join(group_heads)}</tr>'
            f'<tr>{"".join(doc_heads)}</tr></thead><tbody>{"".join(matrix_rows)}</tbody></table></div>'
        )
        status_sub = "계정(행)이 자료실 문서(열)를 지금 볼 수 있는지 한눈에 비교합니다. 칸에 마우스를 올리면 문서와 특별 부여 사유를 볼 수 있습니다."
        status_badge_txt = f"총 {len(users_list)}개 계정"
    view_tabs = (
        '<nav class="perm-views" aria-label="권한 현황 보기">'
        + "".join(
            f'<a href="{pv_url(key)}"{" aria-current=" + chr(34) + "page" + chr(34) if key == view else ""}>{label}</a>'
            for key, label in (("account", "계정 기준"), ("doc", "문서 기준"), ("grid", "격자 비교"))
        )
        + "</nav>"
    )
    status_panel = f"""
    <div class="panel" id="perm-status">
      <div class="panel-header">
        <div>
          <h2>계정별 자료실 문서 열람 권한 현황</h2>
          <div class="panel-sub">{status_sub}</div>
        </div>
        <span class="badge b-replay">{status_badge_txt}</span>
      </div>
      {view_tabs}
      <p class="muted" role="status" id="perm-status-message" hidden></p>
      {filter_bar}
      {status_body}
    </div>
    """

    body = f"""
    {head_html}
    {err_banner}{notice_banner}
    {metrics_html}

    <div class="grid-2col-half perm-split">
      <div class="panel" style="margin-bottom:0;height:100%;">
        <div class="panel-header">
          <div>
            <h2>자료실 문서 특별 권한 부여 · 회수</h2>
            <div class="panel-sub">타 부서 업무 협조(예: 행정 사원의 인사 문서 열람)가 필요할 때 개별 문서를 선택해 권한을 부여하거나 회수합니다.</div>
          </div>
          <span class="badge {'b-allow' if active_grants else 'b-replay'}">활성 {len(active_grants)}건</span>
        </div>

        <form method="post" action="/permissions/action" class="perm-form-card">
          {csrf_hidden}
          <input type="hidden" name="action" value="grant_doc" />
          <div class="perm-form-row1">
            <div>
              <label for="permUserSelect" class="perm-field-label">1. 대상 계정</label>
              <select id="permUserSelect" name="username" onchange="syncPermDocSelect()" class="perm-input">
                {"".join(user_options)}
              </select>
            </div>
            <div>
              <label for="permDocSelect" class="perm-field-label">2. 부여할 자료실 문서 (개별 선택)</label>
              <select id="permDocSelect" name="document_id" class="perm-input">
                {"".join(doc_options)}
              </select>
            </div>
          </div>
          <div class="perm-form-row2">
            <div>
              <label for="permDurationSelect" class="perm-field-label">3. 유지 시간 (자동 회수)</label>
              <select id="permDurationSelect" name="duration_minutes" class="perm-input">
                <option value="10">10분 후 자동 회수</option>
                <option value="30">30분 후 자동 회수</option>
                <option value="60" selected>1시간 후 자동 회수</option>
                <option value="120">2시간 후 자동 회수</option>
                <option value="240">4시간 후 자동 회수</option>
                <option value="480">8시간 후 자동 회수</option>
                <option value="1440">24시간 후 자동 회수</option>
              </select>
            </div>
            <div>
              <label for="permGrantReason" class="perm-field-label">4. 부여 사유</label>
              <input id="permGrantReason" name="reason" type="text" value="타 부서 업무 협조 지원" maxlength="200" required class="perm-input" />
            </div>
          </div>
          <div class="perm-form-foot">
            <div class="perm-scope-bar">
              <span id="permUserScopeHint">선택한 계정의 기본 열람 가능 문서는 자동으로 제외됩니다.</span>
              <span class="muted">만료 시각이 지나면 ERP에서 자동 회수됩니다.</span>
            </div>
            <button type="submit" class="secondary perm-submit" {dis_grant}>권한 부여</button>
          </div>
        </form>

        <table class="tbl-perm-grants">
          <thead><tr><th>대상 계정</th><th>추가 부여된 문서 · 사유</th><th>조치</th></tr></thead>
          <tbody>{grant_tbody}</tbody>
        </table>
        {grant_pager}
        <div class="panel-header" style="margin-top:16px;">
          <h2>문서 열람 요청</h2>
          <span class="badge b-warn">승인 대기 {len(request_rows)}{"+" if len(request_rows) == 25 else ""}건</span>
        </div>
        <table class="tbl-perm-grants">
          <thead><tr><th>요청 계정</th><th>문서 · 요청 사유</th><th>조치</th></tr></thead>
          <tbody>{request_tbody}</tbody>
        </table>
      </div>

      <div class="panel" style="margin-bottom:0;height:100%;">
        <div class="panel-header">
          <div>
            <h2>퇴사 · 계정 전체 권한 회수</h2>
            <div class="panel-sub">퇴사·보직 해임 시 추가 부여된 문서 권한을 모두 회수하고, 기본 문서 열람과 ERP 로그인·활성 세션을 즉시 차단합니다.</div>
          </div>
          <span class="badge {'b-locked' if revoked_cnt else 'b-replay'}">퇴사 차단 {revoked_cnt}명</span>
        </div>
        <table class="tbl-retire">
          <thead><tr><th>상태</th><th>대상 계정 · 권한 범위</th><th>조치</th></tr></thead>
          <tbody>{"".join(account_rows)}</tbody>
        </table>
      </div>
    </div>

    {status_panel}

    <script>
    (function() {{
      var panel = document.getElementById("perm-status");
      var pending;
      var renderedSearch = window.location.search;

      async function loadPermStatus(url, link) {{
        if (pending) pending.abort();
        var request = new AbortController();
        pending = request;
        window.__permStatusLoading = true;
        panel.setAttribute("aria-busy", "true");
        try {{
          var response = await fetch(url, {{signal: request.signal}});
          if (!response.ok) throw new Error("permission status response");
          var page = new DOMParser().parseFromString(await response.text(), "text/html");
          var incoming = page.getElementById("perm-status");
          if (!incoming) throw new Error("permission status content");
          if (request.signal.aborted) return;

          var focused = link && document.activeElement === link;
          var rowKey = focused ? link.getAttribute("data-perm-detail") : null;
          var scrollTop = window.scrollY;
          if (link && url.search !== window.location.search) history.pushState(history.state, "", url);
          panel.replaceChildren(...incoming.childNodes);
          renderedSearch = url.search;
          setPermMatrixFilter(activePermFilter);
          if (focused) {{
            var nextFocus = rowKey === null
              ? panel.querySelector(".perm-views a[aria-current='page']")
              : Array.from(panel.querySelectorAll("a[data-perm-detail]")).find(function(action) {{
                  return action.getAttribute("data-perm-detail") === rowKey;
                }});
            if (nextFocus) nextFocus.focus({{preventScroll: true}});
          }}
          if (window.scrollY !== scrollTop) window.scrollTo({{top: scrollTop, behavior: "instant"}});
        }} catch (error) {{
          if (request.signal.aborted) return;
          var message = panel.querySelector("#perm-status-message");
          message.textContent = "권한 현황을 불러오지 못했습니다. 다시 시도해 주세요.";
          message.hidden = false;
        }} finally {{
          if (pending === request) {{
            pending = null;
            window.__permStatusLoading = false;
            panel.removeAttribute("aria-busy");
          }}
        }}
      }}

      panel.addEventListener("click", function(event) {{
        var link = event.target.closest(".perm-views a, a[data-perm-detail]");
        if (!link || event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
        var url = new URL(link.href);
        event.preventDefault();
        if (!pending && url.search === renderedSearch && url.search === window.location.search) return;
        loadPermStatus(url, link);
      }});
      window.addEventListener("popstate", function() {{
        if (window.location.pathname === "/permissions" && (pending || window.location.search !== renderedSearch)) {{
          loadPermStatus(new URL(window.location.href));
        }}
      }});
    }})();
    </script>

    <script>
    (function() {{
      var accessMap = {access_json};
      var metaMap = {meta_json};
      window.syncPermDocSelect = function() {{
        var uSel = document.getElementById("permUserSelect");
        var dSel = document.getElementById("permDocSelect");
        var hint = document.getElementById("permUserScopeHint");
        if (!uSel || !dSel) return;
        var states = accessMap[uSel.value] || {{}};
        var meta = metaMap[uSel.value];
        var firstSelectable = null;
        for (var i = 0; i < dSel.options.length; i++) {{
          var opt = dSel.options[i];
          var base = opt.getAttribute("data-base-label") || opt.textContent;
          var st = states[opt.value];
          if (st === "default") {{
            opt.disabled = true;
            opt.textContent = base + " — 기본 열람 가능";
          }} else if (st === "granted") {{
            opt.disabled = true;
            opt.textContent = base + " — 이미 부여됨";
          }} else {{
            opt.disabled = false;
            opt.textContent = base;
            if (!firstSelectable) firstSelectable = opt.value;
          }}
        }}
        if (firstSelectable && (dSel.selectedOptions.length === 0 || dSel.selectedOptions[0].disabled)) {{
          dSel.value = firstSelectable;
        }}
        if (hint && meta) {{
          hint.innerHTML = "<b>" + uSel.value + "</b> (" + meta.dept + " · " + meta.role + ") — 기본 열람 <b>" + meta.default_cnt + "건</b> · 특별 부여 <b>" + meta.granted_cnt + "건</b> · 추가 부여 가능 <b>" + meta.selectable_cnt + "건</b>";
        }}
      }};
      syncPermDocSelect();
    }})();
    </script>
    """
    return _page_shell(
        "관제 대시보드 · 권한 부여",
        body,
        current_user=current_user,
        auth_enabled=auth_enabled,
        refresh_seconds=5,
        active_path="/permissions",
        csrf_token=csrf_token,
    )


def render_incident_list(
    store: DashboardStore | DbDashboardStore,
    current_user: str | None = None,
    auth_enabled: bool = False,
    csrf_token: str = "",
    login_range: str = "hourly",
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
    } | {i.target_ip for i in blocked_incs if i.target_ip and _incident_type(i) == "ip"}
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
    waf_types = ("waf_detected", "waf_blocked")
    waf_events = store.list_recent_events(limit=1, source="caddy", event_types=waf_types)
    if hasattr(store, "count_recent_events"):
        waf_count = store.count_recent_events(source="caddy", event_types=waf_types)
    else:
        waf_count = len(store.list_recent_events(limit=100000, source="caddy", event_types=waf_types))
    waf_stats = {"count": waf_count, "last_received_utc": waf_events[0].get("received_at_utc") or waf_events[0]["event_ts_utc"]} if waf_events else {"count": 0, "last_received_utc": None}
    et_key = event_tab if event_tab in _EVENT_TREND_TABS else "hourly"
    lf_safe = login_range if login_range in _LOGIN_RANGES else "hourly"
    timeline_svg, timeline_sub = _bk_area_chart(store, et_key)
    et_chips = "".join(
        f'<a class="range-chip{" active" if key == et_key else ""}" href="/?lf={lf_safe}&et={key}"'
        + (' aria-current="true"' if key == et_key else "")
        + f'>{esc(label)}</a>'
        for key, label in _EVENT_TREND_TABS.items()
    )

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
            f'<a href="{link_href}" style="color:var(--text);font-weight: 600;white-space:nowrap;">{esc(title_ko)}</a>'
            f'<span style="color:{status_col};font-size:12px;white-space:nowrap;">● {status_txt}</span>'
            f"</div>"
            f'<div style="display:flex;align-items:center;gap:10px;white-space:nowrap;flex-shrink:0;margin-left:auto;">'
            f"{ts_html}"
            f'<strong style="color:var(--text);min-width:58px;text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums;">{cnt:,} 이벤트</strong>'
            f"</div></div>"
        )

    ev_modal_rows = "".join(
        f"<tr>"
        f"<td>{_fmt_log_time(ev['event_ts_utc'])}</td>"
        f"<td>{_fmt_source_badge(ev['source'])}</td>"
        f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
        f"<td>{_event_line(ev, no_action=True)}</td>"
        f"<td class='raw-col'>{_raw_cell(ev)}</td>"
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
                    f"<form method='post' action='/incidents/{esc(inc.incident_id)}/release' style='display:inline-block;'>{release_fields()}"
                    f"{csrf_hidden}<input type='hidden' name='approval_id' value='{esc(latest_ap.approval_id)}' />"
                    f"<button type='submit' class='btn-emerald' style='padding:5px 10px;font-size:12px;'>{_svg_icon('unlock', 'var(--on-accent)', 12)} 즉시 차단 해제</button></form> "
                    f"<a href='/incidents/{esc(inc.incident_id)}' class='btn-ghost' style='padding:5px 10px;font-size:12px;'>상세 콘솔 →</a>"
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
                    f"<button type='submit' style='padding:5px 10px;font-size:12px;'>{_svg_icon('shield_off', 'var(--text)', 12)} 10분 즉시 차단 승인</button></form>"
                )
            else:
                act_html = f"<a href='/incidents/{esc(inc.incident_id)}' class='btn-ghost' style='padding:5px 10px;font-size:12px;'>상세 분석 보기 →</a>"

            out.append(
                f"<tr class='clickable-row' data-incident-row>"
                f"<td><a data-incident-detail href='/incidents/{esc(inc.incident_id)}'><strong><code>{esc(inc.incident_id)}</code></strong></a></td>"
                f"<td><strong style='color:var(--text);'>{esc(_title_parts(inc.title)[0])}</strong><div style='font-size:12px;color:var(--text-2);'>{_title_en_tag(_title_parts(inc.title)[1])}근거 {len(inc.evidence_events)}건 · 상관 연결 {len(inc.correlations)}건</div></td>"
                f"<td>{_incident_response_status(inc)}</td>"
                f"<td><code style='color:var(--danger);font-weight: 600;'>{esc(inc.target_ip or '여러 출발지')}</code></td>"
                f"<td><strong style='color:var(--accent);'>{esc(inc.username or '여러 계정')}</strong></td>"
                f"<td>{_fmt_ts(inc.created_at_utc, include_utc=False)}</td>"
                f"<td style='white-space:nowrap;'>{act_html}</td>"
                f"</tr>"
            )
        return "".join(out)

    all_approvals_rows = [_approval_row(ap, inc.incident_id, block_effects.get(ap.approval_id)) for inc in incidents for ap in inc.approvals]
    approvals_table_html = "".join(all_approvals_rows) or "<tr><td colspan='8' class='empty'>기록된 방화벽 승인·해제 이력이 없습니다.</td></tr>"
    holo_templates_html = f"""
    <template id="holo-tpl-events">
      <div class="pop-note">전체 수집 이벤트 <b>{total_collected:,}건</b> 중 최신 <b>{min(25, len(recent_events))}건</b>을 표시합니다. 과거 기록은 이벤트 화면에서 검색·페이지 이동으로 확인할 수 있습니다.</div>
      <div class="pop-stats three">
        <div class="pop-stat"><div class="k"><i class="d source-gateway"></i>Gateway · 방화벽</div><div class="v">{gw_cnt:,}건</div><a href="/logs/gateway">전용 화면 →</a></div>
        <div class="pop-stat"><div class="k"><i class="d source-caddy"></i>Caddy · 웹 프록시</div><div class="v">{caddy_cnt:,}건</div><a href="/logs/caddy">전용 화면 →</a></div>
        <div class="pop-stat"><div class="k"><i class="d source-erp"></i>ERP · 인증 서버</div><div class="v">{erp_cnt:,}건</div><a href="/logs/erp">전용 화면 →</a></div>
      </div>
      <table class="log-tbl overview-pop-table">
        <thead><tr><th>시각 (KST)</th><th>출처</th><th>이벤트</th><th>내용</th><th class='raw-col'>원본 raw_id</th></tr></thead>
        <tbody>{ev_modal_rows}</tbody>
      </table>
      <div class="pop-foot"><a class="btn-ghost" href="/events">전체 이벤트 보기 →</a></div>
    </template>

    <template id="holo-tpl-open">
      <div class="pop-note">
        현재 미처리(<code>open</code>) 상태인 보안 사건 <b>{open_cnt}건</b> (즉시 차단 승인 가능: <b>{eligible_open_cnt}건</b>)의 상세 목록입니다. 이 창에서 바로 차단을 승인하거나 상세 콘솔로 이동할 수 있습니다.
      </div>
      <table class="overview-pop-table">
        <thead><tr><th>사건 ID</th><th>탐지 내용 · 근거 수</th><th>상태</th><th>공격 의심 IP</th><th>대상 계정</th><th>발생 시각</th><th>즉시 조치 / 상세</th></tr></thead>
        <tbody>{_inc_detail_rows_html(open_incs, "현재 미처리(open) 상태인 보안 사건이 없습니다.")}</tbody>
      </table>
    </template>

    <template id="holo-tpl-blocked">
      <div class="pop-note">
        현재 게이트웨이 방화벽에 <code>DROP</code> 차단 규칙이 적용 중인 사건 <b>{blocked_cnt}건</b>입니다. 이 창에서 바로 차단을 해제하거나 상태를 조회할 수 있습니다.
      </div>
      <table class="overview-pop-table">
        <thead><tr><th>사건 ID</th><th>탐지 내용 · 근거 수</th><th>상태</th><th>차단된 IP</th><th>대상 계정</th><th>발생 시각</th><th>즉시 해제 / 상세</th></tr></thead>
        <tbody>{_inc_detail_rows_html(blocked_incs, "현재 활성 차단(blocked) 중인 사건이 없습니다.")}</tbody>
      </table>
    </template>

    <template id="holo-tpl-released">
      <div class="pop-note">
        차단 해제 및 통신 복구가 완료된 사건(<b>{released_cnt}건</b>) 및 전체 방화벽 승인·해제 감사 이력입니다.
      </div>
      <h4 class="pop-h">해제 · 복구 완료 사건 목록</h4>
      <table class="overview-pop-table" style="margin-bottom:20px;">
        <thead><tr><th>사건 ID</th><th>탐지 내용 · 근거 수</th><th>상태</th><th>대상 IP</th><th>대상 계정</th><th>발생 시각</th><th>재차단 / 상세</th></tr></thead>
        <tbody>{_inc_detail_rows_html(released_incs, "아직 차단 해제(released)된 사건이 없습니다.")}</tbody>
      </table>
      <h4 class="pop-h">승인 · 해제 감사 이력</h4>
      <table class="overview-pop-table">
        <thead>{_approval_head(True)}</thead>
        <tbody>{approvals_table_html}</tbody>
      </table>
    </template>
    """

    donut_html = _bk_donut(stats_map)
    now_utc = datetime.now(timezone.utc)
    csrf_hidden_w = f'<input type="hidden" name="csrf_token" value="{esc(csrf_token)}" />' if csrf_token else ""

    health_html = _health_strip(stats_map, waf_stats)

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
        f"<td class='nowrap'><form method='post' action='/incidents/{esc(inc.incident_id)}/release' style='display:inline'>{release_fields()}"
        f"{csrf_hidden_w}<input type='hidden' name='approval_id' value='{esc(ap.approval_id)}' />"
        f"<button type='submit' class='btn-emerald' {'' if auth_ok else 'disabled'}>해제</button></form></td></tr>"
        for inc, ap in active_aps
    ) or "<tr><td colspan='5' class='empty'>현재 차단 중인 IP가 없습니다.</td></tr>"
    next_expiry = min((d for d in (_parse_utc(ap.expires_at_utc) for _, ap in active_aps) if d is not None), default=None)
    next_txt = f" · 다음 해제 {_remaining(next_expiry.isoformat(), plain=True)}" if next_expiry else ""

    # --- 최다 의심 출발지 · 계정 (최근 인증 실패 기준) ---
    # 로그인 실패 추이 그래프와 같은 기간·같은 데이터로 집계해 숫자가 어긋나지 않게 한다.
    from collections import Counter
    lf_key, lf_boundaries = _login_window(login_range)
    try:
        login_events = [
            event for event in store.get_login_events(lf_boundaries[0])
            if lf_boundaries[0] <= event[0] < lf_boundaries[-1]
        ]
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
            f'<div class="topn-row"><a class="pv" href="#" data-pv="{esc(k)}" title="{esc(k)} · 이 값으로 필터">{esc(k)}</a>'
            f'<span class="topn-bar"><i style="width:{max(4, int(v / top * 100))}%"></i></span><b>{v}</b></div>'
            for k, v in items
        )

    fail_total = sum(fail_ip.values())

    # --- 최근 이벤트 · 승인 이력 ---
    recent_ev_rows = "".join(
        f"<tr><td>{_fmt_log_time(ev['event_ts_utc'])}{_run_badge(ev)}</td><td>{_fmt_source_badge(ev['source'])}</td>"
        f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
        f"<td>{_event_line(ev, no_action=True)}</td>"
        f"<td class='raw-col'>{_raw_cell(ev)}</td></tr>"
        for ev in _collapse_runs(recent_events[:30])[:8]
    ) or "<tr><td colspan='5' class='empty'>수집된 이벤트가 없습니다.</td></tr>"
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

    def _metric(tpl: str, modal_title: str, modal_badge: str, label: str, value: str, sub: str, tone: str = "", primary: bool = False) -> str:
        return (
            f'<div class="metric{" is-primary" if primary else ""}" role="button" tabindex="0" onclick="openHoloTemplate(\'{tpl}\', \'{modal_title}\', \'{modal_badge}\')" '
            f'onkeydown="if(event.key===\'Enter\'||event.key===\' \'){{event.preventDefault();this.click()}}">'
            f'<div class="metric-label">{label}</div>'
            f'<div class="metric-val {tone}">{value}</div>'
            f'<div class="metric-sub">{sub}</div></div>'
        )

    metrics_html = (
        _metric("holo-tpl-open", f"미처리 보안 사건 ({open_cnt}건)", "조치 필요", "미처리 사건", f"{open_cnt}",
                f"즉시 승인 가능 {eligible_open_cnt}건{oldest_txt}", "is-danger" if open_cnt > 0 else "", True)
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

    {_incident_queue_content(incidents, overview=True)}

    <div class="overview-login-grid">
      {_login_failure_panel(store, lf_key, login_events, event_tab=et_key, boundaries=lf_boundaries, incidents=incidents)}
      <div class="panel" id="login-failure-ranking">
        <div class="panel-header">
          <div>
            <h2>실패 많은 IP · 계정</h2>
            <div class="panel-sub">{_LOGIN_RANGES[lf_key][1]} 누적 실패 {fail_total}건 · 왼쪽 그래프와 같은 기간</div>
          </div>
        </div>
        <div class="topn-grid">
          <div><div class="topn-title">출발지 IP</div>{_topn(fail_ip, "집계할 인증 실패가 없습니다.")}</div>
          <div><div class="topn-title">계정</div>{_topn(fail_user, "집계할 인증 실패가 없습니다.")}</div>
        </div>
      </div>
    </div>

      <div class="panel" id="active-blocks-overview">
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

    <div class="grid-2col" style="margin-top:20px;">
      <div class="panel" id="event-trend" style="margin-bottom:0;scroll-margin-top:20px;">
        <div class="panel-header" style="margin-bottom:6px;flex-wrap:nowrap;align-items:flex-start;gap:12px;">
          <div style="min-width:0;flex:1;">
            <h2>이벤트 추이</h2>
            <div class="panel-sub" id="event-trend-subtitle">{esc(timeline_sub)}</div>
          </div>
        </div>
        <nav class="chart-periods" aria-label="이벤트 집계 단위">{et_chips}</nav>
        <p class="panel-sub" role="status" hidden></p>
        {timeline_svg}
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
          <div class="panel-sub">가장 최근에 수집된 3계층 이벤트 · 실시간 수집이 기본이며 재현·가상 수집만 따로 표시</div>
        </div>
        <a class="btn-ghost" href="/events">전체 보기 {_svg_icon("arrow_right", "currentColor", 13)}</a>
      </div>
      <table class="log-tbl">
        <thead><tr><th>시각 (KST)</th><th>출처</th><th>이벤트</th><th>내용</th><th class='raw-col'>원본 raw_id</th></tr></thead>
        <tbody>{recent_ev_rows}</tbody>
      </table>
    </div>

      <div class="panel" style="margin-top:20px;">
        <div class="panel-header">
          <div>
            <h2>승인 · 조치 이력</h2>
            <div class="panel-sub">최근 방화벽 차단 승인과 해제 기록</div>
          </div>
        </div>
        <table class="overview-history">
          <thead><tr><th>경과</th><th>상태</th><th>대상 IP · 승인자</th><th>사건</th></tr></thead>
          <tbody>{history_rows}</tbody>
        </table>
      </div>

    """
    return _page_shell("관제 대시보드 · 현황 및 사건 목록", body, current_user=current_user, auth_enabled=auth_enabled, refresh_seconds=5, active_path="/", csrf_token=csrf_token)


_STREAM_HEAD = (
    '<div class="panel-header"><div><h2>스트림</h2>'
    '<div class="panel-sub">최근 50건 · 5초마다 자동 갱신 · IP와 계정을 누르면 그 값으로 필터됩니다.</div></div>'
    '<div class="panel-actions">{toggle}<a class="btn-ghost" href="{href}">{icon} 지금 새로고침</a></div></div>'
)


def _stream_head(href: str, group: bool | None = None) -> str:
    toggle = ""
    if group is not None:
        # 원본 로그 화면은 한 줄에 한 건이 기본이다. 반복 묶기는 사용자가 직접 켠다.
        toggle = (f'<a class="btn-ghost" href="{html.escape(href)}{"" if group else "?group=1"}" '
                  f'aria-pressed="{str(group).lower()}">{"원본 그대로 보기" if group else "반복 묶어 보기"}</a>')
    return _STREAM_HEAD.format(href=html.escape(href), icon=_svg_icon("refresh", "currentColor", 13), toggle=toggle)


def _waf_rule_label(rule_id: Any) -> str:
    """Show the attack family first, while retaining the original rule IDs."""
    raw = str(rule_id or "").strip()
    if raw == "ERP-LOGIN-BODY-LIMIT":
        label, origin = "로그인 요청 크기 초과", "자체 규칙"
    else:
        ids = [part.strip() for part in raw.split(",")]
        ids = [part for part in ids if part.isdecimal()]
        families = []
        if any(part.startswith("942") for part in ids):
            families.append("SQL 인젝션")
        if any(part.startswith("941") for part in ids):
            families.append("XSS")
        label = " · ".join(families) + " 의심" if families else "기타 WAF 규칙 일치"
        origin = "OWASP CRS 규칙" if ids else "규칙 ID"
    return (f'<span class="waf-type">{html.escape(label)}</span>'
            f'<div class="cell-sub waf-rule-id">{html.escape(origin)} {html.escape(raw or "-")}</div>')


def _gateway_trend_panel(store: DashboardStore | DbDashboardStore, now_utc: datetime | None = None) -> str:
    now = (now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    kst = timezone(timedelta(hours=9))
    rows = []
    for index in range(24):
        hour = start + timedelta(hours=index)
        local = hour.astimezone(kst)
        rows.append({"t": local.strftime("%H시"), "span": local.strftime("%m-%d %H:00") + " KST",
                     "allow": 0, "deny": 0})
    for stamp, source, kind, *_ in store.get_trend_events(start):
        if source != "gateway" or kind not in {"fw_allow", "fw_deny"} or stamp > now:
            continue
        index = int((stamp - start).total_seconds() // 3600)
        if 0 <= index < 24:
            rows[index]["allow" if kind == "fw_allow" else "deny"] += 1
    allowed, denied = sum(r["allow"] for r in rows), sum(r["deny"] for r in rows)
    payload = {"rows": rows, "height": 160, "series": [
        {"key": "allow", "label": "허용", "color": "var(--text-3)"},
        {"key": "deny", "label": "차단", "color": "var(--danger)"},
    ]}
    return ('<section class="panel"><div class="panel-header"><div><h2>허용 · 차단 추이</h2>'
            f'<div class="panel-sub">최근 24개 시간대 · 한국시간 · 허용 {allowed:,}건 · 차단 {denied:,}건 · 조사용 기록 포함</div>'
            '</div></div>'
            f'<div class="bk-chart" id="bk-gateway-traffic" data-chart="{_bk_json_attr(payload)}"></div></section>')


def _icmp_denial_panel(store: DashboardStore | DbDashboardStore, now_utc: datetime | None = None) -> str:
    """Recorded live ICMP denials, with raw IDs for evidence lookup."""
    now = (now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    hours = [now - timedelta(hours=23 - index) for index in range(24)]
    counts = dict(store.get_icmp_denial_hours(hours[0], now + timedelta(hours=1)))
    values = [counts.get(hour.strftime("%Y-%m-%dT%H"), 0) for hour in hours]
    total = sum(values)
    recent = store.get_recent_icmp_denials(limit=10)
    rows = "".join(
        f'<tr><td>{_fmt_log_time(row["event_ts_utc"])}</td>'
        f'<td><code>{html.escape(str(row.get("src_ip") or "-"))}</code> → '
        f'<code>{html.escape(str(row.get("dst_ip") or "-"))}</code></td>'
        f'<td><span class="ev-act warn">거부</span><div class="cell-sub">{html.escape("브로드캐스트 요청 차단" if row.get("rule_id") == "POLICY-ICMP-BROADCAST" else "허용된 웹 접속 이외의 요청")}</div><div class="waf-rule-id">{html.escape(str(row.get("rule_id") or "-"))}</div></td>'
        f'<td>{_copy_id_chip(row.get("raw_id"))}'
        f'<div class="cell-sub">{html.escape(str(row.get("file_path") or "gateway.jsonl"))}'
        f' · 위치 {html.escape(str(row.get("line_offset") if row.get("line_offset") is not None else "-"))}</div></td></tr>'
        for row in recent
    ) or '<tr><td colspan="4" class="empty">기록된 ICMP 거부가 없습니다.</td></tr>'
    return (
        '<details class="panel" id="icmp-denials"><summary style="cursor:pointer;font-size:13px;color:var(--text-2);">'
        f'<strong>ICMP 차단</strong> · 최근 24개 시간대 {total:,}건'
        ' <span class="muted">· 상세 기록 펼치기</span></summary>'
        '<div class="panel-sub" style="margin:12px 0 6px;">핑 등 ICMP 트래픽 · 실시간 수집 기록만 집계 · 아래는 최근 10건</div>'
        '<table class="icmp-trace"><thead><tr><th>시각</th><th>출발지 → 목적지</th><th>거부 규칙</th><th>원본 raw_id</th></tr></thead>'
        f'<tbody>{rows}</tbody></table><p class="panel-sub" style="margin-top:12px;">ICMP 거부는 실시간으로 수집된 게이트웨이 기록만 집계합니다. 핑은 웹 접속 허용 기록과 별개이며 위 건수에 포함되지 않습니다. 같은 출발지에서 60초 안에 10건 이상 쌓이면 사건(RULE-GW-ICMP-DENIAL-001)이 만들어지고, IP 차단 승인 대상은 아닙니다. 규칙 ID와 원본 raw_id로 근거를 추적할 수 있습니다.</p></details>'
    )


def render_source_logs(
    store: DashboardStore | DbDashboardStore,
    log_kind: str,
    current_user: str | None = None,
    auth_enabled: bool = False,
    csrf_token: str = "",
    group: bool = False,
    scope_query: dict[str, str] | None = None,
) -> bytes:
    esc = html.escape
    scoped_events, scope_controls, extra_panel = source_scope(store, log_kind, scope_query)
    if log_kind == "erp":
        events = scoped_events
        ok_cnt = sum(1 for e in events if e.get("event_type") == "login_success")
        fail_cnt = sum(1 for e in events if e.get("event_type") == "login_failed")
        out_cnt = sum(1 for e in events if e.get("event_type") == "logout")
        trust_cnt = sum(1 for e in events if e.get("client_ip_trusted"))
        head = _page_head("로그 소스", "ERP 인증", "ERP 서버의 로그인 성공 · 실패(401) · 로그아웃 기록입니다.")
        metrics = _stat_strip([
            ("조회 이벤트", f"{len(events)}", "선택 기간 전체", ""),
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
        outside_attempts = sum(bool(event_time_context(e).get("outside")) for e in events)
        exception_attempts = sum(bool(event_time_context(e).get("exception")) for e in events)
        insight += _insight("심야 · 휴일 로그인 시도", f'<span class="insight-item">{outside_attempts}건 · 승인 예외 {exception_attempts}건 · 성공·실패·거부 포함</span>')
        headers = "<tr><th>이벤트</th><th>발생 시각</th><th>단말 IP</th><th>계정</th><th>IP 신뢰</th><th>수집 방식</th><th>추적 ID</th></tr>"
        rows = "".join(
            f'<tr class="{"row-erp-failed" if ev.get("event_type") == "login_failed" else ""}">'
            f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))} {_time_badge(ev)}</td>"
            f"<td>{_fmt_log_time(ev['event_ts_utc'])}{_run_badge(ev)}</td>"
            f"<td>{_fmt_ip_badge(ev.get('client_ip'), alert=(ev.get('event_type') == 'login_failed'))}</td>"
            f"<td>{_fmt_user_badge(ev.get('username'), ev.get('department'), ev.get('user_role'))}</td>"
            f"<td>{_fmt_trusted_badge(bool(ev['client_ip_trusted']))}</td>"
            f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
            f"<td><div class='idstack'>{_copy_id_chip(ev.get('request_id'), prefix='req:')}{_copy_id_chip(ev.get('raw_id'), prefix='raw:')}</div></td>"
            f"</tr>"
            for ev in (_collapse_runs(events[:50]) if group else events[:50])
        )
        colspan = 7
    elif log_kind == "gateway":
        extra_panel += _icmp_denial_panel(store)
        events = scoped_events
        allow_cnt = sum(1 for e in events if e.get("event_type") == "fw_allow")
        deny_cnt = sum(1 for e in events if e.get("event_type") == "fw_deny")
        apr_cnt = sum(1 for e in events if str(e.get("rule_id") or "").startswith("APR-"))
        pol_cnt = sum(1 for e in events if e.get("rule_id") == "POLICY-CLIENT-CADDY-ONLY")
        head = _page_head("로그 소스", "방화벽", "게이트웨이의 패킷 통과(fw_allow), 정책 차단(POLICY), 관제 승인 차단(APR) 기록입니다.")
        metrics = _stat_strip([
            ("조회 이벤트", f"{len(events)}", "선택 기간 전체", ""),
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
        for ev in (_collapse_runs(events[:50]) if group else events[:50]):
            rule_id = str(ev.get("rule_id") or "-")
            if rule_id == "POLICY-CLIENT-CADDY-ONLY":
                rule_html = f'<span class="ev-act warn">우회 정책 차단</span><div class="cell-sub">{esc(rule_id)}</div>'
            elif rule_id == "POLICY-ICMP-BROADCAST":
                rule_html = f'<span class="ev-act warn">ICMP 브로드캐스트 거부</span><div class="cell-sub">{esc(rule_id)}</div>'
            elif rule_id.startswith("APR-"):
                rule_html = f'<span class="ev-act bad">SOAR 승인 차단</span><div class="cell-sub">{esc(rule_id)}</div>'
            else:
                rule_html = f'<span class="muted">{esc(rule_id)}</span>'
            is_deny = ev.get("event_type") == "fw_deny"
            src_port = ev.get("src_port")
            flow_html = (
                f'<span class="flow{" bad" if is_deny else ""}">{_pv(ev.get("src_ip"), mono=True, bad=is_deny)}'
                f'<span class="port">{":" + esc(str(src_port)) if src_port else ""}</span>'
                f'<span class="ev-arrow">→</span><code>{esc(str(ev.get("dst_ip") or "-"))}'
                f'{":" + esc(str(ev["dst_port"])) if ev.get("dst_port") is not None else ""}</code></span>'
            )
            row_list.append(
                f"<tr>"
                f"<td>{_fmt_event_type(ev['event_type'], ev.get('outcome'))}</td>"
                f"<td>{_fmt_log_time(ev['event_ts_utc'])}{_run_badge(ev)}</td>"
                f"<td>{flow_html}</td>"
                + (f"<td>{rule_html}</td>" if has_rule else "")
                + f"<td>{_fmt_ingest_mode(ev['ingest_mode'])}</td>"
                f"<td>{_copy_id_chip(ev['raw_id'])}</td>"
                f"</tr>"
            )
        rows = "".join(row_list)
        colspan = 6
    elif log_kind == "waf":
        events = scoped_events
        blocked = sum(event["event_type"] == "waf_blocked" for event in events)
        detected = len(events) - blocked
        rule_set = {str(event.get("rule_id") or "").strip() for event in events if str(event.get("rule_id") or "").strip()}
        head = _page_head("로그 소스", "WAF", "웹 요청에 적용된 보안 규칙과 판정 기록입니다.")
        metrics = _stat_strip([
            ("조회 판정", str(len(events)), "선택 기간 전체 · 최신 50건 표", ""),
            ("탐지", str(detected), "DetectionOnly 감시 판정", ""),
            ("차단", str(blocked), "요청 차단 판정", "is-danger" if blocked else ""),
            ("일치 규칙 묶음", str(len(rule_set)), "OWASP CRS · 자체 크기 제한", ""),
        ])
        insight = ""
        headers = (
            "<tr><th>판정</th><th>발생 시각</th><th>단말 IP</th>"
            "<th>공격 유형</th><th>request_id</th><th>원본 raw_id</th></tr>"
        )
        rows = "".join(
            "<tr>"
            f"<td>{_fmt_event_type(event['event_type'], event.get('outcome'))}</td>"
            f"<td>{_fmt_log_time(event['event_ts_utc'])}</td>"
            f"<td>{_fmt_ip_badge(event.get('client_ip'), alert=(event['event_type'] == 'waf_blocked'))}</td>"
            f"<td>{_waf_rule_label(event.get('rule_id'))}</td>"
            f"<td>{_copy_id_chip(event.get('request_id'))}</td>"
            f"<td>{_copy_id_chip(event['raw_id'])}</td>"
            "</tr>"
            for event in events[:50]
        )
        colspan = 6
    else:
        events = scoped_events
        ok_cnt = sum(1 for e in events if e.get("status_code") is not None and int(e["status_code"]) < 400)
        err_cnt = sum(1 for e in events if e.get("status_code") is not None and int(e["status_code"]) >= 400)
        auth_err_cnt = sum(1 for e in events if e.get("status_code") in (401, 403))
        head = _page_head("로그 소스", "웹 프록시", "Caddy를 통과하는 HTTPS 요청과 응답 상태 코드, 상관 추적 request_id 기록입니다.")
        metrics = _stat_strip([
            ("조회 요청", f"{len(events)}", "선택 기간 전체", ""),
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
        for ev in (_collapse_runs(events[:50]) if group else events[:50]):
            sc = ev.get("status_code")
            is_err = sc is not None and int(sc) >= 400
            sc_html = f'<span class="ev-act {"bad" if is_err else "good"}">HTTP {sc if sc is not None else "-"}</span>'
            method = str(ev.get("http_method") or "-").upper()
            req_html = f'<span class="mth">{esc(method)}</span><code>{esc(str(ev.get("http_path") or "-"))}</code>'
            row_list.append(
                f"<tr>"
                f"<td>{sc_html}</td>"
                f"<td>{_fmt_log_time(ev['event_ts_utc'])}{_run_badge(ev)}</td>"
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
    {scope_controls}
    {metrics}
    {insight}
    {extra_panel}
    <div class="panel">
      <div class="panel-header"><div><h2>로그 기록</h2><div class="panel-sub">선택 기간 전체 {len(events):,}건 · 최신 50건 표시</div></div>
      <a class="btn-ghost" href="/logs/{log_kind}?{html.escape(urllib.parse.urlencode({**(scope_query or {}), 'group': '0' if group else '1'}))}">{'원본 그대로 보기' if group else '반복 묶어 보기'}</a></div>
      <table class="log-tbl log-source-tbl"><thead>{headers}</thead><tbody>{table_body}</tbody></table>
    </div>
    """
    body = collection_error_panel(store, "caddy" if log_kind == "waf" else log_kind) + body
    return _page_shell(
        f"관제 대시보드 · {({'erp': 'ERP 인증', 'gateway': '방화벽', 'caddy': '웹 프록시', 'waf': 'WAF'}).get(log_kind, log_kind)}",
        body,
        current_user=current_user,
        auth_enabled=auth_enabled,
        refresh_seconds=5,
        active_path=f"/logs/{log_kind}",
        csrf_token=csrf_token,
    )


def _event_pagination(
    current: int, total: int, *, base: str = "/events", param: str = "page", label: str = "이벤트 페이지",
) -> str:
    """Keep short ranges continuous and mark every omitted range explicitly."""
    pages = set(range(1, total + 1)) if total <= 7 else {1, total} | set(
        range(max(1, current - 1), min(total, current + 1) + 1)
    )
    if current <= 3:
        pages.update(range(1, min(5, total) + 1))
    elif current >= total - 2:
        pages.update(range(max(1, total - 4), total + 1))
    def link(n: int) -> str:
        return f"{base}?{param}={n}"

    parts = [f'<a href="{link(current - 1)}" rel="prev" aria-label="이전 페이지">← 이전</a>' if current > 1
             else '<span aria-disabled="true">← 이전</span>']
    previous = 0
    for page in sorted(pages):
        if previous and page - previous == 2:
            parts.append(f'<a href="{link(previous + 1)}" aria-label="{previous + 1}페이지">{previous + 1}</a>')
        elif previous and page - previous > 2:
            parts.append('<span class="pager-gap" aria-label="중간 페이지 생략">…</span>')
        parts.append(f'<span aria-current="page" aria-label="현재 {page}페이지">{page}</span>' if page == current
                     else f'<a href="{link(page)}" aria-label="{page}페이지">{page}</a>')
        previous = page
    parts.append(f'<a href="{link(current + 1)}" rel="next" aria-label="다음 페이지">다음 →</a>' if current < total
                 else '<span aria-disabled="true">다음 →</span>')
    return f'<nav class="event-pager" aria-label="{html.escape(label)}">' + ''.join(parts) + '</nav>'


def _request_summary_context(group: list[dict[str, Any]], primary: dict[str, Any]) -> str:
    """요청 카드를 펼치기 전에도 요약 줄에서 경로·응답·목적지·규칙을 바로 읽을 수 있게 한 줄 컨텍스트를 만든다."""
    esc = html.escape
    et = str(primary.get("event_type") or "")
    src = str(primary.get("source") or "")
    if et in ("waf_detected", "waf_blocked"):
        rule_raw = str(primary.get("rule_id") or "-").strip() or "-"
        return f'<span class="request-summary-ctx"><span class="is-bad">규칙 {esc(rule_raw)}</span></span>'
    if src == "gateway":
        dst = f"{primary.get('dst_ip') or '-'}:{primary.get('dst_port') or '-'}"
        rule_id = str(primary.get("rule_id") or "").strip()
        rule_part = f' · <span class="is-bad">{esc(rule_id)}</span>' if (et == "fw_deny" and rule_id and rule_id != "-") else ""
        return f'<span class="request-summary-ctx">→ {esc(dst)}{rule_part}</span>'
    # Caddy 또는 ERP 요청: 경로와 HTTP 상태 코드를 함께 표시
    http_ev = next((item for item in group if item.get("http_path")), primary)
    method = str(http_ev.get("http_method") or "").strip().upper()
    path = str(http_ev.get("http_path") or "").strip()
    sc = primary.get("status_code") if primary.get("status_code") is not None else http_ev.get("status_code")
    parts: list[str] = []
    if path and path != "-":
        parts.append(esc(f"{method} {path}".strip()))
    if sc is not None:
        try:
            is_err = int(sc) >= 400
        except (TypeError, ValueError):
            is_err = False
        sc_cls = ' class="is-bad"' if is_err else ""
        parts.append(f"<span{sc_cls}>HTTP {esc(str(sc))}</span>")
    if not parts:
        return ""
    return f'<span class="request-summary-ctx">{" · ".join(parts)}</span>'


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
    total_collected = sum(int(s.get("count", 0)) for s in stats)
    waf_types = ("waf_detected", "waf_blocked")
    waf_events = store.list_recent_events(limit=1, source="caddy", event_types=waf_types)
    if hasattr(store, "count_recent_events"):
        waf_count = store.count_recent_events(source="caddy", event_types=waf_types)
    else:
        waf_count = len(store.list_recent_events(limit=100000, source="caddy", event_types=waf_types))
    waf_stats = (
        {"count": waf_count, "last_received_utc": waf_events[0].get("received_at_utc") or waf_events[0]["event_ts_utc"]}
        if waf_events
        else {"count": 0, "last_received_utc": None}
    )

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

    def flow_id(event: dict[str, Any]) -> str:
        if event.get("source") not in {"caddy", "erp"}:
            return ""
        return str(event.get("request_id") or "").strip()

    def suspect(event: dict[str, Any]) -> bool:
        status = event.get("status_code")
        return _is_suspect_event(str(event.get("source") or ""), str(event.get("event_type") or ""),
                                 str(event.get("outcome") or ""), int(status) if status is not None else None,
                                 str(event.get("http_path") or ""))

    def display_source(event: dict[str, Any]) -> str:
        if event.get("source") == "caddy" and event.get("event_type") in ("waf_detected", "waf_blocked"):
            return "waf"
        return str(event.get("source") or "")

    members: dict[str, list[dict[str, Any]]] = {}
    for ev in events:
        rid_key = flow_id(ev)
        if rid_key:
            members.setdefault(rid_key, []).append(ev)
    group_anomaly = {key: any(map(suspect, group)) for key, group in members.items()}
    layer_order = {"caddy": 0, "waf": 1, "erp": 2}
    cards = []
    visible_events = 0
    flow_cnt = 0
    anomaly_card_cnt = 0
    src_card_counts: dict[str, int] = {"gateway": 0, "caddy": 0, "waf": 0, "erp": 0}
    emitted: set[str] = set()
    for ev in events:
        rid_key = flow_id(ev)
        is_anomaly = group_anomaly[rid_key] if rid_key else suspect(ev)
        if anomaly_only and not is_anomaly:
            continue
        if rid_key and rid_key in emitted:
            continue
        if rid_key:
            emitted.add(rid_key)
        group = sorted(
            members[rid_key] if rid_key else [ev],
            key=lambda item: (layer_order.get(display_source(item), 9), str(item["event_ts_utc"])),
        )
        visible_events += len(group)
        is_multi = len(group) > 1
        if is_multi:
            flow_cnt += 1
        if is_anomaly:
            anomaly_card_cnt += 1
        raw_sources = tuple(dict.fromkeys(str(item["source"]) for item in group))
        disp_sources = tuple(dict.fromkeys(display_source(item) for item in group))
        filter_tokens = tuple(dict.fromkeys([*raw_sources, *disp_sources]))
        for tok in filter_tokens:
            if tok in src_card_counts:
                src_card_counts[tok] += 1
        path = '<span class="request-path-arrow" aria-hidden="true">→</span>'.join(
            _fmt_source_badge(source) for source in disp_sources
        )
        primary = max(group, key=lambda item: (suspect(item), item["source"] == "erp"))
        status = "차단" if primary["event_type"] in ("fw_deny", "waf_blocked") else "이상" if is_anomaly else "정상"
        who = (
            _fmt_user_badge(primary.get("username"), primary.get("department"), primary.get("user_role"))
            if primary.get("username") else ""
        )
        summary_ctx = _request_summary_context(group, primary)
        stages = "".join(
            f'<li class="request-stage">'
            f'<div class="request-stage-source"><span class="request-step-num">{idx}</span>{_fmt_source_badge(display_source(item))}</div>'
            f'<div class="request-stage-result">{_fmt_event_type(item["event_type"], item.get("outcome"))}</div>'
            f'<div class="request-stage-info">{_fmt_ip_badge(item.get("device_ip"), alert=suspect(item))} '
            f'{_event_line(item, detail_only=True)}</div>'
            f'<div class="request-stage-time"><span class="request-stage-meta-label">발생 시각</span>'
            f'{_fmt_log_time(item["event_ts_utc"])}</div>'
            f'<div class="request-stage-raw"><span class="request-stage-meta-label">원본 로그</span>'
            f'{_raw_cell(item)}</div></li>'
            for idx, item in enumerate(group, start=1)
        )
        flow_summary = " → ".join(
            f"{idx}단계 {({'erp': 'ERP', 'caddy': 'Caddy', 'gateway': 'Gateway', 'waf': 'WAF'}).get(display_source(item), display_source(item))}"
            for idx, item in enumerate(group, start=1)
        )
        request_id = (
            f'<div class="request-id-line">'
            f'<div class="request-id-left"><span class="muted">상관 요청 ID (request_id)</span>{_copy_id_chip(rid_key)}</div>'
            f'<div class="request-id-right"><span class="muted">처리 경로:</span> <b>{esc(flow_summary)}</b></div>'
            f'</div>'
            if rid_key
            else (
                f'<div class="request-id-line">'
                f'<div class="request-id-left"><span class="muted">단일 계층 이벤트</span></div>'
                f'<div class="request-id-right"><span class="muted">처리 경로:</span> <b>{esc(flow_summary)}</b></div>'
                f'</div>'
            )
        )
        flow_attr = ' data-flow="1"' if is_multi else ""
        count_label = f"{len(group)}단계" if is_multi else "1건"
        count_cls = "request-count-pill is-flow" if is_multi else "request-count-pill"
        cards.append(
            f'<details class="request-card" data-source="{esc(" ".join(filter_tokens))}" '
            f'data-anomaly="{"1" if is_anomaly else "0"}"{flow_attr}>'
            f'<summary><span class="request-status{" is-anomaly" if is_anomaly else ""}">{status}</span>'
            f'<span class="request-main">{_fmt_event_type(primary["event_type"], primary.get("outcome"), show_code=False)}{_time_badge(primary)}'
            f'<span class="request-path">{path}</span>{summary_ctx}</span>'
            f'<span class="request-peer"><span>{esc(str(primary.get("device_ip") or "-"))}</span>'
            f'<span>{who}</span></span>'
            f'<span class="request-feed-time">{_fmt_log_time(ev["event_ts_utc"])}</span>'
            f'<span class="request-feed-count"><span class="{count_cls}">{count_label}</span></span>'
            f'<i class="request-chevron" aria-hidden="true"></i></summary>'
            f'<div class="request-layers">{request_id}'
            f'<div class="export-actions" style="margin-bottom:10px;margin-left:0;"><a class="export-button" title="이 접속 흐름과 원본 로그를 JSON으로 저장" href="/exports?{esc(urllib.parse.urlencode({"kind": "flow", "request_id": rid_key, "raw_id": primary.get("raw_id", "")}))}">JSON 저장</a>'
            f'<button type="button" class="export-button" title="이 접속 흐름을 PDF로 저장" onclick="printSocFlow(this)">PDF 저장</button></div>'
            f'<div class="request-stages-wrap">'
            f'<div class="request-stages-head" aria-hidden="true">'
            f'<span>단계 · 출처</span><span>이벤트 · 판정</span><span>단말 IP · 요청 상세</span><span>발생 시각 (KST)</span><span>원본 raw_id</span>'
            f'</div>'
            f'<ol class="request-stages">{stages}</ol></div></div></details>'
        )
    feed = "".join(cards) or '<p class="empty">표시할 이벤트가 없습니다.</p>'
    normal_card_cnt = max(0, len(cards) - anomaly_card_cnt)
    metrics_html = _stat_strip([
        ("표시 요청 묶음", f"{len(cards)}건", f"현재 화면 이벤트 {visible_events}건 · 누적 {total_collected:,}건", ""),
        ("다계층 상관 흐름", f"{flow_cnt}건", "Caddy → ERP request_id 일치 묶음", "is-accent" if flow_cnt else ""),
        ("이상 · 차단 징후", f"{anomaly_card_cnt}건", "인증 실패 · 방화벽/WAF 차단 · 오류", "is-danger" if anomaly_card_cnt else ""),
        ("정상 처리", f"{normal_card_cnt}건", "정상 통과 및 인증 · 열람 성공", ""),
    ])
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
            '<div class="alert-banner is-info">'
            f'<span><strong>적용된 시간 · 조건 필터:</strong> {esc(" · ".join(parts_desc))} (요청 묶음 {len(cards)}건 · 원본 {visible_events}건)</span>'
            '<a class="range-chip" href="/events">전체 보기로 해제</a>'
            "</div>"
        )

    body = f"""
    {_page_head("관제 · 상관 분석", "이벤트", "웹 프록시(Caddy), 웹 방화벽(WAF), 인증 서버(ERP), 게이트웨이(Gateway) 로그를 요청 흐름 단위로 묶어 조회합니다.")}
    {_health_strip(stats_map, waf_stats)}
    {metrics_html}
    <div class="panel">
      {filter_banner}
      {_stream_head("/events")}
      <div class="filter-chip-bar" role="toolbar" aria-label="계층 및 이상 징후 필터">
        <button type="button" class="filter-chip active" data-filter="all" onclick="setEventFilterChip('all')">전체 <span class="chip-cnt">{len(cards)}</span></button>
        <button type="button" class="filter-chip" data-filter="gateway" onclick="setEventFilterChip('gateway')"><i class="chip-dot" style="background:var(--source-gateway)"></i>Gateway <span class="chip-cnt">{src_card_counts['gateway']}</span></button>
        <button type="button" class="filter-chip" data-filter="caddy" onclick="setEventFilterChip('caddy')"><i class="chip-dot" style="background:var(--source-caddy)"></i>Caddy <span class="chip-cnt">{src_card_counts['caddy']}</span></button>
        <button type="button" class="filter-chip" data-filter="waf" onclick="setEventFilterChip('waf')"><i class="chip-dot" style="background:var(--source-waf)"></i>WAF <span class="chip-cnt">{src_card_counts['waf']}</span></button>
        <button type="button" class="filter-chip" data-filter="erp" onclick="setEventFilterChip('erp')"><i class="chip-dot" style="background:var(--source-erp)"></i>ERP <span class="chip-cnt">{src_card_counts['erp']}</span></button>
        <button type="button" class="filter-chip" data-filter="flow" onclick="setEventFilterChip('flow')">요청 흐름만 ({flow_cnt})</button>
        <button type="button" class="filter-chip" data-filter="anomaly" onclick="setEventFilterChip('anomaly')"><i class="chip-dot" style="background:var(--danger)"></i>이상 징후만 <span class="chip-cnt">{anomaly_card_cnt}</span></button>
        <span id="eventsFilterCount" class="muted" style="margin-left:auto;font-size:12.5px;">표시: {len(cards)} / {len(cards)}건</span>
        {('<button type="button" class="btn-ghost action-btn-sm" onclick="toggleAllEventCards(this)" aria-pressed="false">모두 펼치기</button>' if cards else '')}
      </div>
      <div class="request-feed">
        {('<div class="request-feed-head" aria-hidden="true"><span>상태</span><span>이벤트 · 출처 · 요약</span><span>접속 IP · 계정</span><span class="request-feed-time">발생 시각</span><span class="request-feed-count">단계 · 기록</span><span></span></div>' if cards else "")}
        {feed}
      </div>
      {"" if is_time_filtered else (
          f'<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:14px;padding-top:12px;border-top:1px solid var(--line-soft);font-size:12px;">'
          f'<span class="muted">총 <b>{total_count:,}</b>건 · {((cur_page - 1) * page_size + 1) if total_count else 0:,}–{min(cur_page * page_size, total_count):,}건</span>'
          + _event_pagination(cur_page, total_pages) + '</div>'
      )}
      <div class="stream-foot-note">
        <span>같은 <code>request_id</code>를 공유하는 Caddy · WAF · ERP 기록은 하나의 요청 카드로 묶이며, Gateway 방화벽 패킷 기록은 개별 카드로 표시됩니다.</span>
        <span>행 클릭: 단계별 상세 펼치기 · IP/계정 클릭: 즉시 검색 필터</span>
      </div>
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


def _render_login_access_panel(
    inc: IncidentView, state: dict | None, note: str, current_user: str | None, csrf_token: str,
) -> str:
    esc = html.escape
    path = f"/incidents/{esc(inc.incident_id)}"
    csrf = f'<input type="hidden" name="csrf_token" value="{esc(csrf_token)}">'
    body = f'<p class="notice">{esc(note)}</p>' if note else ""
    if state is not None:
        status = state["status"]
        label = {"pending": "승인 대기", "active": "승인됨 · 이용 가능", "expired": "기간 만료", "revoked": "승인 취소"}[status]
        body += f"<p><strong>{label}</strong></p>"
        if state.get("approved_by"):
            body += (
                f'<p>승인 담당자 <strong>{esc(state["approved_by"])}</strong> · {_fmt_ts(state["approved_at"])}</p>'
                f'<p>만료 시각 {_fmt_ts(state["expires_at"])}</p>'
                f'<p>승인 사유 {esc(state["approval_reason"] or "-")}</p>'
            )
        if state.get("revoked_by"):
            body += f'<p>취소 담당자 <strong>{esc(state["revoked_by"])}</strong> · {_fmt_ts(state["revoked_at"])}</p>'
        if state.get("incident_id") in (None, inc.incident_id) and csrf_token:
            if status in ("pending", "revoked") and role_can(current_user, "approve"):
                body += f"""<form method="post" action="{path}/grant-login" class="pop-form">
                  {csrf}
                  <label>승인 사유 <input name="reason" type="text" maxlength="200" required></label>
                  <button type="submit">5분 임시 접속 승인</button>
                </form>"""
            elif status == "active" and role_can(current_user, "release"):
                body += f"""<form method="post" action="{path}/revoke-login" class="pop-form">
                  {csrf}<button type="submit" class="secondary">임시 승인 취소</button>
                </form>"""
    return f"""<div class="panel"><h2>ERP 임시 접속 승인</h2>
      <p>이 사건에 기록된 계정과 IP 조합에 한해 승인 시각부터 5분 동안 새 로그인을 허용합니다.</p>
      <p>로그인할 때는 올바른 비밀번호가 필요합니다. 로그인한 세션에는 ERP의 기존 세션 정책이 적용됩니다.</p>
      {body}</div>"""


def _render_account_lock_panel(
    inc: IncidentView, state: dict | None, note: str, current_user: str | None, csrf_token: str,
) -> str:
    esc = html.escape
    path = f"/incidents/{esc(inc.incident_id)}"
    csrf = f'<input type="hidden" name="csrf_token" value="{esc(csrf_token)}">'
    automatic_lock = any(alert.rule_id == AUTO_ACCOUNT_LOCK_RULE_ID for alert in inc.alerts)
    body = f'<p class="notice">{esc(note)}</p>' if note else ""
    if state is not None:
        status = state["status"]
        label = {"available": "잠금 없음", "active": "계정 잠금 중", "expired": "잠금 만료", "unlocked": "잠금 해제"}[status]
        body += f"<p><strong>{label}</strong></p>"
        if state.get("locked_at"):
            body += (f'<p>잠금 실행자 <strong>{esc(state["locked_by"])}</strong> · {_fmt_ts(state["locked_at"])}</p>'
                     f'<p>만료 시각 {_fmt_ts(state["expires_at"])}</p><p>잠금 사유 {esc(state["reason"])}</p>')
        if state.get("unlocked_at"):
            body += (f'<p>해제 담당자 <strong>{esc(state["unlocked_by"])}</strong> · {_fmt_ts(state["unlocked_at"])}</p>'
                     f'<p>해제 사유 {esc(state["unlock_reason"])}</p>')
        if status == "active" and state.get("incident_id") != inc.incident_id:
            body += f'<p><a href="/incidents/{esc(state["incident_id"])}">잠금을 시작한 사건 열기</a></p>'
        elif csrf_token and status == "available" and role_can(current_user, "approve"):
            body += f"""<form method="post" action="{path}/lock-account" class="pop-form">
              {csrf}
              <label>잠금 시간(분, 최대 24시간) <input name="duration" type="number" value="10" min="1" max="{MAX_ACCOUNT_LOCK_MINUTES}" required style="width:84px;padding:6px 8px;text-align:center;font-variant-numeric:tabular-nums;"></label>
              <label>잠금 사유 <input name="reason" type="text" maxlength="200" required></label>
              <button type="submit">계정 임시 잠금</button>
            </form>"""
        elif csrf_token and status == "active" and role_can(current_user, "release"):
            body += f"""<form method="post" action="{path}/unlock-account" class="pop-form">
              {csrf}
              <label>해제 사유 <input name="reason" type="text" maxlength="200" required></label>
              <button type="submit" class="secondary">잠금 해제 승인</button>
            </form>"""
    heading = "ERP 계정 자동 잠금" if automatic_lock else "ERP 계정 잠금 · 의심 로그인 관찰"
    return f"""<div class="panel"><h2>{heading}</h2>
      <p>대상 계정 <strong>{esc(inc.username)}</strong> · 모든 접속 단말에서 이 계정의 로그인과 기존 세션을 제한합니다.</p>
      <p>같은 계정이 5분 안에 5회 실패하면 ERP가 자동으로 10분간 잠급니다. 보안팀은 만료 전에 잠금을 해제할 수 있습니다.</p>
      {body}</div>"""


def render_incident_detail(
    inc: IncidentView,
    error_msg: str | None = None,
    current_user: str | None = None,
    auth_enabled: bool = False,
    csrf_token: str = "",
    *,
    followup_success: FollowupLoginSuccess | None = None,
    block_effects: dict[str, dict[str, Any]] | None = None,
    login_access_state: dict | None = None,
    login_access_note: str = "",
    account_lock_state: dict | None = None,
    account_lock_note: str = "",
    release_audit_rows: list[dict] | None = None,
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
        LOGIN_FAILURE_REVIEW_RULE_ID: "회 연속 인증 실패",
        LOGIN_SOURCE_DENIED_RULE_ID: "회 접속 거부",
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
        f"<td>{_fmt_user_badge(ev.username, ev.details.get('department'), ev.details.get('role'))}</td>"
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
        f"<span style='color:var(--text-3);font-size:12px;'>(파일 오프셋: <code>{rec.line_offset}</code>)</span></div>"
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
    brute_alert = next((a for a in inc.alerts if a.rule_id == LOGIN_FAILURE_RULE_ID), None)
    ip_total_alert = next((a for a in inc.alerts if a.rule_id == IP_MULTI_ACCOUNT_FAILURE_RULE_ID), None)
    rule_label = "MITRE ATT&CK · T1110.001" if brute_alert else ("MITRE ATT&CK · T1110" if ip_total_alert else "조사용 · 차단 불가")
    attack_summary = ""
    if brute_alert:
        attack_summary = (
            '<div class="pop-note" style="margin-top:16px;word-break:keep-all;">'
            '<strong>의심 공격: 비밀번호 추측 (T1110.001)</strong>'
            f'<p>같은 계정과 출발지 IP에서 5분 안에 로그인 실패 {brute_alert.failure_count}회가 기록되어 탐지했습니다.</p>'
            '<p>정상 사용자의 비밀번호 오입력일 수도 있습니다. 담당자가 시각과 계정, 출발지 및 원본 기록을 확인해 판단하세요.</p>'
            '<a href="#incident-evidence">근거 이벤트 확인</a> · <a href="#incident-raw-logs">원본 로그 확인</a>'
            '</div>'
        )
    elif ip_total_alert:
        attack_summary = (
            '<div class="pop-note" style="margin-top:16px;word-break:keep-all;">'
            '<strong>의심 공격: 여러 계정 로그인 시도 (T1110)</strong>'
            f'<p>같은 출발지 IP에서 여러 계정의 로그인 실패 {ip_total_alert.failure_count}회가 기록되어 탐지했습니다.</p>'
            '<p>사용한 비밀번호가 같은지는 로그로 알 수 없습니다. 담당자가 계정과 시각, 원본 기록을 확인해 판단하세요.</p>'
            '<a href="#incident-evidence">근거 이벤트 확인</a> · <a href="#incident-raw-logs">원본 로그 확인</a>'
            '</div>'
        )
    success_review = any(alert.rule_id == LOGIN_SUCCESS_REVIEW_RULE_ID for alert in inc.alerts)
    source_change_review = any(alert.rule_id == LOGIN_SOURCE_CHANGE_RULE_ID for alert in inc.alerts)
    if success_review:
        rule_label = "주의 · 인증 성공 확인 필요"
    if source_change_review:
        rule_label = "주의 · 실패와 성공의 출발지가 다름"
    if inc.is_login_source_denial:
        rule_label = "비인가 IP · ERP 접속 검토"
    elif any(alert.rule_id == AUTO_ACCOUNT_LOCK_RULE_ID for alert in inc.alerts):
        rule_label = "ERP 자동 잠금 · 로그인 5회 실패"
    elif inc.has_account_lock_rule and not (success_review or source_change_review):
        rule_label = "관찰 · 3회 연속 실패"

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
        <form method="post" action="/incidents/{esc(inc.incident_id)}/release" style="display:inline-block; margin-left:10px;">{release_fields()}
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

    action_panel = f"""
    <div class="panel">
      <div class="panel-header">
        <div>
          <h2>게이트웨이 IP 차단</h2>
          <div class="panel-sub">신뢰할 수 있는 실시간 기록을 확인한 뒤 보안팀이 승인하면 해당 IP를 차단합니다.</div>
        </div>
      </div>
      {gate_msg}
      <div class="pop-actions" style="margin-bottom:0;display:inline-flex;max-width:100%;">
        <div class="pop-actions-main">
          <form method="post" action="/incidents/{esc(inc.incident_id)}/approve" class="pop-form" onsubmit="return confirmLongBlock(this)">
            {csrf_hidden}
            {actor_input}
            <label>차단 유지 시간(분, 최대 {MAX_BLOCK_MINUTES:,}분/30일) <input type="number" name="duration_minutes" value="10" min="1" max="{MAX_BLOCK_MINUTES}" oninput="var btns=this.form.querySelectorAll('.dur-preset-btn');for(var j=0;j<btns.length;j++){{btns[j].classList.toggle('is-active',btns[j].dataset.mins===this.value);}}" required {disabled_attr} style="width:88px;padding:6px 8px;text-align:center;font-variant-numeric:tabular-nums;" /></label>
            <span class="duration-presets" aria-label="차단 시간 빠른 선택">
              <button type="button" class="dur-preset-btn is-active" data-mins="10" onclick="this.form.duration_minutes.value='10';var bs=this.parentElement.querySelectorAll('.dur-preset-btn');for(var j=0;j<bs.length;j++)bs[j].classList.toggle('is-active',bs[j]===this);" {disabled_attr}>10분</button>
              <button type="button" class="dur-preset-btn" data-mins="30" onclick="this.form.duration_minutes.value='30';var bs=this.parentElement.querySelectorAll('.dur-preset-btn');for(var j=0;j<bs.length;j++)bs[j].classList.toggle('is-active',bs[j]===this);" {disabled_attr}>30분</button>
              <button type="button" class="dur-preset-btn" data-mins="60" onclick="this.form.duration_minutes.value='60';var bs=this.parentElement.querySelectorAll('.dur-preset-btn');for(var j=0;j<bs.length;j++)bs[j].classList.toggle('is-active',bs[j]===this);" {disabled_attr}>1시간</button>
              <button type="button" class="dur-preset-btn" data-mins="360" onclick="this.form.duration_minutes.value='360';var bs=this.parentElement.querySelectorAll('.dur-preset-btn');for(var j=0;j<bs.length;j++)bs[j].classList.toggle('is-active',bs[j]===this);" {disabled_attr}>6시간</button>
              <button type="button" class="dur-preset-btn" data-mins="1440" onclick="this.form.duration_minutes.value='1440';var bs=this.parentElement.querySelectorAll('.dur-preset-btn');for(var j=0;j<bs.length;j++)bs[j].classList.toggle('is-active',bs[j]===this);" {disabled_attr}>24시간</button>
              <button type="button" class="dur-preset-btn" data-mins="10080" onclick="this.form.duration_minutes.value='10080';var bs=this.parentElement.querySelectorAll('.dur-preset-btn');for(var j=0;j<bs.length;j++)bs[j].classList.toggle('is-active',bs[j]===this);" {disabled_attr}>7일</button>
              <button type="button" class="dur-preset-btn" data-mins="{MAX_BLOCK_MINUTES}" onclick="this.form.duration_minutes.value='{MAX_BLOCK_MINUTES}';var bs=this.parentElement.querySelectorAll('.dur-preset-btn');for(var j=0;j<bs.length;j++)bs[j].classList.toggle('is-active',bs[j]===this);" {disabled_attr}>30일(최대)</button>
            </span>
            <button type="submit" {disabled_attr}>{_svg_icon("shield_off", "currentColor", 13)} 시험 단말 차단 승인</button>
          </form>
          {release_html}
        </div>
      </div>
      {_block_scope_note(inc.target_ip) if can_approve else ""}
      {effect_summary}
      <h3 class="pop-h" style="margin:20px 0 10px;">승인 · 게이트웨이 조치 이력</h3>
      <table>
        <thead>{_approval_head()}</thead>
        <tbody>{approval_rows}</tbody>
      </table>
    </div>
    """
    if inc.is_login_source_denial:
        action_panel = _render_login_access_panel(inc, login_access_state, login_access_note, current_user, csrf_token)
    elif inc.has_account_lock_rule:
        action_panel = _render_account_lock_panel(inc, account_lock_state, account_lock_note, current_user, csrf_token)

    body = f"""
    <div style="margin-bottom:14px;"><a href="/incidents" class="btn-ghost">{_svg_icon("arrow_right", "currentColor", 13).replace("<svg ", '<svg style="transform:rotate(180deg)" ', 1)} 사건 목록</a></div>
    {err_html}

    <div class="panel">
      <div class="detail-head">
        <h1>{esc(_title_parts(inc.title)[0])}</h1>{_title_en_tag(_title_parts(inc.title)[1])}
        {_incident_response_status(inc)}
        <span class="badge b-approved">{esc(rule_label)}</span>
      </div>
      <div class="panel-sub" style="margin:6px 0 16px;"><code>{esc(inc.incident_id)}</code> · ERP · Caddy · Gateway 상관 추적과 담당자 승인 조치</div>
      <div class="pop-stats" style="margin-bottom:0;">
        <div class="pop-stat"><div class="k">출발지 IP</div><div class="v mono">{esc(inc.target_ip or '여러 출발지')}</div></div>
        <div class="pop-stat"><div class="k">관련 계정</div><div class="v">{_fmt_user_badge(inc.username) if inc.username else ('계정명 없음' if inc.is_login_source_denial else '여러 계정')}</div></div>
        <div class="pop-stat"><div class="k">근거 · 상관 연결</div><div class="v">{len(inc.evidence_events)}건 · {len(inc.correlations)}건</div></div>
        <div class="pop-stat"><div class="k">사건 생성</div><div class="v" style="font-size:14px;line-height:1.5;overflow-wrap:anywhere;">{_fmt_ts(inc.created_at_utc)}</div></div>
      </div>
      {attack_summary}
    </div>

    {_case_time_panel(inc)}
    {action_panel}

    {followup_panel}

    {_render_incident_timeline(inc)}

    <div class="panel">
      <div class="panel-header"><div><h2>탐지 경보</h2><div class="panel-sub">이 사건을 만든 탐지 규칙과 시간창</div></div></div>
      <table>
        <thead><tr><th>경보 ID</th><th>규칙 ID</th><th>규칙명</th><th>실패 횟수</th><th>탐지 시간창</th></tr></thead>
        <tbody>{alert_rows}</tbody>
      </table>
    </div>

    <div class="panel" id="incident-evidence">
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
        <span class="chain-step"><span class="d source-erp"></span> ERP 인증 기록 <b>{len(inc.evidence_events)}건</b></span>
        <span class="chain-arrow"><code>request_id</code> 정확 일치 →</span>
        <span class="chain-step"><span class="d source-caddy"></span> Caddy 웹 요청 <b>{sum(1 for c in inc.correlations if c.link_type == "request_id_exact")}건</b></span>
        <span class="chain-arrow">IP · 포트 · 시각 근접 후보 →</span>
        <span class="chain-step"><span class="d source-gateway"></span> 게이트웨이 접속 <b>{sum(1 for c in inc.correlations if c.link_type == "gateway_candidate")}건</b> <em>단정 금지</em></span>
      </div>
      <table>
        <thead><tr><th>연결 유형</th><th>event_id</th><th>상관 분석 근거 설명</th><th>원본 raw_id</th></tr></thead>
        <tbody>{corr_rows}</tbody>
      </table>
    </div>

    <details class="panel" id="incident-raw-logs">
      <summary>
        <div>
          <h2>원본 로그 (raw_logs)</h2>
          <div class="panel-sub">정규화 전에 수집한 원본 JSON 페이로드와 바이트 오프셋 증거</div>
        </div>
      </summary>
      {raw_blocks}
    </details>
    """
    body += release_audit_panel(release_audit_rows or [])
    return _page_shell(f"사건 {inc.incident_id}", body, current_user=current_user, auth_enabled=auth_enabled, active_path=f"/incidents/{inc.incident_id}", csrf_token=csrf_token)


def make_handler(
    store: DashboardStore | DbDashboardStore,
    auth_config: AuthConfig | None = None,
    *,
    login_access_client: LoginAccessClient | None = None,
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
        server_version = "Sentinel"  # 파이썬 버전을 응답에 노출하지 않는다
        sys_version = ""

        def end_headers(self) -> None:
            # 모든 응답에 붙는다: 클릭재킹, MIME 추측, 캐시, 리퍼러 노출을 막는다.
            for name, value in _SECURITY_HEADERS:
                if name == "Cache-Control" and getattr(self, "_public_asset", False):
                    continue
                self.send_header(name, value)
            super().end_headers()

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
                "<body style='color-scheme:light dark;background:Canvas;color:CanvasText;"
                "font-family:sans-serif;padding:48px;text-align:center;'>"
                "<h2>관제 데이터베이스 재연결 중입니다</h2>"
                "<p>잠시 후 자동으로 다시 연결됩니다 (3초 후 새로고침).</p>"
                "</body></html>"
            ).encode("utf-8")
            self._send(HTTPStatus.SERVICE_UNAVAILABLE, "text/html; charset=utf-8", html_body)

        def _redirect(self, location: str, set_cookie: str | None = None) -> None:
            self.send_response(HTTPStatus.SEE_OTHER)
            if set_cookie:
                self.send_header("Set-Cookie", set_cookie)
            self.send_header("Location", location)
            self.end_headers()

        def _send_font(self) -> None:
            data = _font_bytes()
            if data is None:
                self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"not found")
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "font/woff2")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
            self._public_asset = True  # 아래 end_headers가 no-store를 덧붙이지 않게 한다
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            if path == "/static/fonts/PretendardVariable.woff2":
                self._send_font()
                return
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
                if path == "/exports":
                    if auth_enabled and not user:
                        self._send(HTTPStatus.UNAUTHORIZED, "text/plain; charset=utf-8", b"Authentication required")
                        return
                    query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
                    try:
                        filename, content_type, payload = build_export(store, query)
                    except (ValueError, LookupError) as exc:
                        self._send(HTTPStatus.NOT_FOUND if isinstance(exc, LookupError) else HTTPStatus.BAD_REQUEST,
                                   "text/plain; charset=utf-8", str(exc).encode())
                        return
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Disposition", f'attachment; filename="sentinel-{filename}"')
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
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
                            login_range=urllib.parse.parse_qs(parsed.query).get("lf", ["hourly"])[0],
                            event_tab=urllib.parse.parse_qs(parsed.query).get("et", ["hourly"])[0],
                        ),
                    )
                    return

                if path == "/reports":
                    if auth_enabled and not user:
                        self._redirect("/login")
                        return
                    qs = urllib.parse.parse_qs(parsed.query)
                    try:
                        kind = qs.get("kind", ["weekly"])[0]
                        week = report_period(qs.get("week", [""])[0], kind)
                    except ValueError:
                        self._send(HTTPStatus.BAD_REQUEST, "text/plain; charset=utf-8", "유효한 날짜를 선택하세요.".encode())
                        return
                    reports = ReportRepository(store.storage) if isinstance(store, DbDashboardStore) else None
                    report = reports.get(report_key(week, kind)) if reports else None
                    snapshot = report["snapshot"] if report and report["finalized"] else _report_snapshot(store, week, kind)
                    followups = None
                    if reports:
                        try:
                            if report and report["finalized"]:
                                frozen = snapshot.get("followups")
                                followups = (reports.followups_by_ids([item["id"] for item in frozen])
                                             if frozen is not None else None)
                            else:
                                followups = reports.visible_followups(kind, report_key(week, kind))
                        except Exception as exc:
                            if not _is_db_error(exc):
                                raise
                            followups = None
                    message = {"collect": "기간 수치를 새로 집계했습니다. 집계 사실 문장은 자동으로 갱신되며, 핵심 판단은 직접 쓰셔야 합니다.",
                               "draft": "초안을 저장했습니다.", "final": "보고서를 확정했습니다.",
                               "locked": "이미 확정된 보고서입니다.", "summary": "확정하려면 핵심 판단을 입력하세요.",
                               "fu_added": "후속 조치를 등록했습니다.", "fu_updated": "후속 조치 상태를 바꿨습니다.",
                               "fu_invalid": "입력을 확인하세요. 완료는 근거, 미채택은 사유가 필요하고 내용은 비울 수 없습니다.",
                               "fu_missing": "해당 후속 조치를 찾지 못했습니다."}
                    previous = trend = None
                    if reports:
                        try:
                            history = reports.list()
                            prev_day = ((week.replace(day=1) - timedelta(days=1)).replace(day=1) if kind == "monthly"
                                        else week - timedelta(days=7))
                            previous = reports.get(report_key(prev_day, kind))
                            if previous and not previous["finalized"]:
                                previous = None
                            keys = sorted(k for k, fin, _ in history if fin and k.startswith("monthly:") == (kind == "monthly")
                                          and k <= report_key(week, kind))[-8:]
                            trend = []
                            for k in keys:
                                saved = reports.get(k)
                                value = (saved or {}).get("snapshot", {}).get("metrics", {}).get("신규 사건")
                                if value is not None:
                                    trend.append((k, value))
                        except Exception as exc:
                            if not _is_db_error(exc):
                                raise
                    exporting = qs.get("export", [""])[0] == "1"
                    if exporting and not report:
                        self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", "저장된 보고서가 없습니다.".encode())
                        return
                    body = report_body(week, report, snapshot, reports.list() if reports else [], csrf_tok,
                                       reports is not None and role_can(user, "report_write") and not exporting,
                                       message.get(qs.get("result", [""])[0], ""), kind=kind, followups=followups,
                                       previous=previous, trend=trend)
                    if exporting:
                        label = "final" if report["finalized"] else "draft"
                        page = standalone_page(f'{"월간" if kind == "monthly" else "주간"} 관제 보고서 {week}', body,
                                               "full" if qs.get("scope", ["summary"])[0] == "full" else "summary")
                        self.send_response(HTTPStatus.OK)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Disposition", f'attachment; filename="sentinel-report-{kind}-{week}-{label}.html"')
                        self.send_header("Cache-Control", "no-store")
                        data = page.encode("utf-8")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                        return
                    self._send(HTTPStatus.OK, "text/html; charset=utf-8", _page_shell(
                        "보고서", body, current_user=user, auth_enabled=auth_enabled,
                        active_path="/reports", csrf_token=csrf_tok,
                    ))
                    return

                if path == "/incidents":
                    if auth_enabled and not user:
                        self._redirect("/login")
                        return
                    qs = urllib.parse.parse_qs(parsed.query)
                    self._send(
                        HTTPStatus.OK,
                        "text/html; charset=utf-8",
                        render_incident_queue(
                            store, current_user=user, auth_enabled=auth_enabled, csrf_token=csrf_tok,
                            status=qs.get("status", [""])[0], severity=qs.get("severity", [""])[0],
                            incident_type=qs.get("type", [""])[0],
                            login_access_client=login_access_client,
                            error_message=qs.get("error", [None])[0],
                        ),
                    )
                    return

                if path == "/permissions":
                    if auth_enabled and not user:
                        self._redirect("/login")
                        return
                    qs = urllib.parse.parse_qs(parsed.query)
                    gp_raw = qs.get("gp", ["1"])[0].strip()
                    pv_view = qs.get("view", ["account"])[0]
                    pv_acct = qs.get("acct", [""])[0]
                    pv_doc = qs.get("doc", [""])[0]
                    self._send(
                        HTTPStatus.OK,
                        "text/html; charset=utf-8",
                        render_permissions_page(
                            current_user=user,
                            auth_enabled=auth_enabled,
                            csrf_token=csrf_tok,
                            login_access_client=login_access_client,
                            error_message=qs.get("error", [None])[0],
                            notice_message=qs.get("notice", [None])[0],
                            grant_page=int(gp_raw) if gp_raw.isdecimal() and len(gp_raw) <= 4 else 1,
                            view=pv_view, acct=pv_acct, doc=pv_doc,
                        ),
                    )
                    return

                if path in {"/logs/erp", "/logs/gateway", "/logs/caddy", "/logs/waf"}:
                    if auth_enabled and not user:
                        self._redirect("/login")
                        return
                    kind = path.rsplit("/", 1)[-1]
                    self._send(
                        HTTPStatus.OK,
                        "text/html; charset=utf-8",
                        render_source_logs(store, kind, current_user=user, auth_enabled=auth_enabled, csrf_token=csrf_tok,
                                           group=urllib.parse.parse_qs(parsed.query).get("group", [""])[0] == "1",
                                           scope_query={k:v[0] for k,v in urllib.parse.parse_qs(parsed.query).items()}),
                    )
                    return

                if path in {"/events", "/logs/events"}:
                    if auth_enabled and not user:
                        self._redirect("/login")
                        return
                    qs = urllib.parse.parse_qs(parsed.query)
                    def _parse_event_filter_time(raw_val: str) -> datetime | None:
                        s = raw_val.strip()
                        if not s:
                            return None
                        try:
                            dt = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
                            return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
                        except Exception:
                            return None
                    since_q = _parse_event_filter_time(qs.get("from", [""])[0])
                    until_q = _parse_event_filter_time(qs.get("to", [""])[0])
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
                    login_access_state, login_access_note = None, ""
                    account_lock_state, account_lock_note = None, ""
                    if inc.is_login_source_denial:
                        event = inc.login_access_event
                        if event is None:
                            login_access_note = "이 사건은 기록 확인용입니다. 승인이 필요하면 X 단말에서 새로운 로그인 요청을 남겨 주세요."
                        elif login_access_client is None:
                            login_access_note = "ERP 임시 승인 기능이 설정되지 않았습니다."
                        else:
                            try:
                                login_access_state = login_access_client.lookup(event)
                                if login_access_state is None:
                                    login_access_note = "ERP에서 승인 요청을 찾지 못했습니다. 설정을 확인하거나 X 단말에서 다시 로그인해 주세요."
                            except LoginAccessError as exc:
                                login_access_note = str(exc)
                    elif inc.has_account_lock_rule:
                        username = inc.lockable_account
                        if not username:
                            account_lock_note = "이 사건은 기록 확인용입니다. 신뢰할 수 있는 실시간 ERP 기록이 있어야 계정을 잠글 수 있습니다."
                        elif login_access_client is None:
                            account_lock_note = "ERP 연결 설정을 확인해 주세요."
                        else:
                            try:
                                account_lock_state = login_access_client.lookup_account_lock(inc.incident_id, username)
                                if account_lock_state is None:
                                    account_lock_note = "등록된 ERP 계정을 찾을 수 없습니다."
                            except LoginAccessError as exc:
                                account_lock_note = str(exc)
                    self._send(
                        HTTPStatus.OK,
                        "text/html; charset=utf-8",
                        render_incident_detail(
                            inc, err, current_user=user, auth_enabled=auth_enabled,
                            csrf_token=csrf_tok, followup_success=followup_success,
                            block_effects=_block_effects(store, inc.approvals),
                            login_access_state=login_access_state, login_access_note=login_access_note,
                            account_lock_state=account_lock_state, account_lock_note=account_lock_note,
                            release_audit_rows=audit_for_store(store).list_releases(inc.incident_id),
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
            if path in ("/reports", "/reports/followups") and not 0 <= length <= 64_000:
                self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "text/plain", b"Report form too large")
                return
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
            form = urllib.parse.parse_qs(raw_body)

            if not self._verify_origin():
                self._send(HTTPStatus.FORBIDDEN, "text/plain; charset=utf-8", b"Forbidden: Origin mismatch")
                return

            if path == "/reports":
                user = self._current_user()
                if (not auth_enabled or not user or not role_can(user, "report_write")
                        or not auth_config.verify_csrf(self._session_token(), form.get("csrf_token", [""])[0])):
                    self._send(HTTPStatus.FORBIDDEN, "text/plain", b"Report write permission required")
                    return
                try:
                    week_raw = form.get("week", [""])[0]
                    if not week_raw:
                        raise ValueError
                    kind = form.get("kind", ["weekly"])[0]
                    week = report_period(week_raw, kind)
                    intent = form.get("intent", [""])[0]
                    notes = {name: form.get(name, [""])[0].strip() for name, _ in REPORT_FIELDS}
                    if intent not in {"collect", "draft", "final"} or any(len(value) > 2000 for value in notes.values()):
                        raise ValueError
                except ValueError:
                    self._send(HTTPStatus.BAD_REQUEST, "text/plain", b"Invalid report form")
                    return
                if not isinstance(store, DbDashboardStore):
                    self._send(HTTPStatus.SERVICE_UNAVAILABLE, "text/plain", b"Report storage unavailable")
                    return
                if intent == "final" and not notes["summary"]:
                    # Keep the operator's other entries when validation fails.
                    result = "summary"
                else:
                    result = intent
                try:
                    snapshot = _report_snapshot(store, week, kind)
                    existing_report = ReportRepository(store.storage).get(report_key(week, kind))
                    if intent == "collect":
                        generated = calculated_draft(snapshot)
                        # Keep entered text and operator opinions on repeated collection.
                        notes = {key: value or generated.get(key, "") for key, value in notes.items()}
                    elif existing_report and not existing_report["finalized"]:
                        snapshot = existing_report["snapshot"]
                    if intent == "final":
                        # 확정 당시 후속 조치 목록을 얼려 둔다. 이후 상태 변화는 장부에서 따로 본다.
                        snapshot = dict(snapshot, followups=followup_freeze(
                            ReportRepository(store.storage).visible_followups(kind, report_key(week, kind))))
                    if not ReportRepository(store.storage).save(
                        report_key(week, kind), user, result == "final", {"notes": notes, "snapshot": snapshot},
                    ):
                        result = "locked"
                except Exception as exc:
                    if _is_db_error(exc):
                        self._send_db_unavailable()
                        return
                    raise
                self._redirect(f"/reports?kind={kind}&week={week}&result={result}#rp-writing")
                return

            if path == "/reports/followups":
                user = self._current_user()
                if (not auth_enabled or not user or not role_can(user, "report_write")
                        or not auth_config.verify_csrf(self._session_token(), form.get("csrf_token", [""])[0])):
                    self._send(HTTPStatus.FORBIDDEN, "text/plain", b"Report write permission required")
                    return
                if not isinstance(store, DbDashboardStore):
                    self._send(HTTPStatus.SERVICE_UNAVAILABLE, "text/plain", b"Report storage unavailable")
                    return
                try:
                    kind = form.get("kind", ["weekly"])[0]
                    week = report_period(form.get("week", [""])[0], kind)
                except ValueError:
                    self._send(HTTPStatus.BAD_REQUEST, "text/plain", b"Invalid report form")
                    return
                field = lambda name: form.get(name, [""])[0].strip()
                repo = ReportRepository(store.storage)
                try:
                    if field("intent") == "add":
                        existing = repo.get(report_key(week, kind))
                        error = validate_followup_new(field("text"), field("owner"), field("due"))
                        if existing and existing["finalized"]:
                            error = "확정된 보고서에는 새 후속 조치를 등록할 수 없습니다."
                        result = "fu_invalid" if error else "fu_added"
                        if not error:
                            repo.add_followup(kind, report_key(week, kind), field("text"), field("owner"),
                                              field("due"), user)
                    else:
                        error = validate_followup_change(field("status"), field("note"))
                        if error:
                            result = "fu_invalid"
                        elif repo.get_followup(field("followup_id")) is None:
                            result = "fu_missing"
                        else:
                            repo.update_followup(field("followup_id"), field("status"), field("note"), user)
                            result = "fu_updated"
                except Exception as exc:
                    if _is_db_error(exc):
                        self._send_db_unavailable()
                        return
                    raise
                self._redirect(f"/reports?kind={kind}&week={week}&result={result}#rp-followups")
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

            if path == "/permissions/action":
                user = self._current_user()
                if auth_enabled and not user:
                    self._send(HTTPStatus.UNAUTHORIZED, "text/plain; charset=utf-8", b"Authentication required")
                    return
                if auth_enabled and not auth_config.verify_csrf(
                    self._session_token(), form.get("csrf_token", [""])[0]
                ):
                    self._send(HTTPStatus.FORBIDDEN, "text/plain; charset=utf-8", b"Forbidden: Invalid CSRF token")
                    return
                perm_action = form.get("action", [""])[0].strip()
                perm_needed = {
                    "grant_doc": "approve",
                    "approve_doc_request": "approve",
                    "reject_doc_request": "approve",
                    "revoke_doc": "release",
                    "retire_account": "approve",
                    "restore_account": "release",
                }.get(perm_action)
                if not perm_needed:
                    self._redirect(f"/permissions?{urllib.parse.urlencode({'error': '지원하지 않는 권한 조치입니다.'})}")
                    return
                if auth_enabled and not role_can(user, perm_needed):
                    self._send(
                        HTTPStatus.FORBIDDEN,
                        "text/plain; charset=utf-8",
                        "이 계정의 역할에는 해당 조치를 실행할 권한이 없습니다.".encode("utf-8"),
                    )
                    return
                target_user = form.get("username", [""])[0].strip()
                doc_id = form.get("document_id", [""])[0].strip() or None
                reason = form.get("reason", [""])[0].strip()
                duration_raw = form.get("duration_minutes", ["60"])[0].strip()
                duration_minutes = int(duration_raw) if duration_raw.isdecimal() and len(duration_raw) <= 4 else 0
                actor = user or "soc-operator"
                # 권한을 회수한 뒤에는 보던 쪽에 그대로 남는다(쪽 번호가 범위를 넘으면 화면이 마지막 쪽으로 맞춘다).
                gp_raw = form.get("gp", [""])[0].strip()
                keep_page = {"gp": gp_raw} if perm_action == "revoke_doc" and gp_raw.isdecimal() and len(gp_raw) <= 4 else {}
                if perm_action == "revoke_doc":
                    # 권한 현황의 보기와 열어 둔 상세도 그대로 유지한다. 값은 화면이 다시 검증하므로 모양만 확인해서 돌려보낸다.
                    kept_view = form.get("view", [""])[0].strip()
                    if kept_view in ("account", "doc", "grid"):
                        keep_page["view"] = kept_view
                    for key in ("acct", "doc"):
                        kept = form.get(key, [""])[0].strip()
                        if kept and len(kept) <= 64 and re.fullmatch(r"[A-Za-z0-9_.@-]+", kept):
                            keep_page[key] = kept
                try:
                    if perm_action == "grant_doc" and not (1 <= duration_minutes <= 1440):
                        raise LoginAccessError("권한 유지 시간은 1~1440분(최대 24시간) 사이여야 합니다.")
                    if login_access_client is None:
                        raise LoginAccessError("ERP 연동 설정을 확인해 주세요.")
                    if perm_action in ("approve_doc_request", "reject_doc_request"):
                        access_id = form.get("access_request_id", [""])[0].strip()
                        if not re.fullmatch(r"[1-9][0-9]{0,18}", access_id):
                            raise LoginAccessError("요청 번호를 확인해 주세요.")
                        decision = "approve" if perm_action == "approve_doc_request" else "reject"
                        login_access_client.review_document_access(access_id, decision, actor)
                        message = "문서 열람 요청을 승인했습니다." if decision == "approve" else "문서 열람 요청을 반려했습니다."
                        self._redirect(f"/permissions?{urllib.parse.urlencode({'notice': message})}")
                        return
                    login_access_client.update_permission(
                        action=perm_action,
                        username=target_user,
                        operator=actor,
                        reason=reason,
                        document_id=doc_id,
                        duration_minutes=duration_minutes if perm_action == "grant_doc" else None,
                    )
                except LoginAccessError as exc:
                    self._redirect(f"/permissions?{urllib.parse.urlencode({'error': str(exc), **keep_page})}")
                    return
                dur_label = f"{duration_minutes // 60}시간" if duration_minutes % 60 == 0 else f"{duration_minutes}분"
                notice_map = {
                    "grant_doc": f"{target_user} 계정에 선택한 문서 열람 권한을 {dur_label} 동안 부여했습니다.",
                    "revoke_doc": f"{target_user} 계정의 특별 문서 열람 권한을 회수했습니다.",
                    "retire_account": f"{target_user} 계정을 퇴사 처리하여 모든 권한과 활성 세션을 회수·차단했습니다.",
                    "restore_account": f"{target_user} 계정의 기본 권한을 복구(재직 전환)했습니다.",
                }
                self._redirect(f"/permissions?{urllib.parse.urlencode({'notice': notice_map.get(perm_action, '처리가 완료되었습니다.'), **keep_page})}")
                return

            action_suffix = "/" + path.rsplit("/", 1)[-1]
            login_actions = {"/grant-login": ("approve", "approve"), "/revoke-login": ("revoke", "release")}
            account_actions = {"/lock-account": ("lock", "approve"), "/unlock-account": ("unlock", "release")}
            erp_actions = login_actions | account_actions
            if path.startswith("/incidents/") and action_suffix in {"/approve", "/release", "/refresh", *erp_actions}:
                user = self._current_user()
                if (auth_enabled or action_suffix in erp_actions
                        or (action_suffix == "/release" and isinstance(store, DbDashboardStore))) and not user:
                    self._send(HTTPStatus.UNAUTHORIZED, "text/plain; charset=utf-8", b"Authentication required")
                    return
                if auth_enabled and not auth_config.verify_csrf(
                    self._session_token(), form.get("csrf_token", [""])[0]
                ):
                    self._send(HTTPStatus.FORBIDDEN, "text/plain; charset=utf-8", b"Forbidden: Invalid CSRF token")
                    return

                inc_id = urllib.parse.unquote(path[len("/incidents/") : -len(action_suffix)])
                detail_path = f"/incidents/{urllib.parse.quote(inc_id, safe='')}"
                next_url = form.get("next", [""])[0].strip()
                redirect_path = "/incidents" if next_url == "/incidents" else detail_path
                # 상태 조회(/refresh)도 게이트웨이 확인 결과를 DB에 저장하므로 승인 권한이 필요하다(조회 전용 역할은 불가).
                permissions = {"/approve": "approve", "/release": "release", "/refresh": "approve"}
                permissions.update({suffix: permission for suffix, (_, permission) in erp_actions.items()})
                needed = permissions[action_suffix]
                if auth_enabled and needed and not role_can(user, needed):
                    self._send(
                        HTTPStatus.FORBIDDEN,
                        "text/plain; charset=utf-8",
                        "이 계정의 역할에는 해당 조치를 실행할 권한이 없습니다.".encode("utf-8"),
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

                        if action_suffix in login_actions:
                            event = inc.login_access_event
                            action, _ = login_actions[action_suffix]
                            reason = form.get("reason", [""])[0].strip()
                            try:
                                if not event or not login_access_client or not user:
                                    raise LoginAccessError("이 사건에서는 ERP 임시 접속을 승인하거나 취소할 수 없습니다.")
                                if action == "approve" and (not reason or not reason.isprintable() or len(reason) > 200):
                                    raise LoginAccessError("승인 사유를 1~200자로 입력해 주세요.")
                                login_access_client.update(event, inc.incident_id, user, action, reason)
                            except LoginAccessError as exc:
                                self._redirect(f"{redirect_path}?{urllib.parse.urlencode({'error': str(exc)})}")
                                return
                        elif action_suffix in account_actions:
                            username = inc.lockable_account
                            action, _ = account_actions[action_suffix]
                            reason = form.get("reason", [""])[0].strip()
                            minutes_raw = form.get("duration", ["10"])[0].strip()
                            duration = int(minutes_raw) if len(minutes_raw) <= 5 and minutes_raw.isdecimal() else 0
                            try:
                                if not username or not login_access_client or not user:
                                    raise LoginAccessError("이 사건에서는 ERP 계정을 잠그거나 해제할 수 없습니다.")
                                if action == "lock" and not (1 <= duration <= MAX_ACCOUNT_LOCK_MINUTES):
                                    raise LoginAccessError(f"잠금 시간은 1~{MAX_ACCOUNT_LOCK_MINUTES}분(최대 24시간) 사이여야 합니다.")
                                if not reason or len(reason) > 200 or not reason.isprintable():
                                    raise LoginAccessError("조치 사유를 1~200자로 입력해 주세요.")
                                login_access_client.update_account_lock(
                                    inc.incident_id, username, user, action, duration if action == "lock" else 0, reason,
                                )
                            except LoginAccessError as exc:
                                self._redirect(f"{redirect_path}?{urllib.parse.urlencode({'error': str(exc)})}")
                                return
                        elif action_suffix == "/approve":
                            approved_by = user if (auth_enabled and user) else form.get("approved_by", [""])[0]
                            try:
                                duration = _ip_block_minutes(form)
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
                                self._redirect(f"{redirect_path}?{q}")
                                return
                        elif action_suffix == "/release":
                            approval_id = form.get("approval_id", [""])[0]
                            try:
                                ap = release_with_audit(store, inc, approval_id=approval_id,
                                    requested_by=user or "unauthenticated-preview",
                                    reason=form.get("reason", [""])[0],
                                    operation_id=form.get("operation_id", [""])[0])
                            except ActionPolicyError as exc:
                                self._redirect(f"{redirect_path}?{urllib.parse.urlencode({'error': str(exc)})}")
                                return
                            if ap is not None:
                                store.persist_approval(inc, ap)
                                if ap.status != "released" and ap.gateway_response.get("error"):
                                    q = urllib.parse.urlencode({"error": f"차단 해제 실패: {ap.gateway_response.get('message') or ap.gateway_response.get('error')}"})
                                    self._redirect(f"{redirect_path}?{q}")
                                    return
                        elif action_suffix == "/refresh":
                            approval_id = form.get("approval_id", [""])[0]
                            ap = refresh_approval_status(inc, approval_id=approval_id, action_client=store.action_client)
                            if ap is not None:
                                store.persist_approval(inc, ap)
                                audit_for_store(store).observe_release(approval_id, ap.gateway_response)
                except Exception as exc:
                    if _is_db_error(exc):
                        self._send_db_unavailable()
                        return
                    raise

                self._redirect(redirect_path)
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
    *,
    login_access_client: LoginAccessClient | None = None,
) -> None:
    allow_container = os.environ.get("SOC_ALLOW_CONTAINER_BIND") == "1"
    if host != "127.0.0.1" and not (allow_container and host == "0.0.0.0"):
        raise ValueError("Dashboard must bind only to 127.0.0.1 (or 0.0.0.0 inside container)")

    active_store = store or load_sample_store()
    server = ThreadingHTTPServer((host, port), make_handler(
        active_store, auth_config=auth_config, login_access_client=login_access_client,
    ))
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
        login_access_token = os.environ.get("ERP_LOGIN_ACCESS_TOKEN", "").strip()
        login_access_client = LoginAccessClient(login_access_token) if login_access_token else None
        run_server(host=bind_host, port=port_env, store=db_store, auth_config=auth, login_access_client=login_access_client)
    else:
        run_server(host=bind_host, port=port_env)
