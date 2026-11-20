from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .detector import (
    LOGIN_FAILURE_RULE_ID,
    AlertRecord,
    detect_login_failures,
    detect_multi_account_failures,
    detect_multi_source_failures,
)
from .models import NormalizedEvent, RawLogRecord

MAX_BLOCK_MINUTES = 30
ACTION_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,64}$")
CANDIDATE_SERVICE_PORTS = frozenset({80, 443, 8000, 8443})


@dataclass(frozen=True)
class CorrelationLink:
    """Correlation link between an incident and supporting events."""

    correlation_id: str
    incident_id: str
    event_id: str
    raw_id: str
    link_type: str  # "request_id_exact" | "gateway_candidate"
    reason: str


@dataclass
class ApprovalRecord:
    """Human approval and gateway enforcement state for an incident."""

    approval_id: str
    incident_id: str
    target_ip: str
    action_type: str  # "block" | "unblock"
    approved_by: str
    approved_at_utc: str
    expires_at_utc: str
    status: str  # "pending" | "applied" | "released" | "expired" | "rejected" | "apply_failed"
    gateway_response: dict[str, Any] = field(default_factory=dict)


@dataclass
class IncidentView:
    """Full incident view tracing incident -> alerts -> evidence events -> raw_logs."""

    incident_id: str
    title: str
    status: str
    severity: str
    target_ip: str
    username: str
    created_at_utc: str
    updated_at_utc: str
    alerts: list[AlertRecord] = field(default_factory=list)
    evidence_events: list[NormalizedEvent] = field(default_factory=list)
    correlations: list[CorrelationLink] = field(default_factory=list)
    raw_logs_by_id: dict[str, RawLogRecord] = field(default_factory=dict)
    approvals: list[ApprovalRecord] = field(default_factory=list)

    @property
    def block_rule_eligible(self) -> bool:
        # 기존 반복 실패 규칙에서만 차단 승인을 허용한다. 새 두 규칙은 조사용이다.
        return bool(self.alerts) and all(alert.rule_id == LOGIN_FAILURE_RULE_ID for alert in self.alerts)

    @property
    def live_and_trusted_eligible(self) -> bool:
        """Return True only when at least one evidence event is live and client_ip_trusted."""
        if not self.evidence_events:
            return False
        # Do not allow real enforcement if any evidence is synthetic/replay or untrusted.
        return all(
            ev.ingest_mode == "live" and ev.client_ip_trusted
            for ev in self.evidence_events
        )


def _parse_utc(ts_str: str) -> datetime:
    raw = ts_str.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def build_incidents(
    raw_records: list[RawLogRecord],
    events: list[NormalizedEvent],
    *,
    threshold: int = 5,
    window_seconds: int = 300,
    gateway_window_seconds: int = 10,
) -> list[IncidentView]:
    """Run detection and build traceable IncidentView objects with correlations."""
    raw_by_id = {rec.raw_id: rec for rec in raw_records}
    events_by_id = {ev.event_id: ev for ev in events}
    alerts = detect_login_failures(events, threshold=threshold, window_seconds=window_seconds)
    # 기존 규칙의 결과에 새 두 규칙의 경보를 더해, 같은 방식으로 사건을 만든다.
    alerts.extend(detect_multi_account_failures(events))
    alerts.extend(detect_multi_source_failures(events))

    incidents: list[IncidentView] = []
    for alert in alerts:
        inc_id = "INC-" + hashlib.sha256(alert.dedup_key.encode("utf-8")).hexdigest()[:10].upper()
        evidence = [events_by_id[eid] for eid in alert.evidence_event_ids if eid in events_by_id]
        inc_raw_by_id = {
            ev.raw_id: raw_by_id[ev.raw_id]
            for ev in evidence
            if ev.raw_id in raw_by_id
        }

        correlations: list[CorrelationLink] = []
        seen_corr: set[tuple[str, str]] = set()

        # 1. Exact request_id correlation between Caddy and ERP.
        evidence_req_ids = {ev.request_id for ev in evidence if ev.request_id}
        for ev in events:
            if ev.source == "caddy" and ev.request_id and ev.request_id in evidence_req_ids:
                key = (ev.event_id, "request_id_exact")
                if key not in seen_corr:
                    seen_corr.add(key)
                    if ev.raw_id in raw_by_id:
                        inc_raw_by_id[ev.raw_id] = raw_by_id[ev.raw_id]
                    corr_id = "COR-" + hashlib.sha256(f"{inc_id}:{ev.event_id}:req".encode()).hexdigest()[:10].upper()
                    correlations.append(
                        CorrelationLink(
                            correlation_id=corr_id,
                            incident_id=inc_id,
                            event_id=ev.event_id,
                            raw_id=ev.raw_id,
                            link_type="request_id_exact",
                            reason=f"Matched Caddy request_id={ev.request_id}",
                        )
                    )

        # 2. Gateway candidate correlation (address + protocol/port + time proximity).
        # 여러 IP가 나온 사건도 각 IP의 실패 시각으로 방화벽 기록 후보를 찾는다.
        evidence_times_by_ip: dict[str, list[datetime]] = {}
        for ev in evidence:
            if ev.client_ip:
                evidence_times_by_ip.setdefault(ev.client_ip, []).append(_parse_utc(ev.event_ts_utc))
        gw_delta = timedelta(seconds=gateway_window_seconds)
        for ev in events:
            if ev.source != "gateway":
                continue
            if not ev.src_ip or ev.src_ip not in evidence_times_by_ip:
                continue
            if ev.protocol is not None and str(ev.protocol).lower() != "tcp":
                continue
            if ev.dst_port is not None and int(ev.dst_port) not in CANDIDATE_SERVICE_PORTS:
                continue
            gw_dt = _parse_utc(ev.event_ts_utc)
            if any(abs(gw_dt - edt) <= gw_delta for edt in evidence_times_by_ip[ev.src_ip]):
                key = (ev.event_id, "gateway_candidate")
                if key not in seen_corr:
                    seen_corr.add(key)
                    if ev.raw_id in raw_by_id:
                        inc_raw_by_id[ev.raw_id] = raw_by_id[ev.raw_id]
                    corr_id = "COR-" + hashlib.sha256(f"{inc_id}:{ev.event_id}:gw".encode()).hexdigest()[:10].upper()
                    correlations.append(
                        CorrelationLink(
                            correlation_id=corr_id,
                            incident_id=inc_id,
                            event_id=ev.event_id,
                            raw_id=ev.raw_id,
                            link_type="gateway_candidate",
                            reason=f"Gateway src_ip={ev.src_ip} dst_port={ev.dst_port} within {gateway_window_seconds}s",
                        )
                    )

        title = alert.rule_name
        if alert.rule_id == LOGIN_FAILURE_RULE_ID:
            title = f"Repeated login failures: {alert.username} from {alert.client_ip}"

        incidents.append(
            IncidentView(
                incident_id=inc_id,
                title=title,
                status="open",
                severity=alert.severity,
                target_ip=alert.client_ip,
                username=alert.username,
                created_at_utc=alert.window_end_utc,
                updated_at_utc=alert.window_end_utc,
                alerts=[alert],
                evidence_events=evidence,
                correlations=correlations,
                raw_logs_by_id=inc_raw_by_id,
            )
        )

    return incidents


class ActionPolicyError(ValueError):
    """Raised when an enforcement action violates live/trusted/expiry policy."""


class ActionApiClient:
    """HTTP client for gateway enforcement API defined in DESIGN.md section 3."""

    def __init__(self, base_url: str, bearer_token: str, timeout_seconds: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.timeout_seconds = timeout_seconds

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(err_body)
            except json.JSONDecodeError:
                parsed = {"error": "http_error", "message": err_body}
            parsed["http_status"] = exc.code
            return parsed

    def block(
        self,
        *,
        approval_id: str,
        target_ip: str,
        expires_at_utc: str,
        incident_id: str,
        approved_by: str,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/actions/block",
            {
                "approval_id": approval_id,
                "target_ip": target_ip,
                "expires_at_utc": expires_at_utc,
                "incident_id": incident_id,
                "approved_by": approved_by,
            },
        )

    def get_status(self, approval_id: str) -> dict[str, Any]:
        return self._request("GET", f"/actions/{approval_id}")

    def release(self, approval_id: str) -> dict[str, Any]:
        return self._request("POST", f"/actions/{approval_id}/release", {})


def _validate_identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not ACTION_IDENTIFIER_RE.fullmatch(value):
        raise ActionPolicyError(
            f"{field_name} must match ^[A-Za-z0-9._:@-]{{1,64}}$ without spaces"
        )
    return value


def _is_active_approval(ap: ApprovalRecord, now: datetime) -> bool:
    if ap.status not in {"applied", "pending", "unknown"}:
        return False
    try:
        return _parse_utc(ap.expires_at_utc) > now
    except Exception:
        return ap.status == "applied"


def request_human_approval(
    incident: IncidentView,
    *,
    approved_by: str,
    duration_minutes: int = 10,
    action_client: ActionApiClient | None = None,
    now_utc: datetime | None = None,
    existing_incidents: list[IncidentView] | None = None,
    on_before_call: Callable[[ApprovalRecord], None] | None = None,
) -> ApprovalRecord:
    """Validate live+trusted conditions, prevent duplicate blocks, pre-save approval, and call gateway API."""
    clean_actor = _validate_identifier(approved_by, "approved_by")
    _validate_identifier(incident.incident_id, "incident_id")
    if not (1 <= duration_minutes <= MAX_BLOCK_MINUTES):
        raise ActionPolicyError(f"duration_minutes must be between 1 and {MAX_BLOCK_MINUTES}")
    # 화면과 별개로 서버에서도 검사한다. 조사용 사건은 방화벽에 요청을 보내지 않는다.
    if not incident.block_rule_eligible:
        raise ActionPolicyError("조사용 사건은 방화벽 차단을 승인할 수 없습니다.")
    if not incident.live_and_trusted_eligible:
        raise ActionPolicyError(
            "Enforcement blocked: requires live ingest_mode and client_ip_trusted=True on all evidence"
        )

    now = (now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)

    # 1) Idempotent return if this incident already has an active non-expired approval.
    for existing in reversed(incident.approvals):
        if _is_active_approval(existing, now):
            return existing

    # 2) Prevent duplicate blocks across separate incidents targeting the same IP.
    if existing_incidents:
        for other in existing_incidents:
            if other.incident_id == incident.incident_id or other.target_ip != incident.target_ip:
                continue
            for existing in reversed(other.approvals):
                if _is_active_approval(existing, now):
                    raise ActionPolicyError(
                        f"대상 IP({incident.target_ip})에 이미 활성 차단/대기 조치({existing.approval_id})가 존재합니다"
                    )

    expires = now + timedelta(minutes=duration_minutes)
    approved_at_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at_str = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
    approval_id = f"APR-{now.strftime('%Y%m%d%H%M%S')}-{incident.incident_id[-6:]}"

    record = ApprovalRecord(
        approval_id=approval_id,
        incident_id=incident.incident_id,
        target_ip=incident.target_ip,
        action_type="block",
        approved_by=clean_actor,
        approved_at_utc=approved_at_str,
        expires_at_utc=expires_at_str,
        status="pending",
        gateway_response={},
    )
    incident.approvals.append(record)
    incident.updated_at_utc = approved_at_str

    if action_client is not None:
        if on_before_call is not None:
            on_before_call(record)
        try:
            gateway_resp = action_client.block(
                approval_id=approval_id,
                target_ip=incident.target_ip,
                expires_at_utc=expires_at_str,
                incident_id=incident.incident_id,
                approved_by=clean_actor,
            )
            record.gateway_response = gateway_resp
            if gateway_resp.get("status") == "applied":
                record.status = "applied"
                incident.status = "blocked"
            else:
                record.status = "apply_failed"
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            record.status = "unknown"
            record.gateway_response = {"error": "communication_error", "message": str(exc)}
            incident.status = "approved"
    else:
        incident.status = "approved"

    return record


def release_approval(
    incident: IncidentView,
    *,
    approval_id: str,
    action_client: ActionApiClient | None,
    now_utc: datetime | None = None,
) -> ApprovalRecord | None:
    """Call gateway release API for approval_id and update incident/approval state."""
    target_ap = next((a for a in reversed(incident.approvals) if a.approval_id == approval_id), None)
    if target_ap is None or action_client is None:
        return target_ap
    try:
        resp = action_client.release(approval_id)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        target_ap.gateway_response = {"error": "release_communication_error", "message": str(exc)}
        return target_ap
    target_ap.gateway_response = resp
    if resp.get("status") == "released":
        target_ap.status = "released"
        incident.status = "released"
        now = (now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)
        incident.updated_at_utc = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return target_ap


def refresh_approval_status(
    incident: IncidentView,
    *,
    approval_id: str,
    action_client: ActionApiClient | None,
    now_utc: datetime | None = None,
) -> ApprovalRecord | None:
    """Query GET /actions/{approval_id}, verify rule_present, and sync status."""
    target_ap = next((a for a in reversed(incident.approvals) if a.approval_id == approval_id), None)
    if target_ap is None or action_client is None:
        return target_ap
    try:
        resp = action_client.get_status(approval_id)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        target_ap.gateway_response = {"error": "status_communication_error", "message": str(exc)}
        return target_ap

    target_ap.gateway_response = resp
    gw_status = resp.get("status")
    rule_present = resp.get("rule_present")
    now = (now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)

    if gw_status == "applied" and rule_present is False:
        target_ap.status = "expired"
        incident.status = "released"
        incident.updated_at_utc = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif gw_status == "not_found" or resp.get("http_status") == 404:
        if target_ap.status in {"pending", "unknown"}:
            target_ap.status = "rejected"
            incident.status = "open"
            incident.updated_at_utc = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif gw_status in {"applied", "released", "expired"}:
        target_ap.status = gw_status
        if gw_status == "applied":
            incident.status = "blocked"
        else:
            incident.status = "released"
        incident.updated_at_utc = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return target_ap
