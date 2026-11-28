from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .detector import (
    AUTO_ACCOUNT_LOCK_RULE_ID,
    DOC_DENIED_RULE_ID,
    IP_MULTI_ACCOUNT_FAILURE_RULE_ID,
    LOGIN_FAILURE_REVIEW_RULE_ID,
    LOGIN_FAILURE_RULE_ID,
    LOGIN_SOURCE_CHANGE_RULE_ID,
    LOGIN_SOURCE_DENIED_RULE_ID,
    LOGIN_SUCCESS_REVIEW_RULE_ID,
    MULTI_ACCOUNT_RULE_ID,
    AlertRecord,
    detect_automatic_account_locks,
    detect_icmp_denials,
    detect_login_failures,
    detect_ip_multi_account_failures,
    detect_login_failure_reviews,
    detect_login_source_denials,
    detect_login_success_from_different_source,
    detect_multi_account_failures,
    detect_document_access_denials,
    detect_multi_source_failures,
    is_x_login_denial,
)
from .models import NormalizedEvent, RawLogRecord

MAX_BLOCK_MINUTES = 43200
# 계정 수동 잠금은 직원 업무를 막으므로 IP 차단과 따로 최대 24시간으로 제한한다(팀 결정 2026-11-27).
MAX_ACCOUNT_LOCK_MINUTES = 1440
ACCOUNT_LOCK_RULES = frozenset({
    AUTO_ACCOUNT_LOCK_RULE_ID, LOGIN_SUCCESS_REVIEW_RULE_ID, LOGIN_SOURCE_CHANGE_RULE_ID, LOGIN_FAILURE_REVIEW_RULE_ID,
})
# 차단 후보 사건에 같은 실패 기록으로 만든 '의심' 경보를 붙여 한 사건으로 보여 줄 때 쓰는 규칙(팀 합의 2026-11-26).
BLOCK_RULES = frozenset({LOGIN_FAILURE_RULE_ID, IP_MULTI_ACCOUNT_FAILURE_RULE_ID})
SUPPORT_RULES = frozenset({LOGIN_FAILURE_REVIEW_RULE_ID, MULTI_ACCOUNT_RULE_ID})
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


@dataclass(frozen=True)
class IncidentReview:
    operation_id: str
    state: str
    actor: str
    decision: str
    reason: str
    recorded_at_utc: str


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
    reviews: dict[str, IncidentReview] = field(default_factory=dict)

    @property
    def review_state(self) -> str:
        states = [self.reviews.get(alert.alert_id) for alert in self.alerts]
        if not states or any(review is None for review in states):
            return "pending"
        return "closed" if all(review.state == "closed" for review in states) else "reviewing"

    @property
    def is_login_source_denial(self) -> bool:
        return len(self.alerts) == 1 and self.alerts[0].rule_id == LOGIN_SOURCE_DENIED_RULE_ID

    @property
    def login_access_event(self) -> NormalizedEvent | None:
        # 실시간에 ERP가 등록한 요청만 임시 승인의 근거로 쓴다.
        if not self.is_login_source_denial or len(self.evidence_events) != 1 or not self.live_and_trusted_eligible:
            return None
        event = self.evidence_events[0]
        if (is_x_login_denial(event) and event.details.get("access_requested") is True
                and event.username and event.username == self.username and event.client_ip == self.target_ip):
            return event
        return None

    @property
    def block_rule_eligible(self) -> bool:
        # 기존 반복 실패 규칙에서만 차단 승인을 허용한다. 주의 사건은 사람이 검토한다.
        # 같은 실패 기록에서 나온 의심 경보가 함께 붙어 있어도 차단 후보 경보가 하나 이상이면 승인할 수 있다.
        return any(alert.rule_id in BLOCK_RULES for alert in self.alerts) and all(
            alert.rule_id in BLOCK_RULES | SUPPORT_RULES for alert in self.alerts
        )

    @property
    def has_account_lock_rule(self) -> bool:
        return bool(self.alerts) and all(alert.rule_id in ACCOUNT_LOCK_RULES for alert in self.alerts)

    @property
    def lockable_account(self) -> str | None:
        # 여러 계정의 묶음이나 재생 기록에서는 잠글 계정을 결정하지 않는다.
        if self.has_account_lock_rule and self.username and self.live_and_trusted_eligible and all(
            event.source == "erp" and event.username == self.username for event in self.evidence_events
        ):
            return self.username
        return None

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


def group_login_incidents(incidents: list[IncidentView]) -> list[IncidentView]:
    """Show one case when persisted incidents share the same failure evidence."""
    observations = {}
    automatic = {}
    for incident in incidents:
        rules = {alert.rule_id for alert in incident.alerts}
        if rules == {LOGIN_FAILURE_REVIEW_RULE_ID}:
            observations.setdefault((incident.username, incident.target_ip), []).append(incident)
        if rules == {AUTO_ACCOUNT_LOCK_RULE_ID}:
            for event in incident.evidence_events:
                if event.request_id:
                    automatic[(incident.username, incident.target_ip, event.request_id, event.ingest_mode)] = incident

    grouped = {}
    hidden = set()
    for ip_case in incidents:
        if not ip_case.block_rule_eligible or not ip_case.evidence_events:
            continue
        last = max(ip_case.evidence_events, key=lambda event: _parse_utc(event.event_ts_utc))
        lock = automatic.get((ip_case.username, ip_case.target_ip, last.request_id, last.ingest_mode))
        if (lock is None or lock.incident_id in grouped
                or any(event.ingest_mode != last.ingest_mode for event in ip_case.evidence_events)):
            continue
        failures = {event.event_id: event for event in ip_case.evidence_events}
        matching = [
            item for item in observations.get((ip_case.username, ip_case.target_ip), [])
            if item.evidence_events and all(event.event_id in failures for event in item.evidence_events)
        ]
        grouped[lock.incident_id] = replace(
            lock,
            created_at_utc=min([lock.created_at_utc, *(item.created_at_utc for item in matching)]),
            alerts=[*(alert for item in matching for alert in item.alerts), *lock.alerts],
            evidence_events=[*failures.values(), *lock.evidence_events],
            raw_logs_by_id=ip_case.raw_logs_by_id | lock.raw_logs_by_id,
        )
        hidden.update(item.incident_id for item in matching)
    result = [grouped.get(item.incident_id, item) for item in incidents if item.incident_id not in hidden]
    return _merge_support_alerts(result)


def _merge_support_alerts(incidents: list[IncidentView]) -> list[IncidentView]:
    """같은 공격의 '의심' 사건(3회 연속 실패·여러 계정 실패)을 차단 후보 사건에 합쳐 한 건으로 보인다.

    의심 사건의 근거 기록이 모두 차단 후보 사건의 근거 안에 있고 수집 방식이 같을 때만 합친다.
    근거 기록은 늘어나지 않으므로 승인 조건(라이브·신뢰 출발지)은 그대로다.
    """
    supports = [
        item for item in incidents
        if item.alerts and item.evidence_events and all(alert.rule_id in SUPPORT_RULES for alert in item.alerts)
    ]
    absorbed: set[str] = set()
    for base in incidents:
        if not any(alert.rule_id in BLOCK_RULES for alert in base.alerts) or not base.evidence_events:
            continue
        if not all(alert.rule_id in BLOCK_RULES | SUPPORT_RULES for alert in base.alerts):
            continue
        base_ids = {event.event_id for event in base.evidence_events}
        base_modes = {event.ingest_mode for event in base.evidence_events}
        mine = [
            item for item in supports
            if item.incident_id not in absorbed
            and {event.event_id for event in item.evidence_events} <= base_ids
            and {event.ingest_mode for event in item.evidence_events} <= base_modes
        ]
        if not mine:
            continue
        absorbed.update(item.incident_id for item in mine)
        # 승인·차단 상태는 원래 사건 객체에 기록되므로 복사하지 않고 그 객체에 경보를 덧붙인다(같은 경보는 한 번만).
        known = {alert.alert_id for alert in base.alerts}
        for item in mine:
            for alert in item.alerts:
                if alert.alert_id not in known:
                    known.add(alert.alert_id)
                    base.alerts.append(alert)
            base.raw_logs_by_id.update(item.raw_logs_by_id)
            if item.created_at_utc < base.created_at_utc:
                base.created_at_utc = item.created_at_utc
    return [item for item in incidents if item.incident_id not in absorbed]


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
    alerts = detect_login_failures(
        events, threshold=threshold, window_seconds=window_seconds, include_success_reviews=True,
    )
    # 추가 탐지 결과도 기존과 같은 방식으로 사건을 만들고 원본 기록에 연결한다.
    alerts.extend(detect_login_success_from_different_source(
        events, window_seconds=window_seconds, failure_threshold=threshold,
    ))
    alerts.extend(detect_multi_account_failures(events))
    alerts.extend(detect_ip_multi_account_failures(events, window_seconds=window_seconds))
    alerts.extend(detect_multi_source_failures(events))
    alerts.extend(detect_document_access_denials(events))
    alerts.extend(detect_icmp_denials(events))
    alerts.extend(detect_login_source_denials(events))
    alerts.extend(detect_automatic_account_locks(events))
    alerts.extend(detect_login_failure_reviews(events, window_seconds=window_seconds))

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
        elif alert.rule_id == DOC_DENIED_RULE_ID:
            title = f"Repeated document access denials: {alert.username} from {alert.client_ip}"

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
        incident.status = "blocked" if any(a.status == "applied" for a in incident.approvals) else "released"
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
        incident.status = "blocked" if any(a.status == "applied" for a in incident.approvals) else "released"
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
            incident.status = "blocked" if any(a.status == "applied" for a in incident.approvals) else "released"
        incident.updated_at_utc = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return target_ap
