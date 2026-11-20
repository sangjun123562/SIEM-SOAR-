# 관제 대시보드(관제 앱 + Grafana) 표시 항목 및 조치 API 초안

## 1. 관제 앱 (사건 상세 & 방화벽 조치 승인 UI)

### 사건 목록 화면
- `incident_id`, `title`, `severity`, `status` (`open`, `approved`, `blocked`, `released`, `closed`)
- `target_ip`, `username`, `created_at_utc`, `updated_at_utc`

### 사건 상세 화면 (추적성 필수)
- **추적 체인**: `사건(incident_id)` → `경보(alert_id, rule_name, failure_count)` → `근거 이벤트(event_id, request_id, client_ip_trusted)` → `원본 로그(raw_id, raw_payload)`
- **게이트웨이 연결 후보**: `gateway_candidate` 링크 타입으로 별도 표시 (TCP 및 웹/ERP 포트 `80, 443, 8000, 8443` + 시각·IP 근접 후보만 연결, 단독 확정 금지)
- **조치 승인 패널**:
  - 조건 확인 배지: **모든 근거 이벤트**가 `ingest_mode == 'live'` AND `client_ip_trusted == true` 일 때만 승인 버튼 활성화 (혼합·재생·합성·미신뢰 근거 1건이라도 포함 시 차단 금지)
  - 요청 전 `pending` 승인 선저장 후 A의 게이트웨이 조치 API 호출 (응답 유실/타임아웃 시 `unknown` 상태 저장 및 동일 `approval_id`로 `상태 조회` 복구)
  - 동일 사건 중복 승인 시 기존 활성 승인 반환, 타 사건의 동일 `target_ip` 활성 차단 존재 시 중복 차단 거부
  - 승인 이력 및 적용·조회·해제 결과(`pending`, `applied`, `unknown`, `released`, `expired`, `rejected`) 표시

## 2. Grafana (관제 DB 읽기 전용 `grafana_reader`)

1. **로그 도착 상태 패널**: `source` (`gateway`, `caddy`, `erp`)별 최근 5분 수신 건수 및 마지막 `received_at_utc`
2. **최근 사건 현황 테이블**: 최근 `incidents` 목록 (상태, 심각도, 대상 IP, 발생 시각)
3. **방화벽 조치 상태 패널**: `action_approvals`의 `COUNT(DISTINCT target_ip)` 기반 활성 차단 IP 수(`status = 'applied' AND expires_at_utc > NOW()`) 및 상태별 건수

## 3. A ↔ B 게이트웨이 조치 API 계약 (구현 기준)

- **차단 요청 (`POST /actions/block`)**:
  ```json
  {
    "approval_id": "APR-20261117-001",
    "target_ip": "172.28.0.10",
    "expires_at_utc": "2026-11-17T03:00:00Z",
    "incident_id": "INC-...",
    "approved_by": "soc-operator"
  }
  ```
- **응답 / 상태 조회 (`GET /actions/{approval_id}`)**:
  ```json
  {
    "approval_id": "APR-20261117-001",
    "target_ip": "172.28.0.10",
    "status": "applied",
    "rule_present": true,
    "expires_at_utc": "2026-11-17T03:00:00Z",
    "applied_at_utc": "2026-11-17T02:15:01Z"
  }
  ```
- **해제 (`POST /actions/{approval_id}/release`)**: 동일 승인 ID로 게이트웨이 규칙 제거 및 DB 상태(`released`) 동기화.
