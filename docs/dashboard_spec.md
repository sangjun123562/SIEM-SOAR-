# 관제 대시보드(관제 앱 + Grafana) 표시 항목 및 조치 API 초안

## 1. 관제 앱 (사건 상세 & 방화벽 조치 승인 UI)

### 사건 목록 화면
- `incident_id`, `title`, `severity`, `status` (`open`, `approved`, `blocked`, `released`, `closed`)
- `target_ip`, `username`, `created_at_utc`, `updated_at_utc`

### 사건 상세 화면 (추적성 필수)
- **추적 체인**: `사건(incident_id)` → `경보(alert_id, rule_name, failure_count)` → `근거 이벤트(event_id, request_id, client_ip_trusted)` → `원본 로그(raw_id, raw_payload)`
- **게이트웨이 연결 후보**: `gateway_candidate` 링크 타입으로 별도 표시 (단독 확정 금지)
- **조치 승인 패널**:
  - 조건 확인 배지: `ingest_mode == 'live'` AND `client_ip_trusted == true` 일 때만 승인 버튼 활성화
  - 승인 버튼 클릭 시 A의 게이트웨이 조치 API로 요청 전송
  - 승인 이력 및 적용·조회·해제 결과(`status`, `applied_at_utc`, `expires_at_utc`, `released_at_utc`) 표시

## 2. Grafana (관제 DB 읽기 전용 `grafana_reader`)

1. **로그 도착 상태 패널**: `source` (`gateway`, `caddy`, `erp`)별 최근 5분 수신 건수 및 마지막 `received_at_utc`
2. **최근 사건 현황 테이블**: 최근 `incidents` 목록 (상태, 심각도, 대상 IP, 발생 시각)
3. **방화벽 조치 상태 패널**: `action_approvals`의 상태별(`applied`, `released`, `expired`, `pending`) 건수 및 활성 차단 목록

## 3. A ↔ B 게이트웨이 조치 API 계약 (4~5일 차 확정용 초안)

- **요청 (`POST /api/v1/gateway/actions/block`)**:
  ```json
  {
    "approval_id": "APR-20261117-001",
    "target_ip": "172.28.0.10",
    "expires_at_utc": "2026-11-17T03:00:00Z"
  }
  ```
- **응답**:
  ```json
  {
    "approval_id": "APR-20261117-001",
    "target_ip": "172.28.0.10",
    "status": "applied",
    "expires_at_utc": "2026-11-17T03:00:00Z",
    "applied_at_utc": "2026-11-17T02:15:01Z"
  }
  ```
- **해제 (`POST /api/v1/gateway/actions/unblock`)** 및 **조회 (`GET /api/v1/gateway/actions/{approval_id}`)** 도 동일 구조로 반환한다.
