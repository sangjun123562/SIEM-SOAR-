# A ↔ B 공통 로그 형식 합의서 (1일 차)

모든 로그는 **JSON Lines (`.jsonl`, 한 줄에 하나의 완성된 JSON 객체, UTF-8, `\n` 종료)** 형식을 사용한다.
**비밀번호·토큰·쿠키·요청 본문은 절대 로그에 기록하지 않는다.**

## 1. 공통 필수/권장 필드 (원본 로그 → 정규화 매핑)

| 필드명 | 타입 | 설명 | 예시 |
|---|---|---|---|
| `timestamp_utc` | string (ISO-8601 UTC) | 이벤트 발생 시각 (반드시 `Z` 또는 `+00:00` 포함) | `"2026-11-17T02:08:24.123456Z"` |
| `source` | string | 로그 출처 (`gateway`, `caddy`, `erp`) | `"gateway"` |
| `event_type` | string | 이벤트 유형 | `"fw_allow"`, `"fw_deny"`, `"http_request"`, `"login_failed"`, `"login_success"` |
| `outcome` | string | 결과 (`allow`, `deny`, `success`, `failure`) | `"deny"` |
| `ingest_mode` | string (선택, 기본 `live`) | 수집 모드 (`live`, `replay`, `synthetic`) | `"live"` |

## 2. 소스별 세부 필드

### A. 게이트웨이 로그 (`gateway.jsonl`)
- **역할**: 시험 단말·대조 단말의 허용(`fw_allow`) 및 차단(`fw_deny`) 기록
- **필드**:
  - `src_ip` (string): 출발지 IP (예: `"172.28.0.10"`)
  - `src_port` (int): 출발지 포트
  - `dst_ip` (string): 목적지 IP
  - `dst_port` (int): 목적지 포트
  - `protocol` (string): `"TCP"` | `"UDP"`
  - `action` (string): `"allow"` | `"deny"`
  - `rule_id` (string, 선택): 적용된 규칙/승인 ID (예: `"APR-20261117-001"`)

### B. Caddy HTTPS 로그 (`caddy.jsonl`, 3일 차~)
- **역할**: `X-Request-ID`와 `X-Client-IP`를 직접 덮어써서 ERP로 전달
- **필드**:
  - `request_id` (string): Caddy가 생성·덮어쓴 `X-Request-ID`
  - `client_ip` (string): Caddy가 덮어쓴 `X-Client-IP`
  - `peer_ip` (string): Caddy에 직접 연결한 IP
  - `http_method` (string): `"GET"`, `"POST"` 등
  - `http_path` (string): 요청 경로 (예: `"/api/login"`)
  - `status_code` (int): HTTP 응답 코드

### C. Flask ERP 감사 로그 (`erp.jsonl`, 4일 차~)
- **역할**: 로그인 성공/실패 및 구매 요청 생성·승인·반려 기록
- **필드**:
  - `request_id` (string): 전달받은 `X-Request-ID`
  - `client_ip` (string): 전달받은 `X-Client-IP`
  - `peer_ip` (string): ERP 소켓의 직접 연결 상대 IP
  - `client_ip_trusted` (bool): `peer_ip`가 지정된 Caddy일 때만 `true`
  - `username` (string): 로그인 시도 계정 또는 행위자 계정
  - `http_method` (string), `http_path` (string), `status_code` (int)
  - `resource_id` (string, 선택): 구매 요청 ID 등

## 3. 정규화 및 추적 규칙 (`raw_id`)

- 수집기는 각 줄을 읽을 때 `raw_id = sha256(f"{source}:{file_path}:{line_offset}:{raw_line}")` 로 결정론적 ID를 생성한다.
- `(source, file_path, line_offset)` 유니크 제약으로 수집기 재시작 시에도 동일 줄이 중복 저장되지 않는다.
- 상관분석 기준:
  - **Caddy ↔ ERP**: `request_id` 정확 일치로 연결
  - **게이트웨이 ↔ 웹/ERP**: `(src_ip/dst_ip, dst_port, timestamp_utc 근접성)` 으로 **연결 후보(candidate)** 로만 표시하며, 공유 IP만으로 사용자를 확정하거나 다른 사건으로 합치지 않는다.
