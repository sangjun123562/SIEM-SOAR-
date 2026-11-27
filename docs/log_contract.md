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
| `ingest_mode` | string (생성 로그 표시, 누락 시 `replay`) | 최종 모드는 수집기 설정으로 결정 (`live`, `replay`, `synthetic`) | `"live"` |

## 2. 소스별 세부 필드

### A. 게이트웨이 로그 (`gateway.jsonl`)
- **역할**: 시험 단말·대조 단말의 허용(`fw_allow`) 및 차단(`fw_deny`) 기록
- **필드**:
  - `src_ip` (string): 출발지 IP (예: `"172.28.0.10"`)
  - `src_port` (int, TCP/UDP에만 있음): 출발지 포트
  - `dst_ip` (string): 목적지 IP
  - `dst_port` (int, TCP/UDP에만 있음): 목적지 포트
  - `protocol` (string): `"TCP"` | `"UDP"` | `"ICMP"`
  - `action` (string): `"allow"` | `"deny"`
  - `rule_id` (string, 선택): 적용된 규칙/승인 ID (예: `"APR-20261117-001"`)
  - ICMP는 게이트웨이가 `fw_deny`로 기록한 요청만 수집한다. 포트는 없으며, `POLICY-ICMP-BROADCAST`는 브로드캐스트 echo 요청의 명시적 거부를 뜻한다. ICMP 거부 기록만으로 스머프 공격을 확정하지 않는다.

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
- **역할**: 로그인 성공/실패·계정 잠금·문서 열람·임시 권한 부여/회수 기록
- **필드**:
  - `request_id` (string): 전달받은 `X-Request-ID`
  - `client_ip` (string): 전달받은 `X-Client-IP`
  - `peer_ip` (string): ERP 소켓의 직접 연결 상대 IP
  - `client_ip_trusted` (bool): `peer_ip`가 지정된 Caddy일 때만 `true`
  - `username` (string): 로그인 시도 계정 또는 행위자 계정
  - `http_method` (string), `http_path` (string), `status_code` (int)
  - `resource_id` (string, 선택): 구매 요청 ID 등

#### C-1. ERP 이벤트 종류와 추가 필드 (4일 차 A 추가 — 실제 구현 `erp/app.py` 기준)
| `event_type` | `outcome` | `status_code` | 언제 | 추가 필드(선택) |
|---|---|---|---|---|
| `login_success` | success | 200 | 로그인 성공 | `department`, `role` |
| `login_failed` | failure | 401(형식 오류 400) | 로그인 실패 | — |
| `login_source_denied` | failure | 403 | 로그인 허용 조건을 충족하지 못한 출발지에서 인증 전에 거부 | `reason` (`source_not_allowed` 또는 `untrusted_source`), `access_requested` (X 단말 요청을 ERP에 등록했으면 `true`) |
| `login_blocked` | failure | 403 | 잠긴 ERP 계정의 로그인 거부. 비밀번호가 맞아도 틀려도 같은 잠금 안내로 응답 | `reason=account_locked`, `password_valid` (`false`이면 관제가 인증 실패로 집계) |
| `account_locked` | success | 200 | 관제 담당자가 ERP 계정을 수동 잠금 | `incident_id`, `operator`, `lock_reason`, `expires_at_utc` |
| `account_locked` | success | 403 | 신뢰된 출발지의 인증 실패를 계정별로 합산해 5분 내 5회면 ERP가 계정을 10분 잠금 | `incident_id`, `operator=system`, `reason=automatic_login_failure_limit` |
| `account_unlocked` | success | 200 | 관제 담당자가 ERP 계정의 잠금을 수동 해제 | `incident_id`, `operator`, `unlock_reason` |
| `logout` | success | 200 | 로그아웃 | — |
| `document_read` | success / failure | 200 · 401 · 403 · 404 | 자료실 문서 열람(2026-11-22 A 추가). 실패 사유는 `reason`(unauthenticated·forbidden·not_found) | `document_id`, `doc_level`(public·dept·secret), `doc_department`, `user_department`, `user_role`, 임시 권한으로 열었으면 `via`=`grant`·`grant_id` |
| `doc_permission_granted` | success | 200 | 관제 담당자가 대시보드에서 계정에 문서 열람 임시 권한을 부여(ERP 안에는 요청·승인 화면이 없음) | `username`, `operator`, `reason`, `document_id`, 만료 시각(최대 24시간) |
| `doc_permission_revoked` | success | 200 | 관제 담당자가 부여한 임시 문서 권한을 회수 | `username`, `operator`, `reason`, `document_id` |
| `account_permissions_revoked` / `account_permissions_restored` | success | 200 | 관제 담당자가 계정의 권한을 모두 회수 / 복구 | `username`, `operator`, `reason` |

- 추가 필드는 B 정규화기에서 `details`로 들어간다(기존 필드 의미는 바꾸지 않음).
- 2026-11-18 구매 결재 제거로 `access_denied`·`purchase_*` 이벤트는 삭제했다(과거 로그 해석용 정의는 git 이력에 있음).
- 2026-11-25 결정: ERP 안에는 **권한 요청·승인 화면이 없다**(`access_request_*` 이벤트 삭제). 권한 밖 문서는 열람이 막히고 `document_read` 실패로 기록되며, 임시 권한은 관제 대시보드에서 담당자가 부여한다(`doc_permission_*`).
- **미신뢰 요청**(직접 연결 상대가 Caddy가 아님): `client_ip = peer_ip`, `client_ip_trusted = false`, `request_id = "local-..."`(Caddy 로그와 연결되지 않음). 탐지·조치 근거로 쓰지 않는다.
- `username`은 사용자가 입력한 값을 그대로(제어문자 제거, 64자 제한) 기록한다. 비밀번호·쿠키·요청 본문·쿼리 문자열은 기록하지 않는다.
- `ingest_mode`는 항상 `live`(실제 요청에서 생성).

## 3. 정규화 및 추적 규칙 (`raw_id`)

- 수집기는 각 줄을 읽을 때 `raw_id = sha256(f"{source}:{file_path}:{line_offset}:{raw_line}")` 로 결정론적 ID를 생성한다.
- `(source, file_path, line_offset)` 유니크 제약으로 수집기 재시작 시에도 동일 줄이 중복 저장되지 않는다.
- 상관분석 기준:
  - **Caddy ↔ ERP**: `request_id` 정확 일치로 연결
  - **게이트웨이 ↔ 웹/ERP**: `(src_ip/dst_ip, dst_port, timestamp_utc 근접성)` 으로 **연결 후보(candidate)** 로만 표시하며, 공유 IP만으로 사용자를 확정하거나 다른 사건으로 합치지 않는다.


## 4. 수집 출처 신뢰 경계 (보안 수정, B 연동 필요)

- normalize_log_line/collect_file의 keyword-only collection_mode는 수집기 운영 설정이다. 기본은 replay이며 로그 JSON/외부 요청 필드로 직접 지정하지 않는다.
- 검증된 실제 생성기 로그 볼륨에서만 collection_mode="live"를 명시한다. 가져온 파일/재생은 replay, 합성 경로는 synthetic으로 고정한다.
- 최종 live는 수집 경로와 로그 표시가 모두 live일 때만 가능하다. 둘 중 synthetic이면 synthetic, 그 밖은 replay다. 누락은 live로 승격하지 않는다.
- 원본 보관 레코드와 이벤트는 최종 모드를 저장한다. 입력 표시와 다르면 details.reported_ingest_mode에 표시를 보존한다. raw_id 계산은 기존 입력 기준이다.
- client_ip_trusted는 실제 JSON boolean만 허용한다. 문자열/숫자/null/배열 등은 거부하고 누락은 false다. 이 값은 ERP peer 검사·수집 경로의 출처 검증을 대체하지 않는다.
- 기존 DB의 live 레코드는 소급 검증되지 않는다. 이전 적재 자료는 출처 확인 전 자동 조치 근거로 쓰지 않는다. 모드만 바꿔 재적재해도 동일 ID의 과거 값은 자동 변경되지 않는다.
- 차단은 최종 live + 신뢰 IP + 검증된 사람 승인이 모두 필요하다. 혼합 근거에 replay/synthetic이 하나라도 있으면 조치 금지다. 이는 조치 API 구현 시 서버에서 강제할 조건이다.
- Caddy는 원본 access/runtime 로그 encoder에서 query와 요청/응답 헤더를 삭제한 뒤 저장한다. 최종 JSONL 변환만으로 대신하지 않는다. 기존 저장 파일은 자동 삭제하지 않는다.

### ICMP 반복 거부 관찰 규칙
- RULE-GW-ICMP-DENIAL-001: 라이브 gateway/fw_deny/ICMP를 출발지 src_ip별로 집계한다. 60초 이내 서로 다른 이벤트 10건에서 medium 경보·사건을 생성한다.
- 연속 요청 중 경보는 한 번만 생성하고 마지막 거부 이후 60초를 초과해 조용해진 뒤 새 반복이 생기면 다시 판단한다. 재생·합성은 제외하며 원본 raw_id를 근거로 연결한다.
- 시험망 초기 기준이며 스머프 확정 판정이나 IP 차단 승인 대상이 아니다. 기존 로그인 탐지·조치 계약은 유지한다.
