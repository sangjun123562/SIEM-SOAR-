# 관제 시스템 설계 (DESIGN.md)

## 1. 전체 접속 및 로그 흐름

- **접속 경로 (A 담당)**: 테스트 단말·대조 단말 → Linux 게이트웨이 → Caddy HTTPS → Flask ERP → ERP용 PostgreSQL
- **로그 경로 (A 생성 → B 수집)**:
  - 게이트웨이(`gateway.jsonl`), Caddy(`caddy.jsonl`), ERP(`erp.jsonl`)가 파일로 로그를 기록한다.
  - B의 Python 수집기(`src/soc/collector.py`)가 각 로그 파일을 **읽기 전용**으로 읽어 완성된 줄(`\n` 종료)만 처리한다.
  - 원본(`raw_logs`)과 정규화 이벤트(`normalized_events`)를 관제용 PostgreSQL에 트랜잭션으로 저장한 **뒤에만** `collector_offsets`를 갱신한다.
- **추적성**: 사건(`incidents`) → 경보(`alerts`) → 근거 이벤트(`normalized_events`) → 원본 로그(`raw_logs.raw_id`)까지 단일 식별자로 추적한다.

## 2. 핵심 보안 및 정확성 원칙

1. **DB 분리**: 관제용 PostgreSQL은 ERP용 PostgreSQL과 별도 컨테이너·계정·볼륨으로 운영하며 호스트 포트를 공개하지 않는다. ERP 초기화는 ERP DB에만 적용되므로 `raw_id` 증거는 보존된다.
2. **민감정보 비저장**: 비밀번호, 토큰, 쿠키, 요청 본문은 로그에 남기지 않으며 정규화 단계에서도 차단한다.
3. **UTC 단일 기준**: 모든 타임스탬프는 UTC ISO-8601 전체 타임스탬프로 정규화·저장한다.
4. **신뢰 출발지 및 라이브 조건**:
   - `X-Request-ID`, `X-Client-IP`는 Caddy가 덮어쓴다.
   - ERP는 지정된 Caddy로부터의 요청일 때만 `client_ip_trusted = true`로 기록한다.
   - 실제 방화벽 조치 요청은 **라이브 수집(`ingest_mode = 'live'`) + 신뢰된 출발지(`client_ip_trusted = true`) + 사람 승인**이 모두 충족될 때만 허용한다.
5. **중복 방지**:
   - `raw_logs`는 `(source, file_path, line_offset)` 유니크 제약과 결정론적 `raw_id`를 사용해 수집기 재시작·재처리 시 중복을 방지한다.
   - 경보(`alerts`)는 `dedup_key` 유니크 제약으로 동일 시간창·계정·IP 조합의 중복 생성을 방지한다.

## 3. 조치 API 계약 — **초안(A 제안, B 확인 전)**

관제 앱(B)이 사람 승인 후 게이트웨이(A)에 차단·조회·해제를 요청하는 형식이다. 4일 차 게이트에서 합의하고, 합의 전에는 초안이다.

### 3-1. 연결 경로 (4일 차 시험 결과)
- 게이트웨이를 **조치 전용 내부망**(`internal: true`)에 한 번 더 연결하고, 관제 앱도 그 망에만 붙인다. 시험망(단말·Caddy·ERP)과 분리된다.
- 2026-11-17 시험: 임시 내부망에 게이트웨이를 추가 연결했을 때 다른 컨테이너에서 ping·TCP 접속 성공(시험 후 망 삭제). → 이 방식으로 구현 가능.
- 호스트 포트는 공개하지 않는다. 관제 앱(B, 별도 Compose 프로젝트)은 외부(external) 네트워크로 이 망에 붙는다.

### 3-2. 인증
- 모든 요청에 `Authorization: Bearer <조치 토큰>`. 토큰은 두 쪽 `.env`에만 두고 저장소에 올리지 않는다. 틀리면 `401`.
- (선택) 본문 HMAC 서명은 5일 차 이후 검토.

### 3-3. 요청·응답
| 동작 | 요청 | 성공 응답 |
|---|---|---|
| 차단 | `POST /actions/block` `{"approval_id":"APR-...", "target_ip":"172.28.10.11", "expires_at_utc":"2026-11-17T09:00:00Z", "incident_id":"...", "approved_by":"..."}` | `201 {"approval_id", "status":"applied", "target_ip", "expires_at_utc", "applied_at_utc", "rule_id"}` |
| 조회 | `GET /actions/{approval_id}` | `200 {"approval_id", "status":"applied·released·expired", "target_ip", "expires_at_utc", "rule_present": true/false}` |
| 해제 | `POST /actions/{approval_id}/release` | `200 {"approval_id", "status":"released", "released_at_utc"}` |

### 3-4. 게이트웨이가 독립적으로 검사하는 것(관제 앱을 믿지 않고 다시 검사)
- `approval_id` 형식 `^APR-[A-Za-z0-9-]{1,36}$`
- `target_ip`는 **고정 허용 목록(시험 단말 172.28.10.11)** 안. 대조 단말·게이트웨이·서버·DB·대역(CIDR)은 `422 target_not_allowed`
- `expires_at_utc`는 `Z`로 끝나는 절대 UTC, 지금보다 미래, **최대 차단 시간 30분 이내**. 아니면 `422 invalid_expiry`
- **같은 승인 재시도**(같은 approval_id·대상·만료): 규칙을 다시 만들지 않고 처음 결과를 그대로 반환(`200`, 만료 연장 없음)
- **같은 approval_id를 다른 대상·만료로 재사용**: `409 approval_conflict`
- **이미 만료·해제된 승인으로 다시 차단**: `409 approval_closed`
- 만료 시각이 지나면 게이트웨이가 스스로 해제한다. 재시작 시 저장된 승인 기록과 실제 규칙을 대조해 만료된 것은 다시 만들지 않는다(7일 차 시험).
- 명령은 인자 배열로 실행하며 셸 문자열을 조합하지 않는다(현재 `gwctl.sh`의 방식 유지).

### 3-5. 관제 앱(B)이 보내기 전에 지킬 것
- 근거 이벤트가 `ingest_mode = live`이고 `client_ip_trusted = true`이며 **사람 승인**이 있을 때만 호출한다(합성·재생 이벤트로는 호출하지 않음).
- `target_ip`는 근거 이벤트의 `client_ip`(신뢰된 값)에서 가져온다.

### 3-6. 오류 형식
`{"error": "<코드>", "message": "<설명>"}` — 코드: `unauthorized`(401), `invalid_request`(400), `target_not_allowed`(422), `invalid_expiry`(422), `approval_conflict`(409), `approval_closed`(409), `not_found`(404), `apply_failed`(500).
