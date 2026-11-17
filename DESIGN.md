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
