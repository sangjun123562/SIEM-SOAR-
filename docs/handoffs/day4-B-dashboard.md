# 4일 차 B 인수인계 — 관제 웹 대시보드 & 조치 API 계약 확정

- 담당: B / 브랜치: `sangjun`
- 실행 구분: **단위/모의 HTTP 서버 테스트 통과** (`python -m unittest discover -s tests -v`: 21 통과, 1 건너뜀)
- 실제 Docker 게이트웨이 조치 서버와의 5일 차 실연동은 A의 조치 API 구현 후 진행 예정

## 1. A↔B 조치 API 계약 확정 (`DESIGN.md` 3절)
A가 제안한 `DESIGN.md` 3절 계약을 **수정 없이 그대로 확정**했습니다.
- 경로: `POST /actions/block`, `GET /actions/{approval_id}`, `POST /actions/{approval_id}/release`
- 인증: `Authorization: Bearer <조치 토큰>`
- 유효성·멱등성: `^APR-[A-Za-z0-9-]{1,36}$`, 고정 허용 대상 IP(`172.28.10.11`), 절대 UTC 만료(최대 30분), 동일 승인 재시도 시 `200`(만료 연장 없음), `409 approval_conflict` / `approval_closed`, `422 target_not_allowed` / `invalid_expiry`

## 2. B 구현 내용 (A 연동 관련)
- `src/soc/incident_service.py`:
  - `build_incidents()`: 탐지된 경보를 사건(`IncidentView`)으로 묶고, `Caddy↔ERP`는 `request_id` 정확 일치(`request_id_exact`), `게이트웨이↔웹`은 IP·시각 근접 기반 후보(`gateway_candidate`)로 연결
  - `ActionApiClient`: `DESIGN.md` 3절 규격(`POST /actions/block`, `GET /actions/{id}`, `POST /actions/{id}/release`, Bearer 인증)으로 요청 전송
  - `request_human_approval()`: 모든 근거 이벤트가 `ingest_mode == 'live'` AND `client_ip_trusted == True`일 때만 승인 허용 (합성·재생·미신뢰 IP는 차단)
- `src/soc/dashboard.py`: `127.0.0.1:8050` 전용 관제 웹 UI (사건 목록, 사건 상세 `사건→경보→근거→raw_id`, 승인·해제 버튼 및 이력)
- `tests/test_dashboard_and_actions.py`: 상관분석·합성/재생 거부·로컬 모의 게이트웨이 API 호출(`Bearer`, `APR-...`, 차단→해제) 검증 완료

## 3. A에게 넘기는 내용 (5일 차 준비)
- 5일 차에 A 쪽에서 `DESIGN.md` 3절 규격의 게이트웨이 조치 API 서버를 조치망(`10.250.30.2`)에 띄워 주시면, B 관제 앱의 `ActionApiClient`에 해당 URL과 조치 토큰만 연결해 바로 **탐지 → 승인 → 차단 → 해제 복구**를 실연동할 수 있습니다.
