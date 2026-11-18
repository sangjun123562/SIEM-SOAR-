# 5일 차 B 인수인계 — live 수집·관제 DB 실연동·담당자 인증·컨테이너화

- 담당: B / 브랜치: `sangjun`
- 실행 구분: **로컬 DB(SQLite) + 모의 게이트웨이 HTTP 서버 단위·통합 검증 완료** (`23 통과, 1 건너뜀`)
- **미검증**: A PC의 실제 `capstone-a_action_net` + 실제 게이트웨이(`10.250.30.2:8081`) + 실제 `soc-postgres` 컨테이너 간 실연동은 A PC 통합 시험에서 확인 예정

## 1. 구현 완료 내용 (A 요청 1~5번 반영)
1. **live 수집 경로 (`src/soc/live_collector.py`)**:
   - A 볼륨(`capstone-a_gw_logs`, `capstone-a_caddy_logs`, `capstone-a_erp_logs`)을 `:ro`로 읽어 `collection_mode="live"`로만 저장
   - 수집 후 `build_incidents()` 실행 및 `SocRepository.sync_incidents()`로 경보·사건·근거·상관링크를 DB에 영속화
2. **대시보드 ↔ 관제 DB (`src/soc/repository.py`, `src/soc/dashboard.py`)**:
   - `DbDashboardStore`가 관제 DB(`incidents`, `alerts`, `normalized_events`, `raw_logs`, `incident_correlations`, `action_approvals`)를 직접 조회·저장
3. **담당자 인증 및 식별자 규칙 (`src/soc/dashboard.py`, `src/soc/incident_service.py`)**:
   - `/login`, `/logout` 및 HMAC-SHA256 서명 쿠키(`HttpOnly; SameSite=Lax`) 추가 — 미인증 `POST /approve`, `/release`, `/refresh`는 `401` 거부
   - 승인자는 로그인된 세션 사용자에서 자동 지정되며, `incident_id`·`approved_by`는 `^[A-Za-z0-9._:@-]{1,64}$`(공백 금지) 검증 적용
   - `GET /actions/{approval_id}` 상태 조회 버튼(`/refresh`) 추가
4. **컨테이너화 (`Dockerfile.soc`, `docker-compose.soc.yml`, `.env.soc.example`)**:
   - `soc-dashboard`: `capstone-a_action_net` IP **`10.250.30.60`** (`.2`, `.50` 회피), `127.0.0.1:8050:8050`만 바인딩, `cap_drop: [ALL]`, `no-new-privileges:true`, 비 root(`10001:10001`), `read_only: true`, **`cpus: "0.08"`** (0.1 이하)
   - `soc-collector`: `soc_internal` 전용, 3개 로그 볼륨 `:ro` 마운트, **`cpus: "0.06"`**, 비 root·읽기 전용 루트

## 2. A PC 통합 시험 시 실행 방법
1. `.env.soc.example`을 참고해 B 쪽 `.env`(Git 제외)에 `SOC_ACTION_API_TOKEN`, `SOC_OPERATOR_PASSWORD`, `SOC_SESSION_SECRET` 설정
2. `testbed` 기동 후(`capstone-a_action_net` 및 로그 볼륨 존재 상태):
   ```bash
   docker compose -f docker-compose.soc.yml --profile live up -d --build
   ```
3. 브라우저 `http://127.0.0.1:8050` 접속 → `/login` 로그인 → 사건 상세 확인 → 차단 승인 → 대상 차단/대조 정상 확인 → 차단 해제 → 복구 확인
