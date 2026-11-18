# 6일 차 B 인수인계 — 최근 이벤트 화면·API 인증·DB 비밀번호 필수·CPU 조정·Grafana 준비

- 담당: B / 브랜치: `sangjun`
- 실행 구분: **로컬 DB(SQLite) + 모의 게이트웨이 단위·통합 검증 완료** (`25 통과, 1 건너뜀`) + Compose 설정 검증 통과
- **미검증**: A PC 실제 `soc-postgres` + `soc-grafana` 기동 및 실트래픽 화면 확인은 A PC 통합 시험에서 확인 예정

## 1. A 요청 1~5번 반영 내용
1. **최근 이벤트 화면 (`/events`, `/api/events`)**:
   - 로그인한 담당자만 조회 가능(미로그인 `/events` → `/login` 리다이렉트, `/api/events` → `401`)
   - 최근 50건의 이벤트(`시각`, `출처`, `종류(결과)`, `계정`, `단말 IP`, `live/replay`, `raw_id`) + 출처별 마지막 수집 시각/건수 카드 + 5초 자동 새로고침(`<meta http-equiv="refresh" content="5">`)
2. **`/api/incidents` 로그인 필수화**:
   - 인증 활성화(`DbDashboardStore`) 시 미로그인 요청은 `401 Unauthorized` 반환
3. **관제 DB 비밀번호 필수화 (`docker-compose.soc.yml`)**:
   - `POSTGRES_PASSWORD`, `SOC_DB_DSN` 기본값(`soc_admin_change_me`) 제거 및 `:?` 필수 검사 적용 (비어 있으면 기동 거부)
4. **CPU 상한 조정 (`docker-compose.soc.yml`)**:
   - `soc-postgres` CPU 상한을 `0.5` → **`0.35`** 로 하향 (전체 합계 2.00 이내 유지)
5. **8일 차 Grafana 사전 준비 (`grafana/`, `docker-compose.soc.yml`)**:
   - `grafana_reader` 읽기 전용 계정 기반 데이터소스 및 3개 패널(`로그 도착 상태`, `방화벽 조치 상태`, `최근 보안 사건 현황`) 프로비저닝 추가 (`--profile grafana`, `127.0.0.1:3000`, CPU `0.15`, `GF_SECURITY_ADMIN_PASSWORD` 필수)
