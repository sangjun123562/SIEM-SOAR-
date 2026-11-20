# Day 10 B — 16개 안정성·보안·일관성 개선 반영 및 핸드오프

- **담당 / 브랜치**: Role B (`sangjun`, 기반 `main` `666214d`)
- **검증 일시 (UTC)**: 2026-11-20T03:07Z
- **수정 파일**:
  - `src/soc/storage.py`
  - `src/soc/collector.py`
  - `src/soc/live_collector.py`
  - `src/soc/repository.py`
  - `src/soc/incident_service.py`
  - `src/soc/dashboard.py`
  - `db/init/001_schema.sql`
  - `docker-compose.soc.yml`
  - `grafana/dashboards/soc_overview.json`
  - `docs/dashboard_spec.md`
  - `tests/test_day5_live_db_and_auth.py`
  - `tests/test_day6_day7_regression.py`
  - `tests/test_16_hardening_fixes.py`

## 16개 항목별 Role B 조치 내역 및 검증 상태

| 번호 | 항목 | Role B 반영 내용 | 검증 상태 |
|---|---|---|---|
| **1** | 로그 회전·잘림 처리 | `collector_offsets`에 `file_inode`, `generation` 추가. inode 변경 시 `.1` 회전 파일 잔여분 우선 수집 후 세대 증가(`#gN`)·오프셋 0 리셋 | 단위 테스트 통과 (`test_01`) · 실환경 Linux logrotate 재현은 A 합동 시험 필요 |
| **2** | 전체 기록 반복 분석 최적화 | 유휴 폴링(`inserted==0`) 시 DB 재동기화 생략, 탐지는 최신 이벤트 기준 24시간 창 제한, `load_incidents()`는 사건 근거/상관 이벤트만 선택 조회 | 단위 테스트 통과 |
| **3** | 승인 선저장 및 응답 유실 복구 | 게이트웨이 API 호출 전 `pending` 선저장(`on_before_call`), 네트워크 오류 시 `unknown` 저장 및 UI `상태 조회` 복구 버튼 노출 | 단위 테스트 통과 (`test_03_04_05`) |
| **4** | 중복 차단 방지 | 핸들러 액션 락(`action_lock`) 직렬화, 동일 사건 활성 승인 멱등 반환, 타 사건 동일 IP 중복 차단 거부 | 단위 테스트 통과 (`test_03_04_05`) |
| **5** | 실제 상태와 화면 불일치 해소 | `refresh_approval_status`에서 `rule_present=False` 불일치 감지 시 `expired`/`released` 동기화, `DbDashboardStore` 5초 주기/만료 자동 동기화 | 단위 테스트 통과 (`test_03_04_05`) |
| **6** | 깨진 한 줄 격리 | `live_collector`가 `isolate_errors=True`로 줄별 예외 격리·오프셋 전진, 출처별 `try/except`로 타 출처 수집 보호 | 단위 테스트 통과 (`test_06`) |
| **7** | DB 재시작 후 복구 | `PostgresSocStorage.run_with_retry` 자동 재연결, `SocRepository` 동적 커넥션 참조, 장애 지속 시 `503` 3초 자동 새로고침 안내 페이지 반환 | 정적/예외 경로 구현 완료 · 실환경 `soc-postgres` 재시작 시험 필요 |
| **8** | 시간 글씨 대비 개선 | `_fmt_ts` 보조 KST/UTC 라벨 `#64748b` → `#9ec2e6` 상향 | 단위 테스트 및 렌더링 확인 |
| **9** | 한글 아이디 로그인 오류 수정 | `hmac.compare_digest` UTF-8 바이트 비교로 한글 입력 시 `401` 정상 거부 | 단위 테스트 통과 (`test_08_09_10_11`) |
| **10** | 로그인 시도 제한 | `LoginRateLimiter`(5회 실패 시 60초 잠금, `429 Too Many Requests`) 적용 | 단위 테스트 통과 (`test_08_09_10_11`) |
| **11** | CSRF 방어 | 세션 바인딩 `csrf_token` 폼 검증 + `Origin`/`Referer` 호스트 검증 (`403 Forbidden`) | 단위·인증 통합 테스트 통과 (`test_08_09_10_11`, `test_day5`) |
| **12** | 기본 비밀번호·환경변수 강제 | `docker-compose.soc.yml`에서 `SOC_OPERATOR_PASSWORD`, `SOC_SESSION_SECRET`, `SOC_GRAFANA_DB_PASSWORD` 기본값 폴백 제거 및 필수화 | Compose 설정 반영 완료 (DB 계정 역할 분리는 운영 환경 구성 시 적용) |
| **13** | 문서·코드 일치화 | `docs/dashboard_spec.md`의 전체 근거 `all(live & trusted)`, `unknown` 상태, 실제 `/actions/*` 경로, `COUNT(DISTINCT target_ip)` 동기화 | 문서 갱신 완료 |
| **14** | live/replay 경계 정책 | `run_live` 시작 pass 0은 `replay`, 이후 완성 줄만 `live`로 명확히 경계 고정 | 단위 테스트 통과 (`test_live_backlog_replay.py`) |
| **15** | 무관한 통신 후보 필터링 | `gateway_candidate` 상관 조건에 TCP 및 웹/ERP 포트(`80, 443, 8000, 8443`) 조건 추가 | 단위 테스트 통과 (`test_15`) |
| **16** | 차단 IP 중복 집계 수정 | 대시보드 KPI에서 고유 IP 기준(`COUNT` distinct `target_ip`)과 활성 승인 건수 분리 표시, Grafana SQL `COUNT(DISTINCT target_ip)` 수정 | 단위 테스트 통과 (`test_16`) |

## 실행 결과
- `python -m unittest discover -s tests -v`: **35개 중 34개 통과, 1개 skipped** (`SOC_TEST_POSTGRES_DSN` 미설정 PostgreSQL 통합 테스트)
- 미확인 항목(A 합동 시험 권장): Linux 실제 logrotate 회전 시험(#1), `soc-postgres` 강제 재시작 중 화면 복구(#7), 게이트웨이 응답 지연/만료 시 실제 `rule_present` 대조(#3·#5).
