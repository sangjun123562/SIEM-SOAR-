# 5일 차 점검 — 게이트웨이 조치 API (A)

점검일 2026-11-18 / A 고정 브랜치 eldi.

## 판정

**5일 차 완료 기준 통과(A PC, 1회).** 실제 ERP 로그인 실패 → live 수집 → 사건 → 담당자 로그인·승인 → 시험 단말만 차단 → 해제 복구를 `verify_day5_e2e.sh`로 확인했다.

| 항목 | 확인 범위 | 판정 |
|---|---|---|
| 조치 API(DESIGN.md 3절) | 실제 게이트웨이, 조치망 시험 클라이언트 | 통과 |
| B `ActionApiClient` 호환 | B 코드를 읽기 전용으로 불러 차단·조회·해제 | 통과 |
| 시험 단말만 차단·대조 정상·해제 복구 | 실제 HTTPS 요청, DROP 카운터, fw_deny 로그 | 통과 |
| 기존 연결 후속 요청 차단 | 차단 전 연 연결의 두 번째 요청 실패(재연결 없음) | 통과 |
| 재시도·충돌·종료 승인 재차단 | 200 만료 불변 / 409 conflict / 409 closed | 통과 |
| 만료 자동 해제·재시작 대조 | 만료분 재생성 없음, 유효분 복원 | 통과 |
| live 수집 → 관제 DB → 사건 | B 수집기(시작 전 기존 줄은 replay), PostgreSQL | 통과 |
| 담당자 인증 → 승인 → 실제 차단·해제 | B 대시보드(10.250.30.60) → 게이트웨이, 미인증 401 | 통과 |
| 승인 기록 보존 | 관제 DB `action_approvals`, 게이트웨이 감사 | 통과 |

## 구현

- `gateway/actionapi.py`: 게이트웨이 안에서 `10.250.30.2:8081`에만 바인딩, 단일 스레드(동시성 1).
  Bearer 토큰(32자 이상 아니면 기동 거부, 상수 시간 비교), 조치망 대역 외 요청 거부.
  규칙은 `GW_BLOCK`에 `apr:<승인ID>` 주석으로 NFLOG(`fw_deny|<승인ID>`)+양방향 DROP. iptables는 인자 배열로만 실행.
  승인 기록 `approvals.json`(원자적 저장)과 감사 `audit.jsonl`은 `gw_actions` 볼륨. 토큰·본문은 기록하지 않는다.
- `gateway/gw-entry.sh`: 조치망 인터페이스 FORWARD 금지, 8081은 조치망 인터페이스·대역에서만 INPUT 허용.
- `docker-compose.yml`: 게이트웨이 day5 이미지, 토큰 환경 변수, `gw_actions` 볼륨. 시험용 `action-probe`(profile=probe, 조치망 전용, 240초 자체 종료).
  일회용 도우미 CPU 0.02→0.01로 낮춰 A 합계 1.42 유지.
- `scripts/init_env.sh`: 기존 `.env`는 유지하고 없는 `GW_ACTION_TOKEN`만 추가(값 출력 없음).

## 실행한 시험 (UTC 2026-11-18)

- `python -B -m unittest testbed/gateway/test_actionapi.py`: 9/9(가짜 iptables 판정 시험, 실제 차단 아님).
- `bash scripts/verify_day5.sh`: 03:16:20~03:17:08, 요청 19건, pass=26 fail=0, 종료 0.
- `bash scripts/verify_day5_lifecycle.sh`: 03:20:05~03:21:14, 요청 11건, pass=15 fail=0, 종료 0.
- 회귀: `verify_day3.sh` pass=29 fail=0, `verify_day4.sh` 03:30:07~03:31:08 pass=19 fail=0, `verify_network_layout.py` 통과,
  단위 시험 22개 중 21 통과·1 건너뜀(실제 PostgreSQL DSN 미설정).
- 처음 두 차례 verify_day5 실행은 시험 도구 지연(0.05 CPU에서 매 호출 Python 기동)으로 120초 상한에 걸려 **무효**.
  그중 1회는 시험 차단이 약 70초 남아 수동 해제(03:10:35)했다. 도구를 단일 프로세스 방식으로 고친 뒤 위 결과를 얻었다.
  수명 시험의 첫 실행 1건 실패는 시험 스크립트가 새 만료 시각을 보낸 오류(API는 409 conflict로 정상 거부)였고 수정 후 재실행했다.

## A·B 통합 시험 (UTC 2026-11-18)

- `bash scripts/verify_day5_e2e.sh` 06:50:25~06:51:12, 요청 13건, pass=19 fail=0, 종료 0.
  사건 INC-25B99EF6A1, 승인 APR-20261118065050-9EF6A1(관제 DB released, 게이트웨이 감사 출처 10.250.30.60).
- 직전 1회(06:49)는 시험 스크립트의 Windows curl 임시 경로 오류로 로그인 단계부터 무효. 차단은 적용되지 않았다.
- 통합 전 수정: 수집기가 시작 전부터 있던 줄을 live로 저장하던 문제(과거 시험 사건이 차단 가능해짐) → 첫 수집은 replay.
  대시보드가 internal 망만 연결되어 127.0.0.1:8050 전달이 동작하지 않던 문제 → 대시보드 전용 `soc_ui` 망 추가.
- 관제 DB 볼륨은 11-17에 초기화된 기존 `capstone-soc_soc_pg_data`를 재사용했다. 그 안의 11-17 gateway live 15건은 이전 시험 기록이다.
  이전 프로젝트의 정지 컨테이너는 삭제하지 않고 `capstone-socv-postgres-old`로 이름만 바꿨다(볼륨 보존).
- Docker CPU 상한 합계 2.12(A 1.42 + 중계 0.06 + 관제 0.64)로 기준 2.00을 넘는다. 실측 사용률은 낮았으나 조정 대상이다.

## 한계와 B 인수인계

- 시험 승인 ID는 사람이 직접 실행한 격리 시험이며 관제 앱의 인증된 사람 승인이 아니다.
- 시험 단말 차단 중에는 같은 단말을 경유하는 localhost:18888 브라우저 입구도 끊긴다.
- 조치망 통신은 internal bridge 위의 평문 HTTP + Bearer 토큰이다. HMAC·TLS는 미적용.
- B 연결 방법: [docs/handoffs/day5-A-action-api.md](../docs/handoffs/day5-A-action-api.md).
