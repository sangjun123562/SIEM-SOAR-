# 9일 차 점검 — 새 환경 재현 (A) · 전체 회귀

점검일 2026-11-19 / A 고정 브랜치 eldi.

## 판정

| 항목 | 근거 | 판정 |
|---|---|---|
| 새 환경(별도 PC·새 볼륨)에서 설치·망 검증 | B PC `setup_all.sh` (B 보고) | 통과 (B PC 실측) |
| 새 환경에서 Day3·Day4·Day5 실제 시험 | B PC 29/0, 19/0, 26/0 (B 보고) | 통과 (B PC 실측) |
| 새 환경에서 e2e(ERP 실패→사건→승인→차단→복구) | B PC 재실행 pass=20 fail=0 requests=14 종료0 (2026-11-19 UTC08:30:11~08:30:53, 아래 B 보고 링크) | 통과 (B PC 보고) |
| A PC 전체 회귀(현재 main) | 아래 표 | 통과 |
| Python vs Wazuh 규칙 비교·Sigma·ATT&CK·첫 경보 시점 | B logtest v4.9.2 5번째 복합규칙100102 확인·Sigma/ATT&CK 문서 | 비교 기록 확인 (상시 운영 미검증) |

A PC에서 별도 Compose 프로젝트를 동시에 띄우지 않은 이유: 서비스 `container_name`(capstone-a-*)과 시험망 대역(172.28.10/20, 10.250.29/30)이 고정되어
같은 Docker에 두 벌이 공존할 수 없다. 기존 환경을 지우는 대신 **다른 PC(B PC)의 새 Docker·새 볼륨**에서 `setup_all.sh`로 처음부터 재현했다.
B PC 수치는 B가 보고한 값이며 A가 직접 실행한 결과가 아니다. B는 실행 로그·UTC·종료 코드를 PR에 남긴다.

## A PC 전체 회귀 (UTC 2026-11-19, 실제 실행)

| 시험 | 시간 | 결과 |
|---|---|---|
| verify_network_layout.py | 08:14:12 | 통과 |
| verify_day3.sh (HTTPS·헤더·수동 차단·복구) | 08:14:14~ | pass=29 fail=0, 종료 0 |
| verify_day4.sh (ERP 로그인·탐지 N-1/N) | 08:15:09~ | pass=19 fail=0, 종료 0 |
| verify_day5.sh (조치 API 차단·해제) | 08:16:20~08:17:25 | pass=26 fail=0, 요청 19, 종료 0 |
| verify_day5_e2e.sh (A·B 통합) | 08:17:32~08:18:14 | pass=20 fail=0, 요청 14, 종료 0 (INC-DF25D870EB, APR-20261119081756-D870EB) |
| verify_day6.sh (금지 대상 거부) | 08:18:18~08:19:08 | pass=14 fail=0, 요청 15, 종료 0 |

같은 날 별도 실행: verify_day7.sh 18/0, verify_day5_lifecycle.sh 15/0, verify_day8.sh 13/0 ([DAY6_7_STATUS.md](DAY6_7_STATUS.md), [DAY8_STATUS.md](DAY8_STATUS.md)).
모든 시험 후 GW_BLOCK 규칙 0.

## 재현 절차

[NEW_PC_SETUP.md](NEW_PC_SETUP.md) — `bash testbed/scripts/setup_all.sh --check` → `bash testbed/scripts/setup_all.sh` → 검증 스크립트.
B PC 첫 실행에서 발견된 Windows 경로 문제(PR #19)와 e2e 로그인 순서 문제(PR #20)를 수정했다.

## 후속 확인 (2026-11-20)

[B의 E2E·규칙 비교 보고](../docs/handoffs/day9-B-detection-comparison-and-bpc-e2e.md)로 위 대기 항목을 갱신했다. A가 B 시험을 직접 실행한 것으로 해석하지 않는다. [10일 차 A PC 3회 연속 시험](DAY10_STATUS.md)은 별도 실행 결과다.
