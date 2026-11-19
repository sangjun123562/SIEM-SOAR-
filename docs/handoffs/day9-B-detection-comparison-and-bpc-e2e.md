# 9일 차 점검 (B) — B PC E2E 재실행 · Python vs Wazuh 비교 · Sigma/ATT&CK 매핑

점검일: 2026-11-19 / B 고정 브랜치: `sangjun`

---

## 1. B PC `verify_day5_e2e.sh` 재실행 결과 (`origin/main` 375fd6b 반영 후)

- **실행 시각 (UTC)**: `2026-11-19T08:30:11Z ~ 2026-11-19T08:30:53Z` (`elapsed=42s`)
- **결과**: `pass=20 fail=0 requests=14`, **종료 코드 0**
- **생성 사건·승인 ID**: `INC-923540EBC2` / `APR-20261119083035-40EBC2` (`bob@172.28.10.11`)
- **핵심 단계 확인**:
  1. ERP 로그인 실패 5건(`08:30:14Z ~ 08:30:25Z`, 모두 `401`)
  2. 담당자 로그인 후 `INC-923540EBC2` 조회 (`live + trusted` 확인, `08:30:34Z`)
  3. 미인증 승인 거부(`401`, 규칙 0개) → 인증 승인(`APR-20261119083035-40EBC2`, `applied`, 실제 규칙 3개)
  4. 차단 중 시험 단말 `000` (`DROP 0 -> 5`), 대조 단말 `200`
  5. 대시보드 차단 해제(`released`, 규칙 `0`) → 시험 단말 `200` 복구

---

## 2. Python 탐지 vs Wazuh (`wazuh-logtest v4.9.2`) 비교

- Python 규칙: [src/soc/detector.py](../../src/soc/detector.py) (`RULE-ERP-LOGIN-BRUTE-001`, `DEFAULT_THRESHOLD=5`, `DEFAULT_WINDOW_SECONDS=300`)
- Wazuh 규칙: [rules/wazuh/erp_login_rules.xml](../../rules/wazuh/erp_login_rules.xml) (`100101` level 5 → `100102` level 10, `frequency="5" timeframe="300"`)
- 실제 `wazuh/wazuh-manager:4.9.2` (`/var/ossec/bin/wazuh-logtest`)에 동일 ERP JSON 5건 순차 입력 검증 완료:
  - 1~4회 실패: `id: '100101'` (level `5`, `firedtimes: 1..4`)
  - **5회 실패**: `id: '100102'` (level `10`, `frequency: '5'`, `mitre.id: ['T1110.001']`, `mitre.tactic: ['Credential Access']`, `mitre.technique: ['Password Guessing']`)

| 비교 항목 | Python 탐지기 (`detector.py`) | Wazuh (`wazuh-logtest v4.9.2`) |
|---|---|---|
| 그룹화 키 | `(username, client_ip)` (`client_ip_trusted == True` 필수) | `<same_field>username</same_field>` + `<same_field>client_ip</same_field>` (`client_ip_trusted == true`) |
| 시간창 기준 | 로그 내 `event_ts_utc` (UTC `timedelta(seconds=300)`) | 수신/처리 시점 기준 `timeframe="300"` |
| **첫 경보 시점** | **N-1(4건)일 때 0건, 정확히 N=5번째 실패 이벤트 시점** (`window_slice[:5]`)에 첫 `AlertRecord` 발생 | **1~4건은 하위 규칙(`100101`, level 5)만 매칭되고, 정확히 5번째 입력 시점에 복합 규칙(`100102`, level 10) 첫 경보 발생** |
| 중복/재실행 처리 | `dedup_key = sha256(rule_id:username:client_ip:first_event_id)`로 재실행 멱등성 보장 | `frequency` 카운터가 윈도우 내 누적 후 리셋(재입력 시 다시 카운트) |
| 조치 연계 | `live` + `client_ip_trusted` 조건 통과 시 대시보드 수동 승인(`ActionApiClient`)으로 게이트웨이 차단 | Active Response 또는 외부 스크립트 연계 필요 (본 프로젝트는 정책상 Python + 사람 승인 구조 채택) |

---

## 3. Sigma 룰 & MITRE ATT&CK 매핑

- Sigma 룰 파일: [rules/sigma/erp_login_brute_force.yml](../../rules/sigma/erp_login_brute_force.yml)
- **MITRE ATT&CK 매핑**:
  - **Tactic**: `Credential Access` (`TA0006`)
  - **Technique**: `Brute Force: Password Guessing` (`T1110.001`)
- **탐지 조건 요약**:
  - `source: erp`, `event_type: login_failed`, `outcome: [failure, failed, deny]`, `client_ip_trusted: true`
  - `count() by username, client_ip >= 5` within `5m` (`300s`)
