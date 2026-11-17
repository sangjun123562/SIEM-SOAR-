# 4일 차 A 인수인계 — ERP(구매 요청)와 실제 로그인·권한 로그

- 담당: A / 브랜치: `eldi` / 실행 구분: **실제 실행**(Docker 29.9.1, 실제 HTTPS 트래픽, `ingest_mode=live`)
- 준비: `cd testbed && bash scripts/init_env.sh` (시험용 비밀번호·키를 무작위로 만들어 `testbed/.env`에 저장, Git 제외)
- 실행: `docker compose up -d && bash scripts/verify_day4.sh` (요청 17건)
- 결과 (UTC 2026-11-17T08:26~08:27, 종료 코드 0): **verify_day4 pass=19 fail=0**. 회귀: verify_day1 pass=6, verify_day2 pass=17, verify_day3 pass=28.

## 구조
```
단말 → 게이트웨이 → Caddy(HTTPS 8443) ─┬─ /echo → 임시 서버(1~3일 차 시험용)
                                      └─ 나머지 → ERP(Flask, 172.28.20.20:8000) → ERP DB(PostgreSQL 16)
```
- ERP DB는 **ERP와만 붙는 내부망**(`erp_db_net`, 10.250.29.0/24)에 있다. 시험망에는 없어서 단말·Caddy·게이트웨이에서 DB로 갈 길이 없다. 호스트 포트 없음. 관제 DB와 계정·볼륨이 다르다.
- 단말은 ERP(8000)에 직접 접속할 수 없다(게이트웨이 정책 `POLICY-CLIENT-CADDY-ONLY`로 차단·기록, 시험으로 확인).
- ERP 코드 설명은 `erp/README.md`, 화면 출처는 `erp/SOURCE.md`(원본 `eldi96/choi-bujang-secret-vault@246e00a4`의 `public/index.html`, 원본은 읽기만 함).

## 사용자·권한
| 사용자 | 부서 | 직급 |
|---|---|---|
| alice | 영업 | 사원 |
| bob | 영업 | 팀장 |
| carol | 개발 | 사원 |
- 보기: 본인 요청 또는(팀장) 같은 부서 요청. 승인·반려: 같은 부서 팀장, 본인 요청 아님, 대기 상태.
- 권한 밖 시도는 403 + `access_denied` 기록.

## 시험에서 확인한 것
| 항목 | 결과 |
|---|---|
| 정상 로그인(alice·carol·bob, Caddy 경유) | 200, `client_ip_trusted=true`, `peer_ip=172.28.20.5` |
| 로그인 실패(시험 단말 alice 5건, 대조 단말 2건) | 401, 비밀번호 값은 로그 어디에도 없음 |
| **B의 탐지 규칙(실제 ERP 로그)** | **실패 4건까지 경보 0, 5건째 첫 경보 1**(근거 5건), 끝까지 봐도 경보 1 — 대조 단말 2건·미신뢰 1건은 경보 안 됨 |
| 같은 요청 추적 | 신뢰된 ERP 로그의 `request_id`가 모두 `caddy.jsonl`에 있음 |
| Caddy를 거치지 않은 요청(위조 `X-Client-IP: 6.6.6.6`) | 위조값 무시, `client_ip=peer_ip`(172.28.20.10), `client_ip_trusted=false`, `request_id=local-...` |
| 권한 위반 | 개발 사원 carol의 영업 요청 열람 403, 사원 alice의 승인 시도 403 → 둘 다 `access_denied` |
| 업무 | alice 등록 201 → 팀장 bob 승인 200 → 목록에 승인 상태 |
| ERP 직접 접속(시험 단말 → 8000) | 응답 없음 + 게이트웨이 `fw_deny`(정책 rule_id) |

## B에게 넘기는 것
- `erp.jsonl`: Docker 볼륨 **`capstone-a_erp_logs`**(수집기는 `:ro` 마운트). 형식은 `docs/log_contract.md` C·C-1절(**4일 차에 C-1절 추가: 이벤트 종류와 추가 필드 — 공유 계약 변경**).
- B 탐지기의 요구값(`event_type=login_failed`, `outcome=failure`, `client_ip_trusted`, `username`, `client_ip`, `request_id`)을 그대로 남긴다. 실제 로그로 B의 탐지기를 돌려 위 결과를 확인했다(`testbed/scripts/check_erp_log.py`가 `src/soc`를 읽기 전용으로 사용).
- `access_denied`에는 `department`(시도한 사람)와 `resource_department`(대상)가 있어, 원하면 '다른 부서 업무 접근' 탐지 규칙의 재료로 쓸 수 있다(1차 범위 밖, 선택 확장).
- **조치 API 계약 초안**: `DESIGN.md` 3절(승인 ID·고정 대상·절대 UTC 만료·최대 30분·인증·재시도·오류 코드). 4일 차 게이트 합의 필요.

## 시험 중 발견·수정한 것
1. ERP DB망 서브넷 `172.29.0.0/24`가 **Docker Desktop 내부망과 겹쳐** 생성 실패 → `10.250.29.0/24`로 변경.
2. ERP는 네트워크가 2개라 시험망 장치가 `eth1`이었다. 경로 사이드카를 **인터페이스를 주소로 찾는 공용 스크립트**(`scripts/set_route.sh`)로 바꿔 해결(예전처럼 `eth0` 고정이면 깨졌을 것).
3. 내 스크립트 버그 3건: Windows Python에 Unix 경로를 넘김, 3일 차 스크립트 편집 때 주석이 `HERE=` 정의를 덮음, 로그 기록 지연으로 검사 범위가 겹침(2초 대기 추가). 모두 시험 도구 문제였고 대상 동작 문제는 아니었다.

## 미확인 / 다음
- ERP 로그를 **관제 PostgreSQL까지** 넣는 것은 이번에 하지 않았다(2일 차에 게이트웨이 로그로 같은 경로를 확인함). B가 수집 대상에 `erp.jsonl`을 추가하면 함께 확인.
- 로그인 실패 시 계정 잠금·지연은 일부러 넣지 않았다(탐지 시연용). 실서비스라면 필요.
- 요청 수정·삭제, ERP 초기화(8일 차), 조치 API 구현(5일 차)은 아직.
- ERP 세션 쿠키는 서명 쿠키(서버 저장 없음)라 로그아웃 후에도 복사해 둔 쿠키는 만료(1시간) 전까지 유효할 수 있다(시험망 한계, 필요하면 서버 세션 표로 변경).
