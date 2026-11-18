# ERP (구매 요청) — 처음 읽는 사람용 설명

시험망에서 실제 로그인·권한·업무 로그를 만들기 위한 **아주 작은 ERP**입니다. 화면은 방어전 원본 「나만의 자료실」을 바꿔 만들었습니다(출처는 `SOURCE.md`).

## 파일 4개
| 파일 | 하는 일 |
|---|---|
| `app.py` | 서버 전부(Flask). 위에서부터 1 설정 → 2 로그 → 3 요청마다 하는 일 → 4 로그인 → 5 권한 → 6 구매 요청 API 순서 |
| `schema.sql` | DB 테이블 2개: `users`(사용자), `purchase_requests`(구매 요청) |
| `static/index.html` | 화면 한 장(로그인, 등록, 목록, 승인·반려 버튼) |
| `Dockerfile` | 컨테이너 이미지 만들기 |

## 사용자와 권한
| 사용자 | 부서 | 직급 |
|---|---|---|
| alice | 영업 | 사원 |
| bob | 영업 | 팀장 |
| carol | 개발 | 사원 |

- **보기:** 내가 쓴 요청 또는 (팀장이면) 우리 부서 요청
- **승인·반려:** 같은 부서 팀장, 내가 쓴 요청이 아닐 때, 아직 '대기'일 때
- 그 밖의 시도는 **403으로 거부**하고 `access_denied`로 기록합니다(예: carol이 영업 요청 열람, alice가 승인 시도).
- 비밀번호는 저장소에 없습니다. `testbed/scripts/init_env.sh`가 처음 한 번 무작위로 만들어 `testbed/.env`(Git 제외)에 둡니다.

## 로그(`erp.jsonl`)
한 줄에 JSON 하나. 관제 시스템(B)이 읽습니다.

| event_type | 언제 |
|---|---|
| `login_success` / `login_failed` | 로그인 성공 / 실패(형식이 틀린 시도 포함) |
| `access_denied` | 권한 밖 조회·승인·반려 시도 |
| `purchase_created` / `purchase_approved` / `purchase_rejected` | 업무 처리 |
| `logout` | 로그아웃 |

공통 필드: `timestamp_utc, source(erp), event_type, outcome, ingest_mode(live), request_id, client_ip, peer_ip, client_ip_trusted, http_method, http_path, status_code`, 그리고 있으면 `username` 등.

**남기지 않는 것:** 비밀번호, 쿠키, 요청 본문, 쿼리 문자열.
(주의: 사용자명 칸에 입력한 값은 그대로 기록되므로, 실수로 비밀번호를 사용자명 칸에 넣으면 남을 수 있습니다.)

## 접속자 IP를 정하는 규칙 (가장 중요)
- 직접 연결한 상대(`peer_ip`)가 **Caddy(172.28.20.5)일 때만** Caddy가 보낸 `X-Client-IP`·`X-Request-ID`를 믿고 `client_ip_trusted=true`로 기록합니다.
- 그 밖에는 헤더를 무시하고 `client_ip = peer_ip`, `client_ip_trusted=false`, `request_id = local-...`로 기록합니다.
- 관제 시스템은 `client_ip_trusted=true`인 로그만 탐지·차단 근거로 씁니다.

## 일부러 하지 않은 것
- **로그인 실패 시 계정 잠금·지연 없음.** 탐지 시연을 위해 실패가 그대로 쌓이게 했습니다(실서비스라면 필요).
- 요청 수정·삭제 기능 없음(등록·조회·승인·반려만).
