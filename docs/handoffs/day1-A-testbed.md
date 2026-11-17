# 1일 차 A 인수인계 — 시험망 경유·차단·복구

- 담당: A / 브랜치: `eldi` / 실행 구분: **실제 실행**(Docker 29.9.1, Linux 컨테이너, Windows 호스트)
- 파일: `testbed/docker-compose.yml`, `testbed/gateway/Dockerfile`, `testbed/web/server.py`, `testbed/scripts/verify_day1.sh`
- 실행: `cd testbed && docker compose build && docker compose up -d && bash scripts/verify_day1.sh`
- 정리: `docker compose down` (프로젝트 `capstone-a`만 대상. `-v`·전역 prune 금지)

## 구성
| 서비스 | IP | 비고 |
|---|---|---|
| gateway | 172.28.0.2 | `NET_ADMIN`만 예외, NAT 없음, `ip_forward=1` |
| client-test | 172.28.10.11 | 차단 대상 |
| client-ref | 172.28.10.12 | 대조 단말(차단 금지) |
| web | 172.28.20.10:8080 | 임시 HTTP 서버, 출발지 IP를 응답·JSON 로그에 기록 |

호스트 포트 공개 없음. 네트워크 `internal: true`. 자원: CPU 합 약 1.0, 메모리 약 240MB, 로그 10MiB×3.

## 결과 (UTC 2026-11-17T03:25, 종료 코드 0, 6건 요청, pass=6 fail=0)
- 접속 성공: 서버가 본 출발지 = 단말 IP (게이트웨이 NAT 없음), 게이트웨이 FORWARD 카운터 증가(156→180)
- 차단 중: test 접속 실패 + DROP 카운터 0→3, ref 접속 성공
- 해제 후: 규칙 조회에서 제거 확인, test 복구
- 1일 차 수동 차단은 사람이 실행한 격리 시험이며 자동 승인 기능이 아니다.

## 설계 편차 (검토 필요)
단말망/서버망을 별도 Docker 네트워크 두 개로 나누는 구성은 **Docker가 호스트 쪽에서 다른 네트워크 컨테이너 IP로 향하는 패킷을 차단**해 실패했다(게이트웨이 INPUT에도 도달하지 않음. `trusted_host_interfaces`, `nat-unprotected` 시도 실패, `isolated`는 internal 전용). 호스트 Docker 설정은 변경하지 않고, **브리지 하나(internal)에 서브넷만 논리 분리**하고 단말·서버의 직접 경로를 제거해 게이트웨이만 통하게 했다. 단말은 `NET_ADMIN`/`NET_RAW`가 없어 경로를 바꿀 수 없다. 한계: L2는 같은 브리지다.

## 미확인 / 다음
- 기존(열린) 연결의 후속 요청에 차단이 적용되는지: 6일 차.
- 게이트웨이 허용·차단 로그 파일(`gateway.jsonl`): 2일 차. NFLOG 지원은 미확인.
- 라우트 사이드카는 컨테이너 재시작 시 다시 실행해야 한다(`docker compose up -d`로 재적용).
- B에게: `docs/log_contract.md`의 gateway 필드(`src_ip`,`dst_ip`,`dst_port`,`action`,`rule_id`) 그대로 사용 예정. web 로그는 임시 서버용이며 계약 대상이 아니다.
