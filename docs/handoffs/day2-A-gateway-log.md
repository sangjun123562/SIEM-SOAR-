# 2일 차 A 인수인계 — 게이트웨이 허용·차단 로그 파일화

- 담당: A / 브랜치: `eldi` / 실행 구분: **실제 실행**(Docker 29.9.1, 실제 TCP 트래픽, `ingest_mode=live`)
- 실행: `cd testbed && docker compose build gateway && docker compose up -d && bash scripts/verify_day2.sh`
- 결과 (UTC 2026-11-17T03:47, 종료 코드 0): **pass=17 fail=0**, 요청 6건. 앞선 1회는 Git Bash 경로 변환 문제로 실패(게이트웨이 결함 아님, 차단은 한 번도 적용되지 않음).

## 로그 만드는 방식
- iptables `NFLOG`(group 1) → `ulogd2`(JSON) → `nflog2jsonl.py`(계약 형식 변환) → `/var/log/gw/gateway.jsonl`
- **NFLOG는 이 환경(Docker Desktop, WSL2 커널 6.18)에서 동작 확인.**
- 허용: 새 TCP/UDP 연결(conntrack NEW)당 `fw_allow` 1줄. 차단: `GW_BLOCK` 체인에서 `fw_deny` 기록 후 DROP.
- `ingest_mode`는 항상 `live`(실제 패킷에서만 생성).

## B가 알아야 할 것 (`docs/log_contract.md` 대비)
- 필드는 계약 그대로: `timestamp_utc`(Z, 마이크로초), `source`, `event_type`, `outcome`, `ingest_mode`, `src_ip`, `src_port`(int), `dst_ip`, `dst_port`(int), `protocol`, `action`, `rule_id`(**fw_deny에만**, fw_allow에는 없음).
- 파일 위치: Docker 볼륨 `capstone-a_gw_logs`의 `gateway.jsonl`. 수집기는 **읽기 전용 마운트**(`:ro`)로 읽는다(쓰기 시도가 실패함을 확인).
- **차단된 연결은 TCP SYN 재전송 때문에 같은 `src_port`로 `fw_deny`가 1초 간격으로 여러 줄 남는다.** 중복 제거가 필요하면 `(src_ip, src_port, dst_ip, dst_port, 시간창)` 기준으로 B가 판단한다.
- 10MiB에서 회전(`gateway.jsonl.1`, `.2`, 최대 2개). `raw_id`가 `file_path`를 포함하므로 회전 시 영향이 있다(시험 규모에서는 회전 안 됨).
- 개행으로 끝나는 완성된 줄만 쓴다(단일 write, 검증기가 확인).
- 이 볼륨에는 개발 중 수동 요청으로 생긴 줄도 섞여 있다. 시험 데이터는 `verify_day2.sh` 실행분을 사용.

## 차단·해제 도구 `gwctl.sh` (게이트웨이 컨테이너 내부)
`gwctl.sh block|unblock <src_ip> <dst_ip> <rule_id>`, `gwctl.sh list`
- 입력 형식 검증, 셸 조합 없음. 허용 목록 밖의 출발지/목적지 거부(`GW_BLOCKABLE=172.28.10.11`, `GW_DST_ALLOWED=172.28.20.10`).
- 같은 요청 재시도는 규칙을 늘리지 않는다(`already-blocked`). 확인한 거부: 대조 단말, 주입 문자열, 임의 주소.
- **아직 승인 ID 검증·절대 UTC 만료·최대 차단 시간·조치망 인증은 없다**(5일 차). 이 도구는 수동 시험용이며 자동 승인 기능이 아니다.

## 변경 파일
`testbed/docker-compose.yml`(게이트웨이 읽기 전용 루트, 로그 볼륨, 환경변수), `testbed/gateway/{Dockerfile,gw-entry.sh,gwctl.sh,nflog2jsonl.py,ulogd.conf}`, `testbed/scripts/{verify_day2.sh,check_gateway_log.py}`

## 미확인 / 다음
- **B의 수집기·정규화기로 실제 DB 조회**: B 코드가 아직 저장소에 없어 미검증. 2일 차 완료 기준("관제 DB에서 각각 조회")의 마지막 단계가 남음. 올라오면 `gateway.jsonl`을 읽혀 확인.
- `verify_day1.sh`는 게이트웨이에 기본 규칙(GW_BLOCK, NFLOG)이 생긴 뒤 재실행하지 않았다(day2 스크립트가 같은 흐름을 포함).
- 열린 연결 차단(6일), 호스트 재시작 후 규칙 복구(7일).
