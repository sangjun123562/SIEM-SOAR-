# 3일 차 A 인수인계 — Caddy HTTPS, 요청 ID·단말 IP 전달, caddy.jsonl

- 담당: A / 브랜치: `eldi` / 실행 구분: **실제 실행**(Docker 29.9.1, 실제 HTTPS 트래픽, `ingest_mode=live`)
- 실행: `cd testbed && docker compose up -d && bash scripts/verify_day3.sh` (요청 13건)
- 결과 (UTC 2026-11-17T08:06~08:07, 종료 코드 0): **verify_day3 pass=28 fail=0**(우회 차단 시험 포함). 회귀: verify_day1 pass=6, verify_day2 pass=17 (두 스크립트는 Caddy 경유로 바꿔 재실행, 모두 통과).
- 3일 차 계획표의 "임시 80(서버 직접 접속) 제거 후 경유 재시험"은 아래 "우회 차단"으로 완료했다.
- B 정규화기(`main` 821986c 기준)에 실제 `caddy.jsonl` 7줄을 넣어 **7/7 통과**.

## 구조
```
단말 → 게이트웨이(172.28.0.2) → Caddy(172.28.20.5:8443, HTTPS) → web(172.28.20.10:8080, 4일 차에 Flask ERP로 교체)
```
- Caddy→web 연결도 게이트웨이를 지난다. 그래서 `gateway.jsonl`에는 **단말→Caddy(dst_port 8443)** 와 **Caddy→web(src_ip 172.28.20.5)** 허용 기록이 둘 다 남는다. 게이트웨이 로그를 웹 로그와 연결할 때(7일 차 후보 연결) 후자를 사용자 접속으로 오해하지 말 것.
- 단말은 Caddy 내부 CA의 **공개 루트 인증서만** 신뢰(`SSL_CERT_FILE`, 읽기 전용 볼륨 `caddy_ca`). CA 개인키는 별도 볼륨 `caddy_data`에만 있고 단말에는 마운트하지 않는다.

## Caddy가 하는 일 (확인됨)
- `X-Request-ID`와 `X-Client-IP`를 **Caddy가 직접 덮어쓴다**(`header_up`). 클라이언트가 `X-Request-ID: evil-id`, `X-Client-IP: 6.6.6.6`을 보내도 서버는 Caddy 값을 받았다.
- 서버가 받은 `X-Request-ID`와 `caddy.jsonl`의 `request_id`가 일치(UUID).
- 평문 HTTP로 8443에 접속하면 업스트림에 도달하지 않고 400.
- 인증서 검증이 실제로 강제됨(다른 신뢰 저장소로는 `certificate verify failed`).
- 쿼리 문자열(`?password=...&token=...`)과 `Cookie` 값은 `caddy.jsonl`에 남지 않는다(화이트리스트 변환).

## 우회 차단 (정책 체인 `GW_POLICY`)
- 단말망(172.28.10.0/24)은 **Caddy(172.28.20.5:8443)로만** 서버망에 접속할 수 있다. 그 밖의 서버망 접속(예: 임시 서버 `172.28.20.10:8080` 직접 접속 = Caddy 우회)은 `fw_deny`로 기록한 뒤 DROP한다. 모든 단말에 적용되고 승인과 무관한 상시 정책이다.
- 로그에서는 `event_type=fw_deny`, **`rule_id=POLICY-CLIENT-CADDY-ONLY`** 로 보인다. 사람 승인으로 걸리는 차단(`APR-...` 등 `gwctl`이 쓰는 승인 규칙, 체인 `GW_BLOCK`)과 **다르다**. B는 7일 차에 "승인 기록 ↔ 실제 방화벽 상태"를 대조할 때 이 정책 규칙을 승인 조치로 오해하지 말 것. 우회 시도가 반복되면 탐지 규칙의 재료로 쓸 수도 있다.
- 확인: test·ref 모두 `web:8080` 직접 접속이 막힘, `GW_POLICY` DROP 카운터 증가(0→6), 게이트웨이 로그에 두 단말의 `fw_deny`(+rule_id) 기록, 정상 경로(Caddy HTTPS)는 그대로, 단말은 `ip route`를 바꿀 수 없고(NET_ADMIN 없음) 기본 경로도 없다(외부로 나가는 경로 없음; 외부로 패킷을 보내 검사하지는 않았다).
- 이 때문에 1·2일 차 시험 스크립트는 서버 직접 접속 대신 Caddy 경유로 바꿨다(로그 필드·검증 항목은 그대로, 기대 집합에 Caddy 출발지 허용 기록 추가).

## B가 알아야 할 것 (`docs/log_contract.md` caddy 형식)
`caddy.jsonl` 필드: `timestamp_utc, source, event_type(http_request), outcome(success|failure), ingest_mode(live), request_id, client_ip, peer_ip, http_method, http_path(쿼리 제외), status_code`. 계약에 없는 필드는 없다.
- `outcome`: `status_code < 400`이면 `success`, 아니면 `failure`.
- **게이트웨이가 NAT를 하지 않으므로 Caddy에서 `client_ip == peer_ip`** (둘 다 실제 단말 IP). ERP 쪽 `peer_ip`는 Caddy IP(**172.28.20.5**)가 된다. `client_ip_trusted`는 ERP가 `peer_ip == 172.28.20.5`일 때만 `true`로 기록할 예정(4일 차).
- 로그 위치: Docker 볼륨 `capstone-a_caddy_logs`의 `caddy.jsonl`(읽기 전용 마운트 권장), 게이트웨이는 `capstone-a_gw_logs`.
- 변환기는 완성된 줄만 처리하고 변환·기록 후 offset을 저장한다(최소 1회 처리, 비정상 종료 시 마지막 배치가 중복될 수 있음 → 수집기의 `raw_id` 중복 방지로 흡수).

## 변경 파일
`testbed/docker-compose.yml`(Caddy·로그 변환기·볼륨 초기화·CA 내보내기·경로 사이드카), `testbed/caddy/Caddyfile`, `testbed/caddy/caddy2jsonl.py`, `testbed/gateway/gwctl.sh`(목적지 허용 목록을 쉼표 구분 목록으로: 임시 서버+Caddy), `testbed/web/server.py`(X-Request-ID/X-Client-IP 응답·로그), `testbed/scripts/{verify_day3.sh,check_caddy_log.py}`

## 시험 중 발견·수정한 것
1. **경로 사이드카가 멱등이 아니었다.** 게이트웨이를 재빌드하자 사이드카가 다시 실행되어 `ip route del`이 이미 바뀐 경로를 지우고 단말의 게이트웨이 경로가 사라졌다. `ip route replace`로 바꿔 몇 번 실행해도 같은 결과가 되게 했다. (컨테이너 재시작 후 경로가 사라지는 문제는 `docker compose up -d`로 사이드카를 다시 실행해 복구한다.)
2. **내 가정이 틀렸었다**: busybox `wget`은 인증서를 검증한다. 처음에는 Caddy CA를 몰라 모든 HTTPS가 거부됐고, 공개 루트 인증서만 신뢰 볼륨으로 내보내 해결했다.
3. Caddy CA 디렉터리는 `0700`(소유자 전용)이라 root 컨테이너가 읽지 못했다. 권한을 추가하는 대신 내보내기 서비스를 Caddy와 같은 비 root 사용자로 실행했다.

## 미확인 / 한계
- 같은 서버망의 다른 호스트(예: 임시 서버 → Caddy)가 단말처럼 접속하는 경로는 정책 대상이 아니다(정책은 단말망 출발만 제한). 4일 차에도 ERP는 `peer_ip`가 Caddy가 아니면 `client_ip_trusted=false`로 기록하는 이중 방어를 유지한다.
- 3일 차 완료 기준의 "N-1건 경보 없음, N건에서 첫 경보"는 **B 쪽 탐지 규칙**이며 실제 ERP 로그가 있어야 end-to-end 확인 가능(4일 차).
- Caddy 자체 서명 CA는 시험망 전용이며, 컨테이너를 새 볼륨으로 다시 만들면 CA가 새로 만들어진다(단말은 `caddy-ca-export`가 다시 실행되어야 신뢰 인증서가 갱신됨).
- 호스트 재부팅 후 상태, 이미 열린 연결 차단(6일 차)은 확인하지 않았다.
