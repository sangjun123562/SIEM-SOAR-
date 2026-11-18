# A 시험망 — 실제 네트워크 분리

담당 A / 고정 브랜치 `eldi`. 2026-11-18에 기존 단일 bridge 구성을 교체했다.

## 연결 구조

| 네트워크 | 방식 / 대역 | 연결 서비스 |
|---|---|---|
| client_net | internal Macvlan L2 / 172.28.10.0/24 | 시험 단말 .11, 대조 단말 .12, 게이트웨이 .2 |
| server_net | internal Macvlan L2 / 172.28.20.0/24 | Caddy .5, 임시 서버 .10, ERP .20, 게이트웨이 .2 |
| action_net | internal bridge / 10.250.30.0/24 | 게이트웨이 .2; B 조치 클라이언트는 추후 연결 |
| erp_db_net | internal bridge / 10.250.29.0/24 | ERP .20, ERP DB |

단말 → 172.28.10.2(게이트웨이) → 172.28.20.5(Caddy HTTPS) → Flask ERP → ERP DB.
응답도 게이트웨이를 통과한다. 서버끼리의 요청도 기존 로그 경로를 유지하도록 .20.2 경유로 설정한다.
게이트웨이는 NAT를 하지 않으므로 Caddy에서 보는 단말 IP와 ERP가 보는 Caddy IP는 바뀌지 않는다.
ERP DB는 이 웹 요청 경로와 별도 DB망에서 통신한다.

## 호스트 설정을 바꾸지 않는 방법

두 Macvlan 망 모두 `internal: true`이고 `parent`를 지정하지 않는다.
Docker가 Linux VM 내부에 네트워크별 dummy 부모를 만들며, 실제 PC 랜카드나 VLAN 인터페이스에 연결하지 않는다.
`macvlan_mode: bridge`는 Macvlan 장치 사이의 L2 전달 모드로, 종전의 단일 Docker bridge와 다르다.

Windows 방화벽·IP·라우팅·DNS·인증서 저장소 및 Docker daemon 설정은 변경하지 않았다.
라우팅은 기존 일회용 NET_ADMIN 사이드카가 대상 컨테이너 namespace 안에서만 설정한다.
단말에는 NET_ADMIN/NET_RAW가 없고 모든 서비스에 기본 외부 경로와 호스트 공개 포트가 없다.
Docker 내부 가상 자원 생성은 수행하며 CPU·메모리·디스크 사용까지 없다는 뜻은 아니다.

공식 근거:
- [Docker Macvlan driver](https://docs.docker.com/engine/network/drivers/macvlan/)
- [Moby Macvlan 설계: parent 생략 시 dummy 생성](https://github.com/moby/libnetwork/blob/master/docs/macvlan.md)

## 실행과 검증

```bash
cd testbed
docker compose config --quiet
docker compose up -d --pull never
python -B scripts/verify_network_layout.py
bash scripts/verify_day3.sh
bash scripts/verify_day4.sh
```

이미지와 로컬 .env는 사전에 준비되어 있어야 한다. 원본 프로젝트 비밀값은 사용하지 않는다.
경로 사이드카가 모두 종료 코드 0으로 끝난 뒤 시험한다.
컨테이너를 수동으로 restart/start한 경우 namespace 경로가 초기화될 수 있으므로 경로 사이드카를 다시 실행하고
`verify_network_layout.py`를 먼저 통과시킨다. 검증 실패 시 요청 시험을 진행하지 않는다.

전환 전의 `capstone-a_lab_net`은 사용 컨테이너가 없는지와 프로젝트 라벨을 확인한 뒤 제거해야 한다.
기존 /16과 새 /24는 겹치므로 두 구성을 동시에 만들지 않는다.
이번 전환은 `docker compose down` 후 빈 이전 망만 제거했고 `-v`를 쓰지 않았다.
ERP DB·원본 로그·정규화 로그·CA의 named volume 7개를 보존했다.

A 전체 CPU 제한 합계 1.44, 메모리 880 MiB. 관제 DB 0.50 CPU/512 MiB를 포함하면 1.94 CPU/1392 MiB.
새 서비스를 추가하기 전에 예산을 재조정한다.

## 실제 확인한 범위와 남은 일

2026-11-18 UTC:
- 별도 최소 시험망: 두 단말 접속, 대상만 차단, 대조 단말 정상, 해제 복구.
  게이트웨이 FORWARD 전체 차단 시 접속 불가 및 DROP 카운터 증가로 우회 불가 확인.
  임시 시험 자원은 정리했다.
- 실제 ERP 구성: 네트워크 소속·internal·포트 비공개·권한·자원 제한·기본 경로 부재 검증.
- Day3 HTTPS/요청 ID/단말 IP/원본 로그 정제/차단·복구: pass=29 fail=0.
- 전환 뒤 ERP DB에 기존 구매 요청 2건이 남아 있음을 읽기 전용 조회로 확인.
- Day4 ERP 로그인·권한·구매 요청·감사 로그: pass=19 fail=0. 실제 생성 로그로 탐지 함수의 N-1/N, 두 단말 분리도 통과했다. 이번 업무 시험으로 시험용 구매 요청 1건이 추가되었다.
- Day3 UTC 00:10:29~00:11:21, Day4 UTC 00:11:55~00:13:11, 각각 종료 코드 0.

조치망의 네트워크만 준비되었다. 승인 API·인증·만료·B의 관제 앱 연동은 구현 완료가 아니다.
관제 DB 적재·사건 UI·Wazuh 통합을 이번 검증으로 통과 처리하지 않는다.
물리 랜카드를 parent로 지정하거나 host 설정 변경으로 실패를 해결하지 않는다.
다른 PC/Docker 버전의 지원 여부, 호스트 재부팅 및 새 볼륨 환경 재현은 별도 확인 대상이다.
