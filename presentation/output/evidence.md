# 대표 슬라이드 근거

확인일은 2026-11-28 KST. 발표 코드 기준은 원격 GitHub main을 읽기 전용으로 대조해 확인한 `d55e51039c4574e756afa21e8e47624b1ea07f97`. 현재 로컬 eldi HEAD는 `aaa5d6a60937ab0efa5059029e61a182f829d2d1`이고 커밋되지 않은 수정도 있었다. 로컬 보고서 변경을 발표 기준에 합산하지 않았다. 컨테이너 이미지 라벨에서 실행 Git SHA를 확인할 수 없었다.

| 주장 | 근거 파일 또는 기록 | 기준 | 확인 상태 |
| --- | --- | --- | --- |
| 가상 기업 시험망과 SOC 관제 영역을 분리 | `testbed/docker-compose.yml`, `testbed/NETWORKS.md`, `docker-compose.soc.yml` | main d55e510 | 코드 확인 |
| 호스트 Node.js 중계와 시험 단말, Gateway, Caddy, ERP, 분리된 ERP DB | `testbed/browser/README.md`, `testbed/docker-compose.yml`, `testbed/caddy/Caddyfile` | main d55e510 | 코드 및 설계 확인 |
| Gateway·Caddy·ERP 로그 볼륨을 Collector가 읽기 전용으로 수집 | `docker-compose.soc.yml` 77–79행, `src/soc/live_collector.py`, `collector.py` | main d55e510 | 코드 확인 |
| SOC DB를 대시보드 및 선택 실행 Grafana가 조회 | `docker-compose.soc.yml`의 soc-dashboard, soc-grafana, `grafana/provisioning/` | main d55e510 | 코드 확인 |
| IP 조치와 계정·권한 제어의 통로를 분리 | `docker-compose.soc.yml` 115–118행, `testbed/docker-compose.yml`의 action_net, erp_control_net, `src/soc/incident_service.py` | main d55e510 | 코드 확인 |
| Caddy 안의 Coraza가 ERP 프록시 전달 전에 검사하며 기본 설정은 DetectionOnly | `testbed/caddy/Caddyfile`의 erp_waf, `testbed/docker-compose.yml` 207행 | main d55e510 | 코드 확인 |
| WAF 이벤트를 Caddy 로그 경로로 관제에 전달하도록 구현 | `testbed/caddy/caddy2jsonl.py`, `testbed/caddy/WAF.md`, `src/soc/dashboard.py`의 waf_detected/waf_blocked 처리 | main d55e510 | 코드 확인 |
| 개요 첫 행의 사건을 열어 인증 실패·신뢰 IP·실시간 수집 근거를 확인 | 로컬 Sentinel 개요 및 동일 사건 `INC-0E6C379A2C` 상세, 2026-11-28 KST 신규 캡처 | 실행 이미지 SHA 미확인 | 현재 화면 확인 |
| Caddy와 ERP는 요청 ID로 정확히 연결, Gateway는 통신 정보와 시각을 바탕으로 후보 연결 | `src/soc/incident_service.py`의 build_incidents, `docs/log_contract.md` | main d55e510 | 코드 확인 |
| 차단·해제 흐름 3회 연속, 매회 20개 항목 통과·실패 0 | `testbed/DAY10_STATUS.md` 24–48행 | 2026-11-20 A PC, abb755f | 기존 통합 시험 기록 |
| 차단 중 대상 A 접속 불가, 대조 B 정상, 해제 후 A 접속 복구 | 같은 문서 38–48행 | 2026-11-20 A PC, abb755f | 기존 통합 시험 기록 |

기존 14장 PPT와 각 장 노트를 대조했다. 기존 자료의 사건 따라가기와 대상·대조 단말 비교를 활용했다. v2 교재 3편의 414c49e 기준은 역사 자료로 분리했다. 위 화면의 사건과 11월 20일 시험 기록은 서로 다른 증거다. 시험 당시 승인은 인증된 경로를 스크립트로 호출했다.
