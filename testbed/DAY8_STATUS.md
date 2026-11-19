# 8일 차 점검 — A: ERP 초기화 후 증거 보존

점검일 2026-11-19 / A 고정 브랜치 eldi. A PC 격리 시험망에서 실제 실행.

## 판정

**완료 기준 "초기화 후 같은 raw_id 조회 가능" 통과.**
구매 신청·승인·반려는 사용자 결정(2026-11-18)으로 범위에서 제거되어 시험하지 않는다.

| 확인 항목 | 결과 |
|---|---|
| 초기화 전 실제 ERP 로그인이 관제 DB에 live로 저장 | 통과 (raw_id 7cf3c588…) |
| ERP 초기화는 ERP DB만 대상, 실행 전 백업 | 통과 (pg_dump 6,877 bytes, 로컬 보관) |
| ERP 업무 데이터 초기화 | 통과 (purchase_requests 7 → 0, 시험 계정 3개 재생성) |
| 같은 raw_id 조회, 원본 내용 해시 동일 | 통과 |
| 정규화 이벤트·request_id 연결 유지 | 통과 |
| 관제 raw_logs·사건·승인 기록 감소 없음 | 통과 |
| ERP 로그 파일(erp_logs 볼륨) 보존 | 통과 |
| 초기화 후 로그인·새 기록 live 수집 | 통과 |
| 대조 단말 정상 | 통과 |

## 실행

- `bash scripts/verify_day8.sh <백업폴더>` UTC 08:09:16~08:09:40, pass=13 fail=0, 종료 0. 요청 4건, 차단 없음.
- 초기화 도구: `bash scripts/erp_reset.sh --yes [백업폴더]`
  - `--yes` 없으면 실행 거부(종료 2, 데이터 변경 없음 확인).
  - 컨테이너 라벨 `capstone-a/erp-db`, 볼륨 `capstone-a_erp_db_data`, DB `erp_db`를 확인한 뒤 실행.
  - pg_dump 백업 실패 시 중단. 테이블 내용만 TRUNCATE, 볼륨 삭제(down -v) 없음.
  - ERP 재시작으로 시험 계정 재생성, `route-erp` 경로 도우미 재실행.
  - ERP 로그 볼륨·관제 DB·게이트웨이·Caddy 로그는 건드리지 않음.
- 실행 후 `verify_network_layout.py` 재통과.

## 남길 점

- 백업 파일에는 계정 비밀번호 해시가 들어 있으므로 저장소에 올리지 않는다(기본 위치 `$HOME/capstone-erp-backups`).
- 과거 구매 데이터 7건은 이번 초기화로 ERP DB에서 지워졌고 백업 파일에만 남는다. 관련 과거 관제 로그(purchase_*)는 관제 쪽 보관본에 남는다.
- ERP·게이트웨이 컨테이너가 재시작되면 localhost:18888 브라우저 입구(server.cjs)가 종료될 수 있다. 재실행하면 복구된다.
