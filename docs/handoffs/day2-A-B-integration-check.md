# 2일 차 A↔B 통합 확인 (A가 B의 수집기를 실제 게이트웨이 로그로 시험)

- 실행 구분: **실제 실행**(Docker, 실제 TCP 트래픽으로 만든 `gateway.jsonl` 15줄: 허용 12 / 차단 3, `ingest_mode=live`)
- 대상: `main`의 `src/soc/*` (PR #6), 관제 DB는 `docker-compose.soc.yml`의 PostgreSQL 16
- 방법: 관제 DB 컨테이너 + 수집기 컨테이너(DB 네트워크 전용, `cap_drop ALL`, 읽기 전용 루트, 로그 볼륨 `:ro`, 소스 `:ro`)

## 결과 요약
| 항목 | 결과 |
|---|---|
| 정규화(`normalize_log_line`) 실제 로그 15줄 | **15/15 통과**, `rule_id`는 `details`에 저장됨 |
| B의 단위 테스트 3개 | 통과 |
| SQLite(메모리)로 수집 → 재시작 | 15건 저장 → 재시작 0건(중복 없음) |
| **PostgreSQL로 수집** | **수집기는 15건 저장이라 보고하지만 DB에는 0건** (별도 연결로 조회) ← 결함 |
| 위 결함에 commit만 추가한 시험 | 15건 저장, 허용 12 / 차단 3 각각 조회됨, 재시작 시 0건, offset=3741 저장 |

## 결함: `PostgresSocStorage`가 커밋하지 않음 (B 담당 파일 `src/soc/storage.py`)
- `get_offset()`이 먼저 SELECT를 실행해 psycopg3의 암묵 트랜잭션이 열린다. 이후 `with self._conn.transaction():`은 최상위 트랜잭션이 아니라 **savepoint**라서 커밋되지 않는다. 연결을 닫으면 **원본·정규화 이벤트·offset이 모두 롤백**된다.
- SQLite 경로에는 `commit()`이 있어(91행) 단위 테스트가 이를 잡지 못했다.
- 제안 수정(B 확인 후 적용): `save_batch_and_advance_offset` 마지막에 `self._conn.commit()` 추가(또는 연결을 `autocommit=True`로 열고 `transaction()`만 사용). PostgreSQL을 대상으로 한 통합 시험을 추가해 "다른 연결에서 조회되는지"를 확인할 것.

## 기타 관찰 (결함 아님, B 판단)
- `collector_offsets.file_path`에 파일명(`gateway.jsonl`)만 저장되고 전체 경로가 아니다. 회전 파일(`gateway.jsonl.1`)과 구분하려면 정책 필요.
- 차단된 연결은 TCP SYN 재전송으로 같은 `src_port`의 `fw_deny`가 여러 줄 생긴다(15줄 중 차단 3줄 모두 같은 포트 51724 등).
- `rule_id`가 컬럼이 아니라 `details_json`에 들어간다. 경보 규칙의 `rule_id`(alerts 테이블)와 이름이 겹쳐 혼동될 수 있다.

## 2일 차 완료 기준 판정
"실제 허용 로그와 차단 로그가 관제 DB에서 각각 조회됨": **PostgreSQL 커밋 결함이 고쳐지기 전까지는 미충족.** 수정 시험(커밋 추가)에서는 충족됨을 확인했다.
