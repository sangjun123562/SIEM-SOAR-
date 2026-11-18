# 5일 차 A → B 인수인계 — 조치 API 완료와 연결 요청

- 담당: A / 브랜치: `eldi`
- 실행 구분: 격리 시험망 실제 실행(차단·해제 26/26, 만료·재시작 15/15). 상세: [testbed/DAY5_STATUS.md](../../testbed/DAY5_STATUS.md)

## 1. A가 완료한 것
- 주소: `http://10.250.30.2:8081` — 조치망 `capstone-a_action_net`(internal) 안에서만 접속, 호스트 포트 없음.
- 인증: `Authorization: Bearer <조치 토큰>`. 토큰은 별도로 직접 전달한다. 저장소에 올리지 말고 B 쪽 `.env`에만 둔다.
- 경로: `POST /actions/block`, `GET /actions/{approval_id}`, `POST /actions/{approval_id}/release` (DESIGN.md 3절 그대로).
- 게이트웨이 독립 검사: 대상 172.28.10.11만(그 외 422), 절대 UTC 최대 30분, 같은 승인 재시도 200(만료 연장 없음),
  다른 내용 재사용 409 `approval_conflict`, 해제·만료 승인 재차단 409 `approval_closed`, 만료 자동 해제, 재시작 시 기록↔규칙 대조.
- B의 `ActionApiClient`(`src/soc/incident_service.py`)를 수정 없이 사용해 차단·조회·해제 동작을 확인했다.
- 계약 보충: 포트 8081. 성공 응답에 `applied_at_utc`·`released_at_utc` 등이 추가될 수 있다(기존 필드 유지).
  `incident_id`·`approved_by`는 영문·숫자·`._:-@` 1~64자(공백 불가, 위반 시 400).

## 2. B에게 요청하는 작업
1. live 수집: 수집기가 A 로그 볼륨(`gw_logs`, `caddy_logs`, `erp_logs`)을 읽기 전용으로 읽어 관제 PostgreSQL에 저장.
   이 실제 수집 경로만 `ingest_mode=live`를 부여.
2. 대시보드 ↔ 관제 DB: 샘플 synthetic 대신 DB의 사건·경보·근거·`raw_id`를 표시.
3. 승인 안전장치: 담당자 인증(로그인) 추가 — 승인자 문자열 입력은 인증이 아니다. 승인·조치 결과를 관제 DB에 보존.
4. 대시보드 컨테이너화: external network `capstone-a_action_net`에 연결(10.250.30.2·.50 제외 주소),
   화면 포트는 `127.0.0.1`만, `cap_drop: [ALL]`·`no-new-privileges`·비 root·읽기 전용 루트, CPU 0.1 이하(Docker 합계 현재 1.98).
5. B PC에서는 관제 DB + 모의 게이트웨이로 단위 시험까지 확인. 조치망은 같은 PC Docker 안에서만 접근되므로 실제 차단 시험은 하지 않아도 된다.
6. 완료 후 `sangjun` → main PR에 시험 명령·결과·미확인 항목 기록.

## 3. 앞으로의 작업 구조
- 개발: A `testbed/`·`gateway/`·`caddy/`·`erp/`, B `src/soc/`·`db/`·`tests/`·`docker-compose.soc.yml`. 상대 영역은 협의 후 수정.
- 브랜치: A `eldi`, B `sangjun`만 사용, main은 PR 통합. 공유 계약 변경 시 상대에게 알림.
- 통합 시험: B 작업이 main에 들어오면 A PC에서 대시보드 컨테이너를 조치망에 붙여
  **ERP 로그인 실패 → 경보 → 사건 근거 → 사람 승인 → 시험 단말만 차단 → 해제 후 복구**를 실제 검증.
- 9일 차: 새 환경(B PC 등)에서 전체 재현.
- 실제 실행·파일 재생·합성을 구분하고, 모의 시험 통과를 실제 차단 성공으로 보고하지 않는다.

## 4. 주의
- 토큰·`.env`·실제 로그는 GitHub에 올리지 않는다.
- 시험 단말 차단 중에는 그 단말을 경유하는 localhost:18888 브라우저 접속도 함께 끊긴다(정상).
