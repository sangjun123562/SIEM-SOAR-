# 네트워크 보안관제 캡스톤 (담당: B · 관제 대시보드 구현)

가상 기업 내부망의 방화벽(게이트웨이)·웹(Caddy)·ERP(Flask) 로그를 통합 수집·정규화·상관분석하고, 담당자 승인에 따라 시험망에서 실제 차단과 복구를 검증하는 관제 시스템의 **B(관제 대시보드·수집·탐지·승인)** 구현 저장소입니다.

## 디렉터리 구조

```text
├── DESIGN.md                  # 아키텍처, 데이터 흐름, DB·API 설계 요약
├── docker-compose.soc.yml     # 관제용 PostgreSQL (호스트 포트 비공개, 내부망 전용)
├── docs/
│   ├── log_contract.md        # A ↔ B 공통 로그 형식 및 필드 합의서
│   ├── test_answer_sheet.md   # 1~10일 차 시험 정답표
│   └── dashboard_spec.md      # 관제 앱 및 Grafana 표시 항목, 조치 API 계약
├── db/
│   └── init/
│       └── 001_schema.sql     # 관제용 PostgreSQL 스키마 (raw_logs ~ action_approvals)
├── samples/
│   ├── gateway.jsonl          # 1~2일 차 게이트웨이 허용/차단 샘플 로그
│   ├── caddy.jsonl            # 3일 차 Caddy HTTPS 샘플 로그
│   └── erp.jsonl              # 4일 차 ERP 로그인 실패/성공 샘플 로그
├── src/
│   └── soc/
│       ├── __init__.py
│       ├── models.py          # 공통 이벤트·원본·오프셋 데이터 모델
│       ├── normalizer.py      # 게이트웨이·Caddy·ERP 로그 정규화기
│       ├── storage.py         # 저장소 인터페이스 (SQLite 테스트용 / PostgreSQL 운영용)
│       └── collector.py       # 완성 줄 단위 파일 수집기 (DB 커밋 후 오프셋 갱신)
└── tests/
    └── test_collector_and_normalizer.py  # 정규화·오프셋·재시작 중복 방지 시험
```

## 빠른 시작 (1일 차 기준)

1. 공통 로그 계약 확인: [docs/log_contract.md](docs/log_contract.md)
2. 관제 DB 스키마 확인: [db/init/001_schema.sql](db/init/001_schema.sql)
3. 단위 테스트 실행 (로컬 Python 또는 Docker Python 컨테이너):
   ```bash
   pytest -v
   ```
4. 관제 DB 기동 (Docker):
   ```bash
   docker compose -f docker-compose.soc.yml up -d
   ```
