# 네트워크 보안관제 캡스톤 (담당: B · 관제 대시보드 구현)

가상 기업 내부망의 방화벽(게이트웨이)·웹(Caddy)·ERP(Flask) 로그를 통합 수집·정규화·상관분석하고, 담당자 승인에 따라 시험망에서 실제 차단과 복구를 검증하는 관제 시스템의 **B(관제 대시보드·수집·탐지·승인)** 구현 저장소입니다.

## Mg 브랜치 탐지 규칙 안내

ERP 로그인 실패 탐지의 기존 규칙과 추가한 조사용 규칙 두 개, 구현 파일·함수, 팀원 적용 절차는 [ERP 로그인 탐지 규칙 소개 및 적용 안내](Mg_LOGIN_DETECTION_GUIDE_codex.md)를 확인하세요.

## 디렉터리 구조 (현재)

```text
├── TEAM_GUIDELINES.md         # A·B 팀 및 AI 공통 지침 (필독)
├── DESIGN.md                  # 아키텍처, 데이터 흐름, DB·API 설계 요약
├── docker-compose.soc.yml     # 관제용 PostgreSQL (호스트 포트 비공개, 내부망 전용)
├── .gitignore                 # 비밀값·로컬 캐시·로그 제외 규칙
├── db/
│   └── init/
│       └── 001_schema.sql     # 관제용 PostgreSQL 스키마 (raw_logs ~ action_approvals)
└── docs/
    ├── log_contract.md        # A ↔ B 공통 로그 형식 및 필드 합의서
    ├── test_answer_sheet.md   # 1~10일 차 시험 정답표
    └── dashboard_spec.md      # 관제 앱 및 Grafana 표시 항목, 조치 API 계약
```

> 향후 추가 예정: B 담당(`samples/`, `src/soc/`, `tests/`), A 담당(`testbed/`, `gateway/`, `caddy/`, `erp/`)

## 빠른 시작 (1일 차 기준)

1. 팀 공통 지침 확인: [TEAM_GUIDELINES.md](TEAM_GUIDELINES.md)
2. 공통 로그 계약 확인: [docs/log_contract.md](docs/log_contract.md)
3. 관제 DB 스키마 확인: [db/init/001_schema.sql](db/init/001_schema.sql)
4. 관제 DB 기동 (Docker, 사전 게이트 확인 후 실행):
   ```bash
   docker compose -f docker-compose.soc.yml up -d
   ```


## A 현재 시연 범위 (2026-11-20)

ERP는 구매·결재 기능을 제거한 기관 통합 로그인 화면이다.
일반 Chrome에서 계정을 선택해 정상/실패 인증, 세션 확인, 로그아웃을 수행한다.

- [A 망 구성](testbed/NETWORKS.md)
- [일반 브라우저 접속 실행 방법](testbed/browser/README.md)
- [4일 차 완료/미완료 점검](testbed/DAY4_STATUS.md)
- [5일 차 점검](testbed/DAY5_STATUS.md)
- **[새 PC에서 처음부터 실행하기](testbed/NEW_PC_SETUP.md)** — `bash testbed/scripts/setup_all.sh`

브라우저 입구 실행: `node testbed/browser/server.cjs` (Docker CLI가 PATH에 있어야 함).
Windows에서는 `testbed/browser/start.ps1`로 실행할 수 있다.
A·B 통합 로그인 실패→사건→인증 승인→대상 차단→해제·복구는 A PC에서 3회 연속 통과했다(각 pass=20, fail=0, 요청14, 종료0). [10일 차 결과와 잔여 인수](testbed/DAY10_STATUS.md)를 참고한다. README 상호 재현·Grafana 런타임·구성도·발표 리허설까지 완료된 것은 아니다.
