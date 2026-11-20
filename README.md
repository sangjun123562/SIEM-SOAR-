# Mg · C 담당 개발 현황

**ERP 로그인 실패를 찾는 규칙을 1개에서 3개로 늘렸습니다.** 지금까지는 "한 계정이 한 IP에서 계속 틀리는 경우"만 찾았습니다. 이제 실패가 **여러 계정명**이나 **여러 IP**로 흩어진 경우도 관제 화면에 사건으로 나타납니다.

📘 **자세한 설명과 코드 해설** → [ERP 로그인 탐지 규칙 안내서](Mg_LOGIN_DETECTION_GUIDE_codex.md)

## 한눈에 보는 진행 상황

| C 담당 작업 | 상태 | 내용 |
| --- | --- | --- |
| 1. 찾는 규칙이 1개뿐 | ✅ **구현·로컬 검증 완료** | 조사용 규칙 2개를 추가했습니다. 팀 Docker·PostgreSQL 환경에서의 통합 검증만 남았습니다. |
| 2. 정상 직원도 사건이 될 수 있음 | ⏭️ **다음 작업** | 여러 번 틀린 뒤 결국 로그인에 성공했는지를 사건 화면에 보여줄 예정입니다. 담당자가 판단할 때 참고하는 정보이며, 성공했다고 사건이 자동으로 닫히지는 않습니다. |
| 3. 놓치는 로그인 실패 패턴이 있음 | 🔶 **일부 완료** | 여러 계정명·여러 IP 패턴은 1번에서 해결했습니다. 실패 뒤 성공을 보여주는 부분은 2번과 함께 진행합니다. |
| 4. 수집기 재시작 중 기록 분류 | ⏸️ **대기** | 수집기가 꺼져 있던 동안 쌓인 기록과 다시 켠 뒤 들어온 기록을 구분하는 기준을 정할 예정입니다. |

## 탐지 규칙 3개 (기존 1개 + Mg가 추가한 2개)

세 규칙 모두 **최근 5분** 안의 기록만 봅니다.

| 규칙 | 이런 경우 사건이 생깁니다 | 의심 상황 | 코드 위치 |
| --- | --- | --- | --- |
| 기존 · 같은 계정 + 같은 IP | 같은 계정명이 같은 IP에서 **5번** 실패 | 비밀번호 무작위 대입 | [`detect_login_failures()`](src/soc/detector.py#L65) |
| 🆕 **추가 1 · 같은 IP + 여러 계정명** | IP 하나에서 **서로 다른 계정명 3개**가 실패 | 한 PC에서 여러 계정을 돌아가며 시도 | [`detect_multi_account_failures()`](src/soc/detector.py#L156) |
| 🆕 **추가 2 · 같은 계정명 + 여러 IP** | 계정명 하나가 **서로 다른 IP 3곳**에서 실패 | 여러 PC에서 한 계정을 노림 | [`detect_multi_source_failures()`](src/soc/detector.py#L165) |

### 예시: 추가 1은 이렇게 셉니다

같은 IP에서 아래 순서로 로그인 실패가 들어왔다고 해 보겠습니다.

| 시각 | 실패한 계정명 | 서로 다른 계정명 | 결과 |
| --- | --- | --- | --- |
| 09:00 | alice | alice → **1개** | 대기 |
| 09:01 | alice | alice → **1개** (같은 이름은 다시 세지 않음) | 대기 |
| 09:02 | bob | alice, bob → **2개** | 대기 |
| 09:04 | charlie | alice, bob, charlie → **3개** | 🚨 **사건 생성** |

추가 2는 "계정명" 자리에 "IP"를 넣어 똑같이 셉니다.

### 새 사건은 "조사용"입니다

추가 규칙은 공유 IP를 쓰는 사무실이나 장소를 옮겨 다니는 직원처럼 **정상적인 사용에서도** 생길 수 있습니다. 그래서 새 사건은 관제 화면에 **조사용 · 차단 불가**로 표시됩니다. 담당자는 어떤 계정명·IP가 쓰였는지와 원본 로그를 확인합니다. 차단 승인 버튼은 비활성화되고, 누가 요청을 보내더라도 서버가 한 번 더 거부합니다.

## 팀원 적용 방법

> 아래 명령은 **코드 4개 파일**의 변경만 가져옵니다. 내 브랜치의 README 같은 다른 파일은 바뀌지 않습니다.

1. 캡스톤 저장소 폴더에서 **본인 작업 브랜치**로 전환합니다. 저장하지 않은 변경이 있으면 먼저 커밋해 둡니다.
2. 아래 명령을 순서대로 실행합니다. PowerShell과 Git Bash 모두 같은 명령입니다.

```bash
git status --short --branch
git fetch origin Mg
git diff eb86a14 origin/Mg --output=mg_rules.patch -- src/soc/detector.py src/soc/incident_service.py src/soc/dashboard.py tests/test_detector.py
git apply --3way mg_rules.patch
python -B -m unittest discover -s tests -p test_detector.py -v
```

| 명령 | 하는 일 |
| --- | --- |
| `git status` | 지금 본인 브랜치인지, 저장 안 한 변경이 없는지 확인합니다. |
| `git fetch origin Mg` | Mg 브랜치의 최신 내용을 내려받기만 합니다. 이 단계에서는 내 파일이 바뀌지 않습니다. |
| `git diff ... --output=mg_rules.patch` | 원래 `main`(`eb86a14`)과 Mg 브랜치의 코드 4개 파일의 차이를 패치 파일로 저장합니다. |
| `git apply --3way` | 그 차이를 내 브랜치에 적용합니다. 내가 같은 파일을 고쳤다면 Git이 합쳐 보고, 겹치는 부분만 충돌로 표시합니다. |
| `python ... test_detector.py` | 탐지 테스트 7개를 실행합니다. Windows에서 `python`이 안 되면 `py`로 바꿉니다. |

3. 테스트가 모두 통과하면 커밋하고, 임시 패치 파일을 지웁니다.

```bash
git add src/soc/detector.py src/soc/incident_service.py src/soc/dashboard.py tests/test_detector.py
git commit -m "Apply Mg ERP login detection rules"
rm mg_rules.patch
```

충돌이 나면 [안내서의 충돌 해결 방법](Mg_LOGIN_DETECTION_GUIDE_codex.md#충돌이-났을-때)을 따라 하세요.

## 적용 후 확인할 결과

- 기존 규칙: 실패 **4번까지는 경보 없음**, **5번째에 경보**가 납니다.
- 추가 규칙: 서로 다른 계정명(또는 IP)이 **3개가 되는 순간** 사건이 생깁니다. 같은 로그를 다시 읽어도 사건이 중복으로 생기지 않습니다.
- 새 사건에서는 차단 버튼이 비활성화되고, 방화벽 차단 요청이 **0건**이어야 합니다.

**Mg 로컬 검증** — 전체 테스트 **32개 중 31개 통과**, 1개는 PostgreSQL 접속 설정이 없어 건너뛰었습니다. 팀 Docker·PostgreSQL 환경에서는 [안내서의 검증 체크리스트](Mg_LOGIN_DETECTION_GUIDE_codex.md#6-적용-후-검증-체크리스트)로 확인하면 됩니다.
