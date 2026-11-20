# ERP 로그인 탐지 규칙 안내서 · Mg (C 담당)

- **대상** 프로젝트 팀원
- **상태** 구현·로컬 검증 완료 · 팀 Docker·PostgreSQL 통합 검증 대기
- **위치** [GitHub Mg 브랜치](https://github.com/sangjun123562/SIEM-SOAR-/tree/Mg) · [처음 기능을 추가한 커밋 `8eb9127`](https://github.com/sangjun123562/SIEM-SOAR-/commit/8eb9127dcb6dd50258f528d8d14a7b99c2be670d)

## 1. 한 줄 요약

**같은 IP에서 여러 계정명이 실패하거나, 같은 계정명이 여러 IP에서 실패하면 조사용 사건을 만듭니다.** DB 구조와 설정은 바꾸지 않았고, ERP가 이미 남기는 계정명·IP·시각·인증 결과만 사용합니다.

## 2. 무엇이 바뀌었나요?

| 규칙 | 5분 안에 이 조건이면 사건 생성 | 담당자가 할 수 있는 일 |
| --- | --- | --- |
| 기존 · 같은 계정명 + 같은 IP | 같은 조합에서 로그인 실패 **5번** | 근거를 확인하고, 조건이 맞으면 시험 단말 차단을 승인할 수 있습니다. |
| 🆕 추가 1 · 같은 IP + 여러 계정명 | 신뢰된 IP 하나에서 **서로 다른 계정명 3개**가 인증 실패 | 어떤 계정명이 쓰였는지와 원본 로그를 확인합니다. **조사용**입니다. |
| 🆕 추가 2 · 같은 계정명 + 여러 IP | 계정명 하나가 **서로 다른 신뢰된 IP 3곳**에서 인증 실패 | 어느 IP에서 실패했는지와 원본 로그를 확인합니다. **조사용**입니다. |

**추가 규칙이 세는 기록과 세지 않는 기록**

| 셉니다 ✅ | 세지 않습니다 ❌ |
| --- | --- |
| ERP가 인증을 거부한 기록(`401`) | 입력 형식 오류(`400`), Caddy 같은 다른 장비의 기록 |
| 출발지 IP를 믿을 수 있는 기록 | 미신뢰 IP(`client_ip_trusted=false`)의 기록 |
| 최근 5분 안의 기록 | 5분보다 오래된 기록 |

**왜 "조사용"인가요?** 여러 직원이 IP 하나를 함께 쓰는 사무실이나 장소를 옮기며 접속하는 직원처럼, 정상적인 사용에서도 같은 패턴이 생길 수 있습니다. 그래서 추가 규칙의 사건은 **차단 승인을 막아 두고**, 담당자가 근거를 보고 판단하게 했습니다. 화면의 버튼만 막은 것이 아니라 서버도 요청을 거부합니다. 참고로 "계정명"은 로그인 창에 입력된 값이라, 실제로 등록된 계정인지와는 상관없습니다.

**화면에서는** 사건 목록에 **조사용 · 차단 불가**로 표시됩니다. 값이 여러 개인 칸은 **여러 계정** 또는 **여러 출발지**로 나옵니다. 상세 화면에서는 몇 개의 계정명(또는 IP)이 실패했는지, 관측 시간대, 근거 원본 로그를 확인할 수 있습니다. 관제 앱 주소는 `http://localhost:8050`입니다.

## 3. 예시로 이해하기

### 사건이 생기는 경우

같은 IP에서 아래 순서로 실패가 들어왔습니다. 추가 1 규칙의 판단 과정입니다.

| 시각 | 실패한 계정명 | 최근 5분 안의 서로 다른 계정명 | 결과 |
| --- | --- | --- | --- |
| 09:00 | alice | alice → **1개** | 대기 |
| 09:01 | alice | alice → **1개** (같은 이름은 다시 세지 않고 시각만 09:01로 바뀜) | 대기 |
| 09:02 | bob | alice, bob → **2개** | 대기 |
| 09:04 | charlie | alice, bob, charlie → **3개** | 🚨 **사건 생성** |
| 09:05 | dave | dave → **1개** (경보에 쓴 값은 비우고 다시 셈) | 대기 |

09:04 사건의 근거는 alice(09:01), bob(09:02), charlie(09:04)이고, 관측 시간대는 **09:01 ~ 09:04**입니다.

### 5분이 지나서 사건이 생기지 않는 경우

| 시각 | 실패한 계정명 | 최근 5분 안의 서로 다른 계정명 | 결과 |
| --- | --- | --- | --- |
| 09:00 | alice | alice → **1개** | 대기 |
| 09:01 | bob | alice, bob → **2개** | 대기 |
| 09:06 | charlie | alice는 6분 전이라 빠짐 → bob, charlie → **2개** | 사건 없음 |

추가 2 규칙은 표의 "계정명"을 "IP"로 바꾸면 완전히 같은 방식으로 동작합니다.

## 4. 코드 쉽게 읽기

### 어느 파일을 보면 되나요?

| 파일 | 이 기능에서 하는 일 |
| --- | --- |
| [`src/soc/detector.py`](src/soc/detector.py) | **탐지의 핵심.** 로그를 보고 경보를 만듭니다. 처음이라면 이 파일만 읽어도 됩니다. |
| [`src/soc/incident_service.py`](src/soc/incident_service.py) | 경보를 관제 사건으로 만들고, 조사용 사건의 차단 승인을 거부합니다. |
| [`src/soc/dashboard.py`](src/soc/dashboard.py) | 관제 화면에 "조사용 · 차단 불가", "3개 계정명 실패" 같은 문구를 보여줍니다. |
| [`tests/test_detector.py`](tests/test_detector.py) | 위 동작이 맞는지 자동으로 확인하는 테스트입니다. |

### 함수 지도

| 함수 | 역할 |
| --- | --- |
| [`detect_login_failures()`](src/soc/detector.py#L65) | 기존 규칙. 같은 계정명 + 같은 IP의 5번 실패를 찾습니다. |
| [`detect_multi_account_failures()`](src/soc/detector.py#L156) | 추가 1. 공통 함수를 "IP별로 묶고 계정명을 센다"는 설정으로 부릅니다. |
| [`detect_multi_source_failures()`](src/soc/detector.py#L165) | 추가 2. 공통 함수를 "계정명별로 묶고 IP를 센다"는 설정으로 부릅니다. |
| [`_detect_distinct_failures()`](src/soc/detector.py#L174) | **추가 규칙의 실제 계산.** 아래에서 단계별로 설명합니다. |
| [`build_incidents()`](src/soc/incident_service.py#L97) | 세 규칙을 모두 실행하고 결과를 사건으로 묶습니다. |
| [`block_rule_eligible`](src/soc/incident_service.py#L71) | 기존 규칙에서 나온 사건만 `True`입니다. 화면 버튼과 서버 검사가 모두 이 값을 봅니다. |

추가 함수 두 개는 사실상 같은 계산이고 **"무엇으로 묶고 무엇을 세는지"만 반대**입니다. 그래서 계산은 `_detect_distinct_failures()` 한 곳에 두고, `group_by_ip=True/False` 값 하나로 두 규칙을 구분합니다.

### `_detect_distinct_failures()`를 3단계로 읽기

코드에도 `[1단계]`, `[2단계]`, `[3단계]` 주석이 달려 있습니다.

**[1단계] 셀 기록만 골라 묶음별로 모은다**

```python
if group_by_ip:
    group = event.client_ip          # 묶는 기준: IP
    distinct_value = event.username  # 셀 값: 계정명
else:
    group = event.username           # 묶는 기준: 계정명
    distinct_value = event.client_ip # 셀 값: IP
```

`for`로 로그를 하나씩 보면서 `if`로 401 인증 실패, 신뢰된 IP 조건을 확인합니다. 통과한 기록만 `grouped`라는 딕셔너리에 묶음별로 넣습니다. 이때 기록 번호를 키로 쓰기 때문에, 같은 기록이 두 번 들어와도 한 번만 남습니다.

**[2단계] 시간순으로 보면서 최근 5분 안의 서로 다른 값을 센다**

```python
latest[distinct_value] = (event_time, event)
if len(latest) < DISTINCT_FAILURE_THRESHOLD:   # 3개 미만이면 계속
    continue
```

핵심은 `latest` 딕셔너리입니다. **키가 계정명(또는 IP)** 이라서, 같은 이름이 다시 나오면 새 칸이 생기지 않고 기존 칸의 시각만 바뀝니다. 그래서 `len(latest)`가 곧 **서로 다른 값의 개수**입니다. 새 기록을 넣기 전에는 `for`와 `if`로 5분이 지난 값을 빼서 최근 5분 안의 값만 남깁니다.

**[3단계] 3개가 되면 경보를 만들고, 다시 처음부터 센다**

`latest`에 남은 기록들을 시간순으로 정리해 경보 근거로 담습니다. 같은 로그를 다시 읽어도 같은 경보 번호가 나오도록 `hashlib`로 고정 번호를 만듭니다. 마지막으로 `latest.clear()`로 값을 비워서, 한 번의 공격 흐름이 경보 하나로 묶이게 합니다.

### 코드에 나오는 Python 문법

새로 설치한 라이브러리는 없습니다. 모두 Python에 기본으로 들어 있는 기능입니다.

| 문법 | 뜻 |
| --- | --- |
| `defaultdict(dict)` | 처음 보는 키를 쓰면 빈 딕셔너리를 자동으로 만들어 주는 딕셔너리입니다. "없으면 만들기"를 매번 쓰지 않아도 됩니다. |
| `sorted(..., key=lambda item: (item[0], ...))` | `key`에 적은 값 순서로 정렬합니다. 여기서는 "시각 → 기록 번호" 순서입니다. |
| `timedelta(seconds=300)` | 5분이라는 시간 길이입니다. 두 시각을 빼서 이 값과 비교합니다. |
| `hashlib.sha256(...)` | 같은 글자를 넣으면 항상 같은 긴 번호가 나옵니다. 중복 경보를 막는 데 씁니다. |
| `assert 조건` | "여기서는 이 조건이 반드시 참이다"라고 적어 두는 문장입니다. 거짓이면 프로그램이 멈춥니다. |

### Toolkit 원본과의 관계

기존 규칙은 `security-agent-toolkit`의 [`anomaly_detection/login_detection.py`](https://github.com/eldi96/security-agent-toolkit/blob/7695f58f045e214a4540b9d6ded537e004b885fa/anomaly_detection/login_detection.py)를 참고했습니다. 원본은 `pick_login_failures()` → `count_by_ip()` → `pick_alert_ips()` 순서로 동작합니다. 캡스톤은 여기에 계정명·신뢰된 IP·5분 시간창을 더했습니다. **추가 규칙 두 개에 해당하는 코드는 Toolkit에 없어서**, 캡스톤에서 새로 만들었습니다. Toolkit 원본 저장소는 수정하지 않았습니다.

## 5. 팀원 적용 방법

### 코드만 보고 싶을 때

GitHub의 [Mg 브랜치 `src/soc/detector.py`](https://github.com/sangjun123562/SIEM-SOAR-/blob/Mg/src/soc/detector.py#L156)를 열면 한글 주석이 달린 코드를 볼 수 있습니다.

### 내 브랜치에 적용할 때

캡스톤 저장소 폴더에서 **본인 작업 브랜치**로 전환하고, 저장하지 않은 변경은 먼저 커밋합니다. 아래 명령은 원래 `main`(`eb86a14`)과 Mg 브랜치를 비교해 **코드 4개 파일의 변경만** 가져옵니다. 기능, 한글 주석, 테스트가 한 번에 들어옵니다.

```bash
git status --short --branch
git fetch origin Mg
git diff eb86a14 origin/Mg --output=mg_rules.patch -- src/soc/detector.py src/soc/incident_service.py src/soc/dashboard.py tests/test_detector.py
git apply --3way mg_rules.patch
python -B -m unittest discover -s tests -p test_detector.py -v
git add src/soc/detector.py src/soc/incident_service.py src/soc/dashboard.py tests/test_detector.py
git commit -m "Apply Mg ERP login detection rules"
rm mg_rules.patch
```

- PowerShell과 Git Bash 모두 같은 명령입니다. 패치 파일은 반드시 `--output`으로 만드세요. PowerShell 5.1에서 `>`로 저장하면 파일 인코딩이 바뀌어 `git apply`가 읽지 못합니다.
- Windows에서 `python`이 안 되면 `py`로 바꿉니다.
- 이미 적용한 브랜치라면 `git apply`를 다시 하지 말고 테스트만 실행합니다. 다시 적용해도 오류가 나지 않아 적용 여부를 알아채기 어렵습니다. 먼저 `git log --oneline -5`로 적용 커밋이 있는지 확인하세요.

### 충돌이 났을 때

내가 같은 파일의 같은 부분을 고쳤다면 `git apply --3way`가 충돌을 표시합니다.

1. `git status`로 충돌난 파일을 확인합니다.
2. 파일에서 `<<<<<<<`, `=======`, `>>>>>>>` 표시 사이를 보고, 남길 내용을 고른 뒤 표시를 지웁니다.
3. 테스트를 실행해 통과하면 `git add`와 `git commit`을 진행합니다.

혼자 정리하기 어려우면 `git checkout -- src/soc/detector.py src/soc/incident_service.py src/soc/dashboard.py tests/test_detector.py`로 이 네 파일을 마지막 커밋 상태로 되돌린 뒤 Mg에게 물어보세요. 단, 이 네 파일에서 커밋하지 않은 내 수정도 함께 사라지니 먼저 확인하세요.

## 6. 적용 후 검증 체크리스트

```bash
python -B -m unittest discover -s tests -p test_detector.py -v
python -B -m unittest discover -s tests -v
```

- [ ] **기존 탐지** — 같은 계정명·같은 IP 실패 4번까지는 경보가 없고, 5번째에 첫 경보가 납니다.
- [ ] **추가 규칙** — 서로 다른 계정명(또는 IP)이 3개가 되면 사건이 생기고, 같은 값이 반복되면 개수가 늘지 않습니다.
- [ ] **제외 조건** — 5분이 지난 기록, 미신뢰 IP, 입력 형식 오류(400)는 추가 규칙에서 세지 않습니다.
- [ ] **중복 방지** — 같은 로그를 다시 처리해도 같은 사건이 또 생기지 않습니다.
- [ ] **근거와 승인 제한** — 새 사건에서 계정명·IP·원본 로그가 보이고, 차단 버튼은 비활성화되며, 서버도 차단 요청을 거부합니다.
- [ ] **Docker·PostgreSQL 통합** — [새 PC 설치 안내](testbed/NEW_PC_SETUP.md)대로 수집기와 관제 앱을 실행합니다. 격리 시험망의 합성 로그로 사건이 DB에 저장되고 화면에 나타나는지, 기존 승인·해제 흐름도 그대로인지 확인합니다.

## 7. 검증 기록과 남은 일

**Mg 로컬 결과** — 전체 테스트 **32개 중 31개 통과, 1개 건너뜀**입니다. 건너뛴 1개는 PostgreSQL 실연동 테스트로, 테스트 DB 접속 설정이 없어 실행되지 않았습니다. 코드를 읽기 쉽게 고친 뒤에는 고치기 전 코드와 무작위 로그 2,000세트의 결과를 비교해 **경보 541건이 모두 같음**을 확인했습니다.

**남은 일** — 팀 Docker·PostgreSQL 통합 검증이 남아 있습니다. "실패 뒤 로그인 성공 표시"와 "수집기 재시작 중 기록 분류"는 별도 작업으로 진행합니다. 진행 상황은 [README](README.md)에서 확인할 수 있습니다.
