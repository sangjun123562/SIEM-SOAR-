# ERP 로그인 탐지 규칙 안내서 · Mg (C 담당)

- **대상** 프로젝트 팀원
- **상태** 기존 탐지 개선은 [PR #35](https://github.com/sangjun123562/SIEM-SOAR-/pull/35)로 `main` 병합 · 새 주의 사건은 `Mg`에서 로컬 검증 완료 · 팀 Docker·PostgreSQL 통합 검증 대기
- **반영 기준** PR #34의 `fd4f5f0`에 Mg 변경을 검증한 뒤 `main` `4c1a935`로 병합
- **위치** [GitHub Mg 브랜치](https://github.com/sangjun123562/SIEM-SOAR-/tree/Mg) · [처음 기능을 추가한 커밋 `8eb9127`](https://github.com/sangjun123562/SIEM-SOAR-/commit/8eb9127dcb6dd50258f528d8d14a7b99c2be670d)

## 1. 한 줄 요약

**같은 IP에서 여러 계정명이 실패하거나, 같은 계정명이 여러 IP에서 실패하면 조사용 사건을 만듭니다.** 기존 반복 실패 규칙은 입력 오류와 중간에 성공한 별개 실패 묶음을 구분합니다. Mg 기능은 ERP가 이미 남기는 계정명·IP·시각·인증 결과를 사용합니다.

**Mg에서 추가 검토 중인 기능**은 실패 3~4회 뒤 성공을 주의 사건으로 표시합니다. 실수로 성공까지 여러 번 시도한 정상 직원도 같은 기록을 남길 수 있으므로, 계정 사용 여부나 이후 활동을 확인할 근거로 사용합니다.

## 2. 무엇이 바뀌었나요?

| 규칙 | 5분 안에 이 조건이면 사건 생성 | 담당자가 할 수 있는 일 |
| --- | --- | --- |
| 기존 · 같은 계정명 + 같은 IP | 같은 조합의 한 실패 묶음에서 인증 실패 **5번** | 근거와 이후 로그인 성공 기록을 보고, 승인 조건이 맞으면 시험 단말 차단을 승인할 수 있습니다. |
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

### 기존 반복 실패 규칙의 오탐 줄이기

인증 실패(`401`)만 집계하고, 같은 계정명·신뢰된 같은 IP·같은 수집 방식의 로그인 성공이 끼면 기준에 못 미친 앞선 실패와 뒤의 실패를 따로 셉니다. 예를 들어 `2회 실패 → 성공 → 3회 실패`로는 사건이 생기지 않습니다. 성공 전에 이미 인증 실패가 5회였다면 사건은 유지합니다. 상세 화면에서는 마지막 실패 뒤 5분 안에 같은 조건으로 성공한 기록의 시각과 원본 ID를 확인할 수 있습니다.

### 팀 피드백 반영 · 반복 실패 후 로그인 성공

신뢰된 같은 IP에서 같은 계정명으로 **5분 안에 실패 3~4회 뒤 로그인 성공**이 관측되면 관제 목록에 **주의 · 반복 실패 후 로그인 성공**이 표시됩니다. 실패와 성공은 같은 수집 방식에서 가져옵니다. 사건 상세에서 실패·성공 구분, 계정명, IP, 시각, 원본 ID를 함께 확인합니다. 기존 5회 실패 경보가 같은 묶음에서 이미 발생했다면 기존 사건을 확인합니다. 주의 사건의 차단 승인은 화면과 서버 양쪽에서 제한합니다.

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
| [`src/soc/repository.py`](src/soc/repository.py) | 기존 반복 실패 사건의 상세에서 이후 로그인 성공 기록을 찾습니다. |
| [`tests/test_detector.py`](tests/test_detector.py) | 위 동작이 맞는지 자동으로 확인하는 테스트입니다. |
| [`tests/test_day5_live_db_and_auth.py`](tests/test_day5_live_db_and_auth.py) | 성공 표시가 DB를 사용하는 화면에 나타나고, 같은 화면에서 정상적인 승인·해제 절차가 동작하는지 확인합니다. |

### 함수 지도

| 함수 | 역할 |
| --- | --- |
| [`detect_login_failures()`](src/soc/detector.py#L105) | 같은 계정명·IP의 5회 실패 경보를 찾고, 관제용 호출에서는 중간에 성공한 3~4회 실패도 확인합니다. |
| [`detect_multi_account_failures()`](src/soc/detector.py#L220) | 추가 1. 공통 함수를 "IP별로 묶고 계정명을 센다"는 설정으로 부릅니다. |
| [`detect_multi_source_failures()`](src/soc/detector.py#L229) | 추가 2. 공통 함수를 "계정명별로 묶고 IP를 센다"는 설정으로 부릅니다. |
| [`_detect_distinct_failures()`](src/soc/detector.py#L238) | **추가 두 규칙의 실제 계산.** 아래에서 단계별로 설명합니다. |
| [`_build_login_success_review()`](src/soc/detector.py#L79) | 실패 3~4건과 성공 기록을 묶어 주의 사건의 근거로 만듭니다. |
| [`build_incidents()`](src/soc/incident_service.py#L98) | 탐지를 실행하고 결과를 사건으로 묶습니다. |
| [`block_rule_eligible`](src/soc/incident_service.py#L72) | 기존 규칙에서 나온 사건만 `True`입니다. 빠른 승인 화면, 사건 미리보기·상세 버튼과 서버 검사가 모두 이 값을 봅니다. |
| [`find_followup_login_success()`](src/soc/repository.py#L167) | 사건 상세에서 보여줄 첫 로그인 성공 시각과 원본 ID를 찾습니다. |

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

`latest`에 남은 기록들을 시간순으로 정리해 경보 근거로 담습니다. 같은 로그를 다시 읽어도 같은 경보 번호가 나오도록 `hashlib`로 고정 번호를 만듭니다. 마지막으로 `latest.clear()`로 사용한 기록을 비웁니다. 다음 기록부터 다시 세므로 같은 근거를 다음 경보에 재사용하지 않습니다.

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

기존 규칙은 `security-agent-toolkit`의 [`anomaly_detection/login_detection.py`](https://github.com/eldi96/security-agent-toolkit/blob/7695f58f045e214a4540b9d6ded537e004b885fa/anomaly_detection/login_detection.py)를 참고했습니다. 원본은 `pick_login_failures()` → `count_by_ip()` → `pick_alert_ips()` 순서로 동작합니다. 캡스톤은 여기에 계정명·신뢰된 IP·5분 시간창을 더했습니다. **추가 규칙 두 개에 해당하는 코드는 Toolkit에 없어서**, 캡스톤에서 새로 만들었습니다. 향후 Mg 작업은 지정된 [Mg의 security-agent-toolkit](https://github.com/ChoiMgHub/security-agent-toolkit)과 SKT Aleph의 학습 코드·문법을 참고합니다. `if`와 `for`처럼 배운 방식을 우선 쓰고, 함수 역할과 판단 이유는 쉬운 한글 주석으로 설명합니다.

## 5. 팀원 적용 방법

### 코드만 보고 싶을 때

GitHub의 [Mg 브랜치 `src/soc/detector.py`](https://github.com/sangjun123562/SIEM-SOAR-/blob/Mg/src/soc/detector.py#L79)를 열면 한글 주석이 달린 코드를 볼 수 있습니다.

### 내 브랜치에 적용할 때

팀 `main`에 기능이 들어갔으므로, 저장소 루트에서 본인 작업 브랜치를 확인하고 최신 `main`을 병합합니다. 작업 중인 변경은 먼저 보존합니다.

```bash
git status --short --branch
git fetch origin
git merge origin/main
python -B -m unittest discover -s tests -v
```

`fetch`는 내려받고, `merge`는 현재 로컬 작업 브랜치에 반영합니다. 충돌이 나면 `git status`로 파일을 확인해 기존 작업과 팀 변경을 함께 유지하도록 정리한 뒤 테스트합니다. 이미 `main`의 `4c1a935`가 들어온 브랜치라면 기존 기능 검증부터 진행할 수 있습니다.

### 새 주의 사건을 먼저 시험할 때

최신 `main`을 반영한 본인 작업 브랜치에서 아래 명령을 실행합니다. `Mg`의 개인 README와 안내서를 제외한 새 규칙 코드·테스트 4개 파일만 대상으로 합니다. 적용 검사에 실패하면 해당 파일을 확인한 뒤 진행합니다.

```bash
git fetch origin main Mg
git diff origin/main...origin/Mg --output=mg_success_review.patch -- src/soc/detector.py src/soc/incident_service.py src/soc/dashboard.py tests/test_detector.py
git apply --3way --check mg_success_review.patch
git apply --3way mg_success_review.patch
```

## 6. 적용 후 검증 체크리스트

```bash
python -B -m unittest discover -s tests -p test_detector.py -v
python -B -m unittest discover -s tests -v
```

- [ ] **기존 탐지** — 같은 계정명·같은 IP 실패 4번까지는 경보가 없고, 5번째에 첫 경보가 납니다.
- [ ] **오탐 감소** — `인증 실패 4회 + 입력 오류 1회`와 `실패 2회 → 성공 → 실패 3회`는 사건이 생기지 않습니다. 실패 5회 뒤 성공은 사건을 유지하고 성공 시각과 원본 ID를 표시합니다.
- [ ] **추가 규칙** — 서로 다른 계정명(또는 IP)이 3개가 되면 사건이 생기고, 같은 값이 반복되면 개수가 늘지 않습니다.
- [ ] **제외 조건** — 5분이 지난 기록, 미신뢰 IP, 입력 형식 오류(400)는 추가 규칙에서 세지 않습니다.
- [ ] **중복 방지** — 같은 로그를 다시 처리해도 같은 사건이 또 생기지 않습니다.
- [ ] **주의 사건** — 실패 3~4회 뒤 성공 시 주의 사건 한 건과 실패·성공 원본이 표시됩니다. 2회 뒤 성공은 주의 사건이 없고, 5회 뒤 성공은 기존 사건으로 확인합니다.
- [ ] **근거와 승인 제한** — 새 사건에서 계정명·IP·원본 로그가 보이고, 사건 상세와 미리보기의 차단 버튼은 비활성화되고 빠른 승인 목록에 차단 실행 버튼이 나오지 않습니다. 서버도 차단 요청을 거부합니다.
- [ ] **Docker·PostgreSQL 통합** — [새 PC 설치 안내](testbed/NEW_PC_SETUP.md)대로 수집기와 관제 앱을 실행합니다. 격리 시험망의 합성 로그로 사건이 DB에 저장되고 화면에 나타나는지, 기존 승인·해제 흐름도 그대로인지 확인합니다.

## 7. 검증 기록과 남은 일

**최신 Mg 로컬 결과** — 전체 테스트 **43개 중 42개 통과, 1개 건너뜀**입니다. PostgreSQL 실연동 테스트는 테스트 DB 접속 설정이 없어 건너뛰었습니다. 주의 사건의 저장·재처리·화면·승인 제한과 기존 승인·해제 흐름을 로컬에서 확인했습니다.

**남은 일** — 팀 Docker·PostgreSQL 통합 검증과 수집기 재시작 중 기록 분류 작업이 남았습니다. 진행 상황은 [README](README.md)에서 확인할 수 있습니다.
