# 일반 브라우저 접속 도구

가상 기관 로그인 화면을 http://localhost:18888 에서 직접 조작하기 위한 캡스톤용 도구다.
Node.js 20 이상, Docker CLI 및 실행 중인 client-A/Caddy/ERP가 필요하다.

```powershell
# 저장소 루트. PC 전체 환경 설정은 바꾸지 않는다.
.\testbed\browser\start.ps1 -Background   # 권장: 창 없이 실행, 꺼지면 3초 뒤 자동 재시작
.\testbed\browser\stop.ps1                # 정지(감시 실행기·server.cjs·중계 컨테이너만)
.\testbed\browser\start.ps1               # 이 창에서 실행(창을 닫으면 종료)
```

`-Background`는 `supervise.ps1`이 server.cjs를 감시한다. ERP·게이트웨이·시험 단말이 재시작되어
연결이 끊기거나 프로세스가 종료되면 다시 실행해 중계 컨테이너와 인증값을 새로 불러온다.
한 PC에 하나만 실행된다(중복 실행 시 바로 종료). 시작/종료 코드만
`%LOCALAPPDATA%\capstone-erp-ui\supervisor.log`에 남기며 인증값·요청 내용은 기록하지 않는다.

Docker CLI가 PATH에 있으면 다른 환경에서도 아래처럼 실행할 수 있다.

```bash
node testbed/browser/server.cjs
```

계정을 선택하고 로그인한다. 보안 시연 도구에서 인증 실패를 선택하면 클릭당 실패 1건이다.
종료는 실행 터미널의 Ctrl+C. 중계 컨테이너만 내리며 ERP/DB/볼륨은 삭제하지 않는다.
보조 프로세스가 비정상 종료했다면 다음 명령으로 해당 도구만 정리할 수 있다.

```bash
docker compose -f testbed/browser/compose.json down
```

## 연결과 제한

- PC의 IPv4 loopback 18888에만 수신한다. Windows 전역 프록시·라우팅·방화벽·인증서 설정을 바꾸지 않는다.
- PC → localhost HTTP 입구 → Docker exec의 표준입출력 → 시험 단말 namespace → 게이트웨이 → Caddy HTTPS → ERP.
- 컨테이너에 Docker socket을 마운트하지 않는다. PC의 도구가 Docker CLI를 사용하므로 Docker 사용 권한이 필요하다.
- 내부 연결은 Caddy CA를 메모리에서 읽어 TLS 검증한다. OS에 CA를 설치하거나 전체 TLS 검증을 해제하지 않는다.
- Caddy는 시험 단말 IP를 보며 기존 요청 ID/출발지 검사와 게이트웨이 차단이 적용된다.
- localhost Host와 쓰기 요청 Origin을 검사한 뒤, 기존 ERP 주소에 맞춰 Host/Origin을 변환한다.
- 로그인/세션/로그아웃과 화면 경로만 전달한다. 목적지는 Caddy 172.28.20.5:8443으로 고정한다.
- 계정의 시험 인증값은 로컬 입구의 HTML에 실행 시 채워진다. 운영 서비스용 자동 로그인 기능이 아니며 외부 공개하지 않는다. 로그에는 요청 본문·쿠키·인증값을 출력하지 않는다.
- 현 Chrome의 localhost Secure 쿠키 동작을 검증했다. 다른 브라우저의 호환성은 별도 확인 대상이다.
- 단일 입구의 계정들은 모두 같은 시험 단말 IP로 취급된다. 대조 단말은 별도다.
- 중계 0.06 CPU/32MiB, cap_drop ALL/readonly/비 root/포트 비공개. A1.44 + 관제DB0.50 + 중계0.06 = Docker CPU 상한2.00. PC의 Node·브라우저 자원은 별도로 사용한다.
- 대시보드의 차단 승인 API는 이 도구에 포함되지 않는다.

## 관제 기록 초기화 (로컬 선택 기능)

대시보드 왼쪽 하단 **관제 기록 초기화**는 `SOC_ENABLE_PRACTICE_RESET=1`인 로컬 연습 환경에서만 표시된다(기본 0). 담당자 로그인 후 확인하면 관제 DB의 원본/이벤트/경보/사건/비활성 승인 이력을 백업 없이 지운다. 공식 시험 근거가 실행 DB에 섞여 있으면 켜지 않는다.


연습 전용 환경에서 활성화하고 최신 수집기/화면 코드를 함께 반영한다. 다음 환경 변수는 현재 PowerShell 프로세스에만 적용된다.

```powershell
$env:SOC_ENABLE_PRACTICE_RESET = '1'
docker compose -f docker-compose.soc.yml --profile live up -d --build soc-collector soc-dashboard
# 별도 창에서 기존 브라우저 입구 실행 (start.ps1 또는 아래 명령)
node testbed/browser/server.cjs
```

실행한 뒤 `http://127.0.0.1:8050`에서 담당자로 로그인한다. ERP 입구는 동일 호스트의 `http://127.0.0.1:18888`을 사용한다. 초기화를 쓰지 않는 환경은 기본값 0을 유지한다.

- 원본 로그 파일 5종·ERP DB/계정·코드·인증서·기존 백업·공식 문서·로컬 증거 파일·게이트웨이 조치 감사/승인 상태는 유지한다. 원본 파일 정리는 별도 작업이다.
- ERP/Caddy/대시보드/수집기 컨테이너를 끄거나 재시작하지 않는다. 수집기가 현재 배치를 끝낸 뒤 maintenance 표식에 대기를 응답한다. 응답이 없으면 초기화하지 않는다. Caddy 변환 대기분을 확인한 뒤 파일별 inode·EOF와 DB 삭제를 함께 기록한다.
- 초기화 이전 파일 내용은 다시 수집하지 않고, 기준점 이후 새 줄부터 수집한다. 기준점에 걸친 미완성 줄은 완성돼도 건너뛴다. 새 live 로그를 replay로 잘못 바꾸지 않는다.
- 활성/대기/불확실 승인 또는 실제 차단 규칙이 있으면 거부한다. 먼저 해제·상태 확인한다. 초기화 중 새 승인 요청은 거부하고 완료/실패 시 수집 대기를 해제한다(대기 표식은 만료 제한도 있음).
- 로컬 ERP 입구(`start.ps1 -Background`, loopback 18888)가 실행 중이어야 한다. 동일 호스트 담당자 세션 HMAC/만료·CSRF·Origin/Host·확인값을 검증한다. ERP 계정으로는 실행할 수 없다.
- 기존 호스트 도구가 캡스톤 자원만 관리한다. Docker socket 마운트·권한 추가·호스트 보안 설정 변경·Docker 전체 정리는 없다.
- 버튼에 진행·오류를 표시하고 성공하면 메인을 갱신한다. 새 통신이 발생하면 초기화 직후에도 새 로그가 보일 수 있다. 서비스 재시작 없는 방식의 실제 소요 시간은 실행 후 확인한다.
- 검증: `node --test testbed/browser/practice-reset.test.cjs`, `PYTHONPATH=src python -m unittest discover -s tests`. SQLite/가짜 Docker 검증과 실제 PostgreSQL 초기화 성공은 구분한다.

### 초기화 속도 확인 (2026-11-20)

클릭마다 시작하던 새 Python 프로세스를 제거했다. 인증 설정은 Docker metadata에서 읽고, Caddy 변환 대기는 가벼운 파일 크기 비교로 확인한다. 초기화는 이미 실행 중인 수집기에 요청/완료 표식을 전달해 같은 Python과 DB 연결에서 처리한다.

읽기 전용 단계 측정: 기존 대시보드 Python 시작 1.945초, Caddy Python 시작 3.813초, 수집기 모듈 시작 12.109초였다. 이 세 단계의 새 Python 실행은 초기화 경로에서 제거했다.

분리 시험 DB에서 실제 PostgreSQL 삭제·EOF checkpoint·완료 응답까지 3.534초/HTTP200 확인. 시험 행 0건, 기존 관제 DB 보존, 원본 로그 유지. 준비 시 시험 worker를 미리 띄웠으며 실제 상시 수집기도 실행 중인 상태를 재사용한다. 현재 운영 DB를 자동 삭제한 시험 결과와 혼동하지 않는다. UI는 인증 검증을 포함한 처리 시간을 완료 응답에 표시한다.
