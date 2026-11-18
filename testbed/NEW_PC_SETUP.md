# 새 PC에서 처음부터 실행하기 (A 시험망 + B 관제)

다른 PC(예: B PC)에서 A PC와 같은 구성을 코드로 새로 만든다. 컨테이너·볼륨·.env를 복사하지 않는다.
비밀번호·토큰·Caddy 인증서는 그 PC에서 새로 생성되며 로그·사건은 빈 상태로 시작한다.

## 준비물
- Windows + Docker Desktop(WSL2, Linux 컨테이너) 실행 중. Docker 자원 CPU 2개·메모리 3GiB 이상 권장
- Git Bash, Python 3.10+, Node.js 20+(ERP 브라우저 입구용, 없으면 그 기능만 불가)
- 처음 한 번 인터넷(이미지·패키지 다운로드). 시험망 자체는 외부와 막힌 internal 망이다.
- Windows 방화벽·라우팅·프록시·인증서 설정은 바꾸지 않는다.

## 순서 (Git Bash, 저장소 루트)
```bash
git checkout <본인 브랜치> && git pull          # 최신 main 반영
bash testbed/scripts/setup_all.sh --check        # 1) 점검만(아무것도 만들지 않음)
bash testbed/scripts/setup_all.sh                # 2) 설치·실행·망 검증·대시보드 확인
```
3) ERP 브라우저 입구: 새 PowerShell 창에서 `.\testbed\browser\start.ps1` (창을 닫으면 종료)
4) 브라우저: ERP http://localhost:18888 , 대시보드 http://localhost:8050 (아이디 `soc-operator`,
   비밀번호는 루트 `.env`의 `SOC_OPERATOR_PASSWORD`를 직접 열어 확인)

## 동작 확인 (실제 시험)
```bash
cd testbed
bash scripts/verify_day3.sh       # HTTPS·헤더·차단·복구
bash scripts/verify_day4.sh       # ERP 로그인·탐지
bash scripts/verify_day5.sh       # 조치 API 차단·해제
bash scripts/verify_day5_e2e.sh   # ERP 실패 → 사건 → 승인 → 차단 → 복구
```
결과(시각·pass/fail·종료 코드)를 기록해 공유한다. A PC 결과를 B PC 결과로 쓰지 않는다.

## setup_all.sh가 하는 일
1. Docker·Python·Node·자원·시험망 IP 대역 충돌 점검
2. `testbed/.env`, 루트 `.env` 생성(기존 값 유지, 빠진 값만 추가). 조치 토큰을 양쪽에 같게 맞춤. Git 제외 확인
3. 시험망 빌드·실행 → 경로 설정 5개 완료 → 게이트웨이 조치 API 확인 → `verify_network_layout.py`
4. 관제 DB → Grafana 읽기 계정 비밀번호 설정 → 수집기·대시보드 → `localhost:8050`·미로그인 401 확인
실패하면 그 자리에서 멈춘다. 원인을 고친 뒤 다시 실행하면 이미 만든 것은 재사용한다.

## 자주 나는 문제
- `시험망 대역과 겹치는 Docker 망`: 172.28.10/20, 10.250.29/30 대역을 쓰는 다른 Docker 망이 있다. 그 망의 소유를 확인하고 사람이 정리한다.
- 경로 설정 실패·망 검증 실패: Docker Desktop을 재시작한 뒤 `cd testbed && docker compose up -d` 로 경로 도우미를 다시 실행하고 `python -B scripts/verify_network_layout.py`.
- Docker Desktop/PC 재시작 후: 위와 같이 경로 도우미 재실행 → 망 검증 통과 후 시험.
- 대시보드 응답 없음: CPU 상한이 낮아 첫 기동에 수십 초 걸릴 수 있다. `docker logs capstone-soc-dashboard`.
- 다른 PC/Docker 버전에서 Macvlan internal 망 동작은 아직 검증 전이다. 실패하면 로그와 함께 A에게 공유한다.

## 정리
- 정지(데이터 보존): `docker compose -f docker-compose.soc.yml --profile live stop` , `cd testbed && docker compose stop`
- `down -v`, `docker system prune`, 다른 프로젝트 컨테이너 삭제는 하지 않는다.
