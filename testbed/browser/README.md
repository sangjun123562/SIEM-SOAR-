# 일반 브라우저 접속 도구

가상 기관 로그인 화면을 http://localhost:18888 에서 직접 조작하기 위한 캡스톤용 도구다.
Node.js 20 이상, Docker CLI 및 실행 중인 capstone-a-client-test/Caddy/ERP가 필요하다.

```powershell
# 저장소 루트. PC 전체 환경 설정은 바꾸지 않는다.
.\testbed\browser\start.ps1
```

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