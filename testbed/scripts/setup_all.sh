#!/usr/bin/env bash
# 새 PC에서 A 시험망 + B 관제(수집기·관제 DB·대시보드)를 처음부터 띄운다.
#   bash testbed/scripts/setup_all.sh          # 설치·실행·검증
#   bash testbed/scripts/setup_all.sh --check  # 아무것도 만들거나 띄우지 않고 사전 점검만
# 원칙: 호스트 방화벽·라우팅·DNS·프록시를 바꾸지 않는다. 기존 .env는 덮어쓰지 않고 빠진 값만 추가한다.
#       비밀값은 출력하지 않는다. 볼륨 삭제(down -v)·전역 prune을 하지 않는다.
# 처음 한 번 이미지·패키지 다운로드에 인터넷이 필요하다(준비 단계). 시험망 자체는 internal 망이다.
set -u
export MSYS_NO_PATHCONV=1
HERE="$(cd "$(dirname "$0")" && pwd)"; TB="$(cd "$HERE/.." && pwd)"; ROOT="$(cd "$TB/.." && pwd)"
CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1
step() { echo; echo "== $(date -u +%H:%M:%SZ) $*"; }
die()  { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  OK  $*"; }
warn() { echo "  WARN $*"; }
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1"; }
envget() { [ -f "$1" ] && awk -F= -v k="$2" '$1==k{sub(/^[^=]*=/,""); print; exit}' "$1"; }
envadd() { # 파일 키 값 : 키가 없거나 비어 있을 때만 추가(값 출력 없음)
  local cur; cur=$(envget "$1" "$2")
  if [ -z "$cur" ]; then grep -v "^$2=" "$1" > "$1.tmp" 2>/dev/null; echo "$2=$3" >> "$1.tmp"; mv "$1.tmp" "$1"; echo "  set $2"; fi
}

step "1. 사전 점검"
command -v docker >/dev/null || die "docker CLI가 PATH에 없음(Docker Desktop 설치·실행 필요)"
docker info >/dev/null 2>&1 || die "Docker 엔진에 연결 불가(Docker Desktop 실행 확인)"
[ "$(docker info --format '{{.OSType}}')" = linux ] || die "Linux 컨테이너 모드가 아님"
docker compose version >/dev/null 2>&1 || die "docker compose 없음"
ok "Docker $(docker version --format '{{.Server.Version}}'), $(docker compose version --short)"
PY=""; for p in python3 python; do $p -c 'import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)' >/dev/null 2>&1 && { PY=$p; break; }; done
[ -n "$PY" ] || die "Python 3.10 이상 필요"; ok "Python $($PY -V 2>&1)"
command -v node >/dev/null && ok "Node $(node -v) (브라우저 입구용)" || warn "Node.js 없음: localhost:18888 브라우저 입구만 사용 불가"
ncpu=$(docker info --format '{{.NCPU}}'); mem=$(( $(docker info --format '{{.MemTotal}}') / 1048576 ))
[ "$ncpu" -ge 2 ] && [ "$mem" -ge 3000 ] && ok "Docker 자원 CPU $ncpu / 메모리 ${mem}MiB" || warn "Docker 자원 부족 가능(CPU $ncpu / ${mem}MiB, 권장 CPU 2+ / 3GiB+)"
for n in capstone-a_client_net capstone-a_server_net capstone-a_action_net capstone-a_erp_db_net; do
  docker network inspect "$n" >/dev/null 2>&1 && warn "이미 있음: $n (기존 환경 재사용)"
done
# 같은 대역을 쓰는 다른 Docker 망이 있으면 생성이 실패한다(호스트 설정은 바꾸지 않는다).
clash=$(docker network ls -q | xargs -r docker network inspect --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null \
  | grep -E '172\.28\.(10|20)\.|10\.250\.(29|30)\.' | grep -v '^capstone-a_' || true)
[ -z "$clash" ] || die "시험망 대역과 겹치는 Docker 망이 있음: $clash"
ok "시험망 대역 충돌 없음"
for p in 8050 18888; do
  if (netstat -an 2>/dev/null || ss -ltn 2>/dev/null) | grep -E "127\.0\.0\.1[:.]$p .*LISTEN" >/dev/null; then warn "127.0.0.1:$p 이미 사용 중(기존 실행 확인)"; fi
done
if [ $CHECK = 1 ]; then
  [ -f "$TB/.env" ] && (cd "$TB" && docker compose config --quiet) && ok "testbed compose 설정 유효" || warn "testbed/.env 없음 또는 설정 오류(설치 시 생성)"
  [ -f "$ROOT/.env" ] && (cd "$ROOT" && docker compose -f docker-compose.soc.yml --profile live config --quiet) && ok "관제 compose 설정 유효" || warn "루트 .env 없음 또는 설정 오류(설치 시 생성)"
  echo; echo "점검만 완료(--check). 아무것도 만들거나 실행하지 않았다."; exit 0
fi

step "2. 비밀값 파일(.env) 준비 — 값은 출력하지 않음"
umask 077
bash "$HERE/init_env.sh" || die "testbed/.env 생성 실패"
TOK=$(envget "$TB/.env" GW_ACTION_TOKEN); [ ${#TOK} -ge 32 ] || die "조치 토큰 없음"
[ -f "$ROOT/.env" ] || { echo "# 로컬 전용(Git 제외). setup_all.sh가 생성." > "$ROOT/.env"; }
envadd "$ROOT/.env" SOC_ACTION_API_URL "http://10.250.30.2:8081"
envadd "$ROOT/.env" SOC_ACTION_API_TOKEN "$TOK"
[ "$(envget "$ROOT/.env" SOC_ACTION_API_TOKEN)" = "$TOK" ] || die "루트 .env의 SOC_ACTION_API_TOKEN이 testbed 조치 토큰과 다름(직접 확인 필요)"
envadd "$ROOT/.env" SOC_OPERATOR_USER "soc-operator"
envadd "$ROOT/.env" SOC_OPERATOR_PASSWORD "$(rand 16)"
envadd "$ROOT/.env" SOC_SESSION_SECRET "$(rand 48)"
if [ -z "$(envget "$ROOT/.env" POSTGRES_PASSWORD)" ]; then
  PGPW=$(rand 32); envadd "$ROOT/.env" POSTGRES_PASSWORD "$PGPW"
  envadd "$ROOT/.env" SOC_DB_DSN "postgresql://soc_admin:$PGPW@soc-postgres:5432/soc_db"; unset PGPW
fi
envadd "$ROOT/.env" GF_SECURITY_ADMIN_PASSWORD "$(rand 24)"
envadd "$ROOT/.env" SOC_GRAFANA_DB_PASSWORD "$(rand 24)"
unset TOK
# Windows용 git/python에는 MSYS_NO_PATHCONV=1 상태의 /c/... 절대경로를 넘기지 않고 상대경로를 쓴다.
for f in testbed/.env .env; do (cd "$ROOT" && git check-ignore -q "$f") && ok "Git 제외 확인: $f" || die "$f 가 Git 제외 대상이 아님"; done

step "3. A 시험망 빌드·실행 (capstone-a)"
cd "$TB"
docker compose config --quiet || die "testbed compose 설정 오류"
docker compose build || die "시험망 이미지 빌드 실패(인터넷·Docker 확인)"
docker compose up -d || die "시험망 실행 실패"
for i in $(seq 1 60); do
  done_n=0
  for r in route-test route-ref route-web route-caddy route-erp; do
    s=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "capstone-a-$r" 2>/dev/null)
    [ "$s" = "exited 0" ] && done_n=$((done_n+1))
    case "$s" in "exited "[1-9]*) die "경로 설정 실패: $r ($s)";; esac
  done
  [ $done_n = 5 ] && break; sleep 2
done
[ $done_n = 5 ] || die "경로 설정 도우미가 끝나지 않음"
ok "경로 설정 5개 완료"
for i in $(seq 1 30); do docker logs capstone-a-gateway 2>&1 | grep -q "action api listening" && break; sleep 2; done
docker logs capstone-a-gateway 2>&1 | grep -q "action api listening" && ok "게이트웨이 조치 API 실행" || die "게이트웨이 조치 API 미실행(docker logs capstone-a-gateway)"
(cd "$HERE" && $PY -B verify_network_layout.py) || die "망 구성 검증 실패 — 시험 요청을 보내지 말 것"

step "4. B 관제 빌드·실행 (capstone-soc, profile live)"
cd "$ROOT"
docker compose -f docker-compose.soc.yml --profile live config --quiet || die "관제 compose 설정 오류"
docker compose -f docker-compose.soc.yml --profile live build || die "관제 이미지 빌드 실패"
docker compose -f docker-compose.soc.yml --profile live up -d soc-postgres || die "관제 DB 실행 실패"
for i in $(seq 1 30); do docker exec capstone-soc-postgres pg_isready -U soc_admin -d soc_db >/dev/null 2>&1 && break; sleep 2; done
# 초기화 SQL의 Grafana 읽기 계정 고정 비밀번호를 .env 값으로 바꾼다(값 출력 없음).
GPW=$(envget "$ROOT/.env" SOC_GRAFANA_DB_PASSWORD)
printf "DO \$\$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname='grafana_reader') THEN EXECUTE format('ALTER ROLE grafana_reader PASSWORD %%L', '%s'); END IF; END \$\$;\n" "$GPW" \
  | docker exec -i capstone-soc-postgres psql -q -U soc_admin -d soc_db >/dev/null && ok "Grafana 읽기 계정 비밀번호 설정" || warn "Grafana 읽기 계정 설정 실패"
unset GPW
docker compose -f docker-compose.soc.yml --profile live up -d || die "수집기·대시보드 실행 실패"
for i in $(seq 1 40); do c=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1:8050/login 2>/dev/null); [ "$c" = 200 ] && break; sleep 3; done
[ "$c" = 200 ] && ok "대시보드 http://localhost:8050 응답" || die "대시보드 응답 없음(docker logs capstone-soc-dashboard)"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1:8050/api/incidents)" = 401 ] && ok "미로그인 API 401" || warn "미로그인 API가 401이 아님"
docker logs capstone-soc-collector 2>&1 | grep -q "mode=replay" && ok "수집기 실행(첫 수집 replay)" || warn "수집기 로그 확인 필요"

step "완료"
cat <<EOF
- 대시보드: http://localhost:8050  아이디 soc-operator
  비밀번호: 저장소 루트 .env 의 SOC_OPERATOR_PASSWORD (파일을 직접 열어 확인)
- ERP 브라우저 입구(별도 터미널, 계속 실행): PowerShell .\\testbed\\browser\\start.ps1  또는  node testbed/browser/server.cjs
  → http://localhost:18888
- 검증(순서대로, 각 시험은 요청 20건·120초 이하):
  cd testbed && bash scripts/verify_day3.sh && bash scripts/verify_day4.sh && bash scripts/verify_day5.sh && bash scripts/verify_day5_e2e.sh
- 정지(데이터 보존): docker compose -f docker-compose.soc.yml --profile live stop ; (cd testbed && docker compose stop)
  볼륨 삭제(down -v)·docker system prune 은 하지 않는다.
EOF
