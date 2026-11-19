#!/usr/bin/env bash
# ERP 초기화: ERP 전용 DB(capstone-a-erp-db / erp_db)의 데이터만 비운다.
#   bash testbed/scripts/erp_reset.sh --yes [백업폴더]
# - 반드시 --yes 가 있어야 실행한다. 실행 전에 pg_dump 백업을 만든다(백업 실패 시 중단).
# - ERP 로그 볼륨(erp_logs), 관제 DB, 게이트웨이·Caddy 로그는 건드리지 않는다(관제 증거 보존).
# - 볼륨 삭제(down -v)를 하지 않는다. 테이블 내용만 비운 뒤 ERP를 재시작해 시험 계정을 다시 만든다.
set -u
export MSYS_NO_PATHCONV=1
HERE="$(cd "$(dirname "$0")" && pwd)"; TB="$(cd "$HERE/.." && pwd)"
DB=capstone-a-erp-db; ERP=capstone-a-erp
[ "${1:-}" = "--yes" ] || { echo "사용: $0 --yes [백업폴더]  (ERP DB 데이터만 비움, 실행 전 백업)"; exit 2; }
BK="${2:-${ERP_BACKUP_DIR:-$HOME/capstone-erp-backups}}"
die() { echo "FAIL: $*" >&2; exit 1; }

# 대상 확인: 프로젝트 라벨·서비스·DB 이름·볼륨
[ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}/{{index .Config.Labels "com.docker.compose.service"}}' $DB 2>/dev/null)" = "capstone-a/erp-db" ] || die "$DB 가 capstone-a/erp-db 가 아님"
docker inspect -f '{{range .Mounts}}{{.Name}} {{end}}' $DB | grep -qw capstone-a_erp_db_data || die "ERP DB 볼륨 확인 실패"
docker exec $DB psql -U erp_app -d erp_db -Atc "select current_database()" | grep -qx erp_db || die "erp_db 접속 실패"

echo "== 초기화 전"
docker exec $DB psql -U erp_app -d erp_db -Atc "select 'users='||(select count(*) from users)||' purchase_requests='||(select count(*) from purchase_requests)"

echo "== 백업"
mkdir -p "$BK" || die "백업 폴더 생성 실패: $BK"
F="$BK/erp_db_$(date -u +%Y%m%dT%H%M%SZ).sql"
docker exec $DB pg_dump -U erp_app -d erp_db --no-owner > "$F" || die "pg_dump 실패"
[ -s "$F" ] || die "백업 파일이 비어 있음"
echo "  백업: $F ($(wc -c < "$F") bytes)  ※ 계정 해시 포함, 저장소에 올리지 않음"

echo "== ERP DB 데이터 비우기 (users, purchase_requests)"
docker exec $DB psql -v ON_ERROR_STOP=1 -U erp_app -d erp_db -qc "TRUNCATE purchase_requests, users RESTART IDENTITY CASCADE;" || die "TRUNCATE 실패"

echo "== ERP 재시작 → 시험 계정 재생성, 경로 도우미 재실행"
docker restart -t 5 $ERP >/dev/null || die "ERP 재시작 실패"
(cd "$TB" && docker compose up -d --no-deps --force-recreate --pull never route-erp >/dev/null 2>&1) || die "route-erp 실행 실패"
for i in $(seq 1 20); do s=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' capstone-a-route-erp); [ "$s" = "exited 0" ] && break; sleep 1; done
[ "$s" = "exited 0" ] || die "route-erp 실패 ($s)"
for i in $(seq 1 20); do n=$(docker exec $DB psql -U erp_app -d erp_db -Atc "select count(*) from users" 2>/dev/null); [ "$n" = 3 ] && break; sleep 1; done

echo "== 초기화 후"
docker exec $DB psql -U erp_app -d erp_db -Atc "select 'users='||(select count(*) from users)||' purchase_requests='||(select count(*) from purchase_requests)"
[ "$n" = 3 ] || die "시험 계정 재생성 확인 실패(users=$n)"
echo "완료: ERP DB만 초기화. 관제 증거(로그 볼륨·관제 DB)는 변경하지 않음."
