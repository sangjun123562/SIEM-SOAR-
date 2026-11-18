#!/usr/bin/env bash
# testbed/.env 를 처음 한 번 만든다. 값은 모두 무작위이며 이 PC에만 있다(.env는 Git에서 제외됨).
# 이미 있으면 덮어쓰지 않는다. 다시 만들려면 사람이 직접 파일을 지운 뒤 실행한다
# (그러면 ERP DB 비밀번호가 바뀌므로 ERP DB 볼륨도 새로 만들어야 한다).
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$HERE/.env"
if [ -e "$ENV_FILE" ]; then
  echo "이미 있음: $ENV_FILE (변경하지 않음)"
  exit 0
fi
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1"; }
umask 077
{
  echo "# 자동 생성: $(date -u +%Y-%m-%dT%H:%M:%SZ). 시험망 전용 값. 저장소에 올리지 않는다."
  echo "ERP_DB_PASSWORD=$(rand 32)"
  echo "ERP_SECRET_KEY=$(rand 48)"
  echo "DEMO_PW_ALICE=$(rand 20)"
  echo "DEMO_PW_BOB=$(rand 20)"
  echo "DEMO_PW_CAROL=$(rand 20)"
} > "$ENV_FILE"
echo "만들었음: $ENV_FILE"
