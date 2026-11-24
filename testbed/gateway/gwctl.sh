#!/bin/sh
# 수동 차단/해제 도구 (1일 차 수동 시험의 연장. 자동 승인 기능이 아님).
# 사용: gwctl.sh block <src_ip> <dst_ip> <rule_id> | unblock <src_ip> <dst_ip> <rule_id> | list
# 입력은 엄격히 검증하고 셸 문자열 조합을 하지 않는다. 허용 목록 밖의 대상은 거부한다.
set -eu
BLOCKABLE="${GW_BLOCKABLE:-172.28.10.11,172.28.10.12}"   # 차단 가능한 시험 단말(고정 IP)
DST_ALLOWED="${GW_DST_ALLOWED:-172.28.20.10}"   # 쉼표로 구분한 목적지 허용 목록
ip_ok() { echo "$1" | grep -Eq '^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$'; }
die() { echo "DENIED: $*" >&2; exit 2; }

cmd="${1:-}"
case "$cmd" in
  list) iptables -S GW_BLOCK; exit 0 ;;
  block|unblock) ;;
  *) die "usage: block|unblock <src_ip> <dst_ip> <rule_id> | list" ;;
esac
[ $# -eq 4 ] || die "argument count"
src="$2"; dst="$3"; id="$4"
ip_ok "$src" || die "bad src"; ip_ok "$dst" || die "bad dst"
echo "$id" | grep -Eq '^[A-Za-z0-9._-]{1,40}$' || die "bad rule_id"
case ",$BLOCKABLE," in *",$src,"*) ;; *) die "src not in blockable allowlist" ;; esac
case ",$DST_ALLOWED," in *",$dst,"*) ;; *) die "dst not allowed" ;; esac

if [ "$cmd" = block ]; then
  # 같은 요청 재시도는 규칙을 늘리지 않는다(멱등).
  if iptables -C GW_BLOCK -s "$src" -d "$dst" -j DROP 2>/dev/null; then echo "already-blocked"; exit 0; fi
  iptables -A GW_BLOCK -s "$src" -d "$dst" -j NFLOG --nflog-group 1 --nflog-prefix "fw_deny|$id"
  iptables -A GW_BLOCK -s "$src" -d "$dst" -j DROP
  echo "blocked"
else
  # 기록 규칙의 prefix는 block 때와 같은 rule_id여야 삭제된다.
  iptables -D GW_BLOCK -s "$src" -d "$dst" -j NFLOG --nflog-group 1 --nflog-prefix "fw_deny|$id" 2>/dev/null || true
  if iptables -D GW_BLOCK -s "$src" -d "$dst" -j DROP 2>/dev/null; then echo "unblocked"; else echo "not-blocked"; fi
fi
