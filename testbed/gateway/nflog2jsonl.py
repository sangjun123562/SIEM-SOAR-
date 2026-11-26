"""ulogd JSON(표준입력) -> docs/log_contract.md 형식의 gateway.jsonl.

- 한 줄에 JSON 하나, 완성된 줄만 단일 write로 기록한다(수집기가 완성 줄만 읽도록).
- 비밀값·본문은 다루지 않는다. 패킷 헤더 정보(주소·포트·프로토콜)만 사용한다.
- 10MiB에서 회전하고 이전 파일 2개만 유지한다.
- ingest_mode는 항상 live(실제 패킷에서 생성). 재생·합성 로그는 이 경로로 만들지 않는다.
"""
import datetime
import json
import os
import socket
import struct
import sys

OUT = os.environ.get("GW_LOG", "/var/log/gw/gateway.jsonl")
MAX_BYTES = 10 * 1024 * 1024
KEEP = 2
PROTO = {1: "ICMP", 6: "TCP", 17: "UDP"}


def to_ip(v):
    if isinstance(v, str):
        return v
    return socket.inet_ntoa(struct.pack("!I", int(v) & 0xFFFFFFFF))


def rotate():
    for i in range(KEEP, 0, -1):
        src = OUT if i == 1 else f"{OUT}.{i - 1}"
        if os.path.exists(src):
            os.replace(src, f"{OUT}.{i}")


def convert(rec):
    prefix = str(rec.get("oob.prefix", ""))
    kind, _, rule = prefix.partition("|")
    if kind not in ("fw_allow", "fw_deny"):
        return None
    proto = PROTO.get(int(rec.get("ip.protocol", 0)))
    if proto is None:
        return None
    if proto == "ICMP" and kind != "fw_deny":
        return None
    sec = rec.get("oob.time.sec")
    usec = rec.get("oob.time.usec", 0)
    if sec is not None:
        ts = datetime.datetime.fromtimestamp(int(sec) + int(usec) / 1e6, datetime.timezone.utc)
    else:
        ts = datetime.datetime.now(datetime.timezone.utc)
    action = "allow" if kind == "fw_allow" else "deny"
    out = {
        "timestamp_utc": ts.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "source": "gateway",
        "event_type": kind,
        "outcome": action,
        "ingest_mode": "live",
        "src_ip": to_ip(rec["src_ip"]),
        "dst_ip": to_ip(rec["dest_ip"]),
        "protocol": proto,
        "action": action,
    }
    if proto != "ICMP":
        out["src_port"] = int(rec["src_port"])
        out["dst_port"] = int(rec["dest_port"])
    if rule and rule != "-":
        out["rule_id"] = rule
    return out


_drop_count = 0


def _dropped(msg):
    # 진단용: 버려진 레코드를 처음 20건만 stderr(컨테이너 로그)에 남긴다. 패킷 헤더 정보만 포함된다.
    global _drop_count
    if _drop_count < 20:
        _drop_count += 1
        print("nflog2jsonl dropped:", msg, file=sys.stderr, flush=True)


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            ev = convert(json.loads(line))
        except (ValueError, KeyError, TypeError) as e:
            _dropped(f"error={e!r} line={line[:400]}")
            continue
        if ev is None:
            _dropped(f"skipped line={line[:400]}")
            continue
        if os.path.exists(OUT) and os.path.getsize(OUT) >= MAX_BYTES:
            rotate()
        data = (json.dumps(ev, separators=(",", ":")) + "\n").encode()
        fd = os.open(OUT, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)


if __name__ == "__main__":
    main()
