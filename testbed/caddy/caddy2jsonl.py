"""Caddy 접속 로그(JSON) -> docs/log_contract.md의 caddy.jsonl 형식.

- 화이트리스트 방식: 계약에 있는 필드만 만든다. 요청 헤더(쿠키·Authorization 포함), 쿼리 문자열, 본문은 버린다.
- 완성된 줄(개행 종료)만 처리하고, 변환·기록 후에 읽기 위치(offset)를 저장한다(최소 1회 처리; 비정상 종료 시
  마지막 배치가 중복될 수 있음).
- ingest_mode는 항상 live(실제 요청에서 생성된 로그).
"""
import datetime
import json
import ipaddress
import uuid
import os
import sys
import time
from urllib.parse import urlsplit

IN = os.environ.get("CADDY_RAW", "/in/access.json")
OUT = os.environ.get("CADDY_OUT", "/out/caddy.jsonl")
STATE = os.environ.get("CADDY_STATE", "/out/caddy.offset")
WAF_IN = os.environ.get("WAF_RAW", "/in/waf.jsonl")
WAF_STATE = os.environ.get("WAF_STATE", "/out/waf.offset")
MAX_BYTES = 10 * 1024 * 1024
KEEP = 2


def convert(rec):
    req = rec.get("request") or {}
    status = rec.get("status")
    request_id = rec.get("request_id")
    client_ip = rec.get("client_ip")
    if not (isinstance(status, int) and request_id and client_ip and rec.get("ts") is not None):
        return None
    ts = datetime.datetime.fromtimestamp(float(rec["ts"]), datetime.timezone.utc)
    return {
        "timestamp_utc": ts.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "source": "caddy",
        "event_type": "http_request",
        "outcome": "success" if status < 400 else "failure",
        "ingest_mode": "live",
        "request_id": str(request_id),
        "client_ip": str(client_ip),
        "peer_ip": str(req.get("remote_ip", "")),
        "http_method": str(req.get("method", "")),
        "http_path": urlsplit(str(req.get("uri", ""))).path,
        "status_code": status,
    }


def convert_waf(record):
    if record.get("msg") != "CRS match" or type(record.get("blocked")) is not bool:
        return None
    rules = record.get("rule_ids")
    if not isinstance(rules, list) or not rules:
        return None
    if any(type(rule) is not int or not 941000 <= rule < 943000 for rule in rules):
        return None
    blocked = record["blocked"]
    timestamp = datetime.datetime.fromtimestamp(float(record["ts"]), datetime.timezone.utc)
    event = {
        "timestamp_utc": timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "source": "caddy",
        "event_type": "waf_blocked" if blocked else "waf_detected",
        "outcome": "blocked" if blocked else "detected",
        "ingest_mode": "live",
        "request_id": str(uuid.UUID(record["request_id"])),
        "client_ip": str(ipaddress.ip_address(record["client_ip"])),
        "rule_id": ", ".join(str(rule) for rule in sorted(set(rules))),
    }
    score = record.get("score")
    if type(score) is int and score > 0:
        event["anomaly_score"] = score
    if blocked:
        event["status_code"] = 403
    return event


def rotate():
    for i in range(KEEP, 0, -1):
        src = OUT if i == 1 else f"{OUT}.{i - 1}"
        if os.path.exists(src):
            os.replace(src, f"{OUT}.{i}")


def read_state(state=STATE):
    try:
        return int(open(state).read().strip() or 0)
    except (OSError, ValueError):
        return 0


def write_state(n, state=STATE):
    tmp = state + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(n))
    os.replace(tmp, state)


def step(offset, source=IN, state=STATE, converter=convert):
    try:
        size = os.path.getsize(source)
    except OSError:
        return offset
    if size < offset:  # 회전·교체됨
        offset = 0
    if size == offset:
        return offset
    with open(source, "rb") as f:
        f.seek(offset)
        chunk = f.read()
    end = chunk.rfind(b"\n")
    if end == -1:
        return offset
    lines = chunk[: end + 1].splitlines()
    for raw in lines:
        try:
            record = json.loads(raw)
            ev = converter(record)
        except (ValueError, TypeError, AttributeError, KeyError, OverflowError):
            continue
        if ev is None:
            continue
        if os.path.exists(OUT) and os.path.getsize(OUT) >= MAX_BYTES:
            rotate()
        events = [ev]
        if converter is convert and (
            record.get("waf_rule_id") == "ERP-LOGIN-BODY-LIMIT"
            and ev["status_code"] == 413
            and ev["http_method"] == "POST"
            and ev["http_path"] == "/api/login"
        ):
            events.append(dict(ev, event_type="waf_blocked", outcome="blocked",
                               rule_id="ERP-LOGIN-BODY-LIMIT"))
        data = "".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events).encode()
        fd = os.open(OUT, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
    new = offset + end + 1
    write_state(new, state)
    return new


def main():
    offset = read_state()
    waf_offset = read_state(WAF_STATE)
    print("caddy2jsonl started offset=", offset, file=sys.stderr, flush=True)
    while True:
        offset = step(offset)
        waf_offset = step(waf_offset, WAF_IN, WAF_STATE, convert_waf)
        time.sleep(0.5)


if __name__ == "__main__":
    main()
