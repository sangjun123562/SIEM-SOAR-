#!/usr/bin/env python3
"""게이트웨이 조치 API — DESIGN.md 3절 계약 구현 (5일 차, A).

- 조치망(action_net) 주소에만 바인딩한다. 단일 스레드 서버로 동시성 1.
- Authorization: Bearer <GW_ACTION_TOKEN>. 토큰은 환경 변수에만 있고 출력·기록하지 않는다.
- 관제 앱을 믿지 않고 approval_id 형식, 고정 허용 대상, 절대 UTC 만료(최대 30분),
  같은 승인 재시도(만료 연장 없음), 다른 내용의 재사용·종료된 승인 재차단 거부를 다시 검사한다.
- iptables는 인자 배열로만 실행한다(셸 문자열 조합 없음).
- 승인 기록은 전용 볼륨에 원자적으로 저장하고, 시작 시 기록과 실제 규칙을 대조한다.
  만료·해제된 승인의 규칙은 다시 만들지 않는다.
"""
from __future__ import annotations

import datetime as dt
import hmac
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

CHAIN = "GW_BLOCK"
MAX_BLOCK_SECONDS = 30 * 60
MAX_BODY = 4096
APPROVAL_RE = re.compile(r"^APR-[A-Za-z0-9-]{1,36}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
INCIDENT_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
APPROVER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
BLOCK_KEYS = {"approval_id", "target_ip", "expires_at_utc", "incident_id", "approved_by"}
# 허용 목록에 실수로 들어가도 거부할 주소: 게이트웨이 각 주소, 서버망·조치망·DB망 전체, 루프백.
FORBIDDEN_NETS = [ipaddress.ip_network(n) for n in (
    "172.28.10.2/32", "172.28.10.0/32", "172.28.10.255/32",
    "172.28.20.0/24", "10.250.30.0/24", "10.250.29.0/24", "127.0.0.0/8", "0.0.0.0/32")]


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def fmt(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def run_iptables(args: list[str]) -> int:
    """iptables를 인자 배열로 실행하고 종료 코드만 돌려준다."""
    return subprocess.run(["iptables", "-w", "5", *args], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=10, check=False).returncode


def list_chain() -> str:
    return subprocess.run(["iptables", "-w", "5", "-S", CHAIN], capture_output=True, text=True,
                          timeout=10, check=False).stdout


def rule_specs(approval_id: str, target_ip: str) -> list[list[str]]:
    tag = ["-m", "comment", "--comment", "apr:" + approval_id]
    return [
        ["-s", target_ip, *tag, "-j", "NFLOG", "--nflog-group", "1", "--nflog-prefix", "fw_deny|" + approval_id],
        ["-s", target_ip, *tag, "-j", "DROP"],
        ["-d", target_ip, *tag, "-j", "DROP"],
    ]


class ActionStore:
    """승인 기록과 실제 iptables 규칙을 함께 관리한다. 모든 공개 메서드는 lock 안에서 동작한다."""

    def __init__(self, state_dir: str, targets: set[str], runner=run_iptables, lister=list_chain, clock=utcnow):
        self.state_path = os.path.join(state_dir, "approvals.json")
        self.audit_path = os.path.join(state_dir, "audit.jsonl")
        self.targets = targets
        self.run, self.lister, self.clock = runner, lister, clock
        self.lock = threading.Lock()
        self.records: dict[str, dict] = {}
        for t in targets:
            ip = ipaddress.ip_address(t)
            if any(ip in n for n in FORBIDDEN_NETS) or not ip.is_private:
                raise SystemExit("forbidden address in action target allowlist: " + t)
        if os.path.exists(self.state_path):
            with open(self.state_path, encoding="utf-8") as f:
                self.records = json.load(f)

    # ---- 저장·감사 ----
    def _save(self) -> None:
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.records, f, ensure_ascii=False, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)

    def audit(self, event: str, **fields) -> None:
        line = {"timestamp_utc": fmt(self.clock()), "source": "gateway_action_api", "event": event, **fields}
        if os.path.exists(self.audit_path) and os.path.getsize(self.audit_path) >= 10 * 1024 * 1024:
            for i in (2, 1):
                src = self.audit_path if i == 1 else f"{self.audit_path}.{i - 1}"
                if os.path.exists(src):
                    os.replace(src, f"{self.audit_path}.{i}")
        data = (json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        fd = os.open(self.audit_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)

    # ---- 규칙 ----
    def _rule_present(self, rec: dict) -> bool:
        return all(self.run(["-C", CHAIN, *s]) == 0 for s in rule_specs(rec["approval_id"], rec["target_ip"]))

    def _remove_rules(self, approval_id: str, target_ip: str) -> None:
        for s in rule_specs(approval_id, target_ip):
            while self.run(["-C", CHAIN, *s]) == 0:
                if self.run(["-D", CHAIN, *s]) != 0:
                    raise ApiError(500, "apply_failed", "rule removal failed")

    def _apply_rules(self, approval_id: str, target_ip: str) -> None:
        for s in rule_specs(approval_id, target_ip):
            if self.run(["-C", CHAIN, *s]) == 0:
                continue
            if self.run(["-A", CHAIN, *s]) != 0:
                self._remove_rules(approval_id, target_ip)
                raise ApiError(500, "apply_failed", "rule apply failed")

    # ---- 만료 ----
    def _expire_due(self) -> None:
        now = self.clock()
        changed = False
        for rec in self.records.values():
            if rec["status"] == "applied" and parse_utc(rec["expires_at_utc"]) <= now:
                self._remove_rules(rec["approval_id"], rec["target_ip"])
                rec["status"] = "expired"
                rec["expired_at_utc"] = fmt(now)
                changed = True
                self.audit("expired", approval_id=rec["approval_id"], target_ip=rec["target_ip"],
                           rule_present=self._rule_present(rec))
        if changed:
            self._save()

    def expire_tick(self) -> None:
        with self.lock:
            self._expire_due()

    # ---- 시작 대조 ----
    def reconcile(self) -> dict:
        """기록과 실제 규칙을 대조한다. 유효한 차단만 복원하고 만료·해제·미기록 규칙은 제거한다."""
        with self.lock:
            self._expire_due()
            summary = {"restored": [], "kept": [], "removed_orphans": []}
            for rec in self.records.values():
                if rec["status"] == "applied":
                    if self._rule_present(rec):
                        summary["kept"].append(rec["approval_id"])
                    else:
                        self._apply_rules(rec["approval_id"], rec["target_ip"])
                        summary["restored"].append(rec["approval_id"])
                else:
                    self._remove_rules(rec["approval_id"], rec["target_ip"])
            active = {r["approval_id"] for r in self.records.values() if r["status"] == "applied"}
            for line in self.lister().splitlines():
                m = re.search(r'--comment "?apr:(APR-[A-Za-z0-9-]{1,36})"?', line)
                if m and m.group(1) not in active:
                    args = line.split()
                    if args[:2] == ["-A", CHAIN]:
                        spec = [a.strip('"') for a in args[2:]]
                        if self.run(["-D", CHAIN, *spec]) == 0:
                            summary["removed_orphans"].append(m.group(1))
            self.audit("reconcile", **summary)
            return summary

    # ---- API 동작 ----
    def _validate_block(self, body: dict) -> dict:
        if set(body) != BLOCK_KEYS or not all(isinstance(body[k], str) for k in BLOCK_KEYS):
            raise ApiError(400, "invalid_request", "fields must be exactly: " + ", ".join(sorted(BLOCK_KEYS)))
        if not APPROVAL_RE.match(body["approval_id"]):
            raise ApiError(400, "invalid_request", "approval_id format")
        if not INCIDENT_RE.match(body["incident_id"]) or not APPROVER_RE.match(body["approved_by"]):
            raise ApiError(400, "invalid_request", "incident_id or approved_by format")
        if body["target_ip"] not in self.targets:
            raise ApiError(422, "target_not_allowed", "target_ip is not an allowed test terminal")
        if not UTC_RE.match(body["expires_at_utc"]):
            raise ApiError(422, "invalid_expiry", "expires_at_utc must be YYYY-MM-DDTHH:MM:SSZ")
        try:
            exp = parse_utc(body["expires_at_utc"])
        except ValueError:
            raise ApiError(422, "invalid_expiry", "expires_at_utc is not a valid time") from None
        return {"exp": exp}

    def block(self, body: dict, peer: str) -> tuple[int, dict]:
        with self.lock:
            self._expire_due()
            v = self._validate_block(body)
            aid = body["approval_id"]
            rec = self.records.get(aid)
            if rec is not None:
                same = all(rec[k] == body[k] for k in BLOCK_KEYS)
                if not same:
                    raise ApiError(409, "approval_conflict", "approval_id reused with different content")
                if rec["status"] != "applied":
                    raise ApiError(409, "approval_closed", "approval already " + rec["status"])
                self.audit("block_retry", approval_id=aid, target_ip=rec["target_ip"], peer_ip=peer)
                return 200, self._block_view(rec)
            now = self.clock()
            remaining = (v["exp"] - now).total_seconds()
            if remaining <= 0 or remaining > MAX_BLOCK_SECONDS:
                raise ApiError(422, "invalid_expiry", "expiry must be in the future and within 30 minutes")
            self._apply_rules(aid, body["target_ip"])
            rec = {k: body[k] for k in BLOCK_KEYS}
            rec.update(status="applied", applied_at_utc=fmt(now), rule_id=f"{CHAIN}:apr:{aid}",
                       requested_from=peer)
            self.records[aid] = rec
            self._save()
            self.audit("block_applied", approval_id=aid, target_ip=rec["target_ip"], incident_id=rec["incident_id"],
                       approved_by=rec["approved_by"], expires_at_utc=rec["expires_at_utc"], peer_ip=peer,
                       rule_present=self._rule_present(rec))
            return 201, self._block_view(rec)

    @staticmethod
    def _block_view(rec: dict) -> dict:
        return {k: rec[k] for k in ("approval_id", "status", "target_ip", "expires_at_utc", "applied_at_utc", "rule_id")}

    def get(self, aid: str) -> tuple[int, dict]:
        with self.lock:
            self._expire_due()
            rec = self.records.get(aid)
            if rec is None:
                raise ApiError(404, "not_found", "unknown approval_id")
            out = {k: rec[k] for k in ("approval_id", "status", "target_ip", "expires_at_utc")}
            out["rule_present"] = self._rule_present(rec)
            for k in ("applied_at_utc", "released_at_utc", "expired_at_utc", "incident_id"):
                if k in rec:
                    out[k] = rec[k]
            return 200, out

    def release(self, aid: str, peer: str) -> tuple[int, dict]:
        with self.lock:
            self._expire_due()
            rec = self.records.get(aid)
            if rec is None:
                raise ApiError(404, "not_found", "unknown approval_id")
            if rec["status"] == "expired":
                raise ApiError(409, "approval_closed", "approval already expired")
            if rec["status"] == "applied":
                self._remove_rules(aid, rec["target_ip"])
                rec["status"] = "released"
                rec["released_at_utc"] = fmt(self.clock())
                self._save()
                self.audit("released", approval_id=aid, target_ip=rec["target_ip"], peer_ip=peer,
                           rule_present=self._rule_present(rec))
            return 200, {"approval_id": aid, "status": "released", "released_at_utc": rec["released_at_utc"]}


def make_handler(store: ActionStore, token: bytes, clients: list):
    class Handler(BaseHTTPRequestHandler):
        server_version = "gw-action-api"
        sys_version = ""
        timeout = 5

        def log_message(self, *args):  # 헤더·토큰을 남기지 않기 위해 기본 접근 로그를 끈다.
            pass

        def _send(self, status: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _auth(self) -> str:
            peer = self.client_address[0]
            if not any(ipaddress.ip_address(peer) in n for n in clients):
                raise ApiError(401, "unauthorized", "peer not on action network")
            hdr = self.headers.get("Authorization", "")
            if not hdr.startswith("Bearer ") or not hmac.compare_digest(hdr[7:].encode(), token):
                raise ApiError(401, "unauthorized", "missing or invalid bearer token")
            return peer

        def _body(self) -> dict:
            if self.headers.get("Transfer-Encoding"):
                raise ApiError(400, "invalid_request", "chunked body not accepted")
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ApiError(400, "invalid_request", "bad Content-Length") from None
            if n < 0 or n > MAX_BODY:
                raise ApiError(400, "invalid_request", "body too large")
            raw = self.rfile.read(n) if n else b""
            if not raw:
                return {}
            try:
                body = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ApiError(400, "invalid_request", "body must be JSON") from None
            if not isinstance(body, dict):
                raise ApiError(400, "invalid_request", "body must be a JSON object")
            return body

        def _dispatch(self, method: str) -> None:
            path = self.path.split("?", 1)[0]
            try:
                peer = self._auth()
                parts = path.strip("/").split("/")
                if method == "POST" and parts == ["actions", "block"]:
                    status, out = store.block(self._body(), peer)
                elif method == "GET" and len(parts) == 2 and parts[0] == "actions" and APPROVAL_RE.match(parts[1]):
                    status, out = store.get(parts[1])
                elif (method == "POST" and len(parts) == 3 and parts[0] == "actions" and parts[2] == "release"
                      and APPROVAL_RE.match(parts[1])):
                    if self._body():
                        raise ApiError(400, "invalid_request", "release takes an empty body")
                    status, out = store.release(parts[1], peer)
                else:
                    raise ApiError(404, "not_found", "unknown path")
            except ApiError as e:
                if e.status == 401:
                    store.audit("unauthorized", peer_ip=self.client_address[0], method=method, path=path[:80])
                elif e.status != 404 and e.status < 500:
                    store.audit("rejected", peer_ip=self.client_address[0], error=e.code, path=path[:80])
                status, out = e.status, {"error": e.code, "message": e.message}
            except Exception as e:  # 예기치 않은 오류도 내부 정보 없이 계약 형식으로만 응답
                store.audit("internal_error", error=type(e).__name__, path=path[:80])
                status, out = 500, {"error": "apply_failed", "message": "internal error"}
            self._send(status, out)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

    return Handler


def main() -> None:
    token = os.environ.get("GW_ACTION_TOKEN", "")
    if len(token) < 32:
        print("action api disabled: GW_ACTION_TOKEN missing or shorter than 32 chars", file=sys.stderr, flush=True)
        sys.exit(3)
    bind = os.environ.get("GW_ACTION_BIND", "10.250.30.2")
    port = int(os.environ.get("GW_ACTION_PORT", "8081"))
    targets = {t for t in os.environ.get("GW_ACTION_TARGETS", "172.28.10.11,172.28.10.12").split(",") if t}
    clients = [ipaddress.ip_network(c) for c in os.environ.get("GW_ACTION_CLIENTS", "10.250.30.0/24").split(",") if c]
    store = ActionStore(os.environ.get("GW_ACTION_STATE", "/var/lib/gw-actions"), targets)
    summary = store.reconcile()
    print("action api reconcile:", json.dumps(summary), file=sys.stderr, flush=True)

    def ticker():
        while True:
            threading.Event().wait(2)
            try:
                store.expire_tick()
            except Exception as e:  # 만료 해제 실패는 감사 기록에 남기고 다음 주기에 재시도
                store.audit("expire_error", error=type(e).__name__)

    threading.Thread(target=ticker, daemon=True).start()
    httpd = HTTPServer((bind, port), make_handler(store, token.encode(), clients))
    print(f"action api listening on {bind}:{port}", file=sys.stderr, flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
