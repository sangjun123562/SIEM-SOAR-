"""조치 API 단위 시험: 가짜 iptables로 계약(DESIGN.md 3절) 판정만 확인한다. 실제 차단 시험이 아니다.

실행: python -B -m unittest testbed/gateway/test_actionapi.py -v
"""
import datetime as dt
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import actionapi  # noqa: E402
from actionapi import ActionStore, ApiError  # noqa: E402

T0 = dt.datetime(2026, 11, 18, 3, 0, 0, tzinfo=dt.timezone.utc)


class FakeIptables:
    def __init__(self):
        self.rules: list[tuple] = []
        self.fail_append = False

    def __call__(self, args):
        op, chain, spec = args[0], args[1], tuple(args[2:])
        if op == "-C":
            return 0 if spec in self.rules else 1
        if op == "-A":
            if self.fail_append:
                return 1
            self.rules.append(spec)
            return 0
        if op == "-D":
            if spec in self.rules:
                self.rules.remove(spec)
                return 0
            return 1
        return 2

    def lister(self):
        out = ["-N GW_BLOCK"]
        for spec in self.rules:
            out.append(" ".join(["-A", "GW_BLOCK", *[f'"{a}"' if a.startswith(("apr:", "fw_deny|")) else a for a in spec]]))
        return "\n".join(out) + "\n"


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


def body(aid="APR-20261118030000-abc123", target="172.28.10.11", minutes=10, **kw):
    b = {"approval_id": aid, "target_ip": target, "expires_at_utc": actionapi.fmt(T0 + dt.timedelta(minutes=minutes)),
         "incident_id": "INC-0001", "approved_by": "soc-operator"}
    b.update(kw)
    return b


class ActionStoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.ipt, self.clock = FakeIptables(), Clock()
        self.store = self.new_store()

    def tearDown(self):
        self.dir.cleanup()

    def new_store(self):
        return ActionStore(self.dir.name, {"172.28.10.11"}, runner=self.ipt, lister=self.ipt.lister, clock=self.clock)

    def assertApiError(self, status, code, fn, *a):
        with self.assertRaises(ApiError) as cm:
            fn(*a)
        self.assertEqual((cm.exception.status, cm.exception.code), (status, code))

    def test_block_get_release(self):
        st, out = self.store.block(body(), "10.250.30.50")
        self.assertEqual(st, 201)
        self.assertEqual(out["status"], "applied")
        self.assertEqual(len(self.ipt.rules), 3)
        st, g = self.store.get(out["approval_id"])
        self.assertTrue(g["rule_present"])
        st, r = self.store.release(out["approval_id"], "10.250.30.50")
        self.assertEqual((st, r["status"]), (200, "released"))
        self.assertEqual(self.ipt.rules, [])
        self.assertFalse(self.store.get(out["approval_id"])[1]["rule_present"])

    def test_same_retry_does_not_extend_or_duplicate(self):
        _, first = self.store.block(body(), "p")
        self.clock.now += dt.timedelta(minutes=5)
        st, again = self.store.block(body(), "p")
        self.assertEqual(st, 200)
        self.assertEqual(again, first)
        self.assertEqual(len(self.ipt.rules), 3)

    def test_conflict_and_closed(self):
        self.store.block(body(), "p")
        self.assertApiError(409, "approval_conflict", self.store.block, body(minutes=20), "p")
        self.assertApiError(409, "approval_conflict", self.store.block, body(incident_id="INC-9"), "p")
        self.store.release("APR-20261118030000-abc123", "p")
        self.assertApiError(409, "approval_closed", self.store.block, body(), "p")
        self.assertEqual(self.ipt.rules, [])

    def test_target_and_expiry_validation(self):
        for ip in ("172.28.10.12", "172.28.10.2", "172.28.20.20", "172.28.10.0/24", "10.250.30.2"):
            self.assertApiError(422, "target_not_allowed", self.store.block, body(target=ip), "p")
        self.assertApiError(422, "invalid_expiry", self.store.block, body(minutes=31), "p")
        self.assertApiError(422, "invalid_expiry", self.store.block, body(minutes=-1), "p")
        self.assertApiError(422, "invalid_expiry", self.store.block, body(expires_at_utc="2026-11-18T03:10:00+09:00"), "p")
        self.assertApiError(400, "invalid_request", self.store.block, body(aid="APR-../x"), "p")
        self.assertApiError(400, "invalid_request", self.store.block, {**body(), "extra": "x"}, "p")
        self.assertApiError(400, "invalid_request", self.store.block, body(approved_by="a b;rm"), "p")
        self.assertEqual(self.ipt.rules, [])

    def test_forbidden_allowlist_refused(self):
        with self.assertRaises(SystemExit):
            ActionStore(self.dir.name, {"172.28.10.12"}, runner=self.ipt, lister=self.ipt.lister, clock=self.clock)

    def test_expiry_auto_release_and_no_reblock(self):
        self.store.block(body(minutes=1), "p")
        self.clock.now += dt.timedelta(seconds=61)
        self.store.expire_tick()
        self.assertEqual(self.ipt.rules, [])
        st, g = self.store.get("APR-20261118030000-abc123")
        self.assertEqual((g["status"], g["rule_present"]), ("expired", False))
        self.assertApiError(409, "approval_closed", self.store.block, body(minutes=1), "p")
        self.assertApiError(409, "approval_closed", self.store.release, "APR-20261118030000-abc123", "p")

    def test_restart_reconcile(self):
        self.store.block(body(aid="APR-keep"), "p")
        self.store.block(body(aid="APR-short", minutes=1), "p")
        # 재시작으로 namespace 규칙이 사라지고 시간이 흐른 상황 + 기록 없는 고아 규칙
        self.ipt.rules.clear()
        self.ipt.rules.extend(tuple(s) for s in actionapi.rule_specs("APR-orphan", "172.28.10.11"))
        self.clock.now += dt.timedelta(minutes=2)
        s2 = self.new_store()
        summary = s2.reconcile()
        self.assertEqual(summary["restored"], ["APR-keep"])
        self.assertEqual(set(summary["removed_orphans"]), {"APR-orphan"})
        self.assertEqual(s2.get("APR-short")[1]["status"], "expired")
        self.assertEqual(sorted(self.ipt.rules), sorted(tuple(s) for s in actionapi.rule_specs("APR-keep", "172.28.10.11")))

    def test_apply_failure_rolls_back(self):
        self.ipt.fail_append = True
        self.assertApiError(500, "apply_failed", self.store.block, body(), "p")
        self.assertEqual(self.ipt.rules, [])
        self.assertApiError(404, "not_found", self.store.get, "APR-20261118030000-abc123")

    def test_audit_has_no_token_field(self):
        self.store.block(body(), "p")
        with open(os.path.join(self.dir.name, "audit.jsonl"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("block_applied", text)
        self.assertNotIn("Bearer", text)


if __name__ == "__main__":
    unittest.main()
