"""Gateway log contract checks for ICMP broadcast denials."""

import importlib.util
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location("nflog2jsonl", Path(__file__).with_name("nflog2jsonl.py"))
gateway_log = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway_log)


class GatewayIcmpTests(unittest.TestCase):
    def test_broadcast_echo_deny_has_no_tcp_ports(self):
        record = {
            "oob.prefix": "fw_deny|POLICY-ICMP-BROADCAST", "ip.protocol": 1,
            "oob.time.sec": 1795673267, "src_ip": "172.28.10.11", "dest_ip": "172.28.20.255",
        }
        event = gateway_log.convert(record)
        self.assertEqual(event["event_type"], "fw_deny")
        self.assertEqual(event["protocol"], "ICMP")
        self.assertEqual(event["rule_id"], "POLICY-ICMP-BROADCAST")
        self.assertNotIn("src_port", event)
        self.assertNotIn("dst_port", event)

    def test_policy_icmp_deny_is_recorded_but_allow_is_not(self):
        record = {
            "oob.prefix": "fw_deny|POLICY-CLIENT-CADDY-ONLY", "ip.protocol": 1,
            "src_ip": "172.28.10.11", "dest_ip": "172.28.20.5",
        }
        self.assertEqual(gateway_log.convert(record)["rule_id"], "POLICY-CLIENT-CADDY-ONLY")
        record["oob.prefix"] = "fw_allow|-"
        self.assertIsNone(gateway_log.convert(record))


if __name__ == "__main__":
    unittest.main()
