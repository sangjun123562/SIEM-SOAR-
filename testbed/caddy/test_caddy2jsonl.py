"""Regression checks for the Caddy/WAF log conversion boundary."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("caddy2jsonl.py")
SPEC = importlib.util.spec_from_file_location("caddy2jsonl", MODULE_PATH)
converter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(converter)


class WafConversionTests(unittest.TestCase):
    def test_waf_record_is_written_without_access_log_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "waf.jsonl"
            output = base / "caddy.jsonl"
            state = base / "waf.offset"
            source.write_text(json.dumps({
                "msg": "CRS match", "blocked": True, "rule_ids": [942100],
                "ts": 1795673267.0,
                "request_id": "11111111-1111-1111-1111-111111111111",
                "client_ip": "172.28.10.11", "score": 5,
            }) + "\n", encoding="utf-8")
            with patch.object(converter, "OUT", str(output)):
                offset = converter.step(0, str(source), str(state), converter.convert_waf)
            self.assertEqual(offset, source.stat().st_size)
            self.assertEqual(int(state.read_text()), offset)
            events = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "waf_blocked")
            self.assertEqual(events[0]["rule_id"], "942100")
            self.assertEqual(events[0]["status_code"], 403)
            self.assertNotIn("http_method", events[0])


if __name__ == "__main__":
    unittest.main()
