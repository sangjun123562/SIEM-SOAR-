import unittest
from dataclasses import replace
from soc.models import NormalizedEvent
from soc.detector import detect_icmp_denials
from soc.incident_service import build_incidents


class IcmpDetectionTests(unittest.TestCase):
    def events(self, count, start=0):
        return [NormalizedEvent(event_id=f"e{i}", raw_id=f"r{i}", source="gateway",
                event_ts_utc=f"2026-11-26T00:{(i+start)//60:02}:{(i+start)%60:02}Z",
                event_type="fw_deny", outcome="deny", src_ip="172.28.10.11",
                protocol="ICMP", ingest_mode="live") for i in range(count)]

    def test_threshold_dedup_and_evidence(self):
        rows = self.events(20)
        self.assertEqual(detect_icmp_denials(rows[:9]), [])
        first = detect_icmp_denials(rows[:10])[0]
        self.assertEqual(first.failure_count, 10)
        self.assertEqual(detect_icmp_denials(rows + rows), [first])
        case = build_incidents([], rows)[0]
        self.assertEqual(len(case.evidence_events), 10)
        self.assertFalse(case.block_rule_eligible)

    def test_other_sources_modes_protocols_and_separate_ips(self):
        rows = self.events(10)
        for changes in ({"ingest_mode": "replay"}, {"ingest_mode": "synthetic"},
                        {"protocol": "TCP"}, {"source": "erp"}, {"event_type": "fw_allow"}):
            self.assertEqual(detect_icmp_denials([replace(e, **changes) for e in rows]), [])
        split = [replace(e, src_ip="172.28.10.12") if i >= 5 else e for i,e in enumerate(rows)]
        self.assertEqual(detect_icmp_denials(split), [])
        spaced = [replace(e, event_ts_utc=f"2026-11-26T00:{i:02}:00Z") for i,e in enumerate(rows)]
        self.assertEqual(detect_icmp_denials(spaced), [])


if __name__ == "__main__":
    unittest.main()
