import unittest
from orin.analysis.attck import get_attck_enrichment, ATTCK_MAP, DEFAULT_ATTCK

class TestAttck(unittest.TestCase):
    def test_known_mappings(self):
        # Verify general event types mapping
        for event_type, (expected_tech, expected_tactic, expected_url) in ATTCK_MAP.items():
            tech, tactic, url = get_attck_enrichment(event_type)
            self.assertEqual(tech, expected_tech)
            self.assertEqual(tactic, expected_tactic)
            self.assertEqual(url, expected_url)

    def test_suspicious_process_ancestry_refinements(self):
        # Case A: Masquerade in description
        tech, tactic, url = get_attck_enrichment("suspicious_process_ancestry", "Masquerade Fraud: Non-system ancestry parent discovered")
        self.assertEqual(tech, "T1036.004")
        self.assertEqual(tactic, "Defense Evasion")
        
        # Case B: Volatile in description
        tech, tactic, url = get_attck_enrichment("suspicious_process_ancestry", "Process running from volatile system workspace directory")
        self.assertEqual(tech, "T1036")
        self.assertEqual(tactic, "Defense Evasion")

        # Case C: Other/shell execution
        tech, tactic, url = get_attck_enrichment("suspicious_process_ancestry", "Suspicious interactive command parameter flags matched")
        self.assertEqual(tech, "T1059.004")
        self.assertEqual(tactic, "Execution")

    def test_fallback_mapping(self):
        # Verify fallback for completely unknown event types
        tech, tactic, url = get_attck_enrichment("completely_unknown_event_type_here")
        self.assertEqual(tech, DEFAULT_ATTCK[0])
        self.assertEqual(tactic, DEFAULT_ATTCK[1])
        self.assertEqual(url, DEFAULT_ATTCK[2])

if __name__ == "__main__":
    unittest.main()
