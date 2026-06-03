import unittest
from pathlib import Path
from unittest.mock import patch
from orin.core.database import OrinStorage
from orin.analysis.engine import run_analysis_cycle

class TestEngine(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_engine_unit.db")
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()
        
        with self.storage.get_connection() as conn:
            conn.execute(
                "INSERT INTO baseline_users (username, uid, gid) VALUES ('root', 0, 0);"
            )
            conn.commit()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    @patch("orin.analysis.engine.load_config")
    def test_port_whitelisting(self, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": ["code", "antigravity-ide"],
            "critical_paths": [],
            "critical_dirs": []
        }

        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 22, 'TCP', 'sshd');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 35415, 'TCP', 'antigravity-ide (PID: 7374)');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 9999, 'TCP', 'malicious (PID: 666)');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 555, 'TCP', 'code (PID: 999)');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT description FROM security_events WHERE event_type = 'unexpected_port';")
            events = [row["description"] for row in cursor.fetchall()]
            
            self.assertEqual(len(events), 2)
            self.assertTrue(any("9999" in ev for ev in events))
            self.assertTrue(any("555" in ev for ev in events))
            self.assertFalse(any("35415" in ev for ev in events))
            self.assertFalse(any("22" in ev for ev in events))

    @patch("orin.analysis.engine.load_config")
    def test_auto_resolution(self, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": ["code"],
            "critical_paths": [],
            "critical_dirs": []
        }

        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 9999, 'TCP', 'malicious (PID: 666)');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT resolved FROM security_events WHERE event_type = 'unexpected_port' AND description LIKE '%9999%';")
            self.assertEqual(cursor.fetchone()["resolved"], 0)

        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (2, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT resolved FROM security_events WHERE event_type = 'unexpected_port' AND description LIKE '%9999%';")
            self.assertEqual(cursor.fetchone()["resolved"], 1)

    @patch("orin.analysis.engine.load_config")
    def test_risk_score_calculation(self, mock_load_config):
        """Verify the Severity-Tiered Risk Scoring Model calculations."""
        # 1. Zero events -> score 0
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": [],
            "critical_paths": [],
            "critical_dirs": []
        }
        with self.storage.get_connection() as conn:
            # Clean up snapshots and events first
            conn.execute("DELETE FROM collected_ports;")
            conn.execute("DELETE FROM system_snapshots;")
            conn.execute("DELETE FROM security_events;")
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            # Only expected port, no anomalies
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 22, 'TCP', 'sshd');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'root', 0, 0);")
            conn.commit()

        res = run_analysis_cycle(self.db_path)
        self.assertEqual(res["events_count"], 0)
        self.assertEqual(res["risk_score"], 0)

        # 2. A single medium event (unexpected port) -> score 35
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (2, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (2, 22, 'TCP', 'sshd');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (2, 9999, 'TCP', 'malicious');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'root', 0, 0);")
            conn.commit()

        res = run_analysis_cycle(self.db_path)
        self.assertEqual(res["events_count"], 1)
        self.assertEqual(res["risk_score"], 35)

        # 3. 10 medium events (10 unexpected ports) -> score capped at 49 (35 + 9 * 1.5 = 48.5 -> 49)
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (3, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (3, 22, 'TCP', 'sshd');")
            for p in range(9000, 9010): # 10 ports
                conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (3, ?, 'TCP', 'malicious');", (p,))
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (3, 'root', 0, 0);")
            conn.commit()

        res = run_analysis_cycle(self.db_path)
        self.assertEqual(res["events_count"], 10)
        self.assertEqual(res["risk_score"], 49) # 35 + 9 * 1.5 = 48.5, rounded to 49

        # 4. Critical event present (e.g. unauthorized user profile created with UID 0) -> score starts at 90
        with self.storage.get_connection() as conn:
            # Let's clear users baseline to trigger unauthorized user created
            conn.execute("DELETE FROM baseline_users;")
            # Snapshot 4
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (4, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (4, 22, 'TCP', 'sshd');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (4, 'attacker', 0, 0);")
            conn.commit()

        res = run_analysis_cycle(self.db_path)
        self.assertEqual(res["risk_score"], 90)

if __name__ == "__main__":
    unittest.main()
