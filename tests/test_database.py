import unittest
from pathlib import Path
from orin.core.database import OrinStorage

class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_db_unit.db")
        self.storage = OrinStorage(self.db_path)

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_initialize_db(self):
        self.storage.initialize_db()
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row["name"] for row in cursor.fetchall()}
            
            expected_tables = {
                "system_snapshots",
                "baseline_kernel_modules",
                "collected_processes",
                "collected_ports",
                "collected_outbound_connections",
                "collected_kernel_modules",
                "collected_ssh_keys",
                "collected_file_hashes",
                "security_events",
                "baseline_users",
                "collected_users"
            }
            
            for table in expected_tables:
                self.assertIn(table, tables, f"Table {table} missing from DB schema.")

    def test_store_telemetry_apis(self):
        self.storage.initialize_db()
        with self.storage.get_connection() as conn:
            # Test create_snapshot
            snap_id = self.storage.create_snapshot(conn)
            self.assertGreater(snap_id, 0)
            
            # Test store_processes
            self.storage.store_processes(conn, snap_id, [{"pid": 100, "ppid": 1, "name": "systemd", "exe": "/sbin/init", "cmdline": "/sbin/init"}])
            
            # Test store_ports
            self.storage.store_ports(conn, snap_id, [{"port": 80, "protocol": "tcp", "process_name": "nginx"}])
            
            # Test store_outbound_connections
            self.storage.store_outbound_connections(conn, snap_id, [{"local_ip": "10.0.0.1", "local_port": 1234, "remote_ip": "8.8.8.8", "remote_port": 53, "state": "ESTABLISHED", "process_name": "dns"}])
            
            # Test store_kernel_modules
            self.storage.store_kernel_modules(conn, snap_id, [{"module_name": "ext4", "memory_size": 4000, "instances_loaded": 1}])
            
            # Test store_users
            self.storage.store_users(conn, snap_id, [{"username": "alice", "uid": 1000, "gid": 1000, "home_dir": "/home/alice", "login_shell": "/bin/bash"}])
            
            # Test store_ssh_keys
            self.storage.store_ssh_keys(conn, snap_id, [{"user_account": "alice", "key_type": "ssh-rsa", "fingerprint": "fp1", "raw_key_comment": "key1"}])
            
            # Test store_file_hashes
            self.storage.store_file_hashes(conn, snap_id, [{"file_path": "/etc/passwd", "sha256_hash": "sha1", "mtime": 0.0, "ctime": 0.0, "size": 100}])
            
            # Test store_deleted_binaries
            self.storage.store_deleted_binaries(conn, snap_id, [{"pid": 123, "exe": "/bin/evil", "sha256": "sha2", "md5": "md52", "vault_path": "/vault"}])
            
            # Test store_promisc_interfaces
            self.storage.store_promisc_interfaces(conn, snap_id, [{"interface": "eth0", "flags": "0x1103", "is_promiscuous": 1}])
            
            # Test store_wtmp_sessions
            self.storage.store_wtmp_sessions(conn, snap_id, [{"user": "root", "line": "pts/0", "host": "1.2.3.4", "pid": 12, "login_time": "2026-06-04", "logout_time": "", "anomaly_detected": 0, "anomaly_reason": ""}])
            
            # Test store_lastlog_records
            self.storage.store_lastlog_records(conn, snap_id, [{"username": "root", "uid": 0, "line": "pts/0", "host": "1.2.3.4", "login_time": "2026-06-04", "anomaly_detected": 0, "anomaly_reason": ""}])
            
            # Test store_pkg_integrity
            self.storage.store_pkg_integrity(conn, snap_id, [{"package": "sudo", "file_path": "/usr/bin/sudo", "expected_md5": "abc", "actual_md5": "def", "actual_sha256": "xyz", "status": "modified"}])
            
            # Test store_crontabs
            self.storage.store_crontabs(conn, snap_id, [{"source": "/etc/crontab", "user": "root", "schedule": "* * * * *", "command": "reboot"}])
            
            conn.commit()

if __name__ == "__main__":
    unittest.main()
