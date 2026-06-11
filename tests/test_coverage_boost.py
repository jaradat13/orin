# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
import sys
from unittest.mock import MagicMock

# Mock bcrypt before importing anything that depends on it
sys.modules['bcrypt'] = MagicMock()

import unittest
import os
import json
from pathlib import Path
from unittest.mock import patch

from orin.cli import parse_args
from orin.orchestrator import (
    run_orchestration,
    cmd_self_defense,
    cmd_init,
    cmd_collect,
    cmd_analyze,
    cmd_report,
    cmd_serve,
    cmd_hub_serve,
    cmd_schedule,
    cmd_scan,
    cmd_baseline,
    cmd_correlate,
    cmd_delta,
    cmd_diff,
    cmd_export,
    cmd_verify,
    cmd_stream,
    cmd_vault,
    cmd_rules
)
from orin.core.hub_server import TenantManager

class TestCliCoverage(unittest.TestCase):
    def test_parse_args_all_commands(self):
        commands = [
            ["init", "--read-only"],
            ["collect", "--parallel", "--workers", "4", "--timeout", "10.0"],
            ["analyze"],
            ["report", "--format", "html", "--output", "r.html"],
            ["report", "--format", "markdown", "--output", "r.md"],
            ["serve", "--host", "127.0.0.1", "--port", "8080"],
            ["hub-serve", "--host", "127.0.0.1", "--port", "8080"],
            ["schedule", "--install"],
            ["schedule", "--remove"],
            ["schedule", "--status"],
            ["self-defense", "--action", "status"],
            ["self-defense", "--action", "watchdog", "--socket", "/var/run/sd.sock", "--interval", "5"],
            ["self-defense", "--action", "heartbeat", "--socket", "/var/run/sd.sock"],
            ["self-defense", "--action", "generate-profiles", "--output-dir", "/tmp"],
            ["scan", "--host", "127.0.0.1", "--user", "root"],
            ["baseline", "add", "--user", "testuser"],
            ["baseline", "refresh", "--force-overwrite"],
            ["correlate"],
            ["delta", "--base", "1", "--target", "2"],
            ["diff", "v1.json", "v2.json"],
            ["export", "--snapshot", "1", "--secret", "passpasspasspass"],
            ["verify", "--file", "f.enc", "--secret", "passpasspasspass"],
            ["stream"],
            ["rules", "update", "--sigma", "/tmp"],
            ["vault", "stats"],
            ["vault", "prune", "--older-than", "30", "--execute"]
        ]
        for cmd in commands:
            with patch("sys.argv", ["orin", "-d", "test.db"] + cmd):
                args = parse_args()
                self.assertIsNotNone(args)

class TestOrchestratorCoverage(unittest.TestCase):
    @patch("orin.orchestrator.cmd_init")
    @patch("orin.orchestrator.cmd_collect")
    @patch("orin.orchestrator.cmd_analyze")
    @patch("orin.orchestrator.cmd_report")
    @patch("orin.orchestrator.cmd_serve")
    @patch("orin.orchestrator.cmd_hub_serve")
    @patch("orin.orchestrator.cmd_schedule")
    @patch("orin.orchestrator.cmd_scan")
    @patch("orin.orchestrator.cmd_baseline")
    @patch("orin.orchestrator.cmd_correlate")
    @patch("orin.orchestrator.cmd_delta")
    @patch("orin.orchestrator.cmd_diff")
    @patch("orin.orchestrator.cmd_export")
    @patch("orin.orchestrator.cmd_verify")
    @patch("orin.orchestrator.cmd_stream")
    @patch("orin.orchestrator.cmd_vault")
    @patch("orin.orchestrator.cmd_rules")
    @patch("orin.orchestrator.SelfDefenseManager")
    def test_run_orchestration(self, mock_sd, mock_rules, mock_vault, mock_stream, mock_verify,
                               mock_export, mock_diff, mock_delta, mock_correlate, mock_baseline,
                               mock_scan, mock_schedule, mock_hub_serve, mock_serve, mock_report,
                               mock_analyze, mock_collect, mock_init):
        # 1. Simple commands
        simple_cmds = [
            ("init", mock_init),
            ("collect", mock_collect),
            ("analyze", mock_analyze),
            ("report", mock_report),
            ("serve", mock_serve),
            ("hub-serve", mock_hub_serve),
            ("schedule", mock_schedule),
            ("scan", mock_scan),
            ("baseline", mock_baseline),
            ("correlate", mock_correlate),
            ("stream", mock_stream),
            ("rules", mock_rules)
        ]
        for cmd_name, mock_fn in simple_cmds:
            args = MagicMock()
            args.command = cmd_name
            run_orchestration(args)
            mock_fn.assert_called_once_with(args)
            mock_fn.reset_mock()

        # 2. self-defense watchdog
        args = MagicMock()
        args.command = "self-defense"
        args.action = "watchdog"
        args.socket = "/tmp/sd.sock"
        args.interval = 1
        with patch("time.sleep", side_effect=KeyboardInterrupt):
            run_orchestration(args)
        mock_sd.assert_called_once()
        mock_sd.reset_mock()

        # 3. self-defense heartbeat
        args = MagicMock()
        args.command = "self-defense"
        args.action = "heartbeat"
        args.socket = "/tmp/sd.sock"
        mock_sd.return_value.send_heartbeat.return_value = True
        with self.assertRaises(SystemExit) as cm:
            run_orchestration(args)
        self.assertEqual(cm.exception.code, 0)
        mock_sd.reset_mock()

        # 4. self-defense generate-profiles
        args = MagicMock()
        args.command = "self-defense"
        args.action = "generate-profiles"
        args.output_dir = "/tmp/orin_test_profiles"
        with patch("pathlib.Path.mkdir"):
            run_orchestration(args)
        mock_sd.generate_seccomp_profile.assert_called_once()
        mock_sd.reset_mock()

        # 5. self-defense status
        args = MagicMock()
        args.command = "self-defense"
        args.action = "status"
        mock_sd.return_value.validate_security_profiles.return_value = {"status": "ok"}
        run_orchestration(args)
        mock_sd.return_value.validate_security_profiles.assert_called_once()
        mock_sd.reset_mock()

        # 6. delta, diff, export, verify, vault
        args = MagicMock()
        args.command = "delta"
        mock_delta.return_value = 0
        with self.assertRaises(SystemExit) as cm:
            run_orchestration(args)
        self.assertEqual(cm.exception.code, 0)

        args.command = "diff"
        mock_diff.return_value = 0
        with self.assertRaises(SystemExit) as cm:
            run_orchestration(args)
        self.assertEqual(cm.exception.code, 0)

        args.command = "export"
        mock_export.return_value = 0
        with self.assertRaises(SystemExit) as cm:
            run_orchestration(args)
        self.assertEqual(cm.exception.code, 0)

        args.command = "verify"
        mock_verify.return_value = 0
        with self.assertRaises(SystemExit) as cm:
            run_orchestration(args)
        self.assertEqual(cm.exception.code, 0)

        args.command = "vault"
        args.vault_command = "prune"
        args.execute = True
        run_orchestration(args)
        mock_vault.assert_called_once_with(args)
        self.assertFalse(args.dry_run)

    @patch("orin.core.self_defense.main")
    def test_cmd_self_defense(self, mock_sd_main):
        args = MagicMock()
        args._remaining_args = ["status"]
        cmd_self_defense(args)
        mock_sd_main.assert_called_once()

    @patch("orin.core.hub_server.start_server")
    def test_cmd_hub_serve(self, mock_start):
        args = MagicMock()
        args.database = "test.db"
        args.host = "127.0.0.1"
        args.port = 8080
        args.port_opt = None
        args.cert = None
        args.key = None
        args.no_auth = True
        cmd_hub_serve(args)
        mock_start.assert_called_once()

    @patch("orin.orchestrator.OrinStorage")
    @patch("orin.core.database.OrinStorage")
    @patch("orin.core.scanner.run_remote_scan")
    @patch("subprocess.Popen")
    @patch("orin.orchestrator.os.path.exists")
    def test_cmd_scan(self, mock_exists, mock_popen, mock_scan, mock_db_storage, mock_orch_storage):
        mock_exists.return_value = True
        mock_conn = MagicMock()
        for mock_storage_cls in (mock_db_storage, mock_orch_storage):
            mock_storage_cls.return_value.get_connection.return_value.__enter__.return_value = mock_conn

        args = MagicMock()
        args.database = "test.db"
        args.host = "127.0.0.1"
        args.port = 22
        args.init = True
        args.key = None
        args.user = "root"
        args.deploy_only = False
        args.scan_only = False
        
        # Test init path
        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc
        mock_proc.communicate.return_value = ('{"hostname": "remote-host", "modules": [], "users": [], "suid": []}', '')
        mock_proc.returncode = 0
        
        with patch("pathlib.Path.read_text", return_value="agent_code"):
            cmd_scan(args)
        
        # Test scan path
        args.init = False
        mock_scan.return_value = {"snapshot_id": 1, "risk_score": 50, "events_count": 0}
        cmd_scan(args)
        mock_scan.assert_called_once()

    @patch("orin.orchestrator.OrinStorage")
    @patch("orin.core.database.OrinStorage")
    @patch("orin.orchestrator.os.path.exists")
    def test_cmd_baseline(self, mock_exists, mock_db_storage, mock_orch_storage):
        mock_exists.return_value = True
        mock_conn = MagicMock()
        for mock_storage_cls in (mock_db_storage, mock_orch_storage):
            mock_storage_cls.return_value.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Test "add" path
        args = MagicMock()
        args.database = "test.db"
        args.host = None
        args.baseline_command = "add"
        args.user = "testuser"
        args.module = None
        args.suid = None
        
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.side_effect = [
            {"id": 1}, # snapshot_id
            {"username": "testuser", "uid": 1000, "gid": 1000, "home_dir": "/home/testuser", "login_shell": "/bin/bash"} # user info
        ]
        cmd_baseline(args)
        
        # Test "refresh" path
        args = MagicMock()
        args.database = "test.db"
        args.host = None
        args.baseline_command = "refresh"
        args.force_overwrite = True
        mock_cursor.fetchone.side_effect = [{"id": 1}]
        cmd_baseline(args)

    @patch("orin.orchestrator.OrinStorage")
    @patch("orin.core.database.OrinStorage")
    @patch("orin.orchestrator.os.path.exists")
    @patch("orin.analysis.ai.run_ai_correlation")
    def test_cmd_correlate(self, mock_ai, mock_exists, mock_db_storage, mock_orch_storage):
        mock_exists.return_value = True
        mock_ai.return_value = "Correlation Briefing Details"
        args = MagicMock()
        args.database = "test.db"
        args.host = None
        args.url = None
        args.model = "ollama"
        args.output = None
        cmd_correlate(args)

    @patch("orin.analysis.timeline.calculate_snapshot_delta")
    @patch("orin.orchestrator.os.path.exists")
    def test_cmd_delta(self, mock_exists, mock_calc_delta):
        mock_exists.return_value = True
        mock_calc_delta.return_value = {
            "added": [1],
            "removed": [2],
            "modified": [3]
        }
        args = MagicMock()
        args.database = "test.db"
        args.base = 1
        args.target = 2
        args.verbose = True
        cmd_delta(args)
        mock_calc_delta.assert_called_once_with("test.db", 1, 2)

    @patch("orin.analysis.diff.load_snapshot_data")
    @patch("orin.analysis.diff.compare_snapshots")
    def test_cmd_diff(self, mock_compare, mock_load):
        mock_load.side_effect = [{"host": "h1"}, {"host": "h2"}]
        mock_compare.return_value = {
            "total_changes": 5,
            "critical_changes": 1
        }
        args = MagicMock()
        args.base_file = "f1.json"
        args.target_file = "f2.json"
        args.secret = "secretkey"
        args.verbose = True
        cmd_diff(args)
        mock_compare.assert_called_once()

    @patch("orin.core.crypto.generate_signed_export")
    @patch("orin.core.crypto.generate_coc_manifest")
    @patch("orin.orchestrator.os.path.exists")
    def test_cmd_export(self, mock_exists, mock_coc, mock_export_fn):
        mock_exists.return_value = True
        mock_export_fn.return_value = {"snapshot_id": 1, "data": "dummy"}
        mock_coc.return_value = {"evidence_count": 10}
        
        args = MagicMock()
        args.database = "test.db"
        args.snapshot = 1
        args.secret = "passpasspasspass"
        args.output = "output.json"
        
        with patch("builtins.open", unittest.mock.mock_open()):
            cmd_export(args)
            
        mock_export_fn.assert_called_once_with("test.db", 1, "passpasspasspass")

    @patch("orin.core.crypto.verify_signed_export")
    @patch("orin.orchestrator.os.path.exists")
    def test_cmd_verify(self, mock_exists, mock_verify_fn):
        mock_exists.return_value = True
        mock_verify_fn.return_value = {
            "valid": True,
            "snapshot_id": 1,
            "timestamp": "2026-06-11",
            "item_count": 42
        }
        
        args = MagicMock()
        args.file = "export.json"
        args.secret = "passpasspasspass"
        
        cmd_verify(args)
        mock_verify_fn.assert_called_once_with("export.json", "passpasspasspass")

    @patch("subprocess.run")
    @patch("pathlib.Path.exists")
    def test_cmd_stream(self, mock_exists, mock_run):
        mock_exists.return_value = True
        args = MagicMock()
        args.database = "test.db"
        args.verbose = True
        
        cmd_stream(args)
        mock_run.assert_called_once()

    @patch("orin.orchestrator.OrinStorage")
    @patch("orin.core.database.OrinStorage")
    @patch("orin.orchestrator.os.path.exists")
    def test_cmd_vault(self, mock_exists, mock_db_storage, mock_orch_storage):
        mock_exists.return_value = True
        mock_conn = MagicMock()
        
        for mock_storage_cls in (mock_db_storage, mock_orch_storage):
            mock_storage = mock_storage_cls.return_value
            mock_storage.get_connection.return_value.__enter__.return_value = mock_conn
            mock_storage.vault_stats.return_value = {
                'database_size_mb': 10.5,
                'database_size_bytes': 1024 * 1024 * 10,
                'snapshot_count': 5,
                'oldest_snapshot': '2026-06-10',
                'newest_snapshot': '2026-06-11',
                'table_counts': {'system_snapshots': 5}
            }
            mock_storage.vault_prune.return_value = {
                "mode": "legacy",
                "message": "Pruned 10 records"
            }
        
        # Test stats command
        args = MagicMock()
        args.database = "test.db"
        args.vault_command = "stats"
        cmd_vault(args)
        
        # Test prune legacy command
        args = MagicMock()
        args.database = "test.db"
        args.vault_command = "prune"
        args.execute = True
        args.policy_file = None
        args.older_than = 30
        cmd_vault(args)

    @patch("orin.analysis.sigma.validate_rules_directory")
    @patch("pathlib.Path.exists")
    def test_cmd_rules(self, mock_exists, mock_val_dir):
        mock_exists.return_value = True
        mock_val_dir.return_value = ([], [])
        args = MagicMock()
        args.database = "test.db"
        args.rules_command = "update"
        args.sigma = "/tmp"
        args.yara = None
        args.validate_only = True
        cmd_rules(args)
        mock_val_dir.assert_called_once()

class TestHubServerCoverage(unittest.TestCase):
    def test_tenant_manager(self):
        db_file = "test_hub_tenants.db"
        if Path(db_file).exists():
            try:
                Path(db_file).unlink()
            except Exception:
                pass
        
        manager = TenantManager(db_file)
        self.assertEqual(len(manager.tenants), 0)
        
        # Cleanup
        if Path(db_file).exists():
            try:
                Path(db_file).unlink()
            except Exception:
                pass

if __name__ == "__main__":
    unittest.main()
