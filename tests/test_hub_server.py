# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
"""
Unit tests for orin.core.hub_server – TenantManager and supporting functions.
The HTTP handler is tested via integration tests for the core functionality.
"""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from orin.core.hub_server import TenantManager


class TestTenantManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = Path(self.tmp.name)
        self.manager = TenantManager(self.db_path)

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # TenantManager initialization
    # ------------------------------------------------------------------ #
    def test_init_creates_tables(self):
        """Tables should exist after TenantManager initialization."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cursor.fetchall()}
        conn.close()
        self.assertIn("hub_tenants", tables)
        self.assertIn("hub_hosts", tables)
        self.assertIn("hub_admins", tables)
        self.assertIn("hub_audit_log", tables)
        self.assertIn("hub_rate_limits", tables)

    def test_init_with_nonexistent_db(self):
        """Initializing with a new path should create the database file."""
        new_path = self.db_path.parent / "new_hub_test.db"
        try:
            tm = TenantManager(new_path)
            self.assertTrue(new_path.exists())
        finally:
            if new_path.exists():
                os.unlink(new_path)

    def test_init_loads_active_tenants(self):
        """Tenants flagged is_active=1 should be loaded on init."""
        # Create a tenant and then reload
        t_id, api_key = self.manager.create_tenant("test-org")
        # Reload manager
        new_manager = TenantManager(self.db_path)
        self.assertIn(t_id, new_manager.tenants)

    # ------------------------------------------------------------------ #
    # Tenant CRUD
    # ------------------------------------------------------------------ #
    def test_create_tenant_returns_id_and_key(self):
        t_id, api_key = self.manager.create_tenant("org-alpha")
        self.assertIsNotNone(t_id)
        self.assertTrue(api_key.startswith("orin_hub_"))
        self.assertIn(t_id, self.manager.tenants)

    def test_create_tenant_with_metadata(self):
        t_id, _ = self.manager.create_tenant(
            "meta-org", max_hosts=50, metadata={"env": "prod"}, is_admin=True
        )
        tenant = self.manager.tenants[t_id]
        self.assertEqual(tenant["max_hosts"], 50)
        self.assertEqual(tenant["is_admin"], True)

    def test_validate_api_key_success(self):
        t_id, api_key = self.manager.create_tenant("secure-org")
        tenant = self.manager.validate_api_key(api_key)
        self.assertIsNotNone(tenant)
        self.assertEqual(tenant["id"], t_id)

    def test_validate_api_key_wrong_key(self):
        self.manager.create_tenant("secure-org")
        result = self.manager.validate_api_key("wrong_key_xyz")
        self.assertIsNone(result)

    def test_validate_api_key_updates_activity(self):
        t_id, api_key = self.manager.create_tenant("active-org")
        self.assertIsNone(self.manager.tenants[t_id].get("last_activity"))
        self.manager.validate_api_key(api_key)
        self.assertIsNotNone(self.manager.tenants[t_id].get("last_activity"))

    # ------------------------------------------------------------------ #
    # Host management
    # ------------------------------------------------------------------ #
    def test_register_host_success(self):
        t_id, _ = self.manager.create_tenant("hosting-org")
        host_id = self.manager.register_host(t_id, "web01", agent_version="1.0")
        self.assertIsNotNone(host_id)
        self.assertIn("web01", host_id)

    def test_register_host_unknown_tenant(self):
        result = self.manager.register_host("nonexistent-tenant", "host")
        self.assertIsNone(result)

    def test_register_host_respects_limit(self):
        t_id, _ = self.manager.create_tenant("limited-org", max_hosts=1)
        h1 = self.manager.register_host(t_id, "host-a")
        h2 = self.manager.register_host(t_id, "host-b")
        self.assertIsNotNone(h1)
        self.assertIsNone(h2)  # Should be rejected

    def test_update_host_heartbeat(self):
        t_id, _ = self.manager.create_tenant("heartbeat-org")
        host_id = self.manager.register_host(t_id, "server01")
        # Should not raise
        self.manager.update_host_heartbeat(host_id)

    def test_list_hosts_empty(self):
        t_id, _ = self.manager.create_tenant("empty-org")
        hosts = self.manager.list_hosts(t_id)
        self.assertEqual(hosts, [])

    def test_list_hosts_returns_registered(self):
        t_id, _ = self.manager.create_tenant("list-org")
        self.manager.register_host(t_id, "host-a")
        self.manager.register_host(t_id, "host-b")
        hosts = self.manager.list_hosts(t_id)
        self.assertEqual(len(hosts), 2)

    def test_list_hosts_unknown_tenant(self):
        result = self.manager.list_hosts("not-a-tenant")
        self.assertEqual(result, [])

    def test_get_tenant_stats(self):
        t_id, _ = self.manager.create_tenant("stats-org")
        self.manager.register_host(t_id, "h1")
        self.manager.register_host(t_id, "h2")
        stats = self.manager.get_tenant_stats(t_id)
        self.assertIsNotNone(stats)
        self.assertEqual(stats["total_hosts"], 2)

    def test_get_tenant_stats_unknown_tenant(self):
        result = self.manager.get_tenant_stats("no-tenant")
        self.assertIsNone(result)

    # ------------------------------------------------------------------ #
    # Admin user management
    # ------------------------------------------------------------------ #
    def test_create_admin_user(self):
        admin_id = self.manager.create_admin_user("admin1", "secret123")
        self.assertIsNotNone(admin_id)

    def test_create_admin_user_duplicate_raises(self):
        self.manager.create_admin_user("admin1", "secret123")
        with self.assertRaises(ValueError):
            self.manager.create_admin_user("admin1", "other_pass")

    def test_validate_admin_credentials_success(self):
        self.manager.create_admin_user("sysadmin", "strongpass")
        result = self.manager.validate_admin_credentials("sysadmin", "strongpass")
        self.assertIsNotNone(result)
        self.assertEqual(result["username"], "sysadmin")
        # Password hash should NOT be in result
        self.assertNotIn("password_hash", result)

    def test_validate_admin_credentials_wrong_password(self):
        self.manager.create_admin_user("sysadmin", "correct_pass")
        result = self.manager.validate_admin_credentials("sysadmin", "wrong_pass")
        self.assertIsNone(result)

    def test_validate_admin_credentials_unknown_user(self):
        result = self.manager.validate_admin_credentials("nobody", "pass")
        self.assertIsNone(result)

    # ------------------------------------------------------------------ #
    # Audit log
    # ------------------------------------------------------------------ #
    def test_log_audit_event(self):
        self.manager.log_audit_event(
            actor_type="admin",
            action="login",
            actor_id="admin-1",
            resource_type="session",
            details={"ip": "127.0.0.1"},
            ip_address="127.0.0.1",
            user_agent="TestAgent/1.0",
        )
        logs = self.manager.get_audit_logs()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["action"], "login")
        self.assertEqual(logs[0]["actor_type"], "admin")

    def test_get_audit_logs_filtered_by_actor_type(self):
        self.manager.log_audit_event(actor_type="admin", action="login")
        self.manager.log_audit_event(actor_type="agent", action="heartbeat")
        admin_logs = self.manager.get_audit_logs(actor_type="admin")
        self.assertEqual(len(admin_logs), 1)
        self.assertEqual(admin_logs[0]["actor_type"], "admin")

    def test_get_audit_logs_filtered_by_action(self):
        self.manager.log_audit_event(actor_type="admin", action="login")
        self.manager.log_audit_event(actor_type="agent", action="data_upload")
        upload_logs = self.manager.get_audit_logs(action="data_upload")
        self.assertEqual(len(upload_logs), 1)
        self.assertEqual(upload_logs[0]["action"], "data_upload")

    def test_get_audit_logs_limit(self):
        for i in range(10):
            self.manager.log_audit_event(actor_type="system", action=f"action_{i}")
        logs = self.manager.get_audit_logs(limit=5)
        self.assertLessEqual(len(logs), 5)

    # ------------------------------------------------------------------ #
    # Rate limiting
    # ------------------------------------------------------------------ #
    def test_rate_limit_allows_initial_requests(self):
        allowed = self.manager.check_rate_limit("127.0.0.1", "/api/data", max_requests=5)
        self.assertTrue(allowed)

    def test_rate_limit_blocks_after_max(self):
        identifier = "192.168.1.1"
        endpoint = "/api/upload"
        # Make max_requests requests (all should succeed)
        for _ in range(3):
            self.manager.check_rate_limit(identifier, endpoint, max_requests=3)
        # Next request should be blocked
        result = self.manager.check_rate_limit(identifier, endpoint, max_requests=3)
        self.assertFalse(result)

    def test_rate_limit_different_endpoints_independent(self):
        identifier = "10.0.0.1"
        self.manager.check_rate_limit(identifier, "/api/v1", max_requests=1)
        self.manager.check_rate_limit(identifier, "/api/v1", max_requests=1)
        # Different endpoint should still be allowed
        allowed = self.manager.check_rate_limit(identifier, "/api/v2", max_requests=1)
        self.assertTrue(allowed)

    def test_rate_limit_different_identifiers_independent(self):
        endpoint = "/api/data"
        # Fill up for identifier A
        for _ in range(2):
            self.manager.check_rate_limit("client-A", endpoint, max_requests=2)
        result_a = self.manager.check_rate_limit("client-A", endpoint, max_requests=2)
        result_b = self.manager.check_rate_limit("client-B", endpoint, max_requests=2)
        self.assertFalse(result_a)
        self.assertTrue(result_b)


if __name__ == "__main__":
    unittest.main()
