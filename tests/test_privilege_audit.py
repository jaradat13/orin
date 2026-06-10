# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
Test suite for orin.collectors.privilege_audit module.
Tests Identity, Access & Privilege Tracking functionality.
"""
import unittest
from pathlib import Path
from datetime import datetime, timezone
from orin.collectors.privilege_audit import (
    gather_privilege_escalation_events,
    gather_syscall_audit_logs,
    gather_pam_auth_events,
    gather_credential_access_events,
    extract_timestamp_from_log_line,
    gather_all_privilege_events,
)


class TestPrivilegeEscalationDetector(unittest.TestCase):
    """Test eBPF privilege escalation detection."""

    def test_gather_privilege_escalation_events_returns_list(self):
        """Ensure function returns a list structure."""
        result = gather_privilege_escalation_events()
        self.assertIsInstance(result, list)

    def test_gather_privilege_escalation_events_structure(self):
        """Verify event structure if any events are detected."""
        result = gather_privilege_escalation_events()
        for event in result:
            self.assertIn("event_type", event)
            self.assertIn("timestamp", event)
            self.assertIn("details", event)


class TestSyscallAuditLogs(unittest.TestCase):
    """Test syscall audit log parsing."""

    def test_gather_syscall_audit_logs_returns_list(self):
        """Ensure function returns a list structure."""
        result = gather_syscall_audit_logs()
        self.assertIsInstance(result, list)

    def test_gather_syscall_audit_logs_handles_missing_audit_log(self):
        """Verify graceful handling when audit.log doesn't exist."""
        audit_log = Path("/var/log/audit/audit.log")
        if not audit_log.exists():
            result = gather_syscall_audit_logs()
            self.assertEqual(len(result), 0)


class TestPAMAuthenticationTracker(unittest.TestCase):
    """Test PAM authentication event tracking."""

    def test_gather_pam_auth_events_returns_list(self):
        """Ensure function returns a list structure."""
        result = gather_pam_auth_events()
        self.assertIsInstance(result, list)

    def test_gather_pam_auth_events_with_custom_paths(self):
        """Test with non-existent custom log paths."""
        fake_paths = [Path("/tmp/fake_auth.log")]
        result = gather_pam_auth_events(auth_log_paths=fake_paths)
        self.assertIsInstance(result, list)
        # Should handle missing files gracefully
        self.assertEqual(len(result), 0)

    def test_extract_timestamp_syslog_format(self):
        """Test timestamp extraction from syslog format."""
        line = "Jan  5 14:23:45 hostname sshd[1234]: Accepted publickey"
        result = extract_timestamp_from_log_line(line)
        self.assertIsNotNone(result)
        self.assertTrue(result.endswith("Z"))

    def test_extract_timestamp_iso_format(self):
        """Test timestamp extraction from ISO 8601 format."""
        line = "2026-01-05T14:23:45Z hostname sshd[1234]: Accepted"
        result = extract_timestamp_from_log_line(line)
        self.assertEqual(result, "2026-01-05T14:23:45Z")

    def test_extract_timestamp_no_match(self):
        """Test timestamp extraction with no matching pattern."""
        line = "No timestamp here"
        result = extract_timestamp_from_log_line(line)
        self.assertIsNone(result)


class TestCredentialAccessMonitor(unittest.TestCase):
    """Test credential access monitoring."""

    def test_gather_credential_access_events_returns_list(self):
        """Ensure function returns a list structure."""
        result = gather_credential_access_events()
        self.assertIsInstance(result, list)

    def test_gather_credential_access_events_structure(self):
        """Verify event structure if any events are detected."""
        result = gather_credential_access_events()
        for event in result:
            self.assertIn("event_type", event)
            self.assertIn("timestamp", event)
            self.assertIn("details", event)
            self.assertIn("severity", event)


class TestConsolidatedInterface(unittest.TestCase):
    """Test the master collection function."""

    def test_gather_all_privilege_events_returns_dict(self):
        """Ensure master function returns a dictionary."""
        result = gather_all_privilege_events()
        self.assertIsInstance(result, dict)

    def test_gather_all_privilege_events_has_required_keys(self):
        """Verify all required keys are present."""
        result = gather_all_privilege_events()
        required_keys = [
            "collection_timestamp",
            "privilege_escalation_events",
            "syscall_audit_events",
            "pam_authentication_events",
            "credential_access_events",
            "summary",
        ]
        for key in required_keys:
            self.assertIn(key, result)

    def test_gather_all_privilege_events_summary_structure(self):
        """Verify summary contains expected counts."""
        result = gather_all_privilege_events()
        summary = result["summary"]
        self.assertIn("total_privilege_events", summary)
        self.assertIn("total_syscall_events", summary)
        self.assertIn("total_pam_events", summary)
        self.assertIn("total_credential_events", summary)

    def test_gather_all_privilege_events_timestamp_format(self):
        """Verify timestamp is in ISO 8601 format."""
        result = gather_all_privilege_events()
        timestamp = result["collection_timestamp"]
        self.assertTrue(timestamp.endswith("Z"))
        # Should be parseable
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

    def test_gather_all_privilege_events_lists_are_lists(self):
        """Verify all event collections are lists."""
        result = gather_all_privilege_events()
        self.assertIsInstance(result["privilege_escalation_events"], list)
        self.assertIsInstance(result["syscall_audit_events"], list)
        self.assertIsInstance(result["pam_authentication_events"], list)
        self.assertIsInstance(result["credential_access_events"], list)


class TestPAMEventTypes(unittest.TestCase):
    """Test specific PAM event type detection."""

    def setUp(self):
        """Create temporary test log file with sample entries."""
        self.test_log = Path("/tmp/test_auth.log")
        self.sample_entries = [
            "Jan  5 14:23:45 hostname pam_unix(sshd:session): session opened for user testuser",
            "Jan  5 14:24:00 hostname pam_unix(sshd:session): session closed for user testuser",
            "Jan  5 14:25:00 hostname pam_unix(sshd:auth): authentication failure; user=baduser",
            "Jan  5 14:26:00 hostname sudo:   gooduser : TTY=pts/0 ; PWD=/home/gooduser ; USER=root ; COMMAND=/bin/bash",
            "Jan  5 14:27:00 hostname sshd[1234]: Accepted publickey for gooduser from 192.168.1.100",
            "Jan  5 14:28:00 hostname sshd[1234]: Failed password for baduser from 10.0.0.50",
            "Jan  5 14:29:00 hostname su[5678]: Successful su for root by gooduser",
        ]
        with open(self.test_log, "w") as f:
            f.write("\n".join(self.sample_entries))

    def tearDown(self):
        """Clean up test log file."""
        if self.test_log.exists():
            self.test_log.unlink()

    def test_detects_session_opened(self):
        """Test detection of PAM session opened events."""
        result = gather_pam_auth_events(auth_log_paths=[self.test_log])
        session_opened = [e for e in result if e["event_type"] == "pam_session_opened"]
        self.assertGreater(len(session_opened), 0)
        self.assertEqual(session_opened[0]["user"], "testuser")

    def test_detects_session_closed(self):
        """Test detection of PAM session closed events."""
        result = gather_pam_auth_events(auth_log_paths=[self.test_log])
        session_closed = [e for e in result if e["event_type"] == "pam_session_closed"]
        self.assertGreater(len(session_closed), 0)
        self.assertEqual(session_closed[0]["user"], "testuser")

    def test_detects_auth_failure(self):
        """Test detection of PAM authentication failures."""
        result = gather_pam_auth_events(auth_log_paths=[self.test_log])
        auth_failures = [e for e in result if e["event_type"] == "pam_auth_failure"]
        self.assertGreater(len(auth_failures), 0)
        self.assertEqual(auth_failures[0]["user"], "baduser")

    def test_detects_sudo_execution(self):
        """Test detection of sudo command executions."""
        result = gather_pam_auth_events(auth_log_paths=[self.test_log])
        sudo_events = [e for e in result if e["event_type"] == "sudo_execution"]
        self.assertGreater(len(sudo_events), 0)
        self.assertEqual(sudo_events[0]["executor"], "gooduser")
        self.assertEqual(sudo_events[0]["target_user"], "root")
        self.assertEqual(sudo_events[0]["command"], "/bin/bash")

    def test_detects_ssh_login_success(self):
        """Test detection of successful SSH logins."""
        result = gather_pam_auth_events(auth_log_paths=[self.test_log])
        ssh_success = [e for e in result if e["event_type"] == "ssh_login_success"]
        self.assertGreater(len(ssh_success), 0)
        self.assertEqual(ssh_success[0]["user"], "gooduser")
        self.assertEqual(ssh_success[0]["source_ip"], "192.168.1.100")

    def test_detects_ssh_login_failed(self):
        """Test detection of failed SSH login attempts."""
        result = gather_pam_auth_events(auth_log_paths=[self.test_log])
        ssh_failed = [e for e in result if e["event_type"] == "ssh_login_failed"]
        self.assertGreater(len(ssh_failed), 0)
        self.assertEqual(ssh_failed[0]["user"], "baduser")
        self.assertEqual(ssh_failed[0]["source_ip"], "10.0.0.50")

    def test_detects_su_execution(self):
        """Test detection of SU command executions."""
        result = gather_pam_auth_events(auth_log_paths=[self.test_log])
        su_events = [e for e in result if e["event_type"] == "su_execution"]
        self.assertGreater(len(su_events), 0)
        self.assertEqual(su_events[0]["target_user"], "root")


if __name__ == "__main__":
    unittest.main()