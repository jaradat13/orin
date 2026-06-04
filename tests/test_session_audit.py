import unittest
import struct
import io
from pathlib import Path
from unittest.mock import patch, MagicMock
from orin.collectors.session_audit import gather_wtmp_sessions, gather_lastlog_records

class TestSessionAudit(unittest.TestCase):
    @patch("pathlib.Path.exists")
    def test_gather_wtmp_sessions(self, mock_exists):
        mock_exists.return_value = True
        
        # Format: <h2xi32s4s32s256shhiii4I20s
        login_record = struct.pack(
            "<h2xi32s4s32s256shhiii4I20s",
            7, 5555, b"pts/1", b"1", b"alice", b"192.168.1.10",
            0, 0, 0, 1600000000, 0, 0, 0, 0, 0, b""
        )
        logout_record = struct.pack(
            "<h2xi32s4s32s256shhiii4I20s",
            8, 5555, b"pts/1", b"1", b"", b"",
            0, 0, 0, 1600003600, 0, 0, 0, 0, 0, b""
        )
        
        fake_data = login_record + logout_record
        
        with patch("builtins.open", return_value=io.BytesIO(fake_data)):
            sessions = gather_wtmp_sessions(Path("/var/log/wtmp"))
            
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["user"], "alice")
        self.assertEqual(sessions[0]["line"], "pts/1")
        self.assertEqual(sessions[0]["host"], "192.168.1.10")
        self.assertEqual(sessions[0]["pid"], 5555)
        self.assertEqual(sessions[0]["login_time"], "2020-09-13T12:26:40Z")
        self.assertEqual(sessions[0]["logout_time"], "2020-09-13T13:26:40Z")
        self.assertEqual(sessions[0]["anomaly_detected"], 0)

    @patch("pathlib.Path.exists")
    def test_gather_wtmp_tampered_records(self, mock_exists):
        mock_exists.return_value = True
        zero_record = b"\x00" * 384
        
        with patch("builtins.open", return_value=io.BytesIO(zero_record)):
            sessions = gather_wtmp_sessions(Path("/var/log/wtmp"))
            
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["anomaly_detected"], 1)
        self.assertEqual(sessions[0]["anomaly_reason"], "Zeroed-out wtmp record detected (potential log tampering)")

    @patch("pathlib.Path.exists")
    @patch("orin.collectors.session_audit.gather_system_accounts")
    @patch("pathlib.Path.stat")
    def test_gather_lastlog_records(self, mock_stat, mock_gather_accounts, mock_exists):
        mock_exists.return_value = True
        mock_gather_accounts.return_value = [{"username": "alice", "uid": 1000}]
        
        mock_stat_res = MagicMock()
        mock_stat_res.st_size = 292000 + 292
        mock_stat.return_value = mock_stat_res
        
        # Lastlog record format: <I32s256s
        lastlog_record = struct.pack(
            "<I32s256s",
            1600000000, b"pts/1", b"192.168.1.10"
        )
        
        fake_data = b'\x00' * 292000 + lastlog_record
        
        with patch("builtins.open", return_value=io.BytesIO(fake_data)):
            records = gather_lastlog_records(Path("/var/log/lastlog"))
            
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["username"], "alice")
        self.assertEqual(records[0]["line"], "pts/1")
        self.assertEqual(records[0]["host"], "192.168.1.10")
        self.assertEqual(records[0]["login_time"], "2020-09-13T12:26:40Z")
        self.assertEqual(records[0]["anomaly_detected"], 0)

if __name__ == "__main__":
    unittest.main()
