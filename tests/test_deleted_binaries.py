import unittest
from unittest.mock import patch, MagicMock
from orin.collectors.deleted_binaries import gather_deleted_binaries

class TestDeletedBinaries(unittest.TestCase):
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.iterdir")
    @patch("os.readlink")
    @patch("pathlib.Path.mkdir")
    def test_gather_deleted_binaries(self, mock_mkdir, mock_readlink, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        
        # Mock PID directories
        pid_dir = MagicMock()
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        
        # Mock exe_link which is pid_dir / "exe"
        mock_exe_link = MagicMock()
        mock_exe_link.read_bytes.return_value = b"malware_payload"
        pid_dir.__truediv__.return_value = mock_exe_link
        
        non_pid_dir = MagicMock()
        non_pid_dir.is_dir.return_value = True
        non_pid_dir.name = "not_a_pid"
        
        mock_iterdir.return_value = [pid_dir, non_pid_dir]
        mock_readlink.return_value = "/usr/bin/malware (deleted)"
        
        res = gather_deleted_binaries(vault_dir="/tmp/fake_vault")
        
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["pid"], 1234)
        self.assertEqual(res[0]["exe"], "/usr/bin/malware (deleted)")
        self.assertEqual(res[0]["md5"], "ab7f40cb667df91cac7692195a6f7010")
        self.assertEqual(res[0]["sha256"], "0ec75db5b2d2b22d20394741dddc5b7026f3a7af6bc399722a36fb198d274610")

if __name__ == "__main__":
    unittest.main()
