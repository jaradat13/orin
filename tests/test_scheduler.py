# tests/test_scheduler.py
import unittest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
import os
import sys

from orin.core.scheduler import get_orin_path, install_schedule, remove_schedule, show_schedule_status


class TestScheduler(unittest.TestCase):
    @patch("orin.core.scheduler.shutil.which")
    def test_get_orin_path_which(self, mock_which):
        mock_which.return_value = "/usr/bin/orin"
        self.assertEqual(get_orin_path(), "/usr/bin/orin")

    @patch("orin.core.scheduler.shutil.which")
    def test_get_orin_path_fallback(self, mock_which):
        mock_which.return_value = None
        # When sys.argv[0] is not named 'orin', fall through to default path
        with patch("sys.argv", ["python", "main.py"]):
            self.assertEqual(get_orin_path(), "/usr/local/bin/orin")

    @patch("orin.core.scheduler.os.path.exists")
    @patch("orin.core.scheduler.CRON_D_FILE")
    @patch("orin.core.scheduler.get_orin_path")
    def test_install_schedule_system_wide(self, mock_get_path, mock_cron_file, mock_exists):
        mock_exists.return_value = True
        mock_get_path.return_value = "/usr/local/bin/orin"
        
        mock_write = MagicMock()
        mock_cron_file.write_text = mock_write
        
        with patch("sys.stdout") as mock_stdout:
            install_schedule(Path("orin_vault.db"), 10)
            
        mock_write.assert_called_once()
        content = mock_write.call_args[0][0]
        self.assertIn("*/10", content)
        self.assertIn("root /usr/local/bin/orin", content)

    @patch("orin.core.scheduler.os.path.exists")
    @patch("orin.core.scheduler.CRON_D_FILE")
    @patch("orin.core.scheduler.get_orin_path")
    @patch("orin.core.scheduler.subprocess.Popen")
    @patch("orin.core.scheduler.subprocess.check_output")
    def test_install_schedule_user_fallback(self, mock_check_output, mock_popen, mock_get_path, mock_cron_file, mock_exists):
        mock_exists.return_value = False  # system /etc/cron.d doesn't exist
        mock_get_path.return_value = "/usr/local/bin/orin"
        
        # Mock crontab -l returning some old content
        mock_check_output.return_value = b"# Some comment\n*/5 * * * * other_task\n"
        
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (b"", b"")
        mock_popen.return_value = mock_process
        
        with patch("sys.stdout") as mock_stdout:
            install_schedule(Path("orin_vault.db"), 15)
            
        mock_popen.assert_called_once()
        input_data = mock_process.communicate.call_args[1]["input"].decode()
        self.assertIn("*/15", input_data)
        self.assertIn("/usr/local/bin/orin", input_data)
        self.assertIn("other_task", input_data)

    @patch("orin.core.scheduler.CRON_D_FILE")
    def test_remove_schedule_system_wide(self, mock_cron_file):
        mock_cron_file.exists.return_value = True
        mock_cron_file.unlink = MagicMock()
        
        with patch("sys.stdout") as mock_stdout:
            remove_schedule()
            
        mock_cron_file.unlink.assert_called_once()

    @patch("orin.core.scheduler.CRON_D_FILE")
    @patch("orin.core.scheduler.subprocess.Popen")
    @patch("orin.core.scheduler.subprocess.check_output")
    def test_remove_schedule_user(self, mock_check_output, mock_popen, mock_cron_file):
        mock_cron_file.exists.return_value = False
        mock_check_output.return_value = b"# Orin Forensic Engine Automation Schedule\n*/5 * * * * orin collect\n# other comment"
        
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (b"", b"")
        mock_popen.return_value = mock_process
        
        with patch("sys.stdout") as mock_stdout:
            remove_schedule()
            
        mock_popen.assert_called_once()
        input_data = mock_process.communicate.call_args[1]["input"].decode()
        self.assertNotIn("orin collect", input_data)
        self.assertIn("other comment", input_data)

    @patch("orin.core.scheduler.CRON_D_FILE")
    @patch("orin.core.scheduler.subprocess.check_output")
    def test_show_schedule_status_active(self, mock_check_output, mock_cron_file):
        mock_cron_file.exists.return_value = True
        mock_cron_file.read_text.return_value = "System cron text"
        mock_check_output.return_value = b"*/5 * * * * orin collect\n"
        
        with patch("sys.stdout") as mock_stdout:
            show_schedule_status()
            
        output = "".join([call[0][0] for call in mock_stdout.write.call_args_list])
        self.assertIn("System cron text", output)
        self.assertIn("user-level", output)


if __name__ == "__main__":
    unittest.main()
