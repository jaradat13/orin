import unittest
import errno
from unittest.mock import patch, MagicMock
from orin.analysis.unhide import detect_hidden_processes

class TestUnhide(unittest.TestCase):
    @patch("pathlib.Path.exists", autospec=True)
    @patch("pathlib.Path.iterdir")
    @patch("pathlib.Path.read_text")
    @patch("os.kill")
    def test_detect_hidden_processes(self, mock_kill, mock_read_text, mock_iterdir, mock_exists):
        # /proc exists, but the hidden PIDs (200, 250) do not exist in /proc
        def exists_side_effect(self_path):
            p_str = str(self_path)
            if p_str == "/proc":
                return True
            if "200" in p_str or "250" in p_str:
                return False
            return True
        mock_exists.side_effect = exists_side_effect
        
        # Mock visible PIDs
        visible_pid_dir = MagicMock()
        visible_pid_dir.is_dir.return_value = True
        visible_pid_dir.name = "100"
        
        mock_iterdir.return_value = [visible_pid_dir]
        
        # Mock pid_max to a small number
        mock_read_text.return_value = "300\n"
        
        # Mock os.kill
        def kill_side_effect(pid, sig):
            if pid == 200:
                return
            elif pid == 250:
                raise OSError(errno.EPERM, "Operation not permitted")
            else:
                raise OSError(errno.ESRCH, "No such process")
                
        mock_kill.side_effect = kill_side_effect
        
        hidden = detect_hidden_processes()
        
        self.assertEqual(len(hidden), 2)
        pids = {h["pid"] for h in hidden}
        self.assertEqual(pids, {200, 250})

if __name__ == "__main__":
    unittest.main()
