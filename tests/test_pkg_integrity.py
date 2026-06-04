import unittest
import hashlib
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
from orin.collectors.pkg_integrity import gather_pkg_integrity_drift

class TestPkgIntegrity(unittest.TestCase):
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.glob")
    @patch("pathlib.Path.is_symlink")
    @patch("pathlib.Path.is_file")
    def test_gather_pkg_integrity_drift(self, mock_is_file, mock_is_symlink, mock_glob, mock_exists):
        mock_exists.return_value = True
        mock_is_symlink.return_value = False
        mock_is_file.return_value = True
        
        md5sums_file = MagicMock()
        md5sums_file.stem = "acl"
        md5sums_file.read_text.return_value = "1032ed063ad6f6de53fc3bd0ba83e90d  usr/bin/chacl\n"
        mock_glob.return_value = [md5sums_file]
        
        # On-disk binary content is modified
        fake_binary_data = b"modified_chacl_binary_contents"
        expected_actual_md5 = hashlib.md5(fake_binary_data).hexdigest()
        expected_actual_sha256 = hashlib.sha256(fake_binary_data).hexdigest()
        
        with patch("builtins.open", mock_open(read_data=fake_binary_data)):
            violations = gather_pkg_integrity_drift(Path("/var/lib/dpkg/info"))
            
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["package"], "acl")
        self.assertEqual(violations[0]["file_path"], "/usr/bin/chacl")
        self.assertEqual(violations[0]["expected_md5"], "1032ed063ad6f6de53fc3bd0ba83e90d")
        self.assertEqual(violations[0]["actual_md5"], expected_actual_md5)
        self.assertEqual(violations[0]["actual_sha256"], expected_actual_sha256)
        self.assertEqual(violations[0]["status"], "mismatch")

if __name__ == "__main__":
    unittest.main()
