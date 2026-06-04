import unittest
from unittest.mock import patch, mock_open
import errno
from pathlib import Path
from orin.collectors.kernel import gather_loaded_kernel_modules

class TestKernel(unittest.TestCase):
    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_loaded_kernel_modules_success(self, mock_file_open, mock_exists):
        mock_exists.return_value = True
        
        modules_content = (
            "ext4 400000 2 - Live 0xffffffff\n"
            "\n"
            "nfsd 150000 0 - Live 0xffffffff\n"
        )
        mock_file_open.return_value = mock_open(read_data=modules_content).return_value
        
        res = gather_loaded_kernel_modules()
        self.assertEqual(len(res), 2)
        
        ext4_res = res[0]
        self.assertEqual(ext4_res["module_name"], "ext4")
        self.assertEqual(ext4_res["memory_size"], 400000)
        self.assertEqual(ext4_res["instances_loaded"], 2)
        
        nfsd_res = res[1]
        self.assertEqual(nfsd_res["module_name"], "nfsd")
        self.assertEqual(nfsd_res["memory_size"], 150000)
        self.assertEqual(nfsd_res["instances_loaded"], 0)

    @patch("pathlib.Path.exists")
    def test_gather_loaded_kernel_modules_no_file(self, mock_exists):
        mock_exists.return_value = False
        res = gather_loaded_kernel_modules()
        self.assertEqual(res, [])

    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_loaded_kernel_modules_malformed_and_errors(self, mock_file_open, mock_exists):
        mock_exists.return_value = True
        
        # Line 1: Malformed (less than 3 fields)
        # Line 2: Invalid memory_size cast (ValueError)
        modules_content = (
            "short_module 100\n"
            "bad_cast invalid_size 2 - Live\n"
        )
        mock_file_open.return_value = mock_open(read_data=modules_content).return_value
        
        res = gather_loaded_kernel_modules()
        self.assertEqual(len(res), 2)
        
        self.assertEqual(res[0]["module_name"], "ERROR_LINE_1")
        self.assertEqual(res[0]["anomaly_detected"], 1)
        self.assertIn("Malformed kernel module line layout", res[0]["anomaly_reason"])
        
        self.assertEqual(res[1]["module_name"], "ERROR_INVALID_CAST_bad_cast")
        self.assertEqual(res[1]["anomaly_detected"], 1)
        self.assertIn("Type validation fault on row 2", res[1]["anomaly_reason"])

    @patch("pathlib.Path.exists")
    @patch("builtins.open")
    def test_gather_loaded_kernel_modules_permission_denied(self, mock_file_open, mock_exists):
        mock_exists.return_value = True
        mock_file_open.side_effect = PermissionError("Permission denied")
        
        res = gather_loaded_kernel_modules()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["module_name"], "ERROR_PROC_MODULES_IO_FAULT")
        self.assertEqual(res[0]["anomaly_detected"], 1)
        self.assertIn("Failed to access virtual filesystem descriptor node", res[0]["anomaly_reason"])

if __name__ == "__main__":
    unittest.main()
