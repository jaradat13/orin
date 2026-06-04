import unittest
from unittest.mock import patch, MagicMock
from orin.collectors.promisc import gather_promisc_interfaces

class TestPromisc(unittest.TestCase):
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.iterdir")
    def test_gather_promisc_interfaces(self, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        
        # Mock network interface directories
        iface_eth0 = MagicMock()
        iface_eth0.is_dir.return_value = True
        iface_eth0.name = "eth0"
        mock_eth0_flags = MagicMock()
        mock_eth0_flags.read_text.return_value = "0x1103\n"
        iface_eth0.__truediv__.return_value = mock_eth0_flags
        
        iface_lo = MagicMock()
        iface_lo.is_dir.return_value = True
        iface_lo.name = "lo"
        mock_lo_flags = MagicMock()
        mock_lo_flags.read_text.return_value = "0x1003\n"
        iface_lo.__truediv__.return_value = mock_lo_flags
        
        mock_iterdir.return_value = [iface_eth0, iface_lo]
        
        res = gather_promisc_interfaces()
        
        self.assertEqual(len(res), 2)
        eth0_res = next(r for r in res if r["interface"] == "eth0")
        lo_res = next(r for r in res if r["interface"] == "lo")
        
        self.assertEqual(eth0_res["is_promiscuous"], 1)
        self.assertEqual(lo_res["is_promiscuous"], 0)

if __name__ == "__main__":
    unittest.main()
