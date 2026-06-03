import unittest
import sys
import socket
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock

from orin.collectors.connections import (
    _parse_hex_endpoint,
    _parse_proc_net_file,
    gather_listening_ports,
    gather_outbound_connections,
    _get_socket_inode_map
)

class TestConnectionsCollector(unittest.TestCase):
    """Unit tests for the Orin connections collector and parser."""

    def test_parse_hex_endpoint_ipv4(self):
        """Verify that IPv4 hex endpoints are parsed correctly."""
        # 10.0.2.15:80 -> "0F02000A:0050"
        ip, port = _parse_hex_endpoint("0F02000A:0050")
        self.assertEqual(ip, "10.0.2.15")
        self.assertEqual(port, 80)

        # 127.0.0.1:443 -> "0100007F:01BB"
        ip, port = _parse_hex_endpoint("0100007F:01BB")
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(port, 443)

    def test_parse_hex_endpoint_ipv6(self):
        """Verify that IPv6 hex endpoints are parsed correctly, taking host byte order into account."""
        # ::1:631 (localhost cups)
        # On little-endian hosts, the bytes for ::1 are formatted as:
        # 00000000 00000000 00000000 01000000
        # On big-endian hosts, they are:
        # 00000000 00000000 00000000 00000001
        if sys.byteorder == "little":
            hex_ip = "00000000000000000000000001000000"
        else:
            hex_ip = "00000000000000000000000000000001"

        ip, port = _parse_hex_endpoint(f"{hex_ip}:0277")
        self.assertEqual(ip, "::1")
        self.assertEqual(port, 631)

        # Any invalid hex string should fall back to 0.0.0.0, 0
        ip, port = _parse_hex_endpoint("invalid_data")
        self.assertEqual(ip, "0.0.0.0")
        self.assertEqual(port, 0)

    @patch("pathlib.Path.exists", autospec=True)
    def test_parse_proc_net_file_missing(self, mock_exists):
        """Verify that a missing file returns an empty list without raising an error."""
        mock_exists.return_value = False
        res = _parse_proc_net_file(Path("/nonexistent"), "0A", "TCP", {})
        self.assertEqual(res, [])

    @patch("pathlib.Path.exists", autospec=True)
    def test_parse_proc_net_file_parsing(self, mock_exists):
        """Verify that /proc/net file rows are correctly parsed."""
        mock_exists.return_value = True
        fake_content = (
            "  sl  local_address                         remote_address                         st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000\n"
        )
        
        inode_map = {"12345": "nginx (PID: 100)"}
        
        with patch("builtins.open", mock_open(read_data=fake_content)):
            res = _parse_proc_net_file(Path("/proc/net/tcp"), "0A", "TCP", inode_map)
            
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["port"], 80)
        self.assertEqual(res[0]["protocol"], "TCP")
        self.assertEqual(res[0]["process_name"], "nginx (PID: 100)")

    @patch("orin.collectors.connections._get_socket_inode_map")
    @patch("orin.collectors.connections._parse_proc_net_file")
    def test_gather_listening_ports(self, mock_parse, mock_inode):
        """Verify gather_listening_ports aggregates and deduplicates results correctly."""
        mock_inode.return_value = {}
        
        # Mock returns for TCP IPv4, TCP IPv6, UDP IPv4, UDP IPv6
        mock_parse.side_effect = [
            [{"port": 80, "protocol": "TCP", "process_name": "nginx (PID: 100)"}], # tcp
            [{"port": 80, "protocol": "TCP", "process_name": "nginx (PID: 100)"}], # tcp6 (duplicate, will be deduplicated)
            [{"port": 53, "protocol": "UDP", "process_name": "dnsmasq (PID: 200)"}], # udp
            [] # udp6
        ]

        ports = gather_listening_ports()
        self.assertEqual(len(ports), 2)
        # Deduplication checks: Only one TCP port 80 and one UDP port 53
        protocols = {p["protocol"] for p in ports}
        self.assertEqual(protocols, {"TCP", "UDP"})
        self.assertIn(80, [p["port"] for p in ports])
        self.assertIn(53, [p["port"] for p in ports])

    @patch("orin.collectors.connections._get_socket_inode_map")
    @patch("pathlib.Path.exists", autospec=True)
    def test_gather_outbound_connections(self, mock_exists, mock_inode):
        """Verify gather_outbound_connections collects established sockets and filters loopback."""
        mock_inode.return_value = {"9999": "curl (PID: 999)"}
        mock_exists.side_effect = lambda self: self == Path("/proc/net/tcp")

        fake_tcp_content = (
            "  sl  local_address remote_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            # Established external connection (10.0.2.15:1234 -> 8.8.8.8:53)
            "   0: 0F02000A:04D2 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 9999 1 00000000\n"
            # Loopback connection (127.0.0.1 -> 127.0.0.1) - should be skipped
            "   1: 0100007F:04D3 0100007F:01BB 01 00000000:00000000 00:00000000 00:00000000  1000        0 9998 1 00000000\n"
        )

        with patch("builtins.open", mock_open(read_data=fake_tcp_content)):
            connections = gather_outbound_connections()

        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0]["remote_ip"], "8.8.8.8")
        self.assertEqual(connections[0]["remote_port"], 53)
        self.assertEqual(connections[0]["local_ip"], "10.0.2.15")
        self.assertEqual(connections[0]["local_port"], 1234)
        self.assertEqual(connections[0]["process_name"], "curl (PID: 999)")

    @patch("orin.collectors.connections._get_socket_inode_map")
    @patch("pathlib.Path.exists", autospec=True)
    def test_gather_outbound_connections_ipv6(self, mock_exists, mock_inode):
        """Verify gather_outbound_connections collects established IPv6 sockets and filters loopback."""
        mock_inode.return_value = {"8888": "ssh (PID: 888)"}
        mock_exists.side_effect = lambda self: self == Path("/proc/net/tcp6")

        if sys.byteorder == "little":
            hex_external = "B80D0120000000000000000002000000"
            hex_loopback = "00000000000000000000000001000000"
        else:
            hex_external = "20010DB8000000000000000000000002"
            hex_loopback = "00000000000000000000000000000001"

        fake_tcp6_content = (
            "  sl  local_address remote_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            # Established external connection (::1 -> 2001:db8::2)
            f"   0: {hex_loopback}:04D2 {hex_external}:0016 01 00000000:00000000 00:00000000 00000000  1000        0 8888 1 00000000\n"
            # Loopback connection (2001:db8::2 -> ::1) - should be skipped
            f"   1: {hex_external}:04D3 {hex_loopback}:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 8887 1 00000000\n"
        )

        with patch("builtins.open", mock_open(read_data=fake_tcp6_content)):
            connections = gather_outbound_connections()

        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0]["remote_ip"], "2001:db8::2")
        self.assertEqual(connections[0]["remote_port"], 22)
        self.assertEqual(connections[0]["process_name"], "ssh (PID: 888)")

    @patch("orin.collectors.connections.PROC_PATH")
    @patch("os.readlink")
    def test_get_socket_inode_map(self, mock_readlink, mock_proc_path):
        """Verify that _get_socket_inode_map builds the correct mapping from /proc directory structures."""
        mock_proc_path.exists.return_value = True
        
        # Mock directory structure for a process PID 500
        mock_pid_dir = MagicMock()
        mock_pid_dir.is_dir.return_value = True
        mock_pid_dir.name = "500"
        
        mock_proc_path.iterdir.return_value = [mock_pid_dir]

        # comm file mock to return process name
        mock_comm_path = MagicMock()
        mock_comm_path.exists.return_value = True
        mock_comm_path.read_text.return_value = "mydaemon\n"

        # fd directory with symlink
        mock_fd_dir = MagicMock()
        mock_fd_dir.exists.return_value = True
        
        mock_fd_link = MagicMock()
        mock_fd_dir.iterdir.return_value = [mock_fd_link]

        # Connect Paths
        def path_side_effect(name):
            if name == "fd":
                return mock_fd_dir
            elif name == "comm":
                return mock_comm_path
            return MagicMock()

        mock_pid_dir.__truediv__.side_effect = path_side_effect
        mock_readlink.return_value = "socket:[654321]"

        inode_map = _get_socket_inode_map()
        self.assertEqual(inode_map.get("654321"), "mydaemon (PID: 500)")

if __name__ == "__main__":
    unittest.main()
