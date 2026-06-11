#!/usr/bin/env python3
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
Test suite for triggered_pcap module
=====================================
Tests the TriggeredPcapCapture and PacketBuffer classes for correct
ring-buffer behavior, trigger handling, and PCAP file generation.
"""
import os
import sys
import time
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from orin.collectors.triggered_pcap import (
    PacketBuffer,
    TriggeredPcapCapture,
    create_pcap_from_connections,
    on_yara_match,
    on_ioc_hit
)


def test_packet_buffer_basic():
    """Test basic packet buffer operations."""
    print("Testing PacketBuffer basic operations...")

    buffer = PacketBuffer(max_packets=100, max_memory_mb=10.0)

    # Test adding packets
    for i in range(10):
        packet_data = b"test_packet_" + bytes([i])
        timestamp = time.time()
        metadata = {'src_ip': '192.168.1.1', 'dst_ip': '10.0.0.1'}

        result = buffer.add_packet(packet_data, timestamp, metadata)
        assert result, f"Failed to add packet {i}"

    stats = buffer.stats()
    assert stats['current_packets'] == 10, f"Expected 10 packets, got {stats['current_packets']}"
    assert stats['total_packets_seen'] == 10
    assert stats['dropped_packets'] == 0

    print("✓ Basic packet addition works")

    # Test retrieving packets
    packets = buffer.get_packets()
    assert len(packets) == 10, f"Expected 10 packets, got {len(packets)}"

    print("✓ Packet retrieval works")

    # Test filtering by IP
    filtered = buffer.get_packets(src_ip='192.168.1.1')
    assert len(filtered) == 10, "IP filtering failed"

    filtered = buffer.get_packets(src_ip='192.168.1.999')
    assert len(filtered) == 0, "Should return empty for non-existent IP"

    print("✓ Packet filtering works")

    # Test clear
    buffer.clear()
    stats = buffer.stats()
    assert stats['current_packets'] == 0
    assert stats['memory_bytes'] == 0

    print("✓ Buffer clear works")

    return True


def test_packet_buffer_ring_behavior():
    """Test ring-buffer overflow behavior."""
    print("\nTesting PacketBuffer ring-buffer behavior...")

    # Small buffer to force overflow
    buffer = PacketBuffer(max_packets=5, max_memory_mb=0.001)

    # Add more packets than buffer size
    for i in range(20):
        packet_data = b"x" * 100  # 100 bytes each
        timestamp = time.time()
        buffer.add_packet(packet_data, timestamp)

    stats = buffer.stats()

    # Should have at most max_packets
    assert stats['current_packets'] <= 5, f"Buffer exceeded max: {stats['current_packets']}"
    assert stats['dropped_packets'] > 0, "Should have dropped packets"
    assert stats['total_packets_seen'] == 20

    print(f"✓ Ring buffer working: {stats['dropped_packets']} packets dropped, {stats['current_packets']} retained")

    return True


def test_triggered_pcap_initialization():
    """Test TriggeredPcapCapture initialization."""
    print("\nTesting TriggeredPcapCapture initialization...")

    with tempfile.TemporaryDirectory() as tmpdir:
        capture = TriggeredPcapCapture(
            capture_dir=tmpdir,
            pre_trigger_seconds=10.0,
            post_trigger_seconds=20.0,
            max_buffer_mb=25.0
        )

        assert capture.capture_dir == Path(tmpdir)
        assert capture.pre_trigger_seconds == 10.0
        assert capture.post_trigger_seconds == 20.0
        assert capture.max_buffer_mb == 25.0

        stats = capture.get_stats()
        assert stats['is_capturing'] == False
        assert stats['triggers_fired'] == 0

        print("✓ Initialization successful")

    return True


def test_triggered_pcap_start_stop():
    """Test starting and stopping capture."""
    print("\nTesting TriggeredPcapCapture start/stop...")

    with tempfile.TemporaryDirectory() as tmpdir:
        capture = TriggeredPcapCapture(capture_dir=tmpdir)

        # Start capture
        result = capture.start_capture()
        assert result, "Failed to start capture"

        time.sleep(2)  # Let it run briefly

        stats = capture.get_stats()
        assert stats['is_capturing'] == True

        # Stop capture
        files = capture.stop_capture()

        time.sleep(1)  # Allow cleanup
        stats = capture.get_stats()
        assert stats['is_capturing'] == False

        print(f"✓ Start/stop successful, {len(files)} files created")

    return True


def test_trigger_event():
    """Test trigger event handling."""
    print("\nTesting trigger event handling...")

    with tempfile.TemporaryDirectory() as tmpdir:
        capture = TriggeredPcapCapture(
            capture_dir=tmpdir,
            pre_trigger_seconds=5.0,
            post_trigger_seconds=2.0  # Shorter for faster test
        )

        # Start capture
        capture.start_capture()
        time.sleep(1)  # Brief startup

        # Manually add some packets to buffer for testing
        base_time = time.time()
        for i in range(5):
            packet_data = b"test_packet_" + bytes([i]) * 20
            metadata = {'src_ip': '192.168.1.100', 'dst_ip': '10.0.0.50'}
            capture.packet_buffer.add_packet(packet_data, base_time + i * 0.1, metadata)

        time.sleep(0.5)

        # Fire a trigger
        trigger_details = {
            'rule': 'Test_Malware_Rule',
            'file': '/tmp/suspicious.exe',
            'match_string': 'malicious_pattern'
        }

        target_ips = {'192.168.1.100', '10.0.0.50'}

        pcap_file = capture.on_trigger(
            trigger_id='test_trigger_001',
            trigger_type='yara',
            trigger_details=trigger_details,
            target_ips=target_ips
        )

        assert pcap_file, "Trigger did not create PCAP file"
        assert Path(pcap_file).exists(), f"PCAP file not found: {pcap_file}"

        stats = capture.get_stats()
        assert stats['triggers_fired'] == 1
        assert stats['files_written'] >= 1

        print(f"✓ Trigger fired successfully: {pcap_file}")

        # Stop immediately (don't wait for post-trigger)
        capture.stop_capture()

        captured_files = capture.get_captured_pcaps()
        assert len(captured_files) >= 1

        # Verify metadata
        meta = captured_files[0]
        assert meta['trigger_id'] == 'test_trigger_001'
        assert meta['trigger_type'] == 'yara'
        assert meta['trigger_details'] == trigger_details

        print("✓ Trigger metadata correct")

    return True


def test_multiple_triggers():
    """Test multiple concurrent triggers."""
    print("\nTesting multiple concurrent triggers...")

    with tempfile.TemporaryDirectory() as tmpdir:
        capture = TriggeredPcapCapture(capture_dir=tmpdir)
        capture.start_capture()
        time.sleep(0.5)

        # Manually add packets to buffer
        base_time = time.time()
        for i in range(10):
            packet_data = b"multi_test_" + bytes([i]) * 10
            metadata = {'src_ip': f'192.168.1.{i % 3}', 'dst_ip': '10.0.0.1'}
            capture.packet_buffer.add_packet(packet_data, base_time + i * 0.1, metadata)

        # Fire multiple triggers
        for i in range(3):
            trigger_details = {'rule': f'Rule_{i}', 'severity': 'high'}

            pcap_file = capture.on_trigger(
                trigger_id=f'multi_trigger_{i}',
                trigger_type='ioc',
                trigger_details=trigger_details,
                target_ips={f'192.168.1.{i}'}
            )

            assert pcap_file, f"Trigger {i} failed"

        stats = capture.get_stats()
        assert stats['triggers_fired'] == 3

        print(f"✓ Multiple triggers handled: {stats['triggers_fired']} triggers")

        capture.stop_capture()

        captured_files = capture.get_captured_pcaps()
        trigger_files = [f for f in captured_files if f['trigger_type'] != 'manual']
        assert len(trigger_files) == 3

        print(f"✓ All {len(trigger_files)} PCAP files created")

    return True


def test_create_pcap_from_connections():
    """Test creating PCAP from connection records."""
    print("\nTesting create_pcap_from_connections...")

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, 'connections.pcap')

        connections = [
            {
                'local_ip': '192.168.1.10',
                'local_port': 45678,
                'remote_ip': '10.0.0.1',
                'remote_port': 80,
                'protocol': 'TCP'
            },
            {
                'local_ip': '192.168.1.10',
                'local_port': 45679,
                'remote_ip': '10.0.0.2',
                'remote_port': 443,
                'protocol': 'TCP'
            },
            {
                'local_ip': '192.168.1.10',
                'local_port': 53000,
                'remote_ip': '8.8.8.8',
                'remote_port': 53,
                'protocol': 'UDP'
            }
        ]

        result_path = create_pcap_from_connections(connections, output_path)

        if result_path:
            assert Path(result_path).exists(), "PCAP file not created"
            assert Path(result_path).stat().st_size > 0, "PCAP file is empty"
            print(f"✓ Created PCAP with {len(connections)} connections: {result_path}")
        else:
            print("⚠ Scapy not available, skipping actual PCAP creation")

    return True


def test_convenience_functions():
    """Test convenience functions for YARA/IOC integration."""
    print("\nTesting convenience functions...")

    with tempfile.TemporaryDirectory() as tmpdir:
        capture = TriggeredPcapCapture(capture_dir=tmpdir)
        capture.start_capture()
        time.sleep(0.5)

        # Add packets to buffer first
        base_time = time.time()
        for i in range(3):
            packet_data = b"conv_test_" + bytes([i]) * 15
            metadata = {'src_ip': '185.220.101.1', 'dst_ip': '192.168.1.1'}
            capture.packet_buffer.add_packet(packet_data, base_time + i * 0.1, metadata)

        # Test on_yara_match
        yara_match = {
            'rule': 'CryptoMiner_Generic',
            'file': '/tmp/miner',
            'strings': ['stratum+tcp', 'wallet_address']
        }

        result = on_yara_match(yara_match, capture, target_ips={'pool.mining.com'})
        assert result is not None, "on_yara_match failed"
        print(f"✓ on_yara_match created: {os.path.basename(result)}")

        # Test on_ioc_hit
        ioc_match = {
            'type': 'ip',
            'value': '185.220.101.1',
            'source': 'threat_feed',
            'confidence': 0.95
        }

        result = on_ioc_hit(ioc_match, capture, matched_ips={'185.220.101.1'})
        assert result is not None, "on_ioc_hit failed"
        print(f"✓ on_ioc_hit created: {os.path.basename(result)}")

        capture.stop_capture()

    return True


def test_buffer_time_filtering():
    """Test time-based packet filtering."""
    print("\nTesting time-based packet filtering...")

    buffer = PacketBuffer(max_packets=1000)

    base_time = time.time()

    # Add packets with different timestamps
    for i in range(10):
        packet_data = b"packet_" + bytes([i])
        timestamp = base_time + i  # 1 second apart
        buffer.add_packet(packet_data, timestamp)

    # Filter by time range
    start_time = base_time + 3
    end_time = base_time + 7

    filtered = buffer.get_packets(start_time=start_time, end_time=end_time)

    # Should get packets from index 3 to 7 (5 packets)
    assert len(filtered) == 5, f"Expected 5 packets, got {len(filtered)}"

    print(f"✓ Time filtering works: {len(filtered)} packets in range")

    return True


def test_statistics_accuracy():
    """Test accuracy of statistics reporting."""
    print("\nTesting statistics accuracy...")

    buffer = PacketBuffer(max_packets=100, max_memory_mb=1.0)

    # Add known number of packets
    packet_size = 100
    num_packets = 50

    for i in range(num_packets):
        packet_data = b"x" * packet_size
        buffer.add_packet(packet_data, time.time())

    stats = buffer.stats()

    assert stats['current_packets'] == num_packets
    assert stats['total_packets_seen'] == num_packets
    assert stats['memory_bytes'] == num_packets * packet_size
    assert abs(stats['memory_mb'] - (num_packets * packet_size / 1024 / 1024)) < 0.001

    print(f"✓ Statistics accurate: {stats['memory_mb']:.4f} MB used")

    return True


def run_all_tests():
    """Run all tests and report results."""
    print("="*60)
    print("Running Triggered PCAP Module Tests")
    print("="*60)

    tests = [
        ("Packet Buffer Basic", test_packet_buffer_basic),
        ("Packet Buffer Ring Behavior", test_packet_buffer_ring_behavior),
        ("Triggered PCAP Init", test_triggered_pcap_initialization),
        ("Triggered PCAP Start/Stop", test_triggered_pcap_start_stop),
        ("Trigger Event Handling", test_trigger_event),
        ("Multiple Triggers", test_multiple_triggers),
        ("Create PCAP from Connections", test_create_pcap_from_connections),
        ("Convenience Functions", test_convenience_functions),
        ("Time Filtering", test_buffer_time_filtering),
        ("Statistics Accuracy", test_statistics_accuracy),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✅ PASS: {test_name}\n")
            else:
                failed += 1
                print(f"❌ FAIL: {test_name}\n")
        except Exception as e:
            failed += 1
            print(f"❌ ERROR: {test_name} - {e}\n")
            import traceback
            traceback.print_exc()

    print("="*60)
    print(f"Test Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("="*60)

    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)