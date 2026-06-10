#!/usr/bin/env python3
"""
Orin eBPF Real-Time Streamer Consumer

This script loads the eBPF program, attaches to tracepoints,
and consumes events from the ring buffer in real-time.
It queues events to the local SQLite database and triggers threat analysis.
"""

import os
import sys
import time
import signal
import sqlite3
import argparse
from datetime import datetime
from pathlib import Path

try:
    from bcc import BPF
except ImportError:
    print("Error: 'bcc' or 'bpfcc' python package not found.")
    print("Please install it: sudo apt-get install bpfcc-python OR pip install bcc")
    sys.exit(1)

# Configuration
DB_PATH = Path(__file__).parent.parent / "data" / "orin.db"
EBPF_PROGRAM_PATH = Path(__file__).parent / "streamer.c"

# Ensure DB directory exists
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def init_db():
    """Initialize the database schema for streaming events if not exists."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS stream_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp_ns INTEGER,
        timestamp_human TEXT,
        pid INTEGER,
        uid INTEGER,
        event_type INTEGER,
        comm TEXT,
        filename TEXT,
        processed BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_stream_ts ON stream_events(timestamp_ns)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_stream_pid ON stream_events(pid)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_stream_type ON stream_events(event_type)")

    conn.commit()
    conn.close()

def parse_event_type(t):
    types = {1: "EXEC", 2: "CONNECT", 3: "FILE_OPEN"}
    return types.get(t, "UNKNOWN")

def handle_event(ctx, data, size):
    """Callback function called by BCC when an event is available in the ring buffer."""
    # Define the event structure matching the C struct
    # struct event { u32 pid; u32 uid; u32 type; char comm[16]; char filename[256]; u64 timestamp; }
    # Format: III16s256sQ (3 unsigned ints, 16-char string, 256-char string, 1 unsigned long long)
    import ctypes

    class Event(ctypes.Structure):
        _fields_ = [
            ("pid", ctypes.c_uint),
            ("uid", ctypes.c_uint),
            ("etype", ctypes.c_uint),
            ("comm", ctypes.c_char * 16),
            ("filename", ctypes.c_char * 256),
            ("timestamp", ctypes.c_ulonglong)
        ]

    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    ts_ns = event.timestamp
    ts_human = datetime.utcfromtimestamp(ts_ns / 1e9).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    comm_str = event.comm.decode('utf-8', errors='ignore').rstrip('\x00')
    filename_str = event.filename.decode('utf-8', errors='ignore').rstrip('\x00')
    etype = parse_event_type(event.etype)

    print(f"[{ts_human}] {etype} | PID:{event.pid} UID:{event.uid} | Comm:{comm_str} | File:{filename_str}")

    # Store in database
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO stream_events (timestamp_ns, timestamp_human, pid, uid, event_type, comm, filename)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ts_ns, ts_human, event.pid, event.uid, event.etype, comm_str, filename_str))
        conn.commit()
        conn.close()

        # TODO: Trigger async threat engine analysis here based on event data
        # analyze_threat(event)

    except Exception as e:
        print(f"Error storing event: {e}")

def main():
    parser = argparse.ArgumentParser(description="Orin eBPF Real-Time Streamer")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug output")
    args = parser.parse_args()

    print(f"[*] Orin eBPF Streamer Starting...")
    print(f"[*] Loading eBPF program from: {EBPF_PROGRAM_PATH}")

    if not EBPF_PROGRAM_PATH.exists():
        print(f"[!] Error: eBPF program not found at {EBPF_PROGRAM_PATH}")
        sys.exit(1)

    # Initialize Database
    init_db()
    print(f"[*] Database ready at: {DB_PATH}")

    # Load BPF Program
    try:
        b = BPF(src_file=str(EBPF_PROGRAM_PATH))
    except Exception as e:
        print(f"[!] Failed to load eBPF program: {e}")
        print("Note: This requires root privileges and a kernel with BTF support.")
        sys.exit(1)

    print("[*] eBPF program loaded successfully.")

    # Attach to Ring Buffer
    rb = b["rb"]
    rb.open_ring_buffer(handle_event)

    print("[*] Attached to ring buffer. Waiting for events... (Ctrl+C to stop)")

    # Handle graceful shutdown
    running = True
    def signal_handler(sig, frame):
        nonlocal running
        print("\n[*] Shutting down gracefully...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        while running:
            # Poll the ring buffer with a timeout of 100ms
            rb.poll(timeout=100)
    except KeyboardInterrupt:
        pass
    finally:
        rb.close()
        print("[*] Orin eBPF Streamer stopped.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Warning: Not running as root. eBPF programs usually require root privileges.")
        # We don't exit here to allow testing in restricted environments, but it will likely fail.

    main()