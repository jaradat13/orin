# src/orin/core/database.py
"""
orin.core.database – Relational Local Forensic Vault
===================================================
Manages the lifecycle of the Orin offline SQLite storage layer, handles table
schema deployments, maps data-streaming insertions, and enforces row factories.
"""

import sqlite3
import os
import platform
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager


class OrinStorage:
    """Encapsulates connections and schema workflows for the local SQLite vault."""

    def __init__(self, db_path: Path):
        """Initialize storage engine bounds.

        Parameters
        ----------
        db_path : Path
            Filesystem location where the SQLite database will be written.
        """
        self.db_path = Path(db_path)

    @contextmanager
    def get_connection(self):
        """Yield an open transaction-ready database connection handle.

        Foreign-key enforcement is enabled for every connection. Rows are
        returned as sqlite3.Row objects so columns can be accessed by name.
        """
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.row_factory = sqlite3.Row
        # Enable write-ahead-logging for performance resilience if running on disk
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
        except sqlite3.Error:
            pass
        try:
            yield conn
        finally:
            conn.close()

    def initialize_db(self):
        """Deploy table layouts and operational indices."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Core Tracking Tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    hostname TEXT NOT NULL,
                    os_platform TEXT NOT NULL
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    raw_details TEXT,
                    notes TEXT DEFAULT '',
                    suppressed INTEGER DEFAULT 0,
                    reviewed_at TEXT,
                    resolved INTEGER DEFAULT 0
                );
            """)

            # 2. Approved System Baseline Tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baseline_kernel_modules (
                    module_name TEXT PRIMARY KEY,
                    memory_size INTEGER NOT NULL
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baseline_users (
                    username TEXT PRIMARY KEY,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL,
                    home_dir TEXT,
                    login_shell TEXT
                );
            """)

            # 3. Collected Telemetry Tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_processes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    ppid INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    exe TEXT,
                    cmdline TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    process_name TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_outbound_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    local_ip TEXT,
                    local_port INTEGER,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    state TEXT,
                    process_name TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_kernel_modules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    module_name TEXT NOT NULL,
                    memory_size INTEGER NOT NULL,
                    instances_loaded INTEGER NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL,
                    home_dir TEXT,
                    login_shell TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_ssh_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    user_account TEXT NOT NULL,
                    key_type TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    raw_key_comment TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_file_hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    mtime REAL,
                    ctime REAL,
                    size INTEGER,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_deleted_binaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    exe TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    md5 TEXT NOT NULL,
                    vault_path TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_promisc_interfaces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    interface TEXT NOT NULL,
                    flags TEXT NOT NULL,
                    is_promiscuous INTEGER NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_wtmp_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    user TEXT NOT NULL,
                    line TEXT NOT NULL,
                    host TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    login_time TEXT,
                    logout_time TEXT,
                    anomaly_detected INTEGER DEFAULT 0,
                    anomaly_reason TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_lastlog_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    uid INTEGER NOT NULL,
                    line TEXT,
                    host TEXT,
                    login_time TEXT,
                    anomaly_detected INTEGER DEFAULT 0,
                    anomaly_reason TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_pkg_integrity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    package TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    expected_md5 TEXT NOT NULL,
                    actual_md5 TEXT,
                    actual_sha256 TEXT,
                    status TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_crontabs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    user TEXT NOT NULL,
                    schedule TEXT NOT NULL,
                    command TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            # 4. Performance Look-up Optimizations (Indices)
            tables_to_index = [
                "collected_processes", "collected_ports", "collected_outbound_connections",
                "collected_kernel_modules", "collected_users", "collected_ssh_keys",
                "collected_file_hashes", "collected_deleted_binaries", "collected_promisc_interfaces",
                "collected_wtmp_sessions", "collected_lastlog_records", "collected_pkg_integrity",
                "collected_crontabs"
            ]
            for t in tables_to_index:
                cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{t}_snap ON {t}(snapshot_id);")

            # Schema Migration: ensure security_events has the new columns
            cursor.execute("PRAGMA table_info(security_events);")
            columns = {row["name"] for row in cursor.fetchall()}
            if "notes" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN notes TEXT DEFAULT '';")
            if "suppressed" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN suppressed INTEGER DEFAULT 0;")
            if "reviewed_at" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN reviewed_at TEXT;")

            conn.commit()

    def create_snapshot(self, conn: sqlite3.Connection) -> int:
        """Register snapshot details and return its autoincremented key identifier."""
        cursor = conn.cursor()
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        hostname = platform.node() or "unknown_host"
        os_platform = platform.platform() or "Linux"
        
        cursor.execute(
            "INSERT INTO system_snapshots (timestamp, hostname, os_platform) VALUES (?, ?, ?);",
            (now_str, hostname, os_platform)
        )
        return cursor.lastrowid

    # Transaction-Safe Bulk Telemetry Storage APIs
    def store_processes(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["pid"], r["ppid"], r["name"], r["exe"], r["cmdline"]) for r in records]
        )

    def store_ports(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (?, ?, ?, ?);",
            [(snapshot_id, r["port"], r["protocol"], r["process_name"]) for r in records]
        )

    def store_outbound_connections(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            """
            INSERT INTO collected_outbound_connections 
            (snapshot_id, local_ip, local_port, remote_ip, remote_port, state, process_name) 
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r["local_ip"], r["local_port"], r["remote_ip"], r["remote_port"], r["state"], r["process_name"]) for r in records]
        )

    def store_kernel_modules(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_kernel_modules (snapshot_id, module_name, memory_size, instances_loaded) VALUES (?, ?, ?, ?);",
            [(snapshot_id, r["module_name"], r["memory_size"], r["instances_loaded"]) for r in records]
        )

    def store_users(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_users (snapshot_id, username, uid, gid, home_dir, login_shell) VALUES (?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["username"], r["uid"], r["gid"], r["home_dir"], r["login_shell"]) for r in records]
        )

    def store_ssh_keys(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_ssh_keys (snapshot_id, user_account, key_type, fingerprint, raw_key_comment) VALUES (?, ?, ?, ?, ?);",
            [(snapshot_id, r["user_account"], r["key_type"], r["fingerprint"], r["raw_key_comment"]) for r in records]
        )

    def store_file_hashes(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_file_hashes (snapshot_id, file_path, sha256_hash, mtime, ctime, size) VALUES (?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["file_path"], r["sha256_hash"], r["mtime"], r["ctime"], r["size"]) for r in records]
        )

    def store_deleted_binaries(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_deleted_binaries (snapshot_id, pid, exe, sha256, md5, vault_path) VALUES (?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["pid"], r["exe"], r["sha256"], r["md5"], r["vault_path"]) for r in records]
        )

    def store_promisc_interfaces(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_promisc_interfaces (snapshot_id, interface, flags, is_promiscuous) VALUES (?, ?, ?, ?);",
            [(snapshot_id, r["interface"], r["flags"], r["is_promiscuous"]) for r in records]
        )

    def store_wtmp_sessions(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            """
            INSERT INTO collected_wtmp_sessions 
            (snapshot_id, user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r["user"], r["line"], r["host"], r["pid"], r["login_time"], r["logout_time"], r["anomaly_detected"], r["anomaly_reason"]) for r in records]
        )

    def store_lastlog_records(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            """
            INSERT INTO collected_lastlog_records 
            (snapshot_id, username, uid, line, host, login_time, anomaly_detected, anomaly_reason) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r["username"], r["uid"], r["line"], r["host"], r["login_time"], r["anomaly_detected"], r["anomaly_reason"]) for r in records]
        )

    def store_pkg_integrity(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_pkg_integrity (snapshot_id, package, file_path, expected_md5, actual_md5, actual_sha256, status) VALUES (?, ?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["package"], r["file_path"], r["expected_md5"], r["actual_md5"], r["actual_sha256"], r["status"]) for r in records]
        )

    def store_crontabs(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) VALUES (?, ?, ?, ?, ?);",
            [(snapshot_id, r["source"], r["user"], r["schedule"], r["command"]) for r in records]
        )