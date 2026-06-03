# orin/core/database.py
from contextlib import contextmanager
import sqlite3
from pathlib import Path

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS system_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    hostname TEXT NOT NULL,
    os_platform TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline_kernel_modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_name TEXT NOT NULL UNIQUE,
    memory_size INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS collected_processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER NOT NULL,
    name TEXT NOT NULL,
    exe TEXT,
    cmdline TEXT,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collected_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    process_name TEXT,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collected_outbound_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    local_ip TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    state TEXT,
    process_name TEXT,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collected_kernel_modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    module_name TEXT NOT NULL,
    memory_size INTEGER NOT NULL,
    instances_loaded INTEGER NOT NULL,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collected_ssh_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    user_account TEXT NOT NULL,
    key_type TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    raw_key_comment TEXT,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collected_file_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    raw_details TEXT,
    resolved INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS baseline_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL,
    home_dir TEXT,
    login_shell TEXT
);

CREATE TABLE IF NOT EXISTS collected_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL,
    home_dir TEXT,
    login_shell TEXT,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);
"""

class OrinStorage:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def initialize_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()

    