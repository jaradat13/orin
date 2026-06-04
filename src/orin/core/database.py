# orin/core/database.py
"""
orin.core.database – SQLite Vault Schema & ORM
===============================================
Defines the full relational schema used by Orin to store forensic telemetry
across multiple point-in-time snapshots.  The :class:`OrinStorage` class
wraps every database interaction behind a safe ``contextmanager`` connection,
ensuring connections are always closed even when exceptions occur.

Schema overview
---------------
system_snapshots             – One row per ``orin collect`` run.
collected_processes          – Process list for each snapshot.
collected_ports              – Listening TCP/UDP ports per snapshot.
collected_outbound_connections – Established outbound TCP sessions per snapshot.
collected_kernel_modules     – Loaded LKMs per snapshot.
collected_ssh_keys           – SSH authorized_keys inventory per snapshot.
collected_file_hashes        – SHA-256 FIM records per snapshot.
collected_users              – /etc/passwd account entries per snapshot.
security_events              – Persistent alert ledger (append-only by design).
baseline_kernel_modules      – Trusted-module allowlist captured at ``init``.
baseline_users               – Trusted-user allowlist captured at ``init``.
"""
from contextlib import contextmanager
import sqlite3
from pathlib import Path

#: SQL DDL executed once during :meth:`OrinStorage.initialize_db` to create
#: all tables if they do not yet exist.  ``CREATE TABLE IF NOT EXISTS``
#: semantics make it safe to call ``initialize_db`` more than once.
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

CREATE TABLE IF NOT EXISTS collected_deleted_binaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    exe TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    md5 TEXT NOT NULL,
    vault_path TEXT NOT NULL,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collected_promisc_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    interface TEXT NOT NULL,
    flags TEXT NOT NULL,
    is_promiscuous INTEGER NOT NULL,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collected_wtmp_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    user TEXT NOT NULL,
    line TEXT NOT NULL,
    host TEXT NOT NULL,
    pid INTEGER NOT NULL,
    login_time TEXT,
    logout_time TEXT,
    anomaly_detected INTEGER NOT NULL,
    anomaly_reason TEXT,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collected_lastlog_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    uid INTEGER NOT NULL,
    line TEXT NOT NULL,
    host TEXT NOT NULL,
    login_time TEXT,
    anomaly_detected INTEGER NOT NULL,
    anomaly_reason TEXT,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collected_pkg_integrity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    package TEXT NOT NULL,
    file_path TEXT NOT NULL,
    expected_md5 TEXT NOT NULL,
    actual_md5 TEXT,
    actual_sha256 TEXT,
    status TEXT NOT NULL,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collected_crontabs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    user TEXT NOT NULL,
    schedule TEXT NOT NULL,
    command TEXT NOT NULL,
    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id) ON DELETE CASCADE
);
"""


class OrinStorage:
    """Lightweight SQLite access layer for the Orin forensic vault.

    Parameters
    ----------
    db_path : Path
        Absolute (or relative) path to the SQLite database file.  The file
        and any parent directories are created automatically by
        :meth:`initialize_db`.

    Examples
    --------
    >>> from pathlib import Path
    >>> store = OrinStorage(Path("/var/lib/orin/orin_vault.db"))
    >>> store.initialize_db()
    >>> with store.get_connection() as conn:
    ...     conn.execute("SELECT COUNT(*) FROM system_snapshots")
    """

    def __init__(self, db_path: Path):
        """Initialise the storage wrapper.

        Parameters
        ----------
        db_path : Path
            Path to the SQLite ``.db`` file that will be used or created.
        """
        self.db_path = db_path
        
    @contextmanager
    def get_connection(self):
        """Yield an open :class:`sqlite3.Connection`, then close it automatically.

        Foreign-key enforcement is enabled for every connection.  Rows are
        returned as :class:`sqlite3.Row` objects so columns can be accessed
        by name.

        Yields
        ------
        sqlite3.Connection
            A ready-to-use database connection.

        Notes
        -----
        Use this method as a context manager (``with store.get_connection() as
        conn``) to ensure the connection is always released.
        """
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def initialize_db(self) -> None:
        """Create the database file and apply the full schema.

        Parent directories of :attr:`db_path` are created with
        ``parents=True, exist_ok=True``.  All ``CREATE TABLE IF NOT EXISTS``
        statements in :data:`SCHEMA_SQL` are executed atomically inside a
        single :meth:`sqlite3.Connection.executescript` call.

        Raises
        ------
        sqlite3.Error
            If any SQL statement fails to execute.
        """
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()

    