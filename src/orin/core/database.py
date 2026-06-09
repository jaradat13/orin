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
# src/orin/core/database.py
"""
orin.core.database – Relational Local Forensic Vault
===================================================
Manages the lifecycle of the Orin offline SQLite storage layer, handles table
schema deployments, maps data-streaming insertions, and enforces row factories.

Security Features
-----------------
- AES-256-GCM encrypted database files at rest
- Key derivation via PBKDF2-HMAC-SHA256
- Tamper detection via GCM authentication tag
"""

import sqlite3
import platform
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets


def derive_key(passphrase: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """Derive a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.

    Parameters
    ----------
    passphrase : str
        User-provided passphrase for encryption.
    salt : bytes
        Random salt (16 bytes recommended).
    iterations : int
        PBKDF2 iteration count (default: 100,000).

    Returns
    -------
    bytes
        32-byte AES-256 key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode('utf-8'))


class EncryptedStorage:
    """Handles AES-256-GCM encryption/decryption of database files.

    Uses AES-256 in GCM mode for authenticated encryption, providing both
    confidentiality and integrity protection.
    """

    SALT_SIZE = 16
    NONCE_SIZE = 12
    TAG_SIZE = 16

    def __init__(self, passphrase: str):
        """Initialize encrypted storage with a passphrase.

        Parameters
        ----------
        passphrase : str
            Master passphrase for encryption/decryption.
        """
        if len(passphrase) < 12:
            raise ValueError("Passphrase must be at least 12 characters")
        self.passphrase = passphrase
        self._cached_key = None
        self._cached_salt = None

    def _get_or_create_key(self, db_path: Path) -> tuple[bytes, bytes]:
        """Get existing key or create new one for a database file.

        Parameters
        ----------
        db_path : Path
            Path to the encrypted database file.

        Returns
        -------
        tuple[bytes, bytes]
            Tuple of (derived_key, salt).
        """
        meta_path = db_path.with_suffix(db_path.suffix + '.meta')

        if meta_path.exists():
            # Load existing salt
            with open(meta_path, 'rb') as f:
                salt = f.read(self.SALT_SIZE)
            key = derive_key(self.passphrase, salt)
            return key, salt
        else:
            # Generate new salt and derive key
            salt = secrets.token_bytes(self.SALT_SIZE)
            key = derive_key(self.passphrase, salt)

            # Save salt to metadata file
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            with open(meta_path, 'wb') as f:
                f.write(salt)

            return key, salt

    def encrypt_file(self, plaintext_path: Path, ciphertext_path: Path) -> None:
        """Encrypt a database file in-place.

        Parameters
        ----------
        plaintext_path : Path
            Path to the unencrypted database.
        ciphertext_path : Path
            Path where encrypted database will be written.
        """
        key, salt = self._get_or_create_key(ciphertext_path)
        aesgcm = AESGCM(key)

        # Read plaintext
        with open(plaintext_path, 'rb') as f:
            plaintext = f.read()

        # Generate nonce and encrypt
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Write: salt (16) + nonce (12) + ciphertext
        with open(ciphertext_path, 'wb') as f:
            f.write(salt + nonce + ciphertext)

        # Remove plaintext
        plaintext_path.unlink()

    def decrypt_file(self, ciphertext_path: Path, plaintext_path: Path) -> None:
        """Decrypt a database file.

        Parameters
        ----------
        ciphertext_path : Path
            Path to the encrypted database.
        plaintext_path : Path
            Path where decrypted database will be written.
        """
        # Read salt from metadata file
        meta_path = ciphertext_path.with_suffix(ciphertext_path.suffix + '.meta')
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata file not found: {meta_path}")

        with open(meta_path, 'rb') as f:
            salt = f.read(self.SALT_SIZE)

        key = derive_key(self.passphrase, salt)
        aesgcm = AESGCM(key)

        # Read encrypted file: salt (16) + nonce (12) + ciphertext
        with open(ciphertext_path, 'rb') as f:
            stored_salt = f.read(self.SALT_SIZE)
            nonce = f.read(self.NONCE_SIZE)
            ciphertext = f.read()

        if stored_salt != salt:
            raise ValueError("Salt mismatch - possible tampering")

        # Decrypt
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise PermissionError(
                f"Decryption failed - possible tampering or wrong passphrase: {e}"
            )

        # Write plaintext
        plaintext_path.parent.mkdir(parents=True, exist_ok=True)
        with open(plaintext_path, 'wb') as f:
            f.write(plaintext)

    def cleanup(self, db_path: Path) -> None:
        """Remove encrypted database and metadata files.

        Parameters
        ----------
        db_path : Path
            Path to the encrypted database file.
        """
        meta_path = db_path.with_suffix(db_path.suffix + '.meta')
        if db_path.exists():
            db_path.unlink()
        if meta_path.exists():
            meta_path.unlink()


class OrinStorage:
    """Encapsulates connections and schema workflows for the local SQLite vault.

    Supports both plain and AES-256-GCM encrypted database files.
    """

    def __init__(self, db_path: Path, encryption_passphrase: str = None):
        """Initialize storage engine bounds.

        Parameters
        ----------
        db_path : Path
            Filesystem location where the SQLite database will be written.
        encryption_passphrase : str, optional
            If provided, database will be encrypted at rest using AES-256-GCM.
        """
        self.db_path = Path(db_path)
        self.encryption_passphrase = encryption_passphrase
        self.encrypted_storage = None
        self._temp_db_path = None

        if encryption_passphrase:
            self.encrypted_storage = EncryptedStorage(encryption_passphrase)
            self._encrypted_db_path = self.db_path.with_suffix(
                self.db_path.suffix + '.enc'
            )
            self._temp_db_path = self.db_path.with_suffix(
                self.db_path.suffix + '.tmp'
            )

    @contextmanager
    def get_connection(self):
        """Yield an open transaction-ready database connection handle.

        Foreign-key enforcement is enabled for every connection. Rows are
        returned as sqlite3.Row objects so columns can be accessed by name.

        If encryption is enabled, the database is temporarily decrypted,
        used, then re-encrypted on close.
        """
        if self.encrypted_storage and self._encrypted_db_path.exists():
            # Decrypt to temp location
            self.encrypted_storage.decrypt_file(
                self._encrypted_db_path,
                self._temp_db_path
            )
            db_to_use = self._temp_db_path
        elif self.encrypted_storage and self.db_path.exists():
            # Plain DB exists but encryption is enabled - encrypt it first
            self.encrypted_storage.encrypt_file(self.db_path, self._encrypted_db_path)
            self.encrypted_storage.decrypt_file(
                self._encrypted_db_path,
                self._temp_db_path
            )
            db_to_use = self._temp_db_path
        else:
            db_to_use = self.db_path

        conn = sqlite3.connect(db_to_use)
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

            # Re-encrypt if needed
            if self.encrypted_storage and self._temp_db_path.exists():
                self.encrypted_storage.encrypt_file(
                    self._temp_db_path,
                    self._encrypted_db_path
                )
                if self._temp_db_path.exists():
                    self._temp_db_path.unlink()

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
                    resolved INTEGER DEFAULT 0,
                    attck_technique TEXT,
                    attck_tactic TEXT,
                    attck_url TEXT,
                    hostname TEXT
                );
            """)

            # 2. Approved System Baseline Tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baseline_kernel_modules (
                    hostname TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    memory_size INTEGER NOT NULL,
                    PRIMARY KEY (hostname, module_name)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baseline_users (
                    hostname TEXT NOT NULL,
                    username TEXT NOT NULL,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL,
                    home_dir TEXT,
                    login_shell TEXT,
                    PRIMARY KEY (hostname, username)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baseline_suid_binaries (
                    hostname TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    grp TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    PRIMARY KEY (hostname, file_path)
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
                    ancestry_path TEXT,
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

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_suid_binaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    grp TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_auth_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    log_line TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_ebpf_programs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    bpf_id INTEGER,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    gpl_compatible INTEGER NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_ebpf_pinned (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    type TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_ld_preload (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    line TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_special_fds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    fd_num INTEGER NOT NULL,
                    fd_type TEXT NOT NULL,
                    resolved_path TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_persistence_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    source_path TEXT NOT NULL,
                    persistence_type TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    user_owner TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            # 4. Performance Look-up Optimizations (Indices)
            tables_to_index = [
                "collected_processes", "collected_ports", "collected_outbound_connections",
                "collected_kernel_modules", "collected_users", "collected_ssh_keys",
                "collected_file_hashes", "collected_deleted_binaries", "collected_promisc_interfaces",
                "collected_wtmp_sessions", "collected_lastlog_records", "collected_pkg_integrity",
                "collected_crontabs", "collected_suid_binaries", "collected_auth_logs",
                "collected_ebpf_programs", "collected_ebpf_pinned", "collected_ld_preload",
                "collected_special_fds", "collected_persistence_configs"
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
            if "attck_technique" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN attck_technique TEXT;")
            if "attck_tactic" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN attck_tactic TEXT;")
            if "attck_url" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN attck_url TEXT;")
            if "hostname" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN hostname TEXT;")
                current_host = platform.node() or "unknown_host"
                cursor.execute("UPDATE security_events SET hostname = ? WHERE hostname IS NULL;", (current_host,))

            # Backfill existing security events that are missing ATT&CK tagging
            cursor.execute("SELECT id, event_type, description FROM security_events WHERE attck_technique IS NULL;")
            unmapped_rows = cursor.fetchall()
            if unmapped_rows:
                from orin.analysis.attck import get_attck_enrichment
                for row in unmapped_rows:
                    tech, tactic, url = get_attck_enrichment(row["event_type"], row["description"])
                    cursor.execute(
                        "UPDATE security_events SET attck_technique = ?, attck_tactic = ?, attck_url = ? WHERE id = ?;",
                        (tech, tactic, url, row["id"])
                    )

            # Migrate baseline_kernel_modules
            cursor.execute("PRAGMA table_info(baseline_kernel_modules);")
            k_cols = {row["name"] for row in cursor.fetchall()}
            if "hostname" not in k_cols:
                current_host = platform.node() or "unknown_host"
                cursor.execute("""
                    CREATE TABLE baseline_kernel_modules_new (
                        hostname TEXT NOT NULL,
                        module_name TEXT NOT NULL,
                        memory_size INTEGER NOT NULL,
                        PRIMARY KEY (hostname, module_name)
                    );
                """)
                cursor.execute(
                    "INSERT INTO baseline_kernel_modules_new (hostname, module_name, memory_size) SELECT ?, module_name, memory_size FROM baseline_kernel_modules;",
                    (current_host,)
                )
                cursor.execute("DROP TABLE baseline_kernel_modules;")
                cursor.execute("ALTER TABLE baseline_kernel_modules_new RENAME TO baseline_kernel_modules;")

            # Migrate baseline_users
            cursor.execute("PRAGMA table_info(baseline_users);")
            u_cols = {row["name"] for row in cursor.fetchall()}
            if "hostname" not in u_cols:
                current_host = platform.node() or "unknown_host"
                cursor.execute("""
                    CREATE TABLE baseline_users_new (
                        hostname TEXT NOT NULL,
                        username TEXT NOT NULL,
                        uid INTEGER NOT NULL,
                        gid INTEGER NOT NULL,
                        home_dir TEXT,
                        login_shell TEXT,
                        PRIMARY KEY (hostname, username)
                    );
                """)
                cursor.execute(
                    "INSERT INTO baseline_users_new (hostname, username, uid, gid, home_dir, login_shell) SELECT ?, username, uid, gid, home_dir, login_shell FROM baseline_users;",
                    (current_host,)
                )
                cursor.execute("DROP TABLE baseline_users;")
                cursor.execute("ALTER TABLE baseline_users_new RENAME TO baseline_users;")

            conn.commit()

    def create_snapshot(self, conn: sqlite3.Connection, hostname: str = None, os_platform: str = None) -> int:
        """Register snapshot details and return its autoincremented key identifier."""
        cursor = conn.cursor()
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        if hostname is None:
            hostname = platform.node() or "unknown_host"
        if os_platform is None:
            os_platform = platform.platform() or "Linux"

        cursor.execute(
            "INSERT INTO system_snapshots (timestamp, hostname, os_platform) VALUES (?, ?, ?);",
            (now_str, hostname, os_platform)
        )
        return cursor.lastrowid

    # Transaction-Safe Bulk Telemetry Storage APIs
    def store_processes(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline, ancestry_path) VALUES (?, ?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["pid"], r["ppid"], r["name"], r["exe"], r["cmdline"], r.get("ancestry_path", "")) for r in records]
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

    def store_suid_binaries(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_suid_binaries (snapshot_id, file_path, owner, grp, permissions, sha256) VALUES (?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["file_path"], r["owner"], r["grp"], r["permissions"], r["sha256"]) for r in records]
        )

    def store_auth_logs(self, conn: sqlite3.Connection, snapshot_id: int, records: list[str]):
        conn.executemany(
            "INSERT INTO collected_auth_logs (snapshot_id, log_line) VALUES (?, ?);",
            [(snapshot_id, line) for line in records]
        )

    def store_ebpf_programs(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            """
            INSERT INTO collected_ebpf_programs (snapshot_id, bpf_id, name, type, tag, gpl_compatible)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r.get("bpf_id"), r["name"], r["type"], r["tag"], r["gpl_compatible"]) for r in records]
        )

    def store_ebpf_pinned(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            "INSERT INTO collected_ebpf_pinned (snapshot_id, path, type) VALUES (?, ?, ?);",
            [(snapshot_id, r["path"], r["type"]) for r in records]
        )

    def store_ld_preload(self, conn: sqlite3.Connection, snapshot_id: int, records: list[str]):
        conn.executemany(
            "INSERT INTO collected_ld_preload (snapshot_id, line) VALUES (?, ?);",
            [(snapshot_id, line) for line in records]
        )

    def store_special_fds(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            """
            INSERT INTO collected_special_fds (snapshot_id, pid, fd_num, fd_type, resolved_path)
            VALUES (?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r["pid"], r["fd_num"], r["fd_type"], r["resolved_path"]) for r in records]
        )

    def store_persistence_configs(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        conn.executemany(
            """
            INSERT INTO collected_persistence_configs (snapshot_id, source_path, persistence_type, content_hash, user_owner)
            VALUES (?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r["source_path"], r["persistence_type"], r["content_hash"], r["user_owner"]) for r in records]
        )