# orin/core/crypto.py
"""
orin.core.crypto – HMAC-SHA256 Export Signing & Verification
=============================================================
Provides tamper-evident serialisation of Orin forensic snapshots.

Workflow
--------
1. :func:`generate_signed_export`  – reads a snapshot from the SQLite vault,
   serialises it to canonical JSON (keys sorted for determinism), computes an
   HMAC-SHA256 signature, and writes a ``{signature, data}`` bundle to a file.
2. :func:`verify_signed_export`    – reads a bundle file, recomputes the HMAC,
   and raises :exc:`PermissionError` if the signature does not match.

Security notes
--------------
* A minimum passphrase length of 12 characters is enforced by
  :func:`_validate_secret` before any cryptographic operation.
* :func:`hmac.compare_digest` is used for the comparison to prevent
  timing-side-channel leaks.
"""
import hmac
import hashlib
import json
import sqlite3
from pathlib import Path

#: Minimum acceptable length (in characters) for the HMAC passphrase.
#: Enforced by :func:`_validate_secret` before any cryptographic call.
_MIN_SECRET_LENGTH = 12


def _validate_secret(secret_key: str) -> None:
    """Enforce a minimum passphrase strength before any cryptographic operation.

    Parameters
    ----------
    secret_key : str
        The passphrase to validate.

    Raises
    ------
    ValueError
        If ``secret_key`` is shorter than :data:`_MIN_SECRET_LENGTH` characters.
    """
    if len(secret_key) < _MIN_SECRET_LENGTH:
        raise ValueError(
            f"Passphrase is too short ({len(secret_key)} chars). "
            f"Minimum required: {_MIN_SECRET_LENGTH} characters."
        )


def generate_signed_export(db_path: Path, snapshot_id: int, secret_key: str) -> str:
    """Serialise a snapshot payload and bind it with an HMAC-SHA256 signature.

    All sub-tables belonging to ``snapshot_id`` are fetched from the Orin
    SQLite vault, assembled into a single Python dictionary, serialised with
    sorted keys (for byte-for-byte determinism), and then signed.

    Parameters
    ----------
    db_path : Path
        Filesystem path to the Orin SQLite vault.
    snapshot_id : int
        Primary-key ID of the ``system_snapshots`` row to export.
    secret_key : str
        HMAC passphrase.  Must be at least :data:`_MIN_SECRET_LENGTH` chars.

    Returns
    -------
    str
        Pretty-printed JSON string with two top-level keys:
        ``"signature"`` (hex HMAC-SHA256 digest) and ``"data"`` (the
        canonical serialised snapshot payload).

    Raises
    ------
    ValueError
        If ``secret_key`` is too short or if ``snapshot_id`` does not exist.
    sqlite3.Error
        On any unexpected database error.
    """
    _validate_secret(secret_key)

    payload = {
        "snapshot_id": snapshot_id,
        "metadata": {},
        "processes": [],
        "ports": [],
        "outbound": [],
        "kernel_modules": [],
        "ssh_keys": [],
        "users": [],
        "file_hashes": [],
        "deleted_binaries": [],
        "promisc_interfaces": [],
        "wtmp_sessions": [],
        "lastlog_records": [],
        "pkg_integrity": []
    }

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. Fetch Snapshot Metadata
    cursor.execute(
        "SELECT hostname, os_platform, timestamp FROM system_snapshots WHERE id = ?;",
        (snapshot_id,)
    )
    snap = cursor.fetchone()
    if not snap:
        conn.close()
        raise ValueError(f"Snapshot ID {snapshot_id} does not exist.")
    payload["metadata"] = dict(snap)

    # 2. Extract Sub-tables
    cursor.execute(
        "SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["processes"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["ports"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT local_ip, local_port, remote_ip, remote_port, state, process_name "
        "FROM collected_outbound_connections WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["outbound"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT module_name, memory_size, instances_loaded FROM collected_kernel_modules WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["kernel_modules"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT user_account, key_type, fingerprint, raw_key_comment FROM collected_ssh_keys WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["ssh_keys"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["users"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["file_hashes"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT pid, exe, sha256, md5, vault_path FROM collected_deleted_binaries WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["deleted_binaries"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT interface, flags, is_promiscuous FROM collected_promisc_interfaces WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["promisc_interfaces"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason FROM collected_wtmp_sessions WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["wtmp_sessions"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT username, uid, line, host, login_time, anomaly_detected, anomaly_reason FROM collected_lastlog_records WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["lastlog_records"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT package, file_path, expected_md5, actual_md5, actual_sha256, status FROM collected_pkg_integrity WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["pkg_integrity"] = [dict(r) for r in cursor.fetchall()]

    conn.close()

    # Canonical string sorting to preserve exact byte arrays
    serialized_data = json.dumps(payload, sort_keys=True)

    # Compute signature
    signature = hmac.new(
        secret_key.encode("utf-8"),
        serialized_data.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    # Wrap together into the bundle export format
    return json.dumps({"signature": signature, "data": serialized_data}, indent=2)


def verify_signed_export(export_file_path: Path, secret_key: str) -> dict:
    """Verify a signed export bundle and return the decoded payload.

    Reads the ``{signature, data}`` JSON bundle at ``export_file_path``,
    recomputes the HMAC-SHA256 over the raw ``data`` string, and compares it
    against the stored signature using a constant-time digest comparison.

    Parameters
    ----------
    export_file_path : Path
        Path to the signed ``.json`` export file produced by
        :func:`generate_signed_export`.
    secret_key : str
        HMAC passphrase used at export time.

    Returns
    -------
    dict
        The decoded snapshot payload (the parsed value of the ``"data"`` key).

    Raises
    ------
    ValueError
        If ``secret_key`` fails the minimum-length check.
    PermissionError
        If the computed signature does not match the stored signature,
        indicating that the export file has been tampered with.
    FileNotFoundError
        If ``export_file_path`` does not exist.
    json.JSONDecodeError
        If the file is not valid JSON.
    """
    _validate_secret(secret_key)

    with open(export_file_path, "r") as f:
        bundle = json.load(f)

    expected_signature = bundle["signature"]
    raw_data = bundle["data"]

    computed_signature = hmac.new(
        secret_key.encode("utf-8"),
        raw_data.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, computed_signature):
        raise PermissionError(
            "CRITICAL EXPORT INTEGRITY COLD-FAILURE: Payload signature has been modified!"
        )

    return json.loads(raw_data)