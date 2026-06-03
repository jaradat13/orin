# orin/core/crypto.py
import hmac
import hashlib
import json
import sqlite3
from pathlib import Path

_MIN_SECRET_LENGTH = 12


def _validate_secret(secret_key: str) -> None:
    """Enforces a minimum passphrase strength before any cryptographic operation."""
    if len(secret_key) < _MIN_SECRET_LENGTH:
        raise ValueError(
            f"Passphrase is too short ({len(secret_key)} chars). "
            f"Minimum required: {_MIN_SECRET_LENGTH} characters."
        )


def generate_signed_export(db_path: Path, snapshot_id: int, secret_key: str) -> str:
    """Serializes a snapshot payload and binds it with an HMAC signature."""
    _validate_secret(secret_key)

    payload = {
        "snapshot_id": snapshot_id,
        "metadata": {},
        "processes": [],
        "ports": [],
        "outbound": [],
        "kernel_modules": []
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
    """Verifies data integrity using HMAC; raises PermissionError on tampering."""
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