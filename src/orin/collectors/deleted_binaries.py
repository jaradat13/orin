# src/orin/collectors/deleted_binaries.py
"""
orin.collectors.deleted_binaries – In-Memory Executable Recovery
==============================================================
Monitors processes for running deleted binaries by inspecting the virtual
symlinks in /proc/[pid]/exe. If a deleted binary is detected, its active
payload is recovered from the virtual symlink, hashed, and archived.
"""
import hashlib
import os
from pathlib import Path
from orin.core.config import load_config

def gather_deleted_binaries(vault_dir: str = None) -> list[dict]:
    """Crawl `/proc` to find running processes referencing deleted binaries.

    Parameters
    ----------
    vault_dir : str, optional
        Target directory to archive recovered payloads. If None, it is resolved
        from the configuration (key "vault_path") or falls back to
        "/var/lib/orin/vault".

    Returns
    -------
    list[dict]
        Each dict contains details of a recovered deleted binary:
        - pid (int)
        - exe (str)
        - sha256 (str)
        - md5 (str)
        - vault_path (str)
    """
    records = []
    
    if vault_dir is None:
        config = load_config()
        vault_dir = Path(config.get("vault_path", "/var/lib/orin/vault"))
    else:
        vault_dir = Path(vault_dir)

    proc_path = Path("/proc")
    if not proc_path.exists():
        return records

    for pid_dir in proc_path.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue

        pid = int(pid_dir.name)
        exe_link = pid_dir / "exe"

        try:
            # 1. Resolve executable path link
            # Note: Path.is_symlink() is used because exe_link points to a deleted file,
            # so Path.exists() might return False. But it is still a symlink we can read!
            try:
                target_exe = os.readlink(str(exe_link))
            except (FileNotFoundError, PermissionError, OSError):
                continue

            if not target_exe.endswith(" (deleted)"):
                continue

            # 2. Extract active in-memory payload directly from /proc/[pid]/exe
            try:
                payload_bytes = exe_link.read_bytes()
            except (FileNotFoundError, PermissionError, OSError):
                continue

            # 3. Calculate cryptographic hashes
            md5_hash = hashlib.md5(payload_bytes).hexdigest()
            sha256_hash = hashlib.sha256(payload_bytes).hexdigest()

            # 4. Save to vault directory
            try:
                vault_dir.mkdir(parents=True, exist_ok=True)
                dest_file = vault_dir / sha256_hash
                if not dest_file.exists():
                    dest_file.write_bytes(payload_bytes)
                vault_path_str = str(dest_file.resolve())
            except (PermissionError, OSError):
                vault_path_str = "failed_to_write_vault"

            records.append({
                "pid": pid,
                "exe": target_exe,
                "sha256": sha256_hash,
                "md5": md5_hash,
                "vault_path": vault_path_str
            })

        except (FileNotFoundError, PermissionError, OSError, ValueError):
            continue

    return records
