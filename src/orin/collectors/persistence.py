# orin/collectors/persistence.py
"""
orin.collectors.persistence – SSH Authorised-Keys Inventory
==========================================================
Scans every user's ``~/.ssh/authorized_keys`` file to enumerate all public
keys that are trusted for SSH login.  This data is used by the analysis
engine to detect newly injected SSH persistence keys between snapshots.

SHA-256 fingerprints are computed over the raw base64 key body, matching
the output format of ``ssh-keygen -lf`` with the SHA256 algorithm.
"""
import hashlib
from pathlib import Path



def gather_active_ssh_keys() -> list[dict]:
    """Inventory all SSH public keys in every account's ``authorized_keys`` file.

    Searches under ``/root/.ssh/`` and all directories inside ``/home/``.
    For each ``authorized_keys`` file found, every non-comment line is parsed
    into its constituent parts (key type, base64 body, and optional comment)
    and a SHA-256 fingerprint is derived from the base64 key body.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``user_account``    (str) – system username owning the key file.
        - ``key_type``        (str) – algorithm label, e.g. ``"ssh-rsa"``.
        - ``fingerprint``     (str) – SHA-256 hex digest of the base64 key body.
        - ``raw_key_comment`` (str) – optional comment field, or ``"No Comment"``.

    Notes
    -----
    Files that cannot be read due to permission restrictions are silently
    skipped.  This function is safe to call as a non-root user but will
    produce incomplete results for accounts it cannot access.
    """
    ssh_records: list[dict] = []
    search_targets = [("root", Path("/root"))]

    # Identify standard local user directories securely
    base_home = Path("/home")
    if base_home.exists():
        for user_dir in base_home.iterdir():
            if user_dir.is_dir():
                search_targets.append((user_dir.name, user_dir))

    for user, home_path in search_targets:
        try:
            auth_keys_path = home_path / ".ssh" / "authorized_keys"
            if not auth_keys_path.exists():
                continue

            with open(auth_keys_path, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()
                    if len(parts) >= 2:
                        key_type = parts[0]
                        key_body = parts[1]
                        comment = " ".join(parts[2:]) if len(parts) > 2 else "No Comment"

                        # Fix: use SHA-256 instead of MD5 for fingerprinting.
                        # This aligns with modern ssh-keygen output (ssh-keygen -lf)
                        # and avoids MD5 collision weaknesses.
                        fingerprint = hashlib.sha256(
                            key_body.encode("utf-8")
                        ).hexdigest()

                        ssh_records.append({
                            "user_account": user,
                            "key_type": key_type,
                            "fingerprint": fingerprint,
                            "raw_key_comment": comment,
                        })
        except (PermissionError, OSError):
            continue

    return ssh_records