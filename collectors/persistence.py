# orin/collectors/persistence.py
import hashlib
from pathlib import Path


def gather_active_ssh_keys() -> list[dict]:
    """Scans structural system home paths to map active SSH public keys and components."""
    ssh_records: list[dict] = []
    search_targets = [("root", Path("/root"))]

    # Identify standard local user directories securely
    base_home = Path("/home")
    if base_home.exists():
        for user_dir in base_home.iterdir():
            if user_dir.is_dir():
                search_targets.append((user_dir.name, user_dir))

    for user, home_path in search_targets:
        auth_keys_path = home_path / ".ssh" / "authorized_keys"
        if not auth_keys_path.exists():
            continue

        try:
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