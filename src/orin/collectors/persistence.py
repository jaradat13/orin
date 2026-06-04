# orin/collectors/persistence.py
"""
orin.collectors.persistence – SSH Authorized-Keys Inventory
==========================================================
Scans every user's ``~/.ssh/authorized_keys`` file to enumerate all public
keys that are trusted for SSH login. This data is used by the analysis
engine to detect newly injected SSH persistence keys between snapshots.

SHA-256 fingerprints are computed over the raw base64 key body, matching
the output format of ``ssh-keygen -lf`` with the SHA256 algorithm.
"""
import hmac
import hashlib
import pwd
from pathlib import Path

#: Set of standard recognized SSH public key prefix tags to isolate options options
_KNOWN_KEY_TYPES = {
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com"
}

def gather_active_ssh_keys() -> list[dict]:
    """Inventory all SSH public keys across every registered account profile.

    Queries the local system passwd database dynamically, tracks down mapped
    home directory locations, and securely serializes every active public key
    while isolating environment configuration option prefixes safely.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``user_account``    (str) – system username owning the key file.
        - ``key_type``        (str) – algorithm label, e.g. ``"ssh-rsa"``.
        - ``fingerprint``     (str) – SHA-256 hex digest of the base64 key body.
        - ``raw_key_comment`` (str) – optional comment field, or explicit error tag.
    """
    ssh_records: list[dict] = []
    
    try:
        # Real-world defense: Query the dynamic OS account database instead of 
        # guessing home layout paths by recursively walking the /home workspace block.
        system_accounts = pwd.getpwall()
    except OSError as e:
        ssh_records.append({
            "user_account": "root",
            "key_type": "ERROR",
            "fingerprint": "SYSTEM_PASSWD_READ_FAULT",
            "raw_key_comment": f"Failed to interface with systemic passwd database pipeline: {e}"
        })
        return ssh_records

    for account in system_accounts:
        user = account.pw_name
        home_dir = account.pw_dir
        
        if not home_dir:
            continue
            
        auth_keys_path = Path(home_dir) / ".ssh" / "authorized_keys"
        if not auth_keys_path.exists():
            continue

        try:
            with open(auth_keys_path, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    # Real-world defense: Handle real SSH authorized_keys formatting criteria.
                    # If a line starts with environmental restrictions (e.g., choices, ports),
                    # the algorithm descriptor shifts to index position 1.
                    first_token = parts[0].lower()
                    
                    if first_token in _KNOWN_KEY_TYPES or first_token.startswith("ssh-"):
                        key_type = parts[0]
                        key_body = parts[1]
                        comment = " ".join(parts[2:]) if len(parts) > 2 else "No Comment"
                    else:
                        # Index 0 contains an option configuration context (e.g. command="...",from="...")
                        if len(parts) >= 3:
                            key_type = parts[1]
                            key_body = parts[2]
                            comment = " ".join(parts[3:]) if len(parts) > 3 else "No Comment"
                        else:
                            # Structural tracking failure on malformed configuration payload line
                            continue

                    try:
                        fingerprint = hashlib.sha256(key_body.encode("utf-8")).hexdigest()
                        ssh_records.append({
                            "user_account": user,
                            "key_type": key_type,
                            "fingerprint": fingerprint,
                            "raw_key_comment": comment.strip(),
                        })
                    except Exception as crypt_error:
                        ssh_records.append({
                            "user_account": user,
                            "key_type": "ERROR",
                            "fingerprint": f"HASH_FAULT_LINE_{line_num}",
                            "raw_key_comment": f"Malformed base64 block serialization: {crypt_error}"
                        })

        except (PermissionError, OSError) as access_fault:
            # Propagate and surface path manipulation obstacles to the analytical engine
            ssh_records.append({
                "user_account": user,
                "key_type": "ERROR",
                "fingerprint": "ACCESS_DENIED_INVENTORY_FAULT",
                "raw_key_comment": f"Failed to open secure profile target path: {access_fault.strerror}"
            })

    return ssh_records
    