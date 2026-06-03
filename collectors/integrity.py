# orin/collectors/integrity.py
import hashlib
from pathlib import Path

CRITICAL_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/sudoers"
]

def gather_file_integrity_signatures() -> list[dict]:
    """Generates cryptographic verification hashes for critical system configuration files."""
    file_signatures = []
    
    for path_str in CRITICAL_PATHS:
        target_path = Path(path_str)
        if not target_path.exists():
            continue
            
        try:
            file_bytes = target_path.read_bytes()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()
            file_signatures.append({
                "file_path": path_str,
                "sha256_hash": sha256_hash
            })
        except (PermissionError, OSError):
            # Gracefully ignore if the executing scope lacks sudo privileges
            continue
            
    return file_signatures