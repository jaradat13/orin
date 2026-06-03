# src/orin/collectors/integrity.py
import hashlib
from pathlib import Path
from orin.core.config import load_config

def _hash_file_safely(target_path: Path, file_signatures: list) -> None:
    if not target_path.exists() or not target_path.is_file() or target_path.is_symlink():
        return
    try:
        file_bytes = target_path.read_bytes()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        file_signatures.append({
            "file_path": str(target_path.resolve()),
            "sha256_hash": sha256_hash
        })
    except (PermissionError, OSError):
        # Gracefully ignore if lacks permission (e.g. non-root on shadow files)
        pass

def gather_file_integrity_signatures() -> list[dict]:
    """Generates cryptographic verification hashes for critical system files and directories."""
    config = load_config()
    file_signatures = []
    
    # 1. Process explicit critical files
    for path_str in config.get("critical_paths", []):
        _hash_file_safely(Path(path_str), file_signatures)
        
    # 2. Process critical directories recursively
    for dir_str in config.get("critical_dirs", []):
        target_dir = Path(dir_str)
        if target_dir.exists() and target_dir.is_dir():
            try:
                # Recursively glob all files
                for filepath in target_dir.rglob("*"):
                    if filepath.is_file() and not filepath.is_symlink():
                        _hash_file_safely(filepath, file_signatures)
            except (PermissionError, OSError):
                continue
                
    return file_signatures