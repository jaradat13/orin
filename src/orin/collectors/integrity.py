# src/orin/collectors/integrity.py
"""
orin.collectors.integrity – File Integrity Monitor (FIM)
========================================================
Generates SHA-256 checksums for files and directories listed in the Orin
configuration under ``critical_paths`` and ``critical_dirs``.

All hashing is done entirely in-process (no external tools) and skips
symlinks to prevent hash-chain attacks that redirect reads to arbitrary
locations.
"""
import hashlib
from pathlib import Path
from orin.core.config import load_config

def _hash_file_safely(target_path: Path, file_signatures: list) -> None:
    """Compute the SHA-256 digest of a single file and append it to a list.

    The function is a no-op (returns silently) when ``target_path``:
    * does not exist,
    * is not a regular file, or
    * is a symbolic link.

    Symlinks are excluded deliberately to prevent an attacker from replacing a
    monitored file with a link that points to a controlled file.

    Parameters
    ----------
    target_path : Path
        Absolute path to the file to hash.
    file_signatures : list
        Mutable accumulator list.  A ``{file_path, sha256_hash}`` dict is
        appended when hashing succeeds.
    """
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
    """Generate SHA-256 fingerprints for all configured critical paths and directories.

    Reads the active Orin configuration (via :func:`orin.core.config.load_config`)
    and iterates over two sets:

    1. ``critical_paths`` – individual files hashed directly.
    2. ``critical_dirs``  – directories whose contents are recursively
       traversed with ``Path.rglob("*")``; only regular, non-symlink files
       are hashed.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``file_path``   (str) – absolute resolved path of the hashed file.
        - ``sha256_hash`` (str) – lowercase hexadecimal SHA-256 digest.

    Notes
    -----
    Files that cannot be read due to :exc:`PermissionError` or :exc:`OSError`
    are silently skipped so that a non-root run still produces partial results.
    """
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