# src/orin/collectors/pkg_integrity.py
"""
orin.collectors.pkg_integrity – Offline Package Integrity Engine
===============================================================
Parses `/var/lib/dpkg/info/*.md5sums` files on Debian/Ubuntu systems to detect
unauthorized modification or deletion of core system binaries.
"""
import hashlib
from pathlib import Path

# Common binary directories to check (excludes doc, share, etc.)
DEFAULT_BINARY_DIRS = (
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"
)

def gather_pkg_integrity_drift(dpkg_info_dir: Path = Path("/var/lib/dpkg/info")) -> list[dict]:
    """Recalculate hashes of system package binaries and report mismatches or deletions.

    Parameters
    ----------
    dpkg_info_dir : Path, optional
        Filesystem directory where dpkg info is located. Defaults to /var/lib/dpkg/info.

    Returns
    -------
    list[dict]
        Each dict represents a package integrity violation:
        - package (str): name of the Debian package.
        - file_path (str): absolute path to the binary.
        - expected_md5 (str): expected MD5 hash.
        - actual_md5 (str/None): calculated MD5 hash, or None if missing.
        - actual_sha256 (str/None): calculated SHA-256 hash, or None if missing.
        - status (str): "mismatch" or "missing".
    """
    violations = []
    if not dpkg_info_dir.exists() or not dpkg_info_dir.is_dir():
        return violations

    try:
        for md5sums_file in dpkg_info_dir.glob("*.md5sums"):
            package = md5sums_file.stem
            
            try:
                content = md5sums_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for line in content.splitlines():
                line = line.strip()
                if not line or len(line) < 34:
                    continue

                # The first 32 chars are the MD5 hash
                expected_md5 = line[:32]
                file_path_str = line[32:].strip()
                
                # Convert to absolute path
                file_path = Path("/") / file_path_str
                path_str = str(file_path)

                # Skip files not located in system binary/library directories
                if not path_str.startswith(DEFAULT_BINARY_DIRS):
                    continue

                if not file_path.exists():
                    violations.append({
                        "package": package,
                        "file_path": path_str,
                        "expected_md5": expected_md5,
                        "actual_md5": None,
                        "actual_sha256": None,
                        "status": "missing"
                    })
                    continue

                # Skip directories and symbolic links to avoid verification loops
                if file_path.is_symlink() or not file_path.is_file():
                    continue

                # Recalculate hashes of the binary in a single pass
                try:
                    md5_alg = hashlib.md5()
                    sha256_alg = hashlib.sha256()
                    
                    with open(file_path, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            md5_alg.update(chunk)
                            sha256_alg.update(chunk)

                    actual_md5 = md5_alg.hexdigest()
                    actual_sha256 = sha256_alg.hexdigest()
                except (OSError, PermissionError):
                    # Skip files we cannot read due to temporary permission locks
                    continue

                # Verify hash integrity
                if actual_md5 != expected_md5:
                    violations.append({
                        "package": package,
                        "file_path": path_str,
                        "expected_md5": expected_md5,
                        "actual_md5": actual_md5,
                        "actual_sha256": actual_sha256,
                        "status": "mismatch"
                    })

    except Exception:
        pass

    return violations
