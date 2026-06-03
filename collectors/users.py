# orin/collectors/users.py
from pathlib import Path

PASSWD_PATH = Path("/etc/passwd")

def gather_system_accounts() -> list[dict]:
    """Parses /etc/passwd directly to harvest account profiles and privileges."""
    accounts = []
    if not PASSWD_PATH.exists():
        return accounts

    try:
        with open(PASSWD_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                
                # Format layout: username:password:uid:gid:gecos:home:shell
                accounts.append({
                    "username": parts[0],
                    "uid": int(parts[2]),
                    "gid": int(parts[3]),
                    "home_dir": parts[5],
                    "login_shell": parts[6]
                })
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    return accounts