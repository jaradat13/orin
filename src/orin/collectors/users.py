# orin/collectors/users.py
"""
orin.collectors.users – System Account Harvester
================================================
Parses ``/etc/passwd`` directly to enumerate all local user accounts without
relying on external utilities such as ``getent`` or ``id``.

The harvested data feeds both the ``baseline_users`` table (at ``orin init``)
and the ``collected_users`` table (at every ``orin collect`` run), enabling
the analysis engine to detect newly created or privilege-escalated accounts.
"""
from pathlib import Path

#: Filesystem path to the POSIX account database file.
PASSWD_PATH = Path("/etc/passwd")


def gather_system_accounts() -> list[dict]:
    """Parse ``/etc/passwd`` and return structured account records for each entry.

    Lines beginning with ``#`` and blank lines are ignored.  Each colon-
    delimited record must have at least seven fields to be included.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``username``    (str) – login name (field 0).
        - ``uid``         (int) – numeric user ID (field 2).
        - ``gid``         (int) – numeric primary group ID (field 3).
        - ``home_dir``    (str) – home directory path (field 5).
        - ``login_shell`` (str) – login shell path (field 6).

    Notes
    -----
    The password field (field 1) is deliberately excluded; it is always ``"x"``
    on modern systems and the actual hash lives in ``/etc/shadow``.
    """
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