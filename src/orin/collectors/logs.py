# orin/collectors/logs.py
"""
orin.collectors.logs – Authentication Log Parser
================================================
Parses ``/var/log/auth.log`` to extract two categories of forensic indicators:

1. **SSH brute-force attempts** – consecutive failed password events from the
   same source IP, counted via :class:`~collections.Counter`.
2. **Privilege-escalation events** – new account creation (``useradd``) and
   additions to administrative groups (``usermod`` + ``sudo``/``root``).

The module operates entirely offline; no network calls are made.
"""
import re
import sys
from pathlib import Path
from collections import Counter

#: Absolute path to the system authentication log processed by this module.
AUTH_LOG_PATH = Path("/var/log/auth.log")

#: Compiled regex to extract the source IP from a failed SSH password line.
SSH_FAIL_RE = re.compile(r"Failed password for .* from (?P<ip>\S+) port")
#: Compiled regex to extract the new username from a ``useradd`` event.
USER_ADD_RE = re.compile(r"useradd.*new user: name=(?P<user>\S+)")

#: Compiled regex to detect privilege escalation via ``usermod`` adding
#: a user to the ``sudo`` or ``root`` group.  Single-quote characters are
#: matched literally (not escaped) to match real auth.log output such as::
#:
#:     usermod[1234]: add 'alice' to group 'sudo'
GROUP_ADD_RE = re.compile(
    r"usermod.*add '(?P<user>\S+)' to group '(?P<group>sudo|root)'"
)


def parse_authentication_logs() -> dict:
    """Parse ``/var/log/auth.log`` for brute-force indicators and privilege changes.

    Makes a single sequential read pass over :data:`AUTH_LOG_PATH`, applying
    three compiled regular expressions to each line:

    * :data:`SSH_FAIL_RE`   – counts failed SSH password attempts per source IP.
    * :data:`USER_ADD_RE`   – records new system account creation events.
    * :data:`GROUP_ADD_RE`  – records assignments to privileged groups.

    Returns
    -------
    dict
        A dictionary with two keys:

        ``"failed_ssh_counts"`` : dict[str, int]
            Maps source IP address strings to the number of failed password
            attempts observed in the log.

        ``"privileged_additions"`` : list[dict]
            Each entry contains:
            - ``type``    (str) – ``"new_user"`` or
              ``"privileged_group_escalation"``.
            - ``details`` (str) – human-readable description of the event.

    Notes
    -----
    If the log file cannot be opened due to :exc:`PermissionError`, a warning
    is printed to ``stderr`` and empty results are returned.  Run with
    ``sudo`` for full log access.
    """
    results: dict = {
        "failed_ssh_counts": {},
        "privileged_additions": [],
    }

    if not AUTH_LOG_PATH.exists():
        return results

    failed_ips: list[str] = []
    try:
        with open(AUTH_LOG_PATH, "r", errors="ignore") as f:
            for line in f:
                ssh_match = SSH_FAIL_RE.search(line)
                if ssh_match:
                    failed_ips.append(ssh_match.group("ip"))
                    continue

                user_match = USER_ADD_RE.search(line)
                if user_match:
                    results["privileged_additions"].append({
                        "type": "new_user",
                        "details": (
                            f"New local system account created: user={user_match.group('user')}"
                        ),
                    })
                    continue

                group_match = GROUP_ADD_RE.search(line)
                if group_match:
                    results["privileged_additions"].append({
                        "type": "privileged_group_escalation",
                        "details": (
                            f"Account assigned to administrative group: "
                            f"user={group_match.group('user')} "
                            f"group={group_match.group('group')}"
                        ),
                    })
    except PermissionError:
        print(
            "[!] Permission Denied reading /var/log/auth.log. "
            "Run with sudo to analyze auth alerts.",
            file=sys.stderr,
        )

    results["failed_ssh_counts"] = dict(Counter(failed_ips))
    return results