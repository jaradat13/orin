# orin/collectors/logs.py
import re
import sys
from pathlib import Path
from collections import Counter

AUTH_LOG_PATH = Path("/var/log/auth.log")

SSH_FAIL_RE = re.compile(r"Failed password for .* from (?P<ip>\S+) port")
USER_ADD_RE = re.compile(r"useradd.*new user: name=(?P<user>\S+)")

# Fix: use unescaped single quotes to match real auth.log output, e.g.:
#   usermod[1234]: add 'alice' to group 'sudo'
# The original used \' which does not match literal ' in the log file.
GROUP_ADD_RE = re.compile(
    r"usermod.*add '(?P<user>\S+)' to group '(?P<group>sudo|root)'"
)


def parse_authentication_logs() -> dict:
    """Parses local authentication records for brute-force indicators and privilege changes."""
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