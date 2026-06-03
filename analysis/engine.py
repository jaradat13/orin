# orin/analysis/engine.py
import json
import re
from pathlib import Path
from orin.core.database import OrinStorage
from orin.collectors.logs import parse_authentication_logs

# Fix: Removed unconditionally whitelisted high-risk service ports (3306/MySQL,
# 5432/PostgreSQL, 6379/Redis, 8080, 8443). These are valuable attack targets and
# should not be silently ignored on all hosts. The allowlist is now a minimal safe
# default covering only universally expected system-level ports. Operators should
# extend this via a config file or the --allowed-ports CLI flag in main.py.
DEFAULT_EXPECTED_PORTS: set[int] = {22, 80, 443, 631}

SUSPICIOUS_EXACT_NAMES: set[str] = {"nc", "ncat", "netcat", "socat", "nmap", "miner", "xmrig"}

SUSPICIOUS_CMD_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bpython\s+-c\b", re.IGNORECASE),
    re.compile(r"\bbash\s+-i\b", re.IGNORECASE),
    re.compile(r"\bsh\s+-i\b", re.IGNORECASE),
]

VOLATILE_DIRS: set[str] = {"/tmp", "/dev/shm", "/var/tmp"}
BLOCKLIST_FILE_PATH = Path("/var/lib/orin/intel_blocklist.txt")

# Common kernel thread name prefixes that attackers impersonate to hide in plain sight.
# Legitimate instances of these must have PPID 0 or 2 (kthreadd / swapper).
KERNEL_THREAD_PREFIXES = (
    "kworker", "kthreadd", "ksoftirqd", "migration",
    "rcu_sched", "rcu_bh", "watchdog", "kdevtmpfs",
)


def load_offline_intel_blocklist() -> set[str]:
    """Loads malicious indicators into memory with strict defensive string stripping."""
    if not BLOCKLIST_FILE_PATH.exists():
        print("[!] Warning: Offline Threat Intelligence blocklist file missing at "
              "/var/lib/orin/intel_blocklist.txt")
        print("[!] Outbound C2 identification rules will be bypassed during this run.")
        return set()
    try:
        cleaned_ips: set[str] = set()
        with open(BLOCKLIST_FILE_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                cleaned_ips.add(line.split()[0])
        return cleaned_ips
    except Exception as e:
        print(f"[!] Error reading blocklist file definitions: {e}")
        return set()


def _compute_risk_score(events: list[dict]) -> int:
    """
    Computes a 0-100 risk score that reflects both the number and worst
    severity of events found, rather than a raw uncapped sum.

    Scoring model:
      - Base score = weight of the single highest-severity event (anchors the floor).
      - Each additional event of the same or lower severity adds a diminishing
        fraction of its own weight, preventing trivial events from dominating
        while still reflecting volume.
    """
    SEVERITY_WEIGHT = {"critical": 80, "high": 50, "medium": 25, "low": 10}

    if not events:
        return 0

    weights = sorted(
        [SEVERITY_WEIGHT.get(e["severity"], 10) for e in events],
        reverse=True,
    )

    # Base: worst event contributes its full weight
    score = weights[0]

    # Subsequent events contribute 20% of their weight each (diminishing returns)
    for w in weights[1:]:
        score += w * 0.2

    return min(int(score), 100)


def run_analysis_cycle(db_path: Path, expected_ports: set[int] | None = None) -> dict:
    """
    Runs all detection rules against the most recent snapshot.

    Args:
        db_path: Path to the Orin SQLite vault.
        expected_ports: Optional override for the port allowlist. Defaults to
                        DEFAULT_EXPECTED_PORTS when not supplied.
    """
    if expected_ports is None:
        expected_ports = DEFAULT_EXPECTED_PORTS

    storage = OrinStorage(db_path)
    events_found: list[dict] = []
    blacklisted_ips = load_offline_intel_blocklist()

    with storage.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM system_snapshots ORDER BY id DESC LIMIT 1;")
        snapshot_id = cursor.fetchone()["id"]

        # ------------------------------------------------------------------ #
        # 1. Network Listening Ports Rule
        # ------------------------------------------------------------------ #
        cursor.execute(
            "SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;",
            (snapshot_id,),
        )
        for port_row in cursor.fetchall():
            port = port_row["port"]
            if port in expected_ports or (port > 40000 and port_row["process_name"] == "code"):
                continue
            events_found.append({
                "type": "unexpected_port",
                "severity": "medium",
                "description": (
                    f"Unexpected listening network port detected: "
                    f"{port} ({port_row['process_name']})"
                ),
                "raw_details": json.dumps(dict(port_row)),
            })

        # ------------------------------------------------------------------ #
        # 2. Outbound Connection Blocklist Check
        # ------------------------------------------------------------------ #
        cursor.execute(
            "SELECT local_ip, remote_ip, remote_port, process_name "
            "FROM collected_outbound_connections WHERE snapshot_id = ?;",
            (snapshot_id,),
        )
        for conn_row in cursor.fetchall():
            current_remote_ip = conn_row["remote_ip"].strip()
            if current_remote_ip in blacklisted_ips:
                events_found.append({
                    "type": "outbound_c2_communication",
                    "severity": "critical",
                    "description": (
                        f"Active network communication targeting blacklisted C2 IP: "
                        f"{current_remote_ip} on Port {conn_row['remote_port']}"
                    ),
                    "raw_details": json.dumps(dict(conn_row)),
                })

        # ------------------------------------------------------------------ #
        # 3. Process Execution Analysis Rules (with Ancestry Validation)
        # Fix: avoid variable name 'name' collision with later kernel module loop
        # by using unambiguous variable names throughout this block.
        # ------------------------------------------------------------------ #
        cursor.execute(
            "SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;",
            (snapshot_id,),
        )
        for proc_row in cursor.fetchall():
            proc_pid = proc_row["pid"]
            proc_ppid = proc_row["ppid"]
            proc_name = (proc_row["name"] or "").lower()
            proc_exe = (proc_row["exe"] or "").lower()
            proc_cmdline = (proc_row["cmdline"] or "").lower()
            flagged = False
            reason = ""

            # Ancestry Validation: kernel thread impersonation check
            if any(proc_name.startswith(p) for p in KERNEL_THREAD_PREFIXES):
                if proc_ppid not in (0, 2):
                    flagged = True
                    reason = (
                        f"Masquerade Fraud: Non-system ancestry parent discovered "
                        f"for worker (PPID {proc_ppid})"
                    )
            elif proc_name in SUSPICIOUS_EXACT_NAMES:
                flagged = True
                reason = f"Suspicious binary signature running detected: {proc_name}"
            elif any(p.search(proc_cmdline) for p in SUSPICIOUS_CMD_PATTERNS):
                flagged = True
                reason = "Suspicious interactive command parameter flags"
            elif any(proc_exe.startswith(d) for d in VOLATILE_DIRS):
                flagged = True
                reason = "Process running from volatile system workspace directory"

            if flagged:
                events_found.append({
                    "type": "suspicious_process_ancestry",
                    "severity": "high",
                    "description": f"{reason} (PID {proc_pid})",
                    "raw_details": json.dumps(dict(proc_row)),
                })

        # ------------------------------------------------------------------ #
        # 4. Historical Delta Analysis (FIM & SSH Persistence)
        # ------------------------------------------------------------------ #
        cursor.execute(
            "SELECT id FROM system_snapshots WHERE id < ? ORDER BY id DESC LIMIT 1;",
            (snapshot_id,),
        )
        prev_snapshot_row = cursor.fetchone()
        if prev_snapshot_row:
            prev_snapshot_id = prev_snapshot_row["id"]

            # File Integrity Monitoring Check
            cursor.execute(
                """
                SELECT cur.file_path,
                       cur.sha256_hash  AS cur_hash,
                       prev.sha256_hash AS prev_hash
                FROM collected_file_hashes cur
                JOIN collected_file_hashes prev
                  ON cur.file_path = prev.file_path
                WHERE cur.snapshot_id = ? AND prev.snapshot_id = ?;
                """,
                (snapshot_id, prev_snapshot_id),
            )
            for f_row in cursor.fetchall():
                if f_row["cur_hash"] != f_row["prev_hash"]:
                    events_found.append({
                        "type": "file_modification",
                        "severity": "critical",
                        "description": (
                            f"Critical modification change verified on config: {f_row['file_path']}"
                        ),
                        "raw_details": json.dumps(dict(f_row)),
                    })

            # New SSH Key Persistence Modification Checker
            cursor.execute(
                """
                SELECT cur.user_account, cur.fingerprint, cur.raw_key_comment
                FROM collected_ssh_keys cur
                WHERE cur.snapshot_id = ?
                  AND cur.fingerprint NOT IN (
                      SELECT fingerprint FROM collected_ssh_keys WHERE snapshot_id = ?
                  );
                """,
                (snapshot_id, prev_snapshot_id),
            )
            for key_row in cursor.fetchall():
                events_found.append({
                    "type": "new_ssh_authorized_key",
                    "severity": "critical",
                    "description": (
                        f"New unauthorized SSH signature deployed for account "
                        f"'{key_row['user_account']}': {key_row['raw_key_comment']}"
                    ),
                    "raw_details": json.dumps(dict(key_row)),
                })

        # ------------------------------------------------------------------ #
        # 5. Auth Log Parsing Indicators
        # ------------------------------------------------------------------ #
        auth_data = parse_authentication_logs()
        for ip, count in auth_data["failed_ssh_counts"].items():
            if count >= 5:
                events_found.append({
                    "type": "ssh_bruteforce",
                    "severity": "high",
                    "description": (
                        f"SSH brute-force pattern verified from IP {ip}: {count} failures"
                    ),
                    "raw_details": json.dumps({"source_ip": ip, "failed_attempts_count": count}),
                })
        for placement in auth_data["privileged_additions"]:
            events_found.append({
                "type": placement["type"],
                "severity": "critical",
                "description": placement["details"],
                "raw_details": None,
            })

        # ------------------------------------------------------------------ #
        # 6. Kernel Module Integrity Verification
        # Fix: loop variable renamed to mod_name to avoid shadowing proc_name
        # from block 3 and any future variable named 'name' in this function.
        # ------------------------------------------------------------------ #
        cursor.execute("SELECT module_name, memory_size FROM baseline_kernel_modules;")
        trusted_modules = {row["module_name"] for row in cursor.fetchall()}

        cursor.execute(
            "SELECT module_name, memory_size, instances_loaded "
            "FROM collected_kernel_modules WHERE snapshot_id = ?;",
            (snapshot_id,),
        )
        collected_mods = cursor.fetchall()

        if trusted_modules:  # Validate only if baseline parameters have been captured
            for mod in collected_mods:
                mod_name = mod["module_name"]
                if mod_name not in trusted_modules:
                    events_found.append({
                        "type": "untrusted_kernel_module",
                        "severity": "critical",
                        "description": (
                            f"CRITICAL: Untrusted or unsigned LKM kernel driver module "
                            f"detected: {mod_name}"
                        ),
                        "raw_details": json.dumps(dict(mod)),
                    })

        # ------------------------------------------------------------------ #
        # 7. User Privilege Escalation & Backdoor Audit
        # ------------------------------------------------------------------ #
        cursor.execute("SELECT username, uid, login_shell FROM baseline_users;")
        baseline_users_map = {row["username"]: row for row in cursor.fetchall()}

        cursor.execute(
            "SELECT username, uid, login_shell FROM collected_users WHERE snapshot_id = ?;",
            (snapshot_id,),
        )
        for user in cursor.fetchall():
            if user["username"] not in baseline_users_map:
                is_root = user["uid"] == 0
                events_found.append({
                    "type": "unauthorized_user_created",
                    "severity": "critical" if is_root else "high",
                    "description": f"Unauthorized profile: {user['username']}",
                    "raw_details": None,
                })
            elif (
                user["uid"] == 0
                and baseline_users_map[user["username"]]["uid"] != 0
            ):
                events_found.append({
                    "type": "privilege_escalation_hijack",
                    "severity": "critical",
                    "description": f"Hijack: {user['username']} promoted to root",
                    "raw_details": None,
                })

        # ------------------------------------------------------------------ #
        # FINAL: Deduplicate and commit events
        # ------------------------------------------------------------------ #
        if events_found:
            for e in events_found:
                cursor.execute(
                    "SELECT id FROM security_events "
                    "WHERE event_type = ? AND description = ? AND resolved = 0 LIMIT 1;",
                    (e["type"], e["description"]),
                )
                if not cursor.fetchone():
                    cursor.execute(
                        "INSERT INTO security_events "
                        "(event_type, severity, description, raw_details) "
                        "VALUES (?, ?, ?, ?);",
                        (e["type"], e["severity"], e["description"], e["raw_details"]),
                    )
            conn.commit()

    return {
        "status": "success",
        "snapshot_id": snapshot_id,
        "risk_score": _compute_risk_score(events_found),
        "events_count": len(events_found),
    }