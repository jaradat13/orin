# orin/analysis/engine.py
"""
orin.analysis.engine – Threat Detection Rules Engine
=====================================================
Implements the core analysis cycle that evaluates the most recent system
snapshot stored in the Orin SQLite vault against a set of security rules.
"""
import re
import json
from pathlib import Path
from orin.core.database import OrinStorage
from orin.collectors.logs import parse_authentication_logs
from orin.core.config import load_config
from orin.analysis.unhide import detect_hidden_processes

#: Exact process names (lowercased) that are always considered suspicious
SUSPICIOUS_EXACT_NAMES = {"nc", "ncat", "netcat", "socat", "nmap", "miner", "xmrig"}

#: Compiled regex patterns applied against the full command-line string
SUSPICIOUS_CMD_PATTERNS = [
    re.compile(r'\bpython\s+-c\b', re.IGNORECASE),
    re.compile(r'\bbash\s+-i\b', re.IGNORECASE),
    re.compile(r'\bsh\s+-i\b', re.IGNORECASE),
]

#: Filesystem prefixes considered "volatile".
VOLATILE_DIRS = {"/tmp", "/dev/shm", "/var/tmp"}
BLOCKLIST_FILE_PATH = Path("/var/lib/orin/intel_blocklist.txt")

#: Kernel thread name prefixes that are *only* valid when their PPID is 0 or 2.
KERNEL_THREAD_PREFIXES = (
    "kworker", "kthreadd", "ksoftirqd", "migration",
    "rcu_sched", "rcu_bh", "watchdog", "kdevtmpfs",
)

def load_offline_intel_blocklist() -> set[str]:
    """Load the offline threat-intelligence IP blocklist into a set."""
    if not BLOCKLIST_FILE_PATH.exists():
        print("[!] Warning: Offline Threat Intelligence blocklist file missing at /var/lib/orin/intel_blocklist.txt")
        print("[!] Outbound C2 identification rules will be bypassed during this run.")
        return set()
    try:
        cleaned_ips = set()
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

def run_analysis_cycle(db_path: Path) -> dict:
    """Execute all security rules against the most recent snapshot in the vault."""
    config = load_config()
    expected_ports = set(config["expected_ports"])
    whitelisted_processes = set(config["whitelisted_processes"])
    storage = OrinStorage(db_path)
    events_found = []
    max_severity_weight = 0
    blacklisted_ips = load_offline_intel_blocklist()
    
    with storage.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM system_snapshots ORDER BY id DESC LIMIT 1;")
        snapshot_id = cursor.fetchone()["id"]

        # 1. Network Listening Ports Rule
        cursor.execute("SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;", (snapshot_id,))
        active_unexpected_ports = set()
        for port_row in cursor.fetchall():
            port = port_row["port"]
            process_full = port_row["process_name"] or "unknown"
            process_base = process_full.split(" (PID:")[0]
            if port in expected_ports or (port >= 32768 and process_base in whitelisted_processes):
                continue
            active_unexpected_ports.add(port)
            max_severity_weight += 20
            events_found.append({
                "type": "unexpected_port", "severity": "medium",
                "description": f"Unexpected listening network port detected: {port} ({port_row['process_name']})",
                "raw_details": json.dumps(dict(port_row))
            })

        # 2. Outbound Connection Blocklist Check
        cursor.execute("SELECT local_ip, remote_ip, remote_port, process_name FROM collected_outbound_connections WHERE snapshot_id = ?;", (snapshot_id,))
        for conn_row in cursor.fetchall():
            current_remote_ip = conn_row["remote_ip"].strip()
            if current_remote_ip in blacklisted_ips:
                max_severity_weight += 60
                events_found.append({
                    "type": "outbound_c2_communication", "severity": "critical",
                    "description": f"Active network communication targeting blacklisted C2 IP: {current_remote_ip} on Port {conn_row['remote_port']}",
                    "raw_details": json.dumps(dict(conn_row))
                })

        # 3. Process Execution Analysis Rules (Decoupled Decoders)
        cursor.execute("SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;", (snapshot_id,))
        active_processes = set()
        for proc_row in cursor.fetchall():
            active_processes.add(proc_row["pid"])
            ppid = proc_row["ppid"]
            name = (proc_row["name"] or "").lower()
            exe = (proc_row["exe"] or "").lower()
            cmdline = (proc_row["cmdline"] or "").lower()
            flagged, reason = False, ""
            
            # Rule A: Kernel thread ancestry validation
            if any(name.startswith(p) for p in KERNEL_THREAD_PREFIXES):
                if ppid not in (0, 2):
                    flagged, reason = True, f"Masquerade Fraud: Non-system ancestry parent discovered for worker (PPID {ppid})"
            
            # Rule B: Exact signature validation matching
            if not flagged and name in SUSPICIOUS_EXACT_NAMES:
                flagged, reason = True, f"Suspicious binary signature running detected: {name}"
            
            # Rule C: Execution arguments validation matching
            if not flagged and any(p.search(cmdline) for p in SUSPICIOUS_CMD_PATTERNS):
                flagged, reason = True, "Suspicious interactive command parameter flags"
            
            # Rule D: Filesystem path validation matching
            if not flagged and any(exe.startswith(d) for d in VOLATILE_DIRS):
                flagged, reason = True, "Process running from volatile system workspace directory"

            if flagged:
                max_severity_weight += 45
                events_found.append({
                    "type": "suspicious_process_ancestry", "severity": "high",
                    "description": f"{reason} (PID {proc_row['pid']})", 
                    "raw_details": json.dumps(dict(proc_row))
                })

        # 4. Historical Delta Analysis (FIM & SSH Persistence checks)
        cursor.execute("SELECT id FROM system_snapshots WHERE id < ? ORDER BY id DESC LIMIT 1;", (snapshot_id,))
        prev_snapshot_row = cursor.fetchone()
        if prev_snapshot_row:
            prev_snapshot_id = prev_snapshot_row["id"]

            # File Integrity Monitoring Check
            cursor.execute("""
                SELECT cur.file_path, cur.sha256_hash as cur_hash, prev.sha256_hash as prev_hash
                FROM collected_file_hashes cur
                JOIN collected_file_hashes prev ON cur.file_path = prev.file_path
                WHERE cur.snapshot_id = ? AND prev.snapshot_id = ?;
            """, (snapshot_id, prev_snapshot_id))
            for f_row in cursor.fetchall():
                if f_row["cur_hash"] != f_row["prev_hash"]:
                    max_severity_weight += 50
                    events_found.append({
                        "type": "file_modification", "severity": "critical",
                        "description": f"Critical modification change verified on config: {f_row['file_path']}",
                        "raw_details": json.dumps(dict(f_row))
                    })

            # New SSH Key Persistence Modification Checker
            cursor.execute("""
                SELECT cur.user_account, cur.fingerprint, cur.raw_key_comment
                FROM collected_ssh_keys cur
                WHERE cur.snapshot_id = ? AND cur.fingerprint NOT IN (
                    SELECT fingerprint FROM collected_ssh_keys WHERE snapshot_id = ?
                );
            """, (snapshot_id, prev_snapshot_id))
            for key_row in cursor.fetchall():
                max_severity_weight += 55
                events_found.append({
                    "type": "new_ssh_authorized_key", "severity": "critical",
                    "description": f"New unauthorized SSH signature deployed for account '{key_row['user_account']}': {key_row['raw_key_comment']}",
                    "raw_details": json.dumps(dict(key_row))
                })

            # New Cron Job Persistence Modification Checker
            cursor.execute("SELECT COUNT(*) as count FROM collected_crontabs WHERE snapshot_id = ?;", (prev_snapshot_id,))
            has_prev_crontabs = cursor.fetchone()["count"] > 0

            if has_prev_crontabs:
                cursor.execute("""
                    SELECT cur.source, cur.user, cur.schedule, cur.command
                    FROM collected_crontabs cur
                    WHERE cur.snapshot_id = ? AND NOT EXISTS (
                        SELECT 1 FROM collected_crontabs prev
                        WHERE prev.snapshot_id = ?
                          AND prev.source = cur.source
                          AND prev.user = cur.user
                          AND prev.schedule = cur.schedule
                          AND prev.command = cur.command
                    );
                """, (snapshot_id, prev_snapshot_id))
                for cron_row in cursor.fetchall():
                    max_severity_weight += 65
                    events_found.append({
                        "type": "new_cron_job", "severity": "high",
                        "description": f"New scheduled cron job registered for user '{cron_row['user']}' in '{cron_row['source']}': {cron_row['schedule']} - {cron_row['command']}",
                        "raw_details": json.dumps(dict(cron_row))
                    })

        # 5. Auth Log Parsing Indicators
        auth_data = parse_authentication_logs()
        for ip, count in auth_data["failed_ssh_counts"].items():
            if count >= 5:
                max_severity_weight += 40
                events_found.append({
                    "type": "ssh_bruteforce", "severity": "high",
                    "description": f"SSH brute-force pattern verified from IP {ip}: {count} failures",
                    "raw_details": json.dumps({"source_ip": ip, "failed_attempts_count": count})
                })
        for placement in auth_data["privileged_additions"]:
            max_severity_weight += 50
            events_found.append({
                "type": placement["type"], "severity": "critical",
                "description": placement["details"], "raw_details": None
            })

        # 6. Kernel Module Integrity Verification Rule
        cursor.execute("SELECT module_name, memory_size FROM baseline_kernel_modules;")
        trusted_modules = {row["module_name"] for row in cursor.fetchall()}

        cursor.execute("SELECT module_name, memory_size, instances_loaded FROM collected_kernel_modules WHERE snapshot_id = ?;", (snapshot_id,))
        collected_mods = cursor.fetchall()
        
        active_untrusted_mods = set()
        if trusted_modules:
            for mod in collected_mods:
                name = mod["module_name"]
                if name not in trusted_modules:
                    active_untrusted_mods.add(name)
                    max_severity_weight += 80
                    events_found.append({
                        "type": "untrusted_kernel_module", "severity": "critical",
                        "description": f"CRITICAL: Untrusted or unsigned LKM kernel driver module detected: {name}",
                        "raw_details": json.dumps(dict(mod))
                    })

        # 7. User Privilege Escalation & Backdoor Audit Rule
        cursor.execute("SELECT username, uid, login_shell FROM baseline_users;")
        baseline_users_map = {row["username"]: row for row in cursor.fetchall()}
        cursor.execute("SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ?;", (snapshot_id,))
        active_users = set()
        active_user_uids = {}
        for user in cursor.fetchall():
            active_users.add(user["username"])
            active_user_uids[user["username"]] = user["uid"]
            if user["username"] not in baseline_users_map:
                is_root = (user["uid"] == 0)
                max_severity_weight += 90 if is_root else 50
                events_found.append({
                    "type": "unauthorized_user_created", 
                    "severity": "critical" if is_root else "high", 
                    "description": f"Unauthorized profile: {user['username']}",
                    "raw_details": json.dumps(dict(user))
                })
            elif user["uid"] == 0 and baseline_users_map[user["username"]]["uid"] != 0:
                max_severity_weight += 100
                events_found.append({
                    "type": "privilege_escalation_hijack", 
                    "severity": "critical", 
                    "description": f"Hijack: {user['username']} promoted to root",
                    "raw_details": json.dumps(dict(user))
                })

        # 8. Deleted Binaries Execution Check
        cursor.execute("SELECT pid, exe, sha256, md5, vault_path FROM collected_deleted_binaries WHERE snapshot_id = ?;", (snapshot_id,))
        active_deleted_binaries = set()
        for row in cursor.fetchall():
            active_deleted_binaries.add((row["pid"], row["exe"]))
            max_severity_weight += 75
            events_found.append({
                "type": "deleted_binary_execution", "severity": "high",
                "description": f"Running process points to a deleted binary: PID {row['pid']} ({row['exe']})",
                "raw_details": json.dumps(dict(row))
            })

        # 9. Promiscuous Mode Interface Check
        cursor.execute("SELECT interface, flags, is_promiscuous FROM collected_promisc_interfaces WHERE snapshot_id = ?;", (snapshot_id,))
        active_promisc_interfaces = set()
        for row in cursor.fetchall():
            if row["is_promiscuous"] == 1:
                active_promisc_interfaces.add(row["interface"])
                max_severity_weight += 70
                events_found.append({
                    "type": "promiscuous_interface", "severity": "high",
                    "description": f"Promiscuous mode active on interface: {row['interface']}. Host may be capturing traffic outside its addressed unicast scope.",
                    "raw_details": json.dumps(dict(row))
                })

        # 10. WTMP / Lastlog Session Audit Tampering Check
        cursor.execute("SELECT user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason FROM collected_wtmp_sessions WHERE snapshot_id = ?;", (snapshot_id,))
        for row in cursor.fetchall():
            if row["anomaly_detected"] == 1:
                max_severity_weight += 95
                events_found.append({
                    "type": "log_tampering", "severity": "critical",
                    "description": f"WTMP session audit anomaly: {row['anomaly_reason']}",
                    "raw_details": json.dumps(dict(row))
                })

        cursor.execute("SELECT username, uid, line, host, login_time, anomaly_detected, anomaly_reason FROM collected_lastlog_records WHERE snapshot_id = ?;", (snapshot_id,))
        for row in cursor.fetchall():
            if row["anomaly_detected"] == 1:
                max_severity_weight += 95
                events_found.append({
                    "type": "log_tampering", "severity": "critical",
                    "description": f"Lastlog session audit anomaly for user '{row['username']}': {row['anomaly_reason']}",
                    "raw_details": json.dumps(dict(row))
                })

        # 11. Hidden Process (Unhide) Check
        hidden_procs = detect_hidden_processes()
        active_hidden_pids = {hp["pid"] for hp in hidden_procs}
        for hp in hidden_procs:
            max_severity_weight += 95
            events_found.append({
                "type": "hidden_process", "severity": "critical",
                "description": f"CRITICAL: Hidden process detected: PID {hp['pid']} is active in the scheduler but hidden from /proc directory listing.",
                "raw_details": json.dumps(hp)
            })

        # 12. Package Integrity Violation Check
        cursor.execute("SELECT package, file_path, expected_md5, actual_md5, actual_sha256, status FROM collected_pkg_integrity WHERE snapshot_id = ?;", (snapshot_id,))
        active_pkg_violations = set()
        for row in cursor.fetchall():
            active_pkg_violations.add((row["package"], row["file_path"]))
            max_severity_weight += 85
            desc = f"CRITICAL: Package integrity violation in package '{row['package']}': binary '{row['file_path']}' "
            if row["status"] == "missing":
                desc += "is missing from disk."
            else:
                desc += f"has been modified (expected MD5: {row['expected_md5']}, actual MD5: {row['actual_md5']})"
            events_found.append({
                "type": "pkg_integrity_violation", "severity": "critical",
                "description": desc,
                "raw_details": json.dumps(dict(row))
            })

        # 13. Cron Job Persistence Security Rules
        cursor.execute("SELECT source, user, schedule, command FROM collected_crontabs WHERE snapshot_id = ?;", (snapshot_id,))
        for cron_row in cursor.fetchall():
            command = cron_row["command"].lower()
            # Check for volatile directory execution
            if any(dir_path in command for dir_path in VOLATILE_DIRS):
                max_severity_weight += 70
                events_found.append({
                    "type": "cron_volatile_execution", "severity": "high",
                    "description": f"Cron job executes command from volatile system workspace: {cron_row['command']} ({cron_row['source']})",
                    "raw_details": json.dumps(dict(cron_row))
                })
            # Check for suspicious command components
            elif any(p.search(command) for p in SUSPICIOUS_CMD_PATTERNS) or any(re.search(rf"\b{name}\b", command) for name in SUSPICIOUS_EXACT_NAMES):
                max_severity_weight += 80
                events_found.append({
                    "type": "cron_suspicious_command", "severity": "critical",
                    "description": f"Suspicious interactive command or reverse shell signature in cron job: {cron_row['command']} ({cron_row['source']})",
                    "raw_details": json.dumps(dict(cron_row))
                })

        # Final DB Commit Sequence
        if events_found:
            for e in events_found:
                cursor.execute(
                    "SELECT id FROM security_events WHERE event_type = ? AND description = ? AND resolved = 0 LIMIT 1;",
                    (e["type"], e["description"])
                )
                if not cursor.fetchone():
                    cursor.execute(
                        "INSERT INTO security_events (event_type, severity, description, raw_details) VALUES (?, ?, ?, ?);",
                        (e["type"], e["severity"], e["description"], e.get("raw_details"))
                    )

        # Auto-resolve unexpected network ports
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'unexpected_port' AND resolved = 0;")
        for row in cursor.fetchall():
            match = re.search(r"Unexpected listening network port detected: (\d+)", row["description"])
            if match:
                port_num = int(match.group(1))
                if port_num not in active_unexpected_ports:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve unexpected kernel drivers
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'untrusted_kernel_module' AND resolved = 0;")
        for row in cursor.fetchall():
            match = re.search(r"CRITICAL: Untrusted or unsigned LKM kernel driver module detected: (\S+)", row["description"])
            if match:
                mod_name = match.group(1)
                if mod_name not in active_untrusted_mods:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve hidden processes
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'hidden_process' AND resolved = 0;")
        for row in cursor.fetchall():
            match = re.search(r"PID (\d+)", row["description"])
            if match:
                pid_val = int(match.group(1))
                if pid_val not in active_hidden_pids:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve deleted binary executions
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'deleted_binary_execution' AND resolved = 0;")
        for row in cursor.fetchall():
            match = re.search(r"PID (\d+) \((.+)\)", row["description"])
            if match:
                pid_val = int(match.group(1))
                exe_val = match.group(2)
                if (pid_val, exe_val) not in active_deleted_binaries:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve promiscuous interfaces
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'promiscuous_interface' AND resolved = 0;")
        for row in cursor.fetchall():
            match = re.search(r"Promiscuous mode active on interface: (\S+)", row["description"])
            if match:
                iface_val = match.group(1).rstrip('.')
                if iface_val not in active_promisc_interfaces:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve package integrity violations
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'pkg_integrity_violation' AND resolved = 0;")
        for row in cursor.fetchall():
            match = re.search(r"Package integrity violation in package '([^']+)': binary '([^']+)'", row["description"])
            if match:
                pkg_val = match.group(1)
                file_val = match.group(2)
                if (pkg_val, file_val) not in active_pkg_violations:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve unauthorized user created
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'unauthorized_user_created' AND resolved = 0;")
        for row in cursor.fetchall():
            match = re.search(r"Unauthorized profile: (\S+)", row["description"])
            if match:
                user_val = match.group(1)
                if user_val not in active_users:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve privilege escalation hijacks
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'privilege_escalation_hijack' AND resolved = 0;")
        for row in cursor.fetchall():
            match = re.search(r"Hijack: (\S+) promoted to root", row["description"])
            if match:
                user_val = match.group(1)
                if user_val not in active_user_uids or active_user_uids[user_val] != 0:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve suspicious process ancestry
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'suspicious_process_ancestry' AND resolved = 0;")
        for row in cursor.fetchall():
            match = re.search(r"\(PID (\d+)\)", row["description"])
            if match:
                pid_val = int(match.group(1))
                if pid_val not in active_processes:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve cron alerts (volatile, suspicious, new)
        cursor.execute("SELECT source, user, schedule, command FROM collected_crontabs WHERE snapshot_id = ?;", (snapshot_id,))
        active_crontabs = {(c_row["source"], c_row["user"], c_row["schedule"], c_row["command"]) for c_row in cursor.fetchall()}
        
        cursor.execute("SELECT id, raw_details, event_type FROM security_events WHERE event_type IN ('cron_volatile_execution', 'cron_suspicious_command', 'new_cron_job') AND resolved = 0;")
        for row in cursor.fetchall():
            if row["raw_details"]:
                try:
                    details = json.loads(row["raw_details"])
                    cron_key = (details.get("source"), details.get("user"), details.get("schedule"), details.get("command"))
                    if cron_key not in active_crontabs:
                        cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))
                except Exception:
                    pass

        conn.commit()

    # Severity-Tiered Risk Scoring
    if not events_found:
        risk_score = 0
    else:
        severities = [e["severity"].lower() for e in events_found]
        crit_count = severities.count("critical")
        high_count = severities.count("high")
        med_count = severities.count("medium")
        low_count = len(severities) - crit_count - high_count - med_count

        if crit_count > 0:
            risk_score = min(90 + (crit_count - 1) * 5, 100)
        elif high_count > 0:
            risk_score = min(65 + (high_count - 1) * 3 + med_count * 1.5 + low_count * 0.5, 89)
        elif med_count > 0:
            risk_score = min(35 + (med_count - 1) * 1.5 + low_count * 0.5, 64)
        else:
            risk_score = min(15 + (low_count - 1) * 0.5, 34)

        risk_score = int(risk_score + 0.5)

    return {
        "status": "success",
        "snapshot_id": snapshot_id,
        "risk_score": risk_score,
        "events_count": len(events_found)
    }