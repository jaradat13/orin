# orin/analysis/engine.py
import json
import re
from pathlib import Path
from orin.core.database import OrinStorage
from orin.collectors.logs import parse_authentication_logs
from orin.core.config import load_config

SUSPICIOUS_EXACT_NAMES = {"nc", "ncat", "netcat", "socat", "nmap", "miner", "xmrig"}

SUSPICIOUS_CMD_PATTERNS = [
    re.compile(r'\bpython\s+-c\b', re.IGNORECASE),
    re.compile(r'\bbash\s+-i\b', re.IGNORECASE),
    re.compile(r'\bsh\s+-i\b', re.IGNORECASE),
]

VOLATILE_DIRS = {"/tmp", "/dev/shm", "/var/tmp"}
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
        print("[!] Warning: Offline Threat Intelligence blocklist file missing at /var/lib/orin/intel_blocklist.txt")
        print("[!] Outbound C2 identification rules will be bypassed during this run.")
        return set()
    try:
        cleaned_ips = set()
        with open(BLOCKLIST_FILE_PATH, "r") as f:
            for line in f:
                line = line.strip()
                # Ignore empty lines or comment markers safely
                if not line or line.startswith("#"):
                    continue
                # Strip clean to avoid trailing space mismatch escapes
                cleaned_ips.add(line.split()[0])
        return cleaned_ips
    except Exception as e:
        print(f"[!] Error reading blocklist file definitions: {e}")
        return set()

def run_analysis_cycle(db_path: Path) -> dict:
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

        # orin/analysis/engine.py (Inside the process execution iteration block)

        # 3. Process Execution Analysis Rules (Upgraded with Ancestry Validation)
        cursor.execute("SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;", (snapshot_id,))
        for proc_row in cursor.fetchall():
            pid, ppid = proc_row["pid"], proc_row["ppid"]
            name, exe, cmdline = (proc_row["name"] or "").lower(), (proc_row["exe"] or "").lower(), (proc_row["cmdline"] or "").lower()
            flagged, reason = False, ""
            
            # --- Ancestry Validation Engine Block ---
            if any(name.startswith(p) for p in KERNEL_THREAD_PREFIXES):
                # Core kernel workers must strictly emerge out of system thread parent scopes (PID 2 or PID 0)
                if ppid not in (0, 2):
                    flagged, reason = True, f"Masquerade Fraud: Non-system ancestry parent discovered for worker (PPID {ppid})"
            # ----------------------------------------
            
            elif name in SUSPICIOUS_EXACT_NAMES:
                flagged, reason = True, f"Suspicious binary signature running detected: {name}"
            elif any(p.search(cmdline) for p in SUSPICIOUS_CMD_PATTERNS):
                flagged, reason = True, "Suspicious interactive command parameter flags"
            elif any(exe.startswith(d) for d in VOLATILE_DIRS):
                flagged, reason = True, "Process running from volatile system workspace directory"

            if flagged:
                max_severity_weight += 45
                events_found.append({
                    "type": "suspicious_process_ancestry", "severity": "high",
                    "description": f"{reason} (PID {proc_row['pid']})", "raw_details": json.dumps(dict(proc_row))
                })

        # 4. Historical Delta Analysis (FIM & SSH Persistence checks)
        # Use the actual previous snapshot ID rather than assuming snapshot_id - 1,
        # so gaps caused by deletions or failed collections don't silently skip the check.
        cursor.execute(
            "SELECT id FROM system_snapshots WHERE id < ? ORDER BY id DESC LIMIT 1;",
            (snapshot_id,)
        )
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

        cursor.execute(
            """
            SELECT module_name, memory_size, instances_loaded 
            FROM collected_kernel_modules WHERE snapshot_id = ?;
            """,
            (snapshot_id,)
        )
        collected_mods = cursor.fetchall()
        
        active_untrusted_mods = set()
        if trusted_modules: # Validate only if baseline parameters have been captured
            for mod in collected_mods:
                name = mod["module_name"]
                if name not in trusted_modules:
                    active_untrusted_mods.add(name)
                    max_severity_weight += 80 # Heavy penalty weighting for foreign LKM execution
                    events_found.append({
                        "type": "untrusted_kernel_module",
                        "severity": "critical",
                        "description": f"CRITICAL: Untrusted or unsigned LKM kernel driver module detected: {name}",
                        "raw_details": json.dumps(dict(mod))
                    })
        # 7. User Privilege Escalation & Backdoor Audit Rule
        cursor.execute("SELECT username, uid, login_shell FROM baseline_users;")
        baseline_users_map = {row["username"]: row for row in cursor.fetchall()}
        cursor.execute("SELECT username, uid, login_shell FROM collected_users WHERE snapshot_id = ?;", (snapshot_id,))
        for user in cursor.fetchall():
            if user["username"] not in baseline_users_map:
                is_root = (user["uid"] == 0)
                max_severity_weight += 90 if is_root else 50
                events_found.append({"type": "unauthorized_user_created", "severity": "critical" if is_root else "high", "description": f"Unauthorized profile: {user['username']}"})
            elif user["uid"] == 0 and baseline_users_map[user["username"]]["uid"] != 0:
                max_severity_weight += 100
                events_found.append({"type": "privilege_escalation_hijack", "severity": "critical", "description": f"Hijack: {user['username']} promoted to root"})

        # FINAL: Commitment Logic (Corrected Indentation)
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

        # Auto-resolve inactive unexpected ports
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'unexpected_port' AND resolved = 0;")
        for row in cursor.fetchall():
            match = re.search(r"Unexpected listening network port detected: (\d+)", row["description"])
            if match:
                port_num = int(match.group(1))
                if port_num not in active_unexpected_ports:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve inactive untrusted kernel modules
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'untrusted_kernel_module' AND resolved = 0;")
        for row in cursor.fetchall():
            match = re.search(r"CRITICAL: Untrusted or unsigned LKM kernel driver module detected: (\S+)", row["description"])
            if match:
                mod_name = match.group(1)
                if mod_name not in active_untrusted_mods:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        conn.commit()

    return {
        "status": "success",
        "snapshot_id": snapshot_id,
        "risk_score": min(max_severity_weight, 100),
        "events_count": len(events_found)
    }