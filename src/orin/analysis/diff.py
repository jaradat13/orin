# orin/analysis/diff.py
import json
import sqlite3
from pathlib import Path
from orin.core.crypto import verify_signed_export

def load_snapshot_data(file_path: Path, secret_key: str = None) -> dict:
    """Loads snapshot data from either a SQLite database (latest snapshot) or a signed JSON export."""
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
        
    # 1. Try to read as a SQLite database
    try:
        conn = sqlite3.connect(file_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if the database has system_snapshots table
        cursor.execute("SELECT id, hostname, os_platform, timestamp FROM system_snapshots ORDER BY id DESC LIMIT 1;")
        snap = cursor.fetchone()
        if snap:
            snapshot_id = snap['id']
            
            cursor.execute("SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;", (snapshot_id,))
            processes = [dict(r) for r in cursor.fetchall()]
            
            cursor.execute("SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;", (snapshot_id,))
            ports = [dict(r) for r in cursor.fetchall()]
            
            cursor.execute("SELECT local_ip, local_port, remote_ip, remote_port, state, process_name FROM collected_outbound_connections WHERE snapshot_id = ?;", (snapshot_id,))
            outbound = [dict(r) for r in cursor.fetchall()]
            
            cursor.execute("SELECT module_name, memory_size, instances_loaded FROM collected_kernel_modules WHERE snapshot_id = ?;", (snapshot_id,))
            kernel_modules = [dict(r) for r in cursor.fetchall()]
            
            cursor.execute("SELECT user_account, key_type, fingerprint, raw_key_comment FROM collected_ssh_keys WHERE snapshot_id = ?;", (snapshot_id,))
            ssh_keys = [dict(r) for r in cursor.fetchall()]
            
            cursor.execute("SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ?;", (snapshot_id,))
            users = [dict(r) for r in cursor.fetchall()]
            
            cursor.execute("SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ?;", (snapshot_id,))
            file_hashes = [dict(r) for r in cursor.fetchall()]
            
            conn.close()
            return {
                "source": "database",
                "metadata": dict(snap),
                "processes": processes,
                "ports": ports,
                "outbound": outbound,
                "kernel_modules": kernel_modules,
                "ssh_keys": ssh_keys,
                "users": users,
                "file_hashes": file_hashes
            }
    except sqlite3.OperationalError:
        pass # Not a SQLite database with correct tables
    except Exception:
        pass
        
    # 2. Try to read as a signed JSON export
    try:
        if not secret_key:
            raise ValueError("Passphrase (--secret) is required to verify/decrypt the export file.")
        
        verified_data = verify_signed_export(file_path, secret_key)
        return {
            "source": "export",
            "metadata": verified_data["metadata"],
            "processes": verified_data["processes"],
            "ports": verified_data["ports"],
            "outbound": verified_data["outbound"],
            "kernel_modules": verified_data.get("kernel_modules", []),
            "ssh_keys": verified_data.get("ssh_keys", []),
            "users": verified_data.get("users", []),
            "file_hashes": verified_data.get("file_hashes", [])
        }
    except Exception as e:
        raise ValueError(f"Failed to parse '{file_path}' as database or signed export: {e}")


def compare_snapshots(base: dict, target: dict) -> dict:
    """Compares base snapshot data dictionary with target snapshot data dictionary to produce a diff report."""
    diff = {
        "metadata": {
            "base": base["metadata"],
            "target": target["metadata"]
        },
        "ports": {"added": [], "removed": []},
        "outbound": {"added": [], "removed": []},
        "processes": {"added": [], "removed": []},
        "kernel_modules": {"added": [], "removed": []},
        "users": {"added": [], "removed": [], "modified": []},
        "ssh_keys": {"added": [], "removed": []},
        "file_hashes": {"added": [], "removed": [], "modified": []}
    }

    # 1. Ports Diff
    base_ports = {(p["port"], p["protocol"]) for p in base["ports"]}
    target_ports = {(p["port"], p["protocol"]): p for p in target["ports"]}
    for k in (target_ports.keys() - base_ports):
        diff["ports"]["added"].append(target_ports[k])
    
    base_ports_map = {(p["port"], p["protocol"]): p for p in base["ports"]}
    for k in (base_ports - target_ports.keys()):
        diff["ports"]["removed"].append(base_ports_map[k])

    # 2. Outbound Connections Diff
    base_outbound = {(o["remote_ip"], o["remote_port"]) for o in base["outbound"]}
    target_outbound = {(o["remote_ip"], o["remote_port"]): o for o in target["outbound"]}
    for k in (target_outbound.keys() - base_outbound):
        diff["outbound"]["added"].append(target_outbound[k])
    
    base_outbound_map = {(o["remote_ip"], o["remote_port"]): o for o in base["outbound"]}
    for k in (base_outbound - target_outbound.keys()):
        diff["outbound"]["removed"].append(base_outbound_map[k])

    # 3. Processes Diff (Using name, exe, cmdline as identity key)
    base_procs = {(p["name"], p["exe"], p["cmdline"]) for p in base["processes"]}
    target_procs = {(p["name"], p["exe"], p["cmdline"]): p for p in target["processes"]}
    for k in (target_procs.keys() - base_procs):
        diff["processes"]["added"].append(target_procs[k])
    
    base_procs_map = {(p["name"], p["exe"], p["cmdline"]): p for p in base["processes"]}
    for k in (base_procs - target_procs.keys()):
        diff["processes"]["removed"].append(base_procs_map[k])

    # 4. Kernel Modules Diff
    base_mods = {m["module_name"] for m in base["kernel_modules"]}
    target_mods = {m["module_name"]: m for m in target["kernel_modules"]}
    for k in (target_mods.keys() - base_mods):
        diff["kernel_modules"]["added"].append(target_mods[k])
    
    base_mods_map = {m["module_name"]: m for m in base["kernel_modules"]}
    for k in (base_mods - target_mods.keys()):
        diff["kernel_modules"]["removed"].append(base_mods_map[k])

    # 5. Users Diff
    base_users = {u["username"] for u in base["users"]}
    target_users = {u["username"]: u for u in target["users"]}
    for k in (target_users.keys() - base_users):
        diff["users"]["added"].append(target_users[k])
    
    base_users_map = {u["username"]: u for u in base["users"]}
    for k in (base_users - target_users.keys()):
        diff["users"]["removed"].append(base_users_map[k])
        
    for k in (base_users & target_users.keys()):
        b_u = base_users_map[k]
        t_u = target_users[k]
        modifications = {}
        for field in ["uid", "gid", "home_dir", "login_shell"]:
            if b_u.get(field) != t_u.get(field):
                modifications[field] = {"old": b_u.get(field), "new": t_u.get(field)}
        if modifications:
            diff["users"]["modified"].append({"username": k, "changes": modifications})

    # 6. SSH Keys Diff
    base_ssh = {(s["user_account"], s["fingerprint"]) for s in base["ssh_keys"]}
    target_ssh = {(s["user_account"], s["fingerprint"]): s for s in target["ssh_keys"]}
    for k in (target_ssh.keys() - base_ssh):
        diff["ssh_keys"]["added"].append(target_ssh[k])
    
    base_ssh_map = {(s["user_account"], s["fingerprint"]): s for s in base["ssh_keys"]}
    for k in (base_ssh - target_ssh.keys()):
        diff["ssh_keys"]["removed"].append(base_ssh_map[k])

    # 7. File Integrity Monitor Diff
    base_files = {f["file_path"] for f in base["file_hashes"]}
    target_files = {f["file_path"]: f for f in target["file_hashes"]}
    for k in (target_files.keys() - base_files):
        diff["file_hashes"]["added"].append(target_files[k])
    
    base_files_map = {f["file_path"]: f for f in base["file_hashes"]}
    for k in (base_files - target_files.keys()):
        diff["file_hashes"]["removed"].append(base_files_map[k])
        
    for k in (base_files & target_files.keys()):
        b_f = base_files_map[k]
        t_f = target_files[k]
        if b_f["sha256_hash"] != t_f["sha256_hash"]:
            diff["file_hashes"]["modified"].append({
                "file_path": k,
                "old_hash": b_f["sha256_hash"],
                "new_hash": t_f["sha256_hash"]
            })

    return diff


def print_diff_report(diff: dict) -> None:
    """Outputs comparison results cleanly to the console."""
    base_meta = diff["metadata"]["base"]
    target_meta = diff["metadata"]["target"]
    
    print("\n" + "="*70)
    print("                 ORIN FORENSIC SNAPSHOT DIFF REPORT")
    print("="*70)
    print(f"Base   : Host: {base_meta.get('hostname')} | OS: {base_meta.get('os_platform')} | Captured: {base_meta.get('timestamp')}")
    print(f"Target : Host: {target_meta.get('hostname')} | OS: {target_meta.get('os_platform')} | Captured: {target_meta.get('timestamp')}")
    print("="*70)

    # 1. Ports
    added_ports = diff["ports"]["added"]
    removed_ports = diff["ports"]["removed"]
    if added_ports or removed_ports:
        print("\n[🌐] Network Sockets Drift:")
        for p in added_ports:
            print(f"    [+] ADDED Listening Port: {p['port']}/{p['protocol']} ({p['process_name'] or 'unknown'})")
        for p in removed_ports:
            print(f"    [-] REMOVED Listening Port: {p['port']}/{p['protocol']} ({p['process_name'] or 'unknown'})")

    # 2. Outbound Connections
    added_out = diff["outbound"]["added"]
    removed_out = diff["outbound"]["removed"]
    if added_out or removed_out:
        print("\n[📤] Outbound Connections Drift:")
        for o in added_out:
            print(f"    [+] ADDED Outbound Connection: -> {o['remote_ip']}:{o['remote_port']} ({o['process_name'] or 'unknown'})")
        for o in removed_out:
            print(f"    [-] REMOVED Outbound Connection: -> {o['remote_ip']}:{o['remote_port']} ({o['process_name'] or 'unknown'})")

    # 3. Processes
    added_procs = diff["processes"]["added"]
    removed_procs = diff["processes"]["removed"]
    if added_procs or removed_procs:
        print("\n[⚙️] Processes Drift:")
        for p in added_procs:
            print(f"    [+] NEW Process Running: {p['name']} (PID: {p['pid']}, PPID: {p['ppid']})")
            if p['cmdline']:
                print(f"        CMD: {p['cmdline']}")
        for p in removed_procs:
            print(f"    [-] TERMINATED Process: {p['name']} (PID: {p['pid']})")

    # 4. Kernel Modules
    added_mods = diff["kernel_modules"]["added"]
    removed_mods = diff["kernel_modules"]["removed"]
    if added_mods or removed_mods:
        print("\n[🛡️] Loaded Kernel Modules Drift:")
        for m in added_mods:
            print(f"    [+] ADDED Module: {m['module_name']} ({m['memory_size']} bytes)")
        for m in removed_mods:
            print(f"    [-] REMOVED Module: {m['module_name']}")

    # 5. User Accounts
    added_users = diff["users"]["added"]
    removed_users = diff["users"]["removed"]
    modified_users = diff["users"]["modified"]
    if added_users or removed_users or modified_users:
        print("\n[👤] User Accounts Drift:")
        for u in added_users:
            print(f"    [+] ADDED User: {u['username']} (UID: {u['uid']})")
        for u in removed_users:
            print(f"    [-] REMOVED User: {u['username']}")
        for u in modified_users:
            print(f"    [*] MODIFIED User: {u['username']}:")
            for field, change in u["changes"].items():
                print(f"        -> {field}: {change['old']} -> {change['new']}")

    # 6. SSH Keys
    added_ssh = diff["ssh_keys"]["added"]
    removed_ssh = diff["ssh_keys"]["removed"]
    if added_ssh or removed_ssh:
        print("\n[🔑] SSH Authorized Keys Drift:")
        for s in added_ssh:
            print(f"    [+] ADDED SSH Key for {s['user_account']}: comment '{s['raw_key_comment']}'")
        for s in removed_ssh:
            print(f"    [-] REMOVED SSH Key for {s['user_account']}: comment '{s['raw_key_comment']}'")

    # 7. File Integrity Monitor
    added_files = diff["file_hashes"]["added"]
    removed_files = diff["file_hashes"]["removed"]
    modified_files = diff["file_hashes"]["modified"]
    if added_files or removed_files or modified_files:
        print("\n[📂] File Integrity Monitor (FIM) Drift:")
        for f in added_files:
            print(f"    [+] ADDED Monitored File: {f['file_path']}")
        for f in removed_files:
            print(f"    [-] REMOVED Monitored File: {f['file_path']}")
        for f in modified_files:
            print(f"    [🛑] MODIFIED File: {f['file_path']}")
            print(f"        Old Hash: {f['old_hash']}")
            print(f"        New Hash: {f['new_hash']}")

    # If no drift
    if not (added_ports or removed_ports or added_out or removed_out or added_procs or removed_procs or
            added_mods or removed_mods or added_users or removed_users or modified_users or
            added_ssh or removed_ssh or added_files or removed_files or modified_files):
        print("\n🟢 No configuration, network, process, or file integrity drift detected between snapshots.")
        
    print("="*70 + "\n")
