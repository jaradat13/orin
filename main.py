# orin/main.py (Consolidated Version with Delta Subcommand integrated)
import os
import sys
import socket
import platform
import argparse
from pathlib import Path
from orin.core.database import OrinStorage
from orin.collectors.connections import gather_listening_ports, gather_outbound_connections
from orin.collectors.processes import gather_active_processes
from orin.collectors.persistence import gather_active_ssh_keys
from orin.analysis.engine import run_analysis_cycle
from orin.analysis.reporter import compile_markdown_report
from orin.analysis.timeline import calculate_snapshot_delta # New reference import
from orin.collectors.kernel import gather_loaded_kernel_modules # New import entry
from orin.core.crypto import generate_signed_export, verify_signed_export   
from orin.collectors.users import gather_system_accounts

DEFAULT_DB_PATH = Path("/var/lib/orin/orin_vault.db")

def verify_root_privileges(abort_on_fail: bool = False) -> bool:
    """Validates root privilege thresholds."""
    is_root = os.geteuid() == 0
    if not is_root:
        if abort_on_fail:
            print("[-] Critical Error: Root privileges are required to execute this operation.")
            print("[-] Please re-run utilizing: sudo orin <command>\n", file=sys.stderr)
            sys.exit(1)
        else:
            print("[!] Warning: Orin is operating under restricted non-root permissions.")
            print("[!] Comprehensive log and system audits will be bypassed.\n")
    return is_root

def cmd_init(args) -> None:
    """Initializes database vault layouts and captures an immutable module baseline."""
    verify_root_privileges(abort_on_fail=True)
    db_path = Path(args.database)
    print(f"[*] Initializing Orin Security Kernel storage at {db_path}...")
    storage = OrinStorage(db_path)
    try:
        storage.initialize_db()
        
        # 1. Existing Kernel Baseline collection
        baseline_modules = gather_loaded_kernel_modules()
        if baseline_modules:
            with storage.get_connection() as conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO baseline_kernel_modules (module_name, memory_size) VALUES (?, ?);",
                    [(m["module_name"], m["memory_size"]) for m in baseline_modules]
                )
                conn.commit()

        # 2. NEW Account Baseline capture block
        baseline_accounts = gather_system_accounts()
        if baseline_accounts:
            with storage.get_connection() as conn:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO baseline_users (username, uid, gid, home_dir, login_shell)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    [(u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in baseline_accounts]
                )
                conn.commit()

        print(f"[+] Global relational database vault created successfully.")
        print(f"[+] Immutable kernel module baseline generated ({len(baseline_modules)} entries).")
        print(f"[+] User account configuration baseline locked ({len(baseline_accounts)} profiles).")
    except Exception as e:
        print(f"[-] Critical database system layout architecture initialization failure: {e}", file=sys.stderr)
        sys.exit(1)

def cmd_collect(args) -> None:
    """Harvests running system state signatures."""
    db_path = Path(args.database)
    if not db_path.exists():
        print(f"[-] Database missing at {db_path}. Run 'sudo orin init' first.")
        return

    verify_root_privileges(abort_on_fail=False)
    print("[*] Launching system signal collection cycle...")
    storage = OrinStorage(db_path)
    
    ports = gather_listening_ports()
    processes = gather_active_processes()
    outbound = gather_outbound_connections()
    ssh_keys = gather_active_ssh_keys()
    kernel_mods = gather_loaded_kernel_modules() 
    system_users = gather_system_accounts()

    try:
        with storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO system_snapshots (hostname, os_platform) VALUES (?, ?);", (socket.gethostname(), platform.system()))
            snapshot_id = cursor.lastrowid

            if ports:
                conn.executemany("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (?, ?, ?, ?);", [(snapshot_id, p["port"], p["protocol"], p["process_name"]) for p in ports])
            if processes:
                conn.executemany("INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (?, ?, ?, ?, ?, ?);", [(snapshot_id, pr["pid"], pr["ppid"], pr["name"], pr["exe"], pr["cmdline"]) for pr in processes])
            if outbound:
                conn.executemany("INSERT INTO collected_outbound_connections (snapshot_id, local_ip, local_port, remote_ip, remote_port, state, process_name) VALUES (?, ?, ?, ?, ?, ?, ?);", [(snapshot_id, o["local_ip"], o["local_port"], o["remote_ip"], o["remote_port"], o["state"], o["process_name"]) for o in outbound])
            if ssh_keys:
                conn.executemany("INSERT INTO collected_ssh_keys (snapshot_id, user_account, key_type, fingerprint, raw_key_comment) VALUES (?, ?, ?, ?, ?);", [(snapshot_id, s["user_account"], s["key_type"], s["fingerprint"], s["raw_key_comment"]) for s in ssh_keys])
            if kernel_mods:
                conn.executemany("INSERT INTO collected_kernel_modules (snapshot_id, module_name, memory_size, instances_loaded) VALUES (?, ?, ?, ?);", [(snapshot_id, k["module_name"], k["memory_size"], k["instances_loaded"]) for k in kernel_mods])
            if system_users:
                conn.executemany("INSERT INTO collected_users (snapshot_id, username, uid, gid, home_dir, login_shell) VALUES (?, ?, ?, ?, ?, ?);", [(snapshot_id, u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in system_users])  
            conn.commit()
        print(f"[+] Snapshot complete (ID: {snapshot_id}). Tracked {len(ports)} ports, {len(processes)} processes, {len(outbound)} outbound channels, and {len(ssh_keys)} SSH keys.")
    except Exception as e:
        print(f"[-] Failed to write forensic signals: {e}", file=sys.stderr)

def cmd_analyze(args) -> None:
    """Processes newly generated telemetry matrices against local verification baselines."""
    db_path = Path(args.database)
    if not db_path.exists():
        return
    print("[*] Running threat analysis rules engine...")
    result = run_analysis_cycle(db_path)
    print(f"\n==================================================\n                ORIN POSTURE REPORT\n==================================================\n[+] Analyzed Snapshot ID : {result['snapshot_id']}\n[+] Discovered Anomalies : {result['events_count']}\n[+] Risk Score            : {result['risk_score']}/100\n==================================================")

def cmd_delta(args) -> None:
    """Executes the timeline delta query engine between two snapshots."""
    db_path = Path(args.database)
    if not db_path.exists():
        print(f"[-] Storage ledger missing at {db_path}.")
        return

    base_id = args.base
    target_id = args.target

    # 1. Automatic detection fallback logic if explicit targets aren't defined
    if base_id is None or target_id is None:
        storage = OrinStorage(db_path)
        with storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM system_snapshots ORDER BY id DESC LIMIT 2;")
            rows = cursor.fetchall()
            if len(rows) < 2:
                print("[-] Error: At least two historical system snapshots are required to calculate a delta timeline.")
                return
            target_id = rows[0]["id"]
            base_id = rows[1]["id"]

    print(f"[*] Computing structural forensics timeline delta: Snapshot {base_id} -> Snapshot {target_id}...")
    
    # 2. CALCULATE FIRST: Populate the 'diff' dictionary before reading fields
    diff = calculate_snapshot_delta(db_path, base_id, target_id)

    # 3. PRINT HEADERS & VISUAL LAYOUT
    print("\n" + "="*60)
    print(f"           TIMELINE DRIFT ANALYSIS (ID {base_id} -> ID {target_id})")
    print("="*60)
    
    # 4. PLACEMENT FIXED: Display critical alerts at the top of the drift brief
    print(f"\n[🚨] INTERMEDIATE SECURITY EVENTS TRIPPED ({len(diff['triggered_alerts'])}):")
    for a in diff["triggered_alerts"]:
        print(f"    -> [{a['severity'].upper()}] {a['type']} - {a['description']} (@ {a['timestamp']})")

    # 5. RENDER SYSTEM PERFORMANCE INFRASTRUCTURE CHANGES
    print(f"\n[+] NEW LISTENING PORTS DETECTED ({len(diff['new_ports'])}):")
    for p in diff["new_ports"]:
        print(f"    -> Port: {p['port']}/{p['protocol']} | Service: {p['process']}")

    print(f"\n[+] NEWLY SPAWNED PROCESS IMAGES ({len(diff['new_processes'])}):")
    for pr in diff["new_processes"]:
        print(f"    -> PID: {pr['pid']} | PPID: {pr['ppid']} | Image: {pr['name']} | CMD: {pr['cmdline']}")

    print(f"\n[+] NEW ACTIVE OUTBOUND CHANNELS ({len(diff['new_connections'])}):")
    for c in diff["new_connections"]:
        print(f"    -> Remote Host: {c['remote_ip']}:{c['remote_port']} (State: {c['state']})")
    print("="*60 + "\n")

def cmd_report(args) -> None:
    """Compiles markdown audit report files."""
    db_path = Path(args.database)
    report_filename = f"orin_report_{platform.node()}.md"
    output_path = Path.cwd() / report_filename
    compile_markdown_report(db_path, output_path)
    print(f"[+] Standalone Markdown Report written to: {output_path}")


def cmd_export(args) -> None:
    """Signs and bundles forensic snapshot structures."""
    db_path = Path(args.database)
    if not db_path.exists():
        print(f"[-] Missing storage at {db_path}.")
        return

    secret = args.secret or input("Enter master cryptographic passphrase: ")
    output_path = Path.cwd() / f"orin_export_snap_{args.snapshot}.json"
    
    print(f"[*] Packaging and signing snapshot {args.snapshot}...")
    try:
        signed_bundle = generate_signed_export(db_path, args.snapshot, secret)
        output_path.write_text(signed_bundle)
        print(f"[+] Forensic Evidence Vault generated successfully!")
        print(f"[+] Signed Artifact: {output_path}")
    except Exception as e:
        print(f"[-] Export compilation halted: {e}", file=sys.stderr)

def cmd_verify(args) -> None:
    """Audits an external export file signature for telemetry verification."""
    export_path = Path(args.file)
    if not export_path.exists():
        print(f"[-] Export file target not found: {export_path}")
        return

    secret = args.secret or input("Enter master cryptographic passphrase: ")
    print(f"[*] Parsing artifact headers and evaluating cryptographic validation ring...")
    try:
        verified_data = verify_signed_export(export_path, secret)
        meta = verified_data["metadata"]
        print(f"\n[🔒] VERIFICATION SUCCESS: SIGNATURE VALID AND INTACT")
        print(f"    -> Hostname   : {meta['hostname']}")
        print(f"    -> Collected  : {meta['timestamp']}")
        print(f"    -> Processes  : {len(verified_data['processes'])} tracking rows")
        print(f"    -> Connections: {len(verified_data['outbound'])} tracking rows")
    except PermissionError as e:
        print(f"\n[🛑] {e}", file=sys.stderr)
    except Exception as e:
        print(f"[-] Validation processing crash: {e}", file=sys.stderr)


def cmd_status(args) -> None:
    """Displays a structural summary dashboard of the local Orin engine storage state."""
    db_path = Path(args.database)
    if not db_path.exists():
        print(f"[-] Orin is not initialized. Storage missing at {db_path}.")
        return

    storage = OrinStorage(db_path)
    print("\n" + "="*50)
    print("         ORIN ENGINE CORE POSTURE STATUS")
    print("="*50)

    try:
        with storage.get_connection() as conn:
            cursor = conn.cursor()

            # Fetch metric tracking totals
            cursor.execute("SELECT COUNT(*) as total FROM system_snapshots;")
            snapshots_count = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) as total FROM baseline_kernel_modules;")
            baseline_count = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) as total FROM security_events;")
            alerts_count = cursor.fetchone()["total"]

            print(f"[+] Storage Vault Path  : {db_path}")
            print(f"[+] Historical Snapshots: {snapshots_count} recorded cycles")
            print(f"[+] Kernel Baselines    : {baseline_count} approved modules")
            print(f"[+] Security Violations : {alerts_count} total alerts on ledger")
            
            if snapshots_count > 0:
                cursor.execute("SELECT id, timestamp, hostname FROM system_snapshots ORDER BY id DESC LIMIT 1;")
                latest = cursor.fetchone()
                print(f"[+] Latest Snapshot ID  : {latest['id']} (Captured: {latest['timestamp']})")
                print(f"[+] Active Host Target  : {latest['hostname']}")
            
    except Exception as e:
        print(f"[-] Failed to read posture metrics dashboard: {e}", file=sys.stderr)
    
    print("="*50 + "\n")

def main() -> None:
    parser = argparse.ArgumentParser(description="Orin: Fully Offline Investigation Engine.")
    parser.add_argument("--database", type=str, default=str(DEFAULT_DB_PATH), help="Path to SQLite vault.")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init")
    subparsers.add_parser("collect")
    subparsers.add_parser("analyze")
    subparsers.add_parser("report")
    subparsers.add_parser("status", help="Display local engine status dashboard and metric summaries.")
    
    # 1. Delta Subcommand Configuration
    delta_parser = subparsers.add_parser("delta", help="Evaluate structural configuration drift across snapshots.")
    delta_parser.add_argument("--base", type=int, help="Starting baseline snapshot ID index (e.g. 1).")
    delta_parser.add_argument("--target", type=int, help="Concluding target snapshot ID index (e.g. 2).")
    
    # 2. Export Command Setup
    exp_parser = subparsers.add_parser("export", help="Sign and export an invariant snapshot.")
    exp_parser.add_argument("--snapshot", type=int, required=True, help="Snapshot ID matrix index.")
    exp_parser.add_argument("--secret", type=str, help="Cryptographic passphrase key.")

    # 3. Verify Command Setup
    v_parser = subparsers.add_parser("verify", help="Verify standalone artifact bundle signature.")
    v_parser.add_argument("--file", type=str, required=True, help="Path to targeted export JSON.")
    v_parser.add_argument("--secret", type=str, help="Cryptographic passphrase key.")
    
    # 4. PARSE LATE: Only parse parameters after the entire routing pool is declared
    args = parser.parse_args()
    
    # 5. CONSOLIDATE ROUTER MAP: Add export and verify to the active execution ring
    commands = {
        "init": cmd_init, 
        "collect": cmd_collect, 
        "analyze": cmd_analyze, 
        "report": cmd_report, 
        "delta": cmd_delta,
        "export": cmd_export,
        "verify": cmd_verify,
        "status": cmd_status
    }
    
    commands[args.command](args)
if __name__ == "__main__":
    main()