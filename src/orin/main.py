# orin/main.py (Consolidated Version with Delta Subcommand integrated)
"""
orin.main – CLI Entry Point
===========================
Provides the ``orin`` command-line interface via :func:`main`.

Available subcommands
---------------------
init     – Create the SQLite vault and capture immutable baselines.
collect  – Harvest current system state into a new snapshot.
analyze  – Run all threat-detection rules against the latest snapshot.
report   – Compile a Markdown or HTML audit briefing.
status   – Print a dashboard summary of the vault contents.
delta    – Timeline drift analysis between two snapshot IDs.
export   – HMAC-sign and serialise a snapshot to a portable JSON file.
verify   – Verify the integrity of a signed JSON export file.
diff     – Compare two database or export files for drift.

All subcommands share the optional ``--database`` flag (default:
``/var/lib/orin/orin_vault.db``).
"""
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
from orin.analysis.timeline import calculate_snapshot_delta
from orin.collectors.kernel import gather_loaded_kernel_modules
from orin.core.crypto import generate_signed_export, verify_signed_export   
from orin.collectors.users import gather_system_accounts
from orin.collectors.integrity import gather_file_integrity_signatures
from orin.collectors.deleted_binaries import gather_deleted_binaries
from orin.collectors.promisc import gather_promisc_interfaces
from orin.collectors.session_audit import gather_wtmp_sessions, gather_lastlog_records
from orin.collectors.pkg_integrity import gather_pkg_integrity_drift

#: Default path to the Orin SQLite vault. Can be overridden at runtime via
#: the ``--database`` CLI argument on every subcommand.
DEFAULT_DB_PATH = Path("/var/lib/orin/orin_vault.db")

def verify_root_privileges(abort_on_fail: bool = False) -> bool:
    """Check whether the process is running as root."""
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
    """Handle the ``orin init`` subcommand."""
    verify_root_privileges(abort_on_fail=True)
    db_path = Path(args.database)
    print(f"[*] Initializing Orin Security Kernel storage at {db_path}...")
    storage = OrinStorage(db_path)
    try:
        storage.initialize_db()
        
        # 1. Kernel Baseline collection
        baseline_modules = gather_loaded_kernel_modules()
        if baseline_modules:
            with storage.get_connection() as conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO baseline_kernel_modules (module_name, memory_size) VALUES (?, ?);",
                    [(m["module_name"], m["memory_size"]) for m in baseline_modules]
                )
                conn.commit()

        # 2. Account Baseline capture block
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

        print("[+] Global relational database vault created successfully.")
        print(f"[+] Immutable kernel module baseline generated ({len(baseline_modules)} entries).")
        print(f"[+] User account configuration baseline locked ({len(baseline_accounts)} profiles).")
    except Exception as e:
        print(f"[-] Critical database system layout architecture initialization failure: {e}", file=sys.stderr)
        sys.exit(1)

def cmd_collect(args) -> None:
    """Handle the ``orin collect`` subcommand."""
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
    file_hashes = gather_file_integrity_signatures()
    deleted_binaries = gather_deleted_binaries()
    promisc_interfaces = gather_promisc_interfaces()
    wtmp_sessions = gather_wtmp_sessions()
    lastlog_records = gather_lastlog_records()
    pkg_integrity = gather_pkg_integrity_drift()

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
            if file_hashes:
                conn.executemany("INSERT INTO collected_file_hashes (snapshot_id, file_path, sha256_hash) VALUES (?, ?, ?);", [(snapshot_id, f["file_path"], f["sha256_hash"]) for f in file_hashes])
            if deleted_binaries:
                conn.executemany("INSERT INTO collected_deleted_binaries (snapshot_id, pid, exe, sha256, md5, vault_path) VALUES (?, ?, ?, ?, ?, ?);", [(snapshot_id, d["pid"], d["exe"], d["sha256"], d["md5"], d["vault_path"]) for d in deleted_binaries])
            if promisc_interfaces:
                conn.executemany("INSERT INTO collected_promisc_interfaces (snapshot_id, interface, flags, is_promiscuous) VALUES (?, ?, ?, ?);", [(snapshot_id, pi["interface"], pi["flags"], pi["is_promiscuous"]) for pi in promisc_interfaces])
            if wtmp_sessions:
                conn.executemany("INSERT INTO collected_wtmp_sessions (snapshot_id, user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);", [(snapshot_id, w["user"], w["line"], w["host"], w["pid"], w["login_time"], w["logout_time"], w["anomaly_detected"], w["anomaly_reason"]) for w in wtmp_sessions])
            if lastlog_records:
                conn.executemany("INSERT INTO collected_lastlog_records (snapshot_id, username, uid, line, host, login_time, anomaly_detected, anomaly_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?);", [(snapshot_id, l["username"], l["uid"], l["line"], l["host"], l["login_time"], l["anomaly_detected"], l["anomaly_reason"]) for l in lastlog_records])
            if pkg_integrity:
                conn.executemany("INSERT INTO collected_pkg_integrity (snapshot_id, package, file_path, expected_md5, actual_md5, actual_sha256, status) VALUES (?, ?, ?, ?, ?, ?, ?);", [(snapshot_id, k["package"], k["file_path"], k["expected_md5"], k["actual_md5"], k["actual_sha256"], k["status"]) for k in pkg_integrity])
            conn.commit()
        print(f"[+] Snapshot complete (ID: {snapshot_id}). Tracked {len(ports)} ports, {len(processes)} processes, {len(outbound)} outbound channels, {len(ssh_keys)} SSH keys, {len(file_hashes)} file hashes, {len(deleted_binaries)} deleted binaries, {len(promisc_interfaces)} interfaces, {len(wtmp_sessions)} WTMP sessions, {len(lastlog_records)} lastlog records, and {len(pkg_integrity)} package mismatches.")
    except Exception as e:
        print(f"[-] Failed to write forensic signals: {e}", file=sys.stderr)

def cmd_analyze(args) -> None:
    """Handle the ``orin analyze`` subcommand."""
    db_path = Path(args.database)
    if not db_path.exists():
        return
    print("[*] Running threat analysis rules engine...")
    result = run_analysis_cycle(db_path)
    print(f"\n==================================================\n                ORIN POSTURE REPORT\n==================================================\n[+] Analyzed Snapshot ID : {result['snapshot_id']}\n[+] Discovered Anomalies : {result['events_count']}\n[+] Risk Score            : {result['risk_score']}/100\n==================================================")

def cmd_delta(args) -> None:
    """Handle the ``orin delta`` subcommand."""
    db_path = Path(args.database)
    if not db_path.exists():
        print(f"[-] Storage ledger missing at {db_path}.")
        return

    base_id = args.base
    target_id = args.target

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
    
    diff = calculate_snapshot_delta(db_path, base_id, target_id)

    print("\n" + "="*60)
    print(f"           TIMELINE DRIFT ANALYSIS (ID {base_id} -> ID {target_id})")
    print("="*60)
    
    print(f"\n[🚨] INTERMEDIATE SECURITY EVENTS TRIPPED ({len(diff['triggered_alerts'])}):")
    for a in diff["triggered_alerts"]:
        print(f"    -> [{a['severity'].upper()}] {a['type']} - {a['description']} (@ {a['timestamp']})")

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
    """Handle the ``orin report`` subcommand."""
    db_path = Path(args.database)
    fmt = getattr(args, "format", "md").lower()
    
    if getattr(args, "output", None):
        output_path = Path(args.output)
    else:
        report_filename = f"orin_report_{platform.node()}.{fmt}"
        output_path = Path.cwd() / report_filename

    if fmt == "html":
        from orin.analysis.reporter import compile_html_report
        compile_html_report(db_path, output_path)
        print(f"[+] Standalone HTML Report written to: {output_path}")
    else:
        compile_markdown_report(db_path, output_path)
        print(f"[+] Standalone Markdown Report written to: {output_path}")

def cmd_export(args) -> None:
    """Handle the ``orin export`` subcommand."""
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
        print("[+] Forensic Evidence Vault generated successfully!")
        print(f"[+] Signed Artifact: {output_path}")
    except Exception as e:
        print(f"[-] Export compilation halted: {e}", file=sys.stderr)

def cmd_verify(args) -> None:
    """Handle the ``orin verify`` subcommand."""
    export_path = Path(args.file)
    if not export_path.exists():
        print(f"[-] Export file target not found: {export_path}")
        return

    secret = args.secret or input("Enter master cryptographic passphrase: ")
    print("[*] Parsing artifact headers and evaluating cryptographic validation ring...")
    try:
        verified_data = verify_signed_export(export_path, secret)
        meta = verified_data["metadata"]
        print("\n[🔒] VERIFICATION SUCCESS: SIGNATURE VALID AND INTACT")
        print(f"    -> Hostname   : {meta['hostname']}")
        print(f"    -> Collected  : {meta['timestamp']}")
        print(f"    -> Processes  : {len(verified_data['processes'])} tracking rows")
        print(f"    -> Connections: {len(verified_data['outbound'])} tracking rows")
        if "ssh_keys" in verified_data:
            print(f"    -> SSH Keys   : {len(verified_data['ssh_keys'])} tracking rows")
        if "users" in verified_data:
            print(f"    -> User Accts : {len(verified_data['users'])} tracking rows")
        if "file_hashes" in verified_data:
            print(f"    -> File Hashes: {len(verified_data['file_hashes'])} tracking rows")
    except PermissionError as e:
        print(f"\n[🛑] {e}", file=sys.stderr)
    except Exception as e:
        print(f"[-] Validation processing crash: {e}", file=sys.stderr)

def cmd_status(args) -> None:
    """Handle the ``orin status`` subcommand."""
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

def cmd_diff(args) -> None:
    """Handle the ``orin diff`` subcommand."""
    base_file = Path(args.base_file)
    target_file = Path(args.target_file)
    secret = args.secret
    
    if not base_file.exists():
        print(f"[-] Base file does not exist: {base_file}", file=sys.stderr)
        sys.exit(1)
    if not target_file.exists():
        print(f"[-] Target file does not exist: {target_file}", file=sys.stderr)
        sys.exit(1)
        
    if not secret:
        is_export = any(f.suffix.lower() == '.json' for f in [base_file, target_file])
        if is_export:
            if sys.stdin.isatty():
                secret = input("Enter master cryptographic passphrase to verify JSON export: ")
            else:
                print("[-] Error: Master cryptographic passphrase (--secret) is required for JSON export verification in non-interactive shell.", file=sys.stderr)
                sys.exit(1)

    from orin.analysis.diff import load_snapshot_data, compare_snapshots, print_diff_report
    try:
        base_data = load_snapshot_data(base_file, secret)
        target_data = load_snapshot_data(target_file, secret)
        diff_res = compare_snapshots(base_data, target_data)
        print_diff_report(diff_res)
    except Exception as e:
        print(f"[-] Diff calculation failure: {e}", file=sys.stderr)
        sys.exit(1)

def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate subcommand handler."""
    parser = argparse.ArgumentParser(description="Orin: Fully Offline Investigation Engine.")
    parser.add_argument("--database", type=str, default=str(DEFAULT_DB_PATH), help="Path to SQLite vault.")
    
    subparser_base = argparse.ArgumentParser(add_help=False)
    subparser_base.add_argument("--database", type=str, default=argparse.SUPPRESS, help="Path to SQLite vault.")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init", parents=[subparser_base])
    subparsers.add_parser("collect", parents=[subparser_base])
    subparsers.add_parser("analyze", parents=[subparser_base])
    
    report_parser = subparsers.add_parser("report", parents=[subparser_base])
    report_parser.add_argument("--format", type=str, choices=["md", "html"], default="md", help="Format of the output report (md, html).")
    report_parser.add_argument("--output", type=str, help="Custom output filepath.")
    
    subparsers.add_parser("status", parents=[subparser_base], help="Display local engine status dashboard and metric summaries.")
    
    delta_parser = subparsers.add_parser("delta", parents=[subparser_base], help="Evaluate structural configuration drift across snapshots.")
    delta_parser.add_argument("--base", type=int, default=None, help="Starting baseline snapshot ID index (e.g. 1).")
    delta_parser.add_argument("--target", type=int, default=None, help="Concluding target snapshot ID index (e.g. 2).")
    
    exp_parser = subparsers.add_parser("export", parents=[subparser_base], help="Sign and export an invariant snapshot.")
    exp_parser.add_argument("--snapshot", type=int, required=True, help="Snapshot ID matrix index.")
    exp_parser.add_argument("--secret", type=str, help="Cryptographic passphrase key.")

    v_parser = subparsers.add_parser("verify", parents=[subparser_base], help="Verify standalone artifact bundle signature.")
    v_parser.add_argument("--file", type=str, required=True, help="Path to targeted export JSON.")
    v_parser.add_argument("--secret", type=str, help="Cryptographic passphrase key.")
    
    diff_parser = subparsers.add_parser("diff", parents=[subparser_base], help="Evaluate structural configuration drift between two database or export files.")
    diff_parser.add_argument("base_file", type=str, help="Path to base file (SQLite database or signed JSON export).")
    diff_parser.add_argument("target_file", type=str, help="Path to target file (SQLite database or signed JSON export).")
    diff_parser.add_argument("--secret", type=str, help="Cryptographic passphrase key for verifying signed export files.")
    
    args = parser.parse_args()
    
    commands = {
        "init": cmd_init, 
        "collect": cmd_collect, 
        "analyze": cmd_analyze, 
        "report": cmd_report, 
        "delta": cmd_delta,
        "export": cmd_export,
        "verify": cmd_verify,
        "diff": cmd_diff,
        "status": cmd_status
    }
    
    commands[args.command](args)

if __name__ == "__main__":
    main()