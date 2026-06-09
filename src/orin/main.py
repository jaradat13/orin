# src/orin/main.py
"""
Orin – Production-Grade Offline Forensic Investigation & Integrity Engine
========================================================================
Main CLI entrypoint coordinating initialization, telemetry collection, 
threat rules analysis, and forensic reporting.
"""

import os
import sys
import argparse
from pathlib import Path

# Core database and configuration imports
from orin.core.database import OrinStorage

# Collector module imports
from orin.collectors.processes import gather_active_processes
from orin.collectors.connections import gather_listening_ports, gather_outbound_connections
from orin.collectors.kernel import gather_loaded_kernel_modules
from orin.collectors.users import gather_system_accounts
from orin.collectors.persistence import gather_active_ssh_keys
from orin.collectors.integrity import gather_file_integrity_signatures
from orin.collectors.deleted_binaries import gather_deleted_binaries
from orin.collectors.promisc import gather_promisc_interfaces
from orin.collectors.crontabs import gather_crontabs
from orin.collectors.session_audit import gather_wtmp_sessions, gather_lastlog_records
from orin.collectors.suid import gather_suid_binaries
from orin.collectors.logs import gather_auth_logs
from orin.collectors.ebpf import (
    gather_ebpf_programs,
    gather_ebpf_pinned,
    gather_ld_preload,
    gather_special_fds
)
import platform

# Analysis and Reporting imports
from orin.analysis.engine import run_analysis_cycle
from orin.analysis.reporter import compile_markdown_report, compile_html_report
from orin.collectors.pkg_integrity import gather_pkg_integrity_drift


def cmd_init(args):
    """Establish the local secure database architecture and capture trusted baselines."""
    db_path = Path(args.database)
    print(f"[*] Initializing Orin forensic vault at: {db_path}")
    
    storage = OrinStorage(db_path)
    storage.initialize_db()
    
    # Capture system baselines
    print("[*] Recording pristine system configuration baselines...")
    try:
        kernel_modules = gather_loaded_kernel_modules()
        system_users = gather_system_accounts()
        suid_binaries = gather_suid_binaries()
        hostname = platform.node() or "unknown_host"
        
        with storage.get_connection() as conn:
            if kernel_modules:
                conn.executemany(
                    "INSERT OR IGNORE INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES (?, ?, ?);",
                    [(hostname, m["module_name"], m["memory_size"]) for m in kernel_modules]
                )
            if system_users:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO baseline_users (hostname, username, uid, gid, home_dir, login_shell)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    [(hostname, u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in system_users]
                )
            if suid_binaries:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO baseline_suid_binaries (hostname, file_path, owner, grp, permissions, sha256)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    [(hostname, s["file_path"], s["owner"], s["grp"], s["permissions"], s["sha256"]) for s in suid_binaries]
                )
            conn.commit()
            
        print(f"🟢 Success: Baseline initialized. Recorded {len(kernel_modules)} modules, {len(system_users)} accounts, and {len(suid_binaries)} SUID/SGID binaries.")
    except Exception as e:
        print(f"❌ Error: Baseline serialization failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_collect(args):
    """Execute a transaction-isolated telemetry acquisition sequence."""
    db_path = Path(args.database)
    if not db_path.exists():
        print(f"❌ Error: Database vault missing at '{db_path}'. Run 'orin init' first.", file=sys.stderr)
        sys.exit(1)
        
    print(f"[*] Initiating telemetry acquisition phase on database: {db_path}")
    storage = OrinStorage(db_path)
    
    try:
        # 1. Open database connection handle and register system snapshot record
        with storage.get_connection() as conn:
            snapshot_id = storage.create_snapshot(conn)
            print(f"[+] Snapshot record assigned ID: #{snapshot_id}")
            
            # 2. Execute parallel/sequential collector sweeps
            print("    -> Harvesting running process tree metadata...")
            processes = gather_active_processes()
            
            print("    -> Enumerating open listening sockets and network states...")
            ports = gather_listening_ports()
            outbound = gather_outbound_connections()
            promisc = gather_promisc_interfaces()
            
            print("    -> Parsing kernel loadable module configurations...")
            modules = gather_loaded_kernel_modules()
            
            print("    -> Investigating system accounts and active SSH public keys...")
            users = gather_system_accounts()
            ssh_keys = gather_active_ssh_keys()
            
            print("    -> Inspecting crontabs and persistence profiles...")
            crontabs = gather_crontabs()
            
            print("    -> Auditing binary log lifecycles (WTMP and Lastlog)...")
            wtmp = gather_wtmp_sessions()
            lastlog = gather_lastlog_records()
            
            print("    -> Sweeping process execution trees for running deleted binaries...")
            deleted = gather_deleted_binaries()
            
            print("    -> Calculating file integrity check signatures (FIM)...")
            fim = gather_file_integrity_signatures(db_conn=conn)
            
            print("    -> Discovering SUID/SGID binaries...")
            suid = gather_suid_binaries()
            
            print("    -> Gathering system authentication logs...")
            auth_logs = gather_auth_logs()
            
            print("    -> Auditing loaded eBPF programs and map pins...")
            ebpf_programs = gather_ebpf_programs()
            ebpf_pinned = gather_ebpf_pinned()

            print("    -> Auditing dynamic linker preload overrides...")
            ld_preload = gather_ld_preload()

            print("    -> Auditing special process file descriptors...")
            special_fds = gather_special_fds()
            
            # 3. Stream collected telemetry blocks into relational tables inside a unified transaction
            storage.store_processes(conn, snapshot_id, processes)
            storage.store_ports(conn, snapshot_id, ports)
            storage.store_outbound_connections(conn, snapshot_id, outbound)
            storage.store_promisc_interfaces(conn, snapshot_id, promisc)
            storage.store_kernel_modules(conn, snapshot_id, modules)
            storage.store_users(conn, snapshot_id, users)
            storage.store_ssh_keys(conn, snapshot_id, ssh_keys)
            storage.store_crontabs(conn, snapshot_id, crontabs)
            storage.store_wtmp_sessions(conn, snapshot_id, wtmp)
            storage.store_lastlog_records(conn, snapshot_id, lastlog)
            storage.store_deleted_binaries(conn, snapshot_id, deleted)
            storage.store_file_hashes(conn, snapshot_id, fim)
            storage.store_suid_binaries(conn, snapshot_id, suid)
            storage.store_auth_logs(conn, snapshot_id, auth_logs)
            storage.store_ebpf_programs(conn, snapshot_id, ebpf_programs)
            storage.store_ebpf_pinned(conn, snapshot_id, ebpf_pinned)
            storage.store_ld_preload(conn, snapshot_id, ld_preload)
            storage.store_special_fds(conn, snapshot_id, special_fds)

            print("    -> Verifying package integrity against dpkg records...")
            pkg_drift = gather_pkg_integrity_drift()
            storage.store_pkg_integrity(conn, snapshot_id, pkg_drift)
            print(f"       Recorded {len(pkg_drift)} package integrity checks")

            conn.commit()
            
        print(f"🟢 Success: Snapshot acquisition complete. Mapped {len(processes)} processes, {len(fim)} file nodes, and {len(suid)} SUID/SGID binaries.")
    except Exception as e:
        print(f"❌ Error: Critical failure during execution phase: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_analyze(args):
    """Trigger threat detection rules evaluation loops against the latest snapshot data."""
    db_path = Path(args.database)
    if not db_path.exists():
        print("❌ Error: Database vault missing. Run 'orin collect' first.", file=sys.stderr)
        sys.exit(1)
        
    print(f"[*] Running threat intelligence metrics engine on database: {db_path}")
    try:
        metrics = run_analysis_cycle(db_path)
        print("\n" + "="*50)
        print("                 ORIN POSTURE ASSESSMENT")
        print("="*50)
        print(f"Associated Snapshot ID : #{metrics['snapshot_id']}")
        print(f"Calculated Risk Score  : {metrics['risk_score']} / 100")
        print(f"Unresolved Security Anomaly Count: {metrics['events_count']}")
        print("="*50 + "\n")
        
        if metrics['risk_score'] > 70:
            print("[⚠️] Warning: Host risk assessment indicates critical anomalies exist on this box.")
    except Exception as e:
        print(f"❌ Error: Threat rules evaluation process aborted: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_report(args):
    """Compile human-readable Markdown or HTML forensic dashboard outputs."""
    db_path = Path(args.database)
    output_path = Path(args.output)
    fmt = args.format.lower()
    
    print(f"[*] Compiling forensic briefing report target destination: {output_path}")
    try:
        if fmt == "markdown":
            compile_markdown_report(db_path, output_path)
        elif fmt == "html":
            compile_html_report(db_path, output_path)
        else:
            print(f"❌ Error: Unsupported documentation layout syntax: {fmt}", file=sys.stderr)
            sys.exit(1)
        print(f"🟢 Success: Documentation generated successfully at: {output_path.resolve()}")
    except Exception as e:
        print(f"❌ Error: Documentation rendering engine failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_serve(args):
    """Launch the localized HTTP dashboard server console."""
    from orin.core.server import start_server
    db_path = Path(args.database)
    
    port = args.port
    if args.port_opt is not None:
        port = args.port_opt
        
    try:
        start_server(
            db_path=db_path,
            host=args.host,
            port=port,
            username=args.username,
            password=args.password,
            cert_path=args.cert,
            key_path=args.key,
            no_auth=args.no_auth
        )
    except Exception as e:
        print(f"❌ Error: Web console server failed to start: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_schedule(args):
    """Manage the automated telemetry collection cron schedule."""
    from orin.core.scheduler import install_schedule, remove_schedule, show_schedule_status
    
    if args.install:
        install_schedule(Path(args.database), args.interval)
    elif args.remove:
        remove_schedule()
    elif args.status:
        show_schedule_status()
    else:
        # Default behavior: show status
        show_schedule_status()


def cmd_scan(args):
    """Execute a remote security scan over SSH, or baseline a target host."""
    from orin.core.scanner import run_remote_scan
    from orin.core.database import OrinStorage
    import subprocess
    import json
    
    db_path = Path(args.database)
    port = args.port if args.port is not None else 22
    
    if args.init:
        print(f"[*] Initializing baseline for remote host: {args.host}")
        current_dir = Path(__file__).resolve().parent
        agent_path = current_dir / "collectors" / "remote_agent.py"
        if not agent_path.exists():
            print(f"❌ Error: Remote agent script missing at: {agent_path}", file=sys.stderr)
            sys.exit(1)
            
        remote_agent_code = agent_path.read_text(encoding="utf-8")
        
        ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no"]
        if port:
            ssh_cmd.extend(["-p", str(port)])
        if args.key:
            ssh_cmd.extend(["-i", str(args.key)])
        
        agent_config = {
            "critical_paths": [],
            "critical_dirs": []
        }
        config_json_str = json.dumps(agent_config)
        ssh_cmd.extend([f"{args.user}@{args.host}", f"python3 - '{config_json_str}'"])
        
        try:
            proc = subprocess.Popen(
                ssh_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=remote_agent_code)
        except Exception as e:
            print(f"❌ Error: Failed to run remote baseline command: {e}", file=sys.stderr)
            sys.exit(1)
            
        if proc.returncode != 0:
            print(f"❌ Error: SSH baseline collection failed: {stderr}", file=sys.stderr)
            sys.exit(1)
            
        try:
            telemetry = json.loads(stdout.strip())
        except json.JSONDecodeError as e:
            print(f"❌ Error: Failed to parse baseline telemetry: {e}", file=sys.stderr)
            sys.exit(1)
            
        remote_hostname = telemetry.get("hostname", args.host)
        
        storage = OrinStorage(db_path)
        if not db_path.exists():
            storage.initialize_db()
            
        with storage.get_connection() as conn:
            conn.execute("DELETE FROM baseline_kernel_modules WHERE hostname = ?;", (remote_hostname,))
            conn.execute("DELETE FROM baseline_users WHERE hostname = ?;", (remote_hostname,))
            conn.execute("DELETE FROM baseline_suid_binaries WHERE hostname = ?;", (remote_hostname,))
            
            if "modules" in telemetry:
                conn.executemany(
                    "INSERT OR IGNORE INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES (?, ?, ?);",
                    [(remote_hostname, m["module_name"], m["memory_size"]) for m in telemetry["modules"]]
                )
            if "users" in telemetry:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO baseline_users (hostname, username, uid, gid, home_dir, login_shell)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    [(remote_hostname, u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in telemetry["users"]]
                )
            if "suid" in telemetry:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO baseline_suid_binaries (hostname, file_path, owner, grp, permissions, sha256)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    [(remote_hostname, s["file_path"], s["owner"], s["grp"], s["permissions"], s["sha256"]) for s in telemetry["suid"]]
                )
            conn.commit()
            
        print(f"🟢 Success: Baseline initialized for remote host {remote_hostname}.")
    else:
        print(f"[*] Executing remote SSH security scan on {args.host}...")
        try:
            metrics = run_remote_scan(
                host=args.host,
                user=args.user,
                key_path=args.key,
                port=port,
                db_path=db_path
            )
            print("\n" + "="*50)
            print(f"            REMOTE POSTURE ASSESSMENT: {args.host}")
            print("="*50)
            print(f"Associated Snapshot ID : #{metrics['snapshot_id']}")
            print(f"Calculated Risk Score  : {metrics['risk_score']} / 100")
            print(f"Unresolved Security Anomaly Count: {metrics['events_count']}")
            print("="*50 + "\n")
            
            if metrics['risk_score'] > 70:
                print("[⚠️] Warning: Remote host risk assessment indicates critical anomalies exist.")
        except Exception as e:
            print(f"❌ Error: Remote scan failed: {e}", file=sys.stderr)
            sys.exit(1)


def cmd_baseline(args):
    """Manage trusted system baselines (users, kernel modules, SUID binaries)."""
    from orin.core.database import OrinStorage
    import platform
    import sys
    
    db_path = Path(args.database)
    storage = OrinStorage(db_path)
    if not db_path.exists():
        print(f"❌ Error: Database vault missing at '{db_path}'. Run 'orin init' first.", file=sys.stderr)
        sys.exit(1)
        
    hostname = args.host if args.host else (platform.node() or "unknown_host")
    
    if args.baseline_command == "add":
        with storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM system_snapshots WHERE hostname = ? ORDER BY id DESC LIMIT 1;", (hostname,))
            snap_row = cursor.fetchone()
            if not snap_row:
                print(f"❌ Error: No snapshot found for host '{hostname}' in vault. Run 'orin collect' or 'orin scan' first.", file=sys.stderr)
                sys.exit(1)
                
            snapshot_id = snap_row["id"]
            
            if args.user:
                username = args.user
                cursor.execute(
                    "SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ? AND username = ? LIMIT 1;",
                    (snapshot_id, username)
                )
                user_row = cursor.fetchone()
                if not user_row:
                    print(f"❌ Error: User '{username}' not found in the latest collected snapshot #{snapshot_id} for host '{hostname}'.", file=sys.stderr)
                    sys.exit(1)
                    
                conn.execute(
                    "INSERT OR REPLACE INTO baseline_users (hostname, username, uid, gid, home_dir, login_shell) VALUES (?, ?, ?, ?, ?, ?);",
                    (hostname, user_row["username"], user_row["uid"], user_row["gid"], user_row["home_dir"], user_row["login_shell"])
                )
                conn.commit()
                print(f"🟢 Success: Added user '{username}' to baseline for host '{hostname}'.")
                
            elif args.module:
                module_name = args.module
                cursor.execute(
                    "SELECT module_name, memory_size FROM collected_kernel_modules WHERE snapshot_id = ? AND module_name = ? LIMIT 1;",
                    (snapshot_id, module_name)
                )
                mod_row = cursor.fetchone()
                if not mod_row:
                    print(f"❌ Error: Kernel module '{module_name}' not found in the latest collected snapshot #{snapshot_id} for host '{hostname}'.", file=sys.stderr)
                    sys.exit(1)
                    
                conn.execute(
                    "INSERT OR REPLACE INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES (?, ?, ?);",
                    (hostname, mod_row["module_name"], mod_row["memory_size"])
                )
                conn.commit()
                print(f"🟢 Success: Added kernel module '{module_name}' to baseline for host '{hostname}'.")
                
            elif args.suid:
                suid_path = args.suid
                cursor.execute(
                    "SELECT file_path, owner, grp, permissions, sha256 FROM collected_suid_binaries WHERE snapshot_id = ? AND file_path = ? LIMIT 1;",
                    (snapshot_id, suid_path)
                )
                suid_row = cursor.fetchone()
                if not suid_row:
                    print(f"❌ Error: SUID binary '{suid_path}' not found in the latest collected snapshot #{snapshot_id} for host '{hostname}'.", file=sys.stderr)
                    sys.exit(1)
                    
                conn.execute(
                    "INSERT OR REPLACE INTO baseline_suid_binaries (hostname, file_path, owner, grp, permissions, sha256) VALUES (?, ?, ?, ?, ?, ?);",
                    (hostname, suid_row["file_path"], suid_row["owner"], suid_row["grp"], suid_row["permissions"], suid_row["sha256"])
                )
                conn.commit()
                print(f"🟢 Success: Added SUID binary '{suid_path}' to baseline for host '{hostname}'.")
                
    elif args.baseline_command == "refresh":
        with storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM system_snapshots WHERE hostname = ? ORDER BY id DESC LIMIT 1;", (hostname,))
            snap_row = cursor.fetchone()
            if not snap_row:
                print(f"❌ Error: No snapshot found for host '{hostname}' in vault. Run 'orin collect' or 'orin scan' first.", file=sys.stderr)
                sys.exit(1)
                
            snapshot_id = snap_row["id"]
            
            if args.force_overwrite:
                conn.execute("DELETE FROM baseline_kernel_modules WHERE hostname = ?;", (hostname,))
                conn.execute("DELETE FROM baseline_users WHERE hostname = ?;", (hostname,))
                conn.execute("DELETE FROM baseline_suid_binaries WHERE hostname = ?;", (hostname,))
                
            # 1. Refresh kernel modules
            cursor.execute("SELECT module_name, memory_size FROM collected_kernel_modules WHERE snapshot_id = ?;", (snapshot_id,))
            modules = cursor.fetchall()
            if modules:
                conn.executemany(
                    "INSERT OR REPLACE INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES (?, ?, ?);",
                    [(hostname, m["module_name"], m["memory_size"]) for m in modules]
                )
                
            # 2. Refresh users
            cursor.execute("SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ?;", (snapshot_id,))
            users = cursor.fetchall()
            if users:
                conn.executemany(
                    "INSERT OR REPLACE INTO baseline_users (hostname, username, uid, gid, home_dir, login_shell) VALUES (?, ?, ?, ?, ?, ?);",
                    [(hostname, u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in users]
                )
                
            # 3. Refresh SUIDs
            cursor.execute("SELECT file_path, owner, grp, permissions, sha256 FROM collected_suid_binaries WHERE snapshot_id = ?;", (snapshot_id,))
            suids = cursor.fetchall()
            if suids:
                conn.executemany(
                    "INSERT OR REPLACE INTO baseline_suid_binaries (hostname, file_path, owner, grp, permissions, sha256) VALUES (?, ?, ?, ?, ?, ?);",
                    [(hostname, s["file_path"], s["owner"], s["grp"], s["permissions"], s["sha256"]) for s in suids]
                )
                
            conn.commit()
            action_str = "Overwrote and set" if args.force_overwrite else "Appended to"
            print(f"🟢 Success: {action_str} baseline for host '{hostname}' using snapshot #{snapshot_id} ({len(modules)} modules, {len(users)} users, {len(suids)} SUIDs).")


def cmd_correlate(args):
    """Query unresolved security events and query Ollama to identify multi-host correlations."""
    from orin.analysis.ai import run_ai_correlation
    import sys
    
    db_path = Path(args.database)
    hostnames = args.host
    url = args.url
    model = args.model
    output_path = Path(args.output) if args.output else None
    
    try:
        print(f"[*] Analyzing multi-host telemetry and querying local AI model '{model}'...")
        analysis = run_ai_correlation(db_path, hostnames=hostnames, url=url, model=model)
        
        print("\n" + "="*50)
        print("          LOCAL AI CORRELATION BRIEFING")
        print("="*50 + "\n")
        print(analysis)
        print("\n" + "="*50)
        
        if output_path:
            output_path.write_text(analysis, encoding="utf-8")
            print(f"🟢 Success: AI Triage briefing written to: {output_path}")
            
    except Exception as e:
        print(f"❌ Error: AI Correlation failed: {e}", file=sys.stderr)
        sys.exit(1)

def cmd_delta(args):
    db_path = args.database or "orin_vault.db"
    if not os.path.exists(db_path):
        print(f"Error: Database not found: {db_path}")
        return 1

    from orin.analysis.timeline import calculate_snapshot_delta

    try:
        delta = calculate_snapshot_delta(db_path, args.base, args.target)
        # Print formatted output
        print(f"Delta between snapshot {args.base} and {args.target}:")
        print(f"  Added: {len(delta.get('added', []))}")
        print(f"  Removed: {len(delta.get('removed', []))}")
        print(f"  Modified: {len(delta.get('modified', []))}")

        if args.verbose:
            import json
            print(json.dumps(delta, indent=2))
        return 0
    except Exception as e:
        print(f"Error calculating delta: {e}")
        return 1

def cmd_diff(args):
    from orin.analysis.diff import load_snapshot_data, compare_snapshots

    try:
        base_data = load_snapshot_data(args.base_file, secret=args.secret)
        target_data = load_snapshot_data(args.target_file, secret=args.secret)

        report = compare_snapshots(base_data, target_data)

        print("Drift Report:")
        print(f"  Total changes: {report.get('total_changes', 0)}")
        print(f"  Critical changes: {report.get('critical_changes', 0)}")

        if args.verbose:
            import json
            print(json.dumps(report, indent=2))
        return 0
    except Exception as e:
        print(f"Error comparing snapshots: {e}")
        return 1


def cmd_export(args):
    db_path = args.database or "orin_vault.db"
    if not os.path.exists(db_path):
        print(f"Error: Database not found: {db_path}")
        return 1

    if not args.secret:
        print("Error: --secret is required for signing")
        return 1

    from orin.core.crypto import generate_signed_export

    try:
        export_data = generate_signed_export(db_path, args.snapshot, args.secret)

        output_file = args.output or f"export_{args.snapshot}.json"
        with open(output_file, 'w') as f:
            import json
            json.dump(export_data, f, indent=2)

        print(f"Exported snapshot {args.snapshot} to {output_file}")
        print("Signature algorithm: HMAC-SHA256")
        return 0
    except Exception as e:
        print(f"Error exporting snapshot: {e}")
        return 1

def cmd_verify(args):
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        return 1

    if not args.secret:
        print("Error: --secret is required for verification")
        return 1

    from orin.core.crypto import verify_signed_export

    try:
        result = verify_signed_export(args.file, args.secret)

        if result['valid']:
            print("✅ Verification successful!")
            print(f"   Snapshot ID: {result.get('snapshot_id', 'unknown')}")
            print(f"   Timestamp: {result.get('timestamp', 'unknown')}")
            print(f"   Items verified: {result.get('item_count', 0)}")
            return 0
        else:
            print("❌ Verification FAILED - Tamper detected!")
            print(f"   Reason: {result.get('reason', 'unknown')}")
            return 1
    except Exception as e:
        print(f"Error verifying export: {e}")
        return 1


def main():
    """Primary routing mechanism maps arguments directly to operational functions."""
    parser = argparse.ArgumentParser(
        description="Orin Engine – Fully Offline Forensic Collection & Threat Audit Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # Global top-level arguments shared across commands
    parser.add_argument(
        "-d", "--database", 
        default="orin_vault.db", 
        help="Path location to the localized Orin SQLite vault engine file"
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True, title="Engine Core Commands")
    
    # 1. 'init' command mapping
    subparsers.add_parser("init", help="Establish secure vault and register initial system baselines")
    
    # 2. 'collect' command mapping
    subparsers.add_parser("collect", help="Execute an out-of-band granular telemetry capture iteration loop")
    
    # 3. 'analyze' command mapping
    subparsers.add_parser("analyze", help="Evaluate the current snapshot against threat models and calculate risk indexing")
    
    # 4. 'report' command mapping
    report_parser = subparsers.add_parser("report", help="Generate standalone offline human-readable briefs")
    report_parser.add_argument(
        "-o", "--output", 
        required=True, 
        help="Target filesystem path where the briefing will be compiled"
    )
    report_parser.add_argument(
        "-f", "--format", 
        choices=["markdown", "html"], 
        default="html", 
        help="Target output design language rendering template"
    )

    # 5. 'serve' command mapping
    serve_parser = subparsers.add_parser("serve", help="Launch the localized HTTP dashboard server console")
    serve_parser.add_argument(
        "port",
        type=int,
        nargs="?",
        default=8000,
        help="Port to bind the HTTP server (default: 8000)"
    )
    serve_parser.add_argument(
        "--port",
        dest="port_opt",
        type=int,
        default=None,
        help="Port to bind the HTTP server (overrides positional port)"
    )
    serve_parser.add_argument(
        "-H", "--host",
        default="127.0.0.1",
        help="Host address to bind the HTTP server"
    )
    serve_parser.add_argument(
        "--cert",
        default=None,
        help="Path to SSL certificate for HTTPS"
    )
    serve_parser.add_argument(
        "--key",
        default=None,
        help="Path to SSL private key for HTTPS"
    )
    serve_parser.add_argument(
        "--username",
        default=None,
        help="Username for Basic Authentication (alternative to auto-token)"
    )
    serve_parser.add_argument(
        "--password",
        default=None,
        help="Password for Basic Authentication (alternative to auto-token)"
    )
    serve_parser.add_argument(
        "--no-auth",
        dest="no_auth",
        action="store_true",
        default=False,
        help="Disable authentication entirely (use only on trusted private networks)"
    )

    # 6. 'schedule' command mapping
    schedule_parser = subparsers.add_parser("schedule", help="Manage automated recurring forensic collection scheduling")
    schedule_group = schedule_parser.add_mutually_exclusive_group()
    schedule_group.add_argument(
        "--install",
        action="store_true",
        help="Install recurring cron task to automate collect and analyze operations"
    )
    schedule_group.add_argument(
        "--remove",
        action="store_true",
        help="Remove active Orin collection automation schedules"
    )
    schedule_group.add_argument(
        "--status",
        action="store_true",
        help="Query current scheduling status and active cron configuration logs"
    )
    schedule_parser.add_argument(
        "-i", "--interval",
        type=int,
        default=10,
        help="Execution interval in minutes (only applicable with --install)"
    )

    # 7. 'scan' command mapping
    scan_parser = subparsers.add_parser("scan", help="Execute an agentless remote SSH security scan")
    scan_parser.add_argument(
        "--host",
        required=True,
        help="Target hostname or IP address to connect to"
    )
    scan_parser.add_argument(
        "--user",
        required=True,
        help="SSH username for authentication"
    )
    scan_parser.add_argument(
        "--key",
        help="Path to private SSH key for authentication"
    )
    scan_parser.add_argument(
        "-p", "--port",
        type=int,
        default=22,
        help="SSH port of the remote host"
    )
    scan_parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize baseline for the remote host instead of scanning for drift"
    )

    # 8. 'baseline' command mapping
    baseline_parser = subparsers.add_parser("baseline", help="Manage system configuration baselines")
    baseline_subparsers = baseline_parser.add_subparsers(dest="baseline_command", required=True)
    
    # baseline add
    add_parser = baseline_subparsers.add_parser("add", help="Add a specific resource to the trusted baseline")
    add_group = add_parser.add_mutually_exclusive_group(required=True)
    add_group.add_argument("--user", help="Username of the user account to baseline")
    add_group.add_argument("--module", help="Name of the kernel module to baseline")
    add_group.add_argument("--suid", help="File path of the SUID/SGID binary to baseline")
    add_parser.add_argument("--host", help="Target hostname to apply baseline change (defaults to local host)")
    
    # baseline refresh
    refresh_parser = baseline_subparsers.add_parser("refresh", help="Refresh baseline configuration using the latest snapshot state")
    refresh_parser.add_argument("--host", help="Target hostname to refresh (defaults to local host)")
    refresh_parser.add_argument("--force-overwrite", action="store_true", help="Overwrite the baseline completely instead of appending")
    # diff parser
    parser_diff = subparsers.add_parser('diff', help='Compare two database files or exports')
    parser_diff.add_argument('base_file', help='Base snapshot file (.db or .json)')
    parser_diff.add_argument('target_file', help='Target snapshot file (.db or .json)')
    parser_diff.add_argument('--secret', help='Passphrase for signed JSON exports')
    parser_diff.add_argument('-v', '--verbose', action='store_true', help='Show full report')
    parser_diff.set_defaults(func=cmd_diff)
    # delta parser
    parser_delta = subparsers.add_parser('delta', help='Compare two snapshots by ID')
    parser_delta.add_argument('--base', required=True, help='Base snapshot ID')
    parser_delta.add_argument('--target', required=True, help='Target snapshot ID')
    parser_delta.add_argument('--database', help='Path to database file')
    parser_delta.add_argument('-v', '--verbose', action='store_true', help='Show full diff')
    parser_delta.set_defaults(func=cmd_delta)
    # export parser
    parser_export = subparsers.add_parser('export', help='Export snapshot to signed JSON')
    parser_export.add_argument('--snapshot', required=True, help='Snapshot ID to export')
    parser_export.add_argument('--secret', required=True, help='Passphrase for signing')
    parser_export.add_argument('--output', '-o', help='Output file path')
    parser_export.add_argument('--database', help='Path to database file')
    parser_export.set_defaults(func=cmd_export)
    # verify parser
    parser_verify = subparsers.add_parser('verify', help='Verify signed export bundle')
    parser_verify.add_argument('--file', '-f', required=True, help='Export file to verify')
    parser_verify.add_argument('--secret', required=True, help='Passphrase for verification')
    parser_verify.set_defaults(func=cmd_verify)
    
    # 'correlate' command mapping
    correlate_parser = subparsers.add_parser("correlate", help="Run local AI multi-host triage and correlation")
    correlate_parser.add_argument(
        "--host",
        nargs="+",
        help="List of hostnames to correlate (default: all hosts in snapshot DB)"
    )
    correlate_parser.add_argument(
        "--url",
        default="http://127.0.0.1:11434",
        help="Ollama API base URL"
    )
    correlate_parser.add_argument(
        "--model",
        default="gemma3:1b",
        help="Ollama model name to run"
    )
    correlate_parser.add_argument(
        "-o", "--output",
        help="Path to save the generated Markdown report"
    )

    args = parser.parse_args()
    
    # Route matching parameters to core routines
    if args.command == "init":
        cmd_init(args)
    elif args.command == "collect":
        cmd_collect(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "serve":
        cmd_serve(args)
    elif args.command == "schedule":
        cmd_schedule(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "baseline":
        cmd_baseline(args)
    elif args.command == "correlate":
        cmd_correlate(args)
    elif args.command == "delta":
        sys.exit(cmd_delta(args))
    elif args.command == "diff":
        sys.exit(cmd_diff(args))
    elif args.command == "export":
        sys.exit(cmd_export(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))


if __name__ == "__main__":
    main()