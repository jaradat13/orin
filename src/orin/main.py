# src/orin/main.py
"""
Orin – Production-Grade Offline Forensic Investigation & Integrity Engine
========================================================================
Main CLI entrypoint coordinating initialization, telemetry collection, 
threat rules analysis, and forensic reporting.
"""

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

# Analysis and Reporting imports
from orin.analysis.engine import run_analysis_cycle
from orin.analysis.reporter import compile_markdown_report, compile_html_report


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
        
        with storage.get_connection() as conn:
            if kernel_modules:
                conn.executemany(
                    "INSERT OR IGNORE INTO baseline_kernel_modules (module_name, memory_size) VALUES (?, ?);",
                    [(m["module_name"], m["memory_size"]) for m in kernel_modules]
                )
            if system_users:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO baseline_users (username, uid, gid, home_dir, login_shell)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    [(u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in system_users]
                )
            conn.commit()
            
        print(f"🟢 Success: Baseline initialized. Recorded {len(kernel_modules)} modules and {len(system_users)} accounts.")
    except Exception as e:
        print(f"❌ Error: Baseline serialization failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_collect(args):
    """Execute a transaction-isolated telemetry acquisition sequence."""
    db_path = Path(args.database)

def cmd_serve(args):
    """Launch the localized HTTP dashboard server console."""
    from orin.core.server import start_server
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
            
            conn.commit()
            
        print(f"🟢 Success: Snapshot acquisition complete. Mapped {len(processes)} processes and {len(fim)} file nodes.")
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


def main():
    """Primary routing mechanism maps arguments directly to operational functions."""
    parser = argparse.ArgumentParser(
        description="Orin Engine – Fully Offline Forensic Collection & Threat Audit Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_init = True
    
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


if __name__ == "__main__":
    main()