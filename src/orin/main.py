# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# src/orin/main.py
"""
Orin – Production-Grade Offline Forensic Investigation & Integrity Engine
========================================================================
Main CLI entrypoint coordinating initialization, telemetry collection,
threat rules analysis, and forensic reporting.
"""
import re
import os
import sys
import argparse
import time
from pathlib import Path

# Core database and configuration imports
from orin.core.database import OrinStorage

# Collector module imports
from orin.collectors.processes import gather_active_processes
from orin.collectors.connections import gather_listening_ports, gather_outbound_connections
from orin.collectors.kernel import (
    gather_loaded_kernel_modules,
    gather_kernel_symbols,
    analyze_kernel_symbol_overrides,
    check_for_unlinked_modules
)
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
from orin.collectors.privilege_audit import gather_all_privilege_events
import platform

# Analysis and Reporting imports
from orin.analysis.engine import run_analysis_cycle
from orin.analysis.reporter import compile_markdown_report, compile_html_report
from orin.collectors.pkg_integrity import gather_pkg_integrity_drift
from orin.collectors.persistence import gather_system_persistence
from orin.collectors.dns_forensics import (
    gather_dns_queries,
    detect_dns_tunneling_indicators,
    analyze_dns_patterns
)
from orin.core.self_defense import (
    SelfDefenseManager,
    WatchdogConfig,
    WatchdogService,
    SeccompProfile,
    AppArmorProfile,
    SELinuxProfile
)
from orin.core.self_verify import (
    generate_sbom,
    generate_release_manifest,
    self_check,
    print_sbom_summary,
    print_manifest_summary,
    sign_manifest_with_gpg,
    export_sbom
)

def cmd_self_defense(args):
    """Manage Orin agent self-defense mechanisms."""
    from orin.core.self_defense import main as self_defense_main

    # Delegate to self_defense module's CLI
    sys.argv = ['orin', 'self-defense'] + args._remaining_args if hasattr(args, '_remaining_args') else sys.argv[:2]
    self_defense_main()

def cmd_init(args):
    """Establish the local secure database architecture and capture trusted baselines."""
    db_path = Path(args.database)
    if getattr(args, 'read_only', False):
        print("[!] Read-only mode enabled - init operation skipped (cannot modify vault)", file=sys.stderr)
        sys.exit(1)
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

    # Support --vault-path override
    if hasattr(args, 'vault_path') and args.vault_path:
        db_path = Path(args.vault_path)

    read_only = getattr(args, 'read_only', False)

    if not db_path.exists():
        print(f"❌ Error: Database vault missing at '{db_path}'. Run 'orin init' first.", file=sys.stderr)
        sys.exit(1)

    if read_only:
        print(f"[*] Initiating READ-ONLY telemetry acquisition (forensic mode) on database: {db_path}")
    else:
        print(f"[*] Initiating telemetry acquisition phase on database: {db_path}")

    storage = OrinStorage(db_path)

    try:
        # 1. Open database connection handle and register system snapshot record
        with storage.get_connection() as conn:
            if not read_only:
                snapshot_id = storage.create_snapshot(conn)
                print(f"[+] Snapshot record assigned ID: #{snapshot_id}")
            else:
                # In read-only mode, get the latest snapshot ID for reference only
                cursor = conn.cursor()
                cursor.execute("SELECT MAX(id) FROM system_snapshots;")
                result = cursor.fetchone()
                snapshot_id = result[0] if result and result[0] else None
                if snapshot_id:
                    print(f"[*] Using latest snapshot ID for reference: #{snapshot_id}")
                else:
                    print("[!] No snapshots exist in database - running in read-only forensics mode")
                snapshot_id = None  # Don't store new data against any snapshot in read-only mode

            # 2. Execute parallel/sequential collector sweeps
            print("    -> Harvesting running process tree metadata...")
            processes = gather_active_processes()

            print("    -> Enumerating open listening sockets and network states...")
            ports = gather_listening_ports()
            outbound = gather_outbound_connections()
            promisc = gather_promisc_interfaces()

            print("    -> Parsing kernel loadable module configurations...")
            modules = gather_loaded_kernel_modules()

            print("    -> Analyzing kernel symbols for rootkit indicators...")
            symbols = gather_kernel_symbols()
            symbol_analysis = analyze_kernel_symbol_overrides(symbols)
            unlinked_modules = check_for_unlinked_modules(modules, symbols)

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

            print("    -> Tracking identity, access & privilege events...")
            privilege_data = gather_all_privilege_events()
            privilege_escalation = privilege_data["privilege_escalation_events"]
            syscall_audit = privilege_data["syscall_audit_events"]
            pam_events = privilege_data["pam_authentication_events"]
            credential_access = privilege_data["credential_access_events"]

            print("    -> Auditing loaded eBPF programs and map pins...")
            ebpf_programs = gather_ebpf_programs()
            ebpf_pinned = gather_ebpf_pinned()

            print("    -> Auditing dynamic linker preload overrides...")
            ld_preload = gather_ld_preload()

            print("    -> Auditing special process file descriptors...")
            special_fds = gather_special_fds()
            print("    -> Harvesting system persistence configuration artifacts...")
            persistence_configs = gather_system_persistence()

            print("    -> Collecting DNS forensics and tunneling indicators...")
            dns_connections = gather_dns_queries()
            dns_analysis = analyze_dns_patterns(dns_connections)

            # 3. Stream collected telemetry blocks into relational tables inside a unified transaction
            if not read_only:
                storage.store_processes(conn, snapshot_id, processes)
                storage.store_ports(conn, snapshot_id, ports)
                storage.store_outbound_connections(conn, snapshot_id, outbound)
                storage.store_promisc_interfaces(conn, snapshot_id, promisc)
                storage.store_kernel_modules(conn, snapshot_id, modules)
                storage.store_kernel_symbols(conn, snapshot_id, symbols)

                # Prepare kernel analysis with hidden modules
                kernel_analysis = symbol_analysis.copy()
                kernel_analysis["hidden_modules"] = unlinked_modules
                kernel_analysis["hidden_module_count"] = len(unlinked_modules)
                storage.store_kernel_analysis(conn, snapshot_id, kernel_analysis)

                storage.store_users(conn, snapshot_id, users)
                storage.store_ssh_keys(conn, snapshot_id, ssh_keys)
                storage.store_crontabs(conn, snapshot_id, crontabs)
                storage.store_wtmp_sessions(conn, snapshot_id, wtmp)
                storage.store_lastlog_records(conn, snapshot_id, lastlog)
                storage.store_deleted_binaries(conn, snapshot_id, deleted)
                storage.store_file_hashes(conn, snapshot_id, fim)
                storage.store_suid_binaries(conn, snapshot_id, suid)
                storage.store_auth_logs(conn, snapshot_id, auth_logs)
                storage.store_privilege_events(conn, snapshot_id, privilege_escalation)
                storage.store_privilege_events(conn, snapshot_id, syscall_audit)
                storage.store_privilege_events(conn, snapshot_id, pam_events)
                storage.store_privilege_events(conn, snapshot_id, credential_access)
                storage.store_ebpf_programs(conn, snapshot_id, ebpf_programs)
                storage.store_ebpf_pinned(conn, snapshot_id, ebpf_pinned)
                storage.store_ld_preload(conn, snapshot_id, ld_preload)
                storage.store_special_fds(conn, snapshot_id, special_fds)
                storage.store_persistence_configs(conn, snapshot_id, persistence_configs)

                # Store DNS forensics data
                if dns_connections:
                    storage.store_dns_queries(conn, snapshot_id, dns_connections)
                    print(f"       Recorded {len(dns_connections)} DNS connections")

                total_privilege_events = len(privilege_escalation) + len(syscall_audit) + len(pam_events) + len(credential_access)
                print(f"       Recorded {total_privilege_events} privilege/authentication events")


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
            no_auth=args.no_auth,
            passphrase_file=getattr(args, 'passphrase_file', None),
            passphrase_prompt=getattr(args, 'passphrase_prompt', False),
            passphrase_env_var=getattr(args, 'passphrase_env_var', None),
            token_file=getattr(args, 'token_file', None)
        )
    except Exception as e:
        print(f"❌ Error: Web console server failed to start: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_schedule(args):
    """Manage the automated telemetry collection cron schedule."""
    from orin.core.scheduler import install_schedule, remove_schedule, show_schedule_status

    if args.install:
        retention_days = getattr(args, 'retention', None)
        install_schedule(Path(args.database), args.interval, retention_days=retention_days)
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
            # Configure strict host key verification
            strict_host_keys = not args.no_strict_host_keys

            metrics = run_remote_scan(
                host=args.host,
                user=args.user,
                key_path=args.key,
                port=port,
                db_path=db_path,
                strict_host_keys=strict_host_keys,
                known_hosts_file=args.known_hosts_file
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

    from orin.core.crypto import generate_signed_export, generate_coc_manifest

    try:
        export_data = generate_signed_export(db_path, args.snapshot, args.secret)

        output_file = args.output or f"export_{args.snapshot}.json"
        with open(output_file, 'w') as f:
            import json
            json.dump(export_data, f, indent=2)

        # Generate Chain-of-Custody manifest
        output_dir = os.path.dirname(output_file) or "."
        coc_manifest = generate_coc_manifest(db_path, args.snapshot, output_dir)
        coc_file = os.path.join(output_dir, f"coc_manifest_{args.snapshot}.json")

        print(f"Exported snapshot {args.snapshot} to {output_file}")
        print(f"Generated Chain-of-Custody manifest: {coc_file}")
        print("Signature algorithm: HMAC-SHA256")
        print(f"Evidence items in manifest: {coc_manifest['evidence_count']}")
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


def cmd_stream(args):
    """Launch the eBPF real-time streaming consumer."""
    from pathlib import Path
    import subprocess

    # Try multiple possible locations for the ebpf consumer
    possible_paths = [
        Path(__file__).parent.parent / "ebpf" / "consumer.py",  # src/orin -> ebpf/consumer.py
        Path(__file__).parent / ".." / ".." / "ebpf" / "consumer.py",  # Alternative relative path
        Path("/workspace/orin/ebpf/consumer.py"),  # Absolute dev path
    ]

    consumer_path = None
    for p in possible_paths:
        if p.exists():
            consumer_path = p.resolve()
            break

    if not consumer_path:
        print(f"❌ Error: eBPF consumer script not found. Searched: {possible_paths}")
        sys.exit(1)

    print(f"[*] Launching Orin eBPF Real-Time Streamer...")
    print(f"[*] Consumer script: {consumer_path}")

    # Execute the consumer script with the same arguments
    cmd = [sys.executable, str(consumer_path)]
    if args.verbose:
        cmd.append("--verbose")

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: eBPF streamer failed: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stream interrupted by user.")
        sys.exit(0)


def cmd_rules(args):
    """Manage Sigma and YARA rule repositories."""
    from orin.analysis.sigma import validate_rule, validate_rules_directory, load_rules as load_sigma_rules
    from orin.analysis.yara_engine import YaraEngine, YARA_AVAILABLE

    if args.rules_command == "update":
        sigma_dir = args.sigma
        yara_dir = args.yara

        if not sigma_dir and not yara_dir:
            print("❌ Error: Must specify --sigma or --yara directory", file=sys.stderr)
            sys.exit(1)

        if sigma_dir:
            sigma_path = Path(sigma_dir)
            if not sigma_path.exists():
                print(f"❌ Error: Sigma rules directory not found: {sigma_path}", file=sys.stderr)
                sys.exit(1)

            print(f"[*] Validating Sigma rules in: {sigma_path}")
            valid_rules, results = validate_rules_directory(sigma_path)

            total = len(results)
            valid_count = sum(1 for r in results if r.valid)
            invalid_count = total - valid_count

            print(f"\n{'='*60}")
            print(f"Sigma Rules Validation Summary")
            print(f"{'='*60}")
            print(f"Total rules scanned  : {total}")
            print(f"Valid rules          : {valid_count}")
            print(f"Invalid rules        : {invalid_count}")

            if args.validate_only:
                print(f"\n[!] Validation-only mode: rules NOT installed")
            else:
                # Install valid rules to default location
                default_sigma_dir = Path("/var/lib/orin/rules/sigma")
                default_sigma_dir.mkdir(parents=True, exist_ok=True)

                installed = 0
                for rule in valid_rules:
                    try:
                        src = Path(rule["file_path"])
                        dst = default_sigma_dir / src.name
                        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
                        installed += 1
                    except Exception as e:
                        print(f"[!] Failed to install {rule.get('title', 'UNKNOWN')}: {e}")

                print(f"\n[+] Installed {installed} valid Sigma rules to: {default_sigma_dir}")

            # Show validation errors
            if invalid_count > 0:
                print(f"\n[!] Invalid rules:")
                for result in results:
                    if not result.valid:
                        fp = getattr(result, 'file_path', 'unknown')
                        errs = "; ".join(result.errors)
                        print(f"    - {fp}: {errs}")

        if yara_dir:
            yara_path = Path(yara_dir)
            if not yara_path.exists():
                print(f"❌ Error: YARA rules directory not found: {yara_path}", file=sys.stderr)
                sys.exit(1)

            print(f"\n[*] Validating YARA rules in: {yara_path}")

            if not YARA_AVAILABLE:
                print("[!] Warning: yara-python not installed. Skipping syntax validation.")

            yar_files = list(yara_path.glob("*.yar"))
            valid_count = 0
            invalid_count = 0

            for yar_file in yar_files:
                try:
                    content = yar_file.read_text(encoding="utf-8")
                    # Basic syntax check - look for rule definitions
                    if re.search(r'rule\s+\w+', content):
                        valid_count += 1
                        print(f"    ✓ {yar_file.name}")
                    else:
                        print(f"    ✗ {yar_file.name}: No valid rule definitions found")
                        invalid_count += 1
                except Exception as e:
                    print(f"    ✗ {yar_file.name}: {e}")
                    invalid_count += 1

            print(f"\n{'='*60}")
            print(f"YARA Rules Validation Summary")
            print(f"{'='*60}")
            print(f"Total rules scanned  : {len(yar_files)}")
            print(f"Valid rules          : {valid_count}")
            print(f"Invalid rules        : {invalid_count}")

            if not args.validate_only:
                # Install valid rules to default location
                default_yara_dir = Path("/var/lib/orin/rules/yara")
                default_yara_dir.mkdir(parents=True, exist_ok=True)

                installed = 0
                for yar_file in yar_files:
                    try:
                        src = yar_file
                        dst = default_yara_dir / yar_file.name
                        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
                        installed += 1
                    except Exception as e:
                        print(f"[!] Failed to install {yar_file.name}: {e}")

                print(f"\n[+] Installed {installed} YARA rules to: {default_yara_dir}")

    elif args.rules_command == "list":
        show_sigma = args.sigma
        show_yara = args.yara
        verbose = args.verbose

        if not show_sigma and not show_yara:
            show_sigma = show_yara = True

        if show_sigma:
            print(f"\n{'='*70}")
            print("ACTIVE SIGMA RULES")
            print(f"{'='*70}")

            # Check default locations
            default_dirs = [
                Path("./rules"),
                Path("/var/lib/orin/rules/sigma"),
                Path(__file__).resolve().parents[2] / "rules",
            ]

            all_rules = []
            for d in default_dirs:
                if d.exists():
                    all_rules.extend(load_sigma_rules(d))

            if not all_rules:
                print("No Sigma rules found in default locations.")
            else:
                for i, rule in enumerate(all_rules, 1):
                    title = rule.get("title", "Untitled")
                    desc = rule.get("description", "No description")
                    level = rule.get("level", "unknown")
                    rule_id = rule.get("id", "N/A")
                    tags = rule.get("tags", [])

                    print(f"\n[{i}] {title}")
                    print(f"    ID: {rule_id}")
                    print(f"    Level: {level}")
                    print(f"    Description: {desc}")
                    if tags:
                        print(f"    Tags: {', '.join(tags)}")

                    if verbose:
                        detection = rule.get("detection", {})
                        condition = detection.get("condition", "")
                        selections = [k for k in detection.keys() if k != "condition"]
                        print(f"    Condition: {condition}")
                        print(f"    Selections: {', '.join(selections)}")

                        # Parse MITRE ATT&CK from tags
                        attck_tags = [t for t in tags if t.startswith("attack.")]
                        if attck_tags:
                            print(f"    MITRE ATT&CK: {', '.join(attck_tags)}")

            print(f"\nTotal Sigma rules: {len(all_rules)}")

        if show_yara:
            print(f"\n{'='*70}")
            print("ACTIVE YARA RULES")
            print(f"{'='*70}")

            default_yara_dirs = [
                Path("./rules/yara"),
                Path("/var/lib/orin/rules/yara"),
            ]

            yar_files = []
            for d in default_yara_dirs:
                if d.exists():
                    yar_files.extend(d.glob("*.yar"))

            if not yar_files:
                print("No YARA rules found in default locations.")
            else:
                for i, yar_file in enumerate(sorted(yar_files), 1):
                    try:
                        content = yar_file.read_text(encoding="utf-8")
                        # Extract rule names
                        rule_names = re.findall(r'rule\s+(\w+)', content)

                        print(f"\n[{i}] {yar_file.name}")
                        print(f"    Rules: {', '.join(rule_names[:5])}" + ("..." if len(rule_names) > 5 else ""))

                        if verbose:
                            # Extract metadata
                            metas = re.findall(r'meta:\s*\n((?:\s+\w+\s*=\s*".*?"\s*\n)+)', content)
                            if metas:
                                meta_text = metas[0]
                                desc_match = re.search(r'description\s*=\s*"([^"]+)"', meta_text)
                                author_match = re.search(r'author\s*=\s*"([^"]+)"', meta_text)
                                severity_match = re.search(r'severity\s*=\s*"([^"]+)"', meta_text)
                                attack_match = re.search(r'attack\s*=\s*"([^"]+)"', meta_text)

                                if desc_match:
                                    print(f"    Description: {desc_match.group(1)}")
                                if author_match:
                                    print(f"    Author: {author_match.group(1)}")
                                if severity_match:
                                    print(f"    Severity: {severity_match.group(1)}")
                                if attack_match:
                                    print(f"    MITRE ATT&CK: {attack_match.group(1)}")
                    except Exception as e:
                        print(f"\n[{i}] {yar_file.name}: Error reading - {e}")

            print(f"\nTotal YARA files: {len(yar_files)}")

    elif args.rules_command == "validate":
        sigma_path = args.sigma
        yara_path = args.yara
        strict = args.strict

        exit_code = 0

        if sigma_path:
            path = Path(sigma_path)
            print(f"[*] Validating Sigma: {path}")

            if path.is_file():
                content = path.read_text(encoding="utf-8")
                rule = parse_yaml_rule(content)
                result = validate_rule(rule, content)

                if result.valid:
                    print(f"    ✓ {path.name}: VALID")
                    if verbose := getattr(args, 'verbose', False):
                        for op in result.supported_operators:
                            print(f"      Supported: {op}")
                else:
                    print(f"    ✗ {path.name}: INVALID")
                    for err in result.errors:
                        print(f"      Error: {err}")
                    exit_code = 1

                if strict and result.warnings:
                    print(f"    ! Warnings:")
                    for warn in result.warnings:
                        print(f"      - {warn}")
                    exit_code = 1

            elif path.is_dir():
                valid_rules, results = validate_rules_directory(path)

                total = len(results)
                valid_count = sum(1 for r in results if r.valid)
                invalid_count = total - valid_count

                print(f"\n{'='*60}")
                print(f"Validation Results: {valid_count}/{total} valid")
                print(f"{'='*60}")

                if invalid_count > 0:
                    exit_code = 1
                    for result in results:
                        if not result.valid:
                            fp = getattr(result, 'file_path', 'unknown')
                            for err in result.errors:
                                print(f"  ✗ {fp}: {err}")

                if strict:
                    for result in results:
                        if result.warnings:
                            fp = getattr(result, 'file_path', 'unknown')
                            for warn in result.warnings:
                                print(f"  ! {fp}: {warn}")
                            exit_code = 1

        if yara_path:
            if not YARA_AVAILABLE:
                print("[!] Warning: yara-python not installed. Cannot validate YARA syntax.")
                return

            path = Path(yara_path)
            print(f"\n[*] Validating YARA: {path}")

            try:
                engine = YaraEngine()
                if path.is_file():
                    engine.load_rules(rules_dirs=[path.parent])
                    print(f"    ✓ {path.name}: VALID")
                elif path.is_dir():
                    count = engine.load_rules(rules_dirs=[path])
                    print(f"    ✓ Loaded {count} rules from directory")
            except Exception as e:
                print(f"    ✗ Validation failed: {e}")
                exit_code = 1

        sys.exit(exit_code)


def cmd_vault(args):
    """Manage the forensic vault lifecycle (prune, stats)."""
    db_path = Path(args.database)
    if not db_path.exists():
        print(f"❌ Error: Database vault missing at '{db_path}'. Run 'orin init' first.", file=sys.stderr)
        sys.exit(1)

    storage = OrinStorage(db_path)

    if args.vault_command == "stats":
        try:
            with storage.get_connection() as conn:
                stats = storage.vault_stats(conn)
            print("\n" + "=" * 50)
            print("              ORIN VAULT STATISTICS")
            print("=" * 50)
            print(f"Database Path       : {db_path.resolve()}")
            print(f"Database Size       : {stats['database_size_mb']} MB ({stats['database_size_bytes']:,} bytes)")
            print(f"Total Snapshots     : {stats['snapshot_count']}")
            print(f"Oldest Snapshot     : {stats['oldest_snapshot'] or 'N/A'}")
            print(f"Newest Snapshot     : {stats['newest_snapshot'] or 'N/A'}")
            print("-" * 50)
            print("Records by Table:")
            for table, count in sorted(stats['table_counts'].items()):
                print(f"  {table:30s} : {count:,}")
            print("=" * 50 + "\n")
        except Exception as e:
            print(f"❌ Error: Failed to retrieve vault statistics: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.vault_command == "prune":
        older_than_days = args.older_than
        dry_run = args.dry_run

        action = "Would delete" if dry_run else "Deleting"
        print(f"[*] {action} snapshots older than {older_than_days} days...")

        try:
            with storage.get_connection() as conn:
                result = storage.vault_prune(conn, older_than_days, dry_run=dry_run)

            if "message" in result:
                print(f"🟢 {result['message']}")
            else:
                print(f"\n{'=' * 50}")
                print(f"           VAULT PRUNING {'(DRY RUN)' if dry_run else 'COMPLETE'}")
                print('=' * 50)
                print(f"Cutoff Date         : {result['cutoff_date']}")
                print(f"Snapshots {'to be ' if dry_run else ''}deleted   : {result['deleted_snapshots']}")
                print("-" * 50)
                print("Records by Table:")
                for table, count in sorted(result['deleted_by_table'].items()):
                    print(f"  {table:30s} : {count:,}")
                print('=' * 50 + "\n")

                if dry_run:
                    print("Note: This was a dry run. Add --execute to actually delete data.")
        except Exception as e:
            print(f"❌ Error: Vault pruning failed: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("❌ Error: Unknown vault command. Use 'stats' or 'prune'.", file=sys.stderr)
        sys.exit(1)


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
    init_parser = subparsers.add_parser("init", help="Establish secure vault and register initial system baselines")
    init_parser.add_argument(
        "--read-only",
        action="store_true",
        default=False,
        help="Enable read-only mode (prevents any writes to the vault)"
    )

    # 2. 'collect' command mapping
    collect_parser = subparsers.add_parser("collect", help="Execute an out-of-band granular telemetry capture iteration loop")
    collect_parser.add_argument(
        "--read-only",
        action="store_true",
        default=False,
        help="Enable forensic acquisition mode on write-protected systems (no data stored to vault)"
    )
    collect_parser.add_argument(
        "--vault-path",
        type=str,
        default=None,
        help="Override the default vault/database path for this operation"
    )

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
    # Vault passphrase loading options
    serve_parser.add_argument(
        "--passphrase-file",
        dest="passphrase_file",
        default=None,
        help="Path to file containing vault passphrase (reduces shell history exposure)"
    )
    serve_parser.add_argument(
        "--passphrase-prompt",
        dest="passphrase_prompt",
        action="store_true",
        default=False,
        help="Interactively prompt for vault passphrase with masked input"
    )
    serve_parser.add_argument(
        "--passphrase-env-var",
        dest="passphrase_env_var",
        default=None,
        help="Custom environment variable name for vault passphrase (default: ORIN_VAULT_PASSPHRASE)"
    )
    # Session token file storage option
    serve_parser.add_argument(
        "--token-file",
        dest="token_file",
        default=None,
        help="Path to save/load session token file with restricted permissions (0600)"
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
    schedule_parser.add_argument(
        "--retention",
        type=str,
        default=None,
        help="Automatic vault retention policy (e.g., '30d' for 30 days). Enables automatic pruning after each collection."
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
    scan_parser.add_argument(
        "--no-strict-host-keys",
        action="store_true",
        help="Disable SSH host key verification (NOT recommended for production). Default: strict verification enabled."
    )
    scan_parser.add_argument(
        "--known-hosts-file",
        help="Custom path to SSH known_hosts file. Uses default ~/.ssh/known_hosts if not specified."
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

    # 'self-defense' command mapping
    self_defense_parser = subparsers.add_parser("self-defense", help="Manage Orin agent self-defense mechanisms (watchdog, seccomp, AppArmor, SELinux)")
    self_defense_parser.add_argument(
        "--action",
        choices=["watchdog", "heartbeat", "generate-profiles", "status"],
        default="status",
        help="Self-defense action to perform"
    )
    self_defense_parser.add_argument(
        "--socket",
        default="/var/run/orin/watchdog.sock",
        help="Unix socket path for watchdog communication"
    )
    self_defense_parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Health check interval in seconds"
    )
    self_defense_parser.add_argument(
        "--output-dir",
        default="/etc/orin/security",
        help="Output directory for security profiles"
    )

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

    # 'stream' command mapping - eBPF Real-Time Streamer
    stream_parser = subparsers.add_parser("stream", help="Launch eBPF real-time telemetry streaming via ring buffer")
    stream_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug output"
    )

    # 'vault' command mapping - Vault Lifecycle Management
    vault_parser = subparsers.add_parser("vault", help="Manage forensic vault lifecycle (prune, stats)")
    vault_subparsers = vault_parser.add_subparsers(dest="vault_command", required=True)

    # vault stats
    vault_stats_parser = vault_subparsers.add_parser("stats", help="Display vault statistics (size, snapshot count, age)")

    # vault prune
    vault_prune_parser = vault_subparsers.add_parser("prune", help="Delete old snapshots and related data")
    vault_prune_parser.add_argument(
        "--older-than",
        type=int,
        required=True,
        help="Delete snapshots older than this many days"
    )
    vault_prune_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show what would be deleted without actually deleting"
    )
    vault_prune_parser.add_argument(
        "--execute",
        dest="execute",
        action="store_true",
        default=False,
        help="Actually execute the deletion (default: dry-run mode)"
    )

    # Rules management command
    rules_parser = subparsers.add_parser("rules", help="Manage Sigma and YARA rule repositories")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", required=True)

    # orin rules update --sigma <path> | --yara <path>
    rules_update_parser = rules_subparsers.add_parser("update", help="Update rules from offline directory")
    rules_update_parser.add_argument(
        "--sigma",
        type=str,
        metavar="SIGMA_DIR",
        help="Path to directory containing Sigma rules (.yml files)"
    )
    rules_update_parser.add_argument(
        "--yara",
        type=str,
        metavar="YARA_DIR",
        help="Path to directory containing YARA rules (.yar files)"
    )
    rules_update_parser.add_argument(
        "--validate-only",
        action="store_true",
        default=False,
        help="Only validate rules without installing them"
    )

    # orin rules list --sigma | --yara
    rules_list_parser = rules_subparsers.add_parser("list", help="List active rules with descriptions")
    rules_list_parser.add_argument(
        "--sigma",
        action="store_true",
        default=False,
        help="List Sigma rules"
    )
    rules_list_parser.add_argument(
        "--yara",
        action="store_true",
        default=False,
        help="List YARA rules"
    )
    rules_list_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Show detailed information including operators and MITRE mappings"
    )

    # orin rules validate --sigma <path> | --yara <path>
    rules_validate_parser = rules_subparsers.add_parser("validate", help="Validate rule syntax and schema")
    rules_validate_parser.add_argument(
        "--sigma",
        type=str,
        metavar="SIGMA_PATH",
        help="Path to Sigma rule file or directory to validate"
    )
    rules_validate_parser.add_argument(
        "--yara",
        type=str,
        metavar="YARA_PATH",
        help="Path to YARA rule file or directory to validate"
    )
    rules_validate_parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Fail on warnings in addition to errors"
    )

    # Version command with --sbom flag
    version_parser = subparsers.add_parser("version", help="Display Orin version information")
    version_parser.add_argument(
        "--sbom",
        action="store_true",
        default=False,
        help="Display embedded Software Bill of Materials (SBOM)"
    )
    version_parser.add_argument(
        "--self-check",
        action="store_true",
        default=False,
        help="Perform self-integrity check against embedded signatures"
    )
    version_parser.add_argument(
        "--generate-manifest",
        action="store_true",
        default=False,
        help="Generate a release manifest with SHA-256 hashes"
    )
    version_parser.add_argument(
        "--sign-manifest",
        type=str,
        metavar="MANIFEST_PATH",
        help="Sign a release manifest with GPG"
    )
    version_parser.add_argument(
        "--verify-manifest",
        type=str,
        metavar="MANIFEST_PATH",
        help="Verify a release manifest against GPG signature"
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
    elif args.command == "self-defense":
        # Handle self-defense actions directly
        if args.action == "watchdog":
            config = WatchdogConfig(
                watchdog_socket=args.socket,
                check_interval=args.interval
            )
            manager = SelfDefenseManager(config)
            manager.start_watchdog_service()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                manager.stop()
        elif args.action == "heartbeat":
            manager = SelfDefenseManager()
            success = manager.send_heartbeat(args.socket)
            sys.exit(0 if success else 1)
        elif args.action == "generate-profiles":
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            SelfDefenseManager.generate_seccomp_profile(str(output_dir / 'orin-seccomp.json'))
            SelfDefenseManager.generate_apparmor_profile(str(output_dir / 'orin-apparmor'))
            SelfDefenseManager.generate_selinux_policy(str(output_dir / 'orin-selinux.te'))
            print(f"Security profiles generated in {output_dir}")
        elif args.action == "status":
            manager = SelfDefenseManager()
            status = manager.validate_security_profiles()
            import json
            print(json.dumps(status, indent=2))
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
    elif args.command == "stream":
        cmd_stream(args)
    elif args.command == "vault":
        # Handle vault lifecycle commands
        if args.vault_command == "prune":
            # Override dry_run if --execute is specified
            if args.execute:
                args.dry_run = False
            else:
                args.dry_run = True
        cmd_vault(args)
    elif args.command == "rules":
        cmd_rules(args)


if __name__ == "__main__":
    main()