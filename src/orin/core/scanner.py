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
# src/orin/core/scanner.py
"""
orin.core.scanner – Agentless SSH Scanner Core
=============================================
Manages execution of the self-contained remote telemetry agent on target nodes
over SSH, extracts telemetry payloads, stores them in the SQLite vault, and
invokes the threat-rules analyzer cycle.
"""
import sys
import os
import json
import subprocess
from pathlib import Path
from orin.core.database import OrinStorage
from orin.core.config import load_config
from orin.analysis.engine import run_analysis_cycle


def run_remote_scan(
    host: str,
    user: str,
    key_path: str = None,
    port: int = 22,
    db_path: Path = Path("orin_vault.db"),
    config: dict = None
) -> dict:
    """Execute remote telemetry gathering over SSH and run the threat rules analysis.

    Parameters
    ----------
    host : str
        Target hostname or IP address.
    user : str
        SSH user account name.
    key_path : str, optional
        Path to the private SSH key file.
    port : int, optional
        SSH port to connect on (default 22).
    db_path : Path, optional
        Path to local Orin SQLite database.
    config : dict, optional
        Local config overrides. Loaded from config module if None.

    Returns
    -------
    dict
        The risk metrics and analysis results from the analysis cycle.
    """
    if config is None:
        config = load_config()

    # Locate the remote_agent.py script path dynamically
    # Expecting it in orin/collectors/remote_agent.py
    current_dir = Path(__file__).resolve().parent
    agent_path = current_dir.parent / "collectors" / "remote_agent.py"
    if not agent_path.exists():
        raise FileNotFoundError(f"Remote agent script not found at {agent_path}")

    # Read the agent script content
    remote_agent_code = agent_path.read_text(encoding="utf-8")

    # Serialize configuration values needed by the remote FIM and SUID check
    agent_config = {
        "critical_paths": config.get("critical_paths", []),
        "critical_dirs": config.get("critical_dirs", []),
        "vault_path": config.get("vault_path", "/var/lib/orin/vault")
    }
    config_json_str = json.dumps(agent_config)

    # Construct the SSH subprocess execution command list
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no"]
    if port:
        ssh_cmd.extend(["-p", str(port)])
    if key_path:
        ssh_cmd.extend(["-i", str(key_path)])

    # Pipe the script code to python3 running on stdin, passing config as argv[1]
    ssh_cmd.extend([f"{user}@{host}", f"python3 - '{config_json_str}'"])

    print(f"[*] Connecting to remote host {user}@{host}:{port} via SSH...")

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
        raise RuntimeError(f"Failed to spawn SSH subprocess pipeline: {e}")

    if proc.returncode != 0:
        sys.stderr.write(f"[-] SSH Execution Failed (code {proc.returncode}):\n{stderr}\n")
        raise RuntimeError(f"Remote command execution failed over SSH: {stderr.strip()}")

    # Parse stdout response payload as JSON telemetry
    try:
        telemetry = json.loads(stdout.strip())
    except json.JSONDecodeError as json_error:
        sys.stderr.write(f"[-] Raw Response (stdout):\n{stdout}\n")
        sys.stderr.write(f"[-] Error Output (stderr):\n{stderr}\n")
        raise RuntimeError(f"Failed to parse remote telemetry JSON: {json_error}")

    # Extract target host details
    remote_hostname = telemetry.get("hostname", host)
    remote_os = telemetry.get("os_platform", "Linux")

    print(f"[+] Remote telemetry acquired for host: {remote_hostname} ({remote_os})")

    # Determine encryption passphrase from config/environment
    config = config or load_config()
    vault_config = config.get("vault_encryption", {})
    encryption_passphrase = None

    if vault_config.get("enabled", False):
        passphrase_env = vault_config.get("passphrase_env", "ORIN_VAULT_PASSPHRASE")
        encryption_passphrase = os.environ.get(passphrase_env)

        if not encryption_passphrase:
            print("[!] Vault encryption enabled but passphrase not found in environment")
            print(f"    Set {passphrase_env} environment variable to enable encryption")
        elif len(encryption_passphrase) < vault_config.get("min_passphrase_length", 12):
            print(f"[!] Vault passphrase too short (minimum {vault_config.get('min_passphrase_length')} chars)")
            encryption_passphrase = None
        else:
            print("[+] Evidence vault encryption enabled (AES-256-GCM)")

    # Write snapshot to DB
    storage = OrinStorage(db_path, encryption_passphrase=encryption_passphrase)
    with storage.get_connection() as conn:
        snapshot_id = storage.create_snapshot(conn, hostname=remote_hostname, os_platform=remote_os)
        print(f"[+] Assigned Snapshot ID #{snapshot_id} in vault")

        # Persist all collected datasets in database
        if "processes" in telemetry:
            storage.store_processes(conn, snapshot_id, telemetry["processes"])
        if "ports" in telemetry:
            storage.store_ports(conn, snapshot_id, telemetry["ports"])
        if "outbound" in telemetry:
            storage.store_outbound_connections(conn, snapshot_id, telemetry["outbound"])
        if "promisc" in telemetry:
            storage.store_promisc_interfaces(conn, snapshot_id, telemetry["promisc"])
        if "modules" in telemetry:
            storage.store_kernel_modules(conn, snapshot_id, telemetry["modules"])
        if "kernel_symbols" in telemetry:
            storage.store_kernel_symbols(conn, snapshot_id, telemetry["kernel_symbols"])
        if "kernel_analysis" in telemetry:
            storage.store_kernel_analysis(conn, snapshot_id, telemetry["kernel_analysis"])
        if "users" in telemetry:
            storage.store_users(conn, snapshot_id, telemetry["users"])
        if "ssh_keys" in telemetry:
            storage.store_ssh_keys(conn, snapshot_id, telemetry["ssh_keys"])
        if "crontabs" in telemetry:
            storage.store_crontabs(conn, snapshot_id, telemetry["crontabs"])
        if "wtmp" in telemetry:
            storage.store_wtmp_sessions(conn, snapshot_id, telemetry["wtmp"])
        if "lastlog" in telemetry:
            storage.store_lastlog_records(conn, snapshot_id, telemetry["lastlog"])
        if "deleted" in telemetry:
            storage.store_deleted_binaries(conn, snapshot_id, telemetry["deleted"])
        if "fim" in telemetry:
            storage.store_file_hashes(conn, snapshot_id, telemetry["fim"])
        if "suid" in telemetry:
            storage.store_suid_binaries(conn, snapshot_id, telemetry["suid"])
        if "pkg_integrity" in telemetry:
            storage.store_pkg_integrity(conn, snapshot_id, telemetry["pkg_integrity"])
        if "auth_logs" in telemetry:
            storage.store_auth_logs(conn, snapshot_id, telemetry["auth_logs"])
        if "ebpf_programs" in telemetry:
            storage.store_ebpf_programs(conn, snapshot_id, telemetry["ebpf_programs"])
        if "ebpf_pinned" in telemetry:
            storage.store_ebpf_pinned(conn, snapshot_id, telemetry["ebpf_pinned"])
        if "ld_preload" in telemetry:
            storage.store_ld_preload(conn, snapshot_id, telemetry["ld_preload"])
        if "special_fds" in telemetry:
            storage.store_special_fds(conn, snapshot_id, telemetry["special_fds"])

        conn.commit()

    print("[*] Telemetry saved. Executing posture threat assessment cycle...")
    metrics = run_analysis_cycle(db_path)
    return metrics