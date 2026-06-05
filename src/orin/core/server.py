# src/orin/core/server.py
"""
orin.core.server – Web Dashboard HTTP Server
===========================================
Provides a lightweight, zero-dependency local web server utilizing Python's
standard library `http.server`. Exposes the REST API and serves the single-page
HTML console for system audits, timeline drift, and rule configurations.
"""

import sys
import os
import json
import base64
import secrets
import hmac
import ssl
import subprocess
from pathlib import Path
from typing import Any
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone

from orin.core.database import OrinStorage
from orin.core.config import load_config
from orin.analysis.timeline import calculate_snapshot_delta
from orin.collectors.users import gather_system_accounts
from orin.collectors.kernel import gather_loaded_kernel_modules
from orin.core.scheduler import CRON_D_FILE

# Helper for resolving static dashboard assets
DASHBOARD_FILE = Path(__file__).parent / "dashboard.html"


class OrinHTTPHandler(BaseHTTPRequestHandler):
    """Custom HTTP Request Handler for Orin Console and API endpoints."""

    def log_message(self, format, *args):
        # Mute default request logs on stderr to avoid terminal clutter
        pass

    def check_auth(self) -> bool:
        """Validate access via Bearer session token or legacy Basic Auth."""
        session_token = getattr(self.server, "session_token", None)
        no_auth = getattr(self.server, "no_auth", False)

        # Auth explicitly disabled
        if no_auth:
            return True

        parsed_url = urlparse(self.path)
        query = parse_qs(parsed_url.query)

        # --- Bearer token (primary, auto-generated) ---
        if session_token:
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                provided = auth_header[7:].strip()
                if hmac.compare_digest(provided, session_token):
                    return True

            # Accept ?token= on GET requests (initial URL open from terminal)
            token_param = query.get("token", [None])[0]
            if token_param and hmac.compare_digest(token_param, session_token):
                return True

            self._send_token_required()
            return False

        # --- Legacy Basic Auth fallback ---
        username = getattr(self.server, "username", None)
        password = getattr(self.server, "password", None)
        if username and password:
            auth_header = self.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Basic "):
                self.send_auth_challenge()
                return False
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                u, p = decoded.split(":", 1)
                if hmac.compare_digest(u, username) and hmac.compare_digest(p, password):
                    return True
            except Exception:
                pass
            self.send_auth_challenge()
            return False

        # No auth configured
        return True

    def _send_token_required(self):
        """Respond with a user-friendly 401 page when token is missing or wrong."""
        body = (
            b"<!DOCTYPE html><html><head><title>401 \xe2\x80\x94 Orin Access Denied</title>"
            b"<style>body{font-family:monospace;background:#0d1117;color:#e6edf3;"
            b"display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
            b"div{text-align:center;padding:2rem}code{background:#161b22;padding:.2em .4em;border-radius:4px}"
            b"</style></head><body><div>"
            b"<h1 style='color:#f85149'>&#128274; 401 &mdash; Access Denied</h1>"
            b"<p>This Orin console requires a valid session token.</p>"
            b"<p>Use the URL printed in the terminal where <code>sudo orin serve</code> is running.</p>"
            b"</div></body></html>"
        )
        self.send_response(401)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("WWW-Authenticate", 'Bearer realm="Orin Forensic Console"')
        self.end_headers()
        self.wfile.write(body)

    def send_auth_challenge(self):
        """Respond with HTTP 401 WWW-Authenticate challenge (Basic Auth legacy)."""
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Orin Forensic Console"')
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>401 Unauthorized</h1><p>Invalid credentials.</p>")



    def send_json(self, data, status=200):
        """Helper to send a JSON response payload."""
        try:
            payload = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as e:
            self.send_error_response(str(e))

    def send_error_response(self, message, status=500):
        """Helper to send standard JSON error summaries."""
        self.send_json({"status": "error", "message": message}, status)

    def do_GET(self):
        """Handle GET routes: dashboard assets and API endpoints."""
        if not self.check_auth():
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # 1. Serve Dashboard HTML Console — inject session token as JS constant
        if path in ("/", "/index.html"):
            if not DASHBOARD_FILE.exists():
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Dashboard template not found.")
                return

            session_token = getattr(self.server, "session_token", None) or ""
            html = DASHBOARD_FILE.read_text(encoding="utf-8")
            # Inject session token as a JS constant so the dashboard can pick
            # it up and include it in all subsequent API fetch() calls.
            token_script = (
                f'<script>const ORIN_SESSION_TOKEN = "{session_token}";</script>\n'
            )
            html = html.replace("</head>", token_script + "</head>", 1)
            content = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # 2. API: Status and Posture Metrics
        if path == "/api/status":
            self.handle_api_status()
            return

        # 3. API: Active Alerts Ledger
        if path == "/api/alerts":
            self.handle_api_alerts()
            return

        # 4. API: System Snapshot List
        if path == "/api/snapshots":
            self.handle_api_snapshots()
            return

        # 5. API: Rule Configuration Loader
        if path == "/api/config":
            self.send_json(load_config())
            return

        # 6. API: Snapshot Timeline Diff delta
        if path == "/api/delta":
            self.handle_api_delta(parsed_url)
            return

        # 7. API: Automation Schedule Status
        if path == "/api/schedule/status":
            self.handle_api_schedule_status()
            return

        # 8. API: Snapshot Telemetry details
        if path == "/api/snapshot/telemetry":
            self.handle_api_snapshot_telemetry(parsed_url)
            return

        # Fallback for unrecognized paths
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def do_POST(self):
        """Handle POST routes: updates, captures, and baseline managers."""
        if not self.check_auth():
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # Read JSON body content
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = {}
        if content_length > 0:
            try:
                post_data = json.loads(self.rfile.read(content_length).decode("utf-8"))
            except Exception as e:
                self.send_error_response(f"Malformed JSON body request: {e}", 400)
                return

        # 1. API: Trigger on-demand collect & analysis cycle
        if path == "/api/collect":
            self.handle_api_collect()
            return

        # 2. API: Update alert flags and analyst annotations
        if path == "/api/alerts/action":
            self.handle_api_alert_action(post_data)
            return

        # 3. API: Refresh baseline ledger from system state
        if path == "/api/baseline/refresh":
            self.handle_api_baseline_refresh()
            return

        # 4. API: Explicitly allowlist/baseline single entities
        if path == "/api/baseline/add":
            self.handle_api_baseline_add(post_data)
            return

        # 5. API: Serialize config file updates atomically
        if path == "/api/config/update":
            self.handle_api_config_update(post_data)
            return

        # 6. API: Install automation schedule
        if path == "/api/schedule/install":
            self.handle_api_schedule_install(post_data)
            return

        # 7. API: Remove automation schedule
        if path == "/api/schedule/remove":
            self.handle_api_schedule_remove()
            return

        # 8. API: Trigger a remote agentless SSH scan
        if path == "/api/scan":
            self.handle_api_scan(post_data)
            return

        # 9. API: Local AI correlation
        if path == "/api/correlate":
            self.handle_api_correlate(post_data)
            return

        # 10. API: Process Kill action
        if path == "/api/process/kill":
            self.handle_api_process_kill(post_data)
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    # API GET Router Handlers
    def handle_api_status(self):
        """Fetch statistics and live risk score assessment from the vault."""
        db_path = self.server.db_path
        if not db_path.exists():
            self.send_json({
                "vault_path": str(db_path),
                "total_snapshots": 0,
                "total_baseline_modules": 0,
                "total_baseline_users": 0,
                "total_alerts": 0,
                "unresolved_alerts": 0,
                "risk_score": 0,
                "latest_snapshot": None,
                "total_hosts": 0,
                "fleet_hosts": []
            })
            return

        storage = OrinStorage(db_path)
        try:
            import platform
            with storage.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) as total FROM system_snapshots;")
                total_snapshots = cursor.fetchone()["total"]
                
                cursor.execute("SELECT COUNT(*) as total FROM baseline_kernel_modules;")
                total_baseline_modules = cursor.fetchone()["total"]
                
                cursor.execute("SELECT COUNT(*) as total FROM baseline_users;")
                total_baseline_users = cursor.fetchone()["total"]
                
                cursor.execute("SELECT COUNT(*) as total FROM security_events;")
                total_alerts = cursor.fetchone()["total"]
                
                cursor.execute("PRAGMA table_info(security_events);")
                columns = {row["name"] for row in cursor.fetchall()}
                has_suppressed = "suppressed" in columns
                suppressed_cond = " AND suppressed = 0" if has_suppressed else ""
                
                cursor.execute(f"SELECT COUNT(*) as total FROM security_events WHERE resolved = 0{suppressed_cond};")
                unresolved_alerts = cursor.fetchone()["total"]

                latest_snapshot = None
                if total_snapshots > 0:
                    cursor.execute("SELECT id, timestamp, hostname, os_platform FROM system_snapshots ORDER BY id DESC LIMIT 1;")
                    latest = cursor.fetchone()
                    latest_snapshot = dict(latest)

                cursor.execute(f"SELECT severity FROM security_events WHERE resolved = 0{suppressed_cond};")
                unresolved_sevs = [row["severity"].lower() for row in cursor.fetchall()]
                
                risk_score = 0
                if unresolved_sevs:
                    crit_count = unresolved_sevs.count("critical")
                    high_count = unresolved_sevs.count("high")
                    med_count = unresolved_sevs.count("medium")
                    low_count = len(unresolved_sevs) - crit_count - high_count - med_count

                    if crit_count > 0:
                        risk_score = min(90 + (crit_count - 1) * 5, 100)
                    elif high_count > 0:
                        risk_score = min(65 + (high_count - 1) * 3 + med_count * 1.5 + low_count * 0.5, 89)
                    elif med_count > 0:
                        risk_score = min(35 + (med_count - 1) * 1.5 + low_count * 0.5, 64)
                    else:
                        risk_score = min(15 + (low_count - 1) * 0.5, 34)

                    risk_score = int(risk_score + 0.5)

                # Fleet statistics query
                cursor.execute("SELECT DISTINCT hostname FROM system_snapshots;")
                unique_hosts = [row["hostname"] for row in cursor.fetchall()]
                
                fleet_hosts = []
                for h in unique_hosts:
                    cursor.execute("SELECT id, timestamp, os_platform FROM system_snapshots WHERE hostname = ? ORDER BY id DESC LIMIT 1;", (h,))
                    h_snap = cursor.fetchone()
                    if not h_snap:
                        continue
                    h_snap_id = h_snap["id"]
                    h_timestamp = h_snap["timestamp"]
                    h_os = h_snap["os_platform"]
                    
                    cursor.execute(f"SELECT severity FROM security_events WHERE resolved = 0{suppressed_cond} AND (hostname = ? OR (hostname IS NULL AND ? = ?));", (h, h, platform.node() or "unknown_host"))
                    h_unresolved_sevs = [row["severity"].lower() for row in cursor.fetchall()]
                    
                    h_risk_score = 0
                    if h_unresolved_sevs:
                        crit_count = h_unresolved_sevs.count("critical")
                        high_count = h_unresolved_sevs.count("high")
                        med_count = h_unresolved_sevs.count("medium")
                        low_count = len(h_unresolved_sevs) - crit_count - high_count - med_count

                        if crit_count > 0:
                            h_risk_score = min(90 + (crit_count - 1) * 5, 100)
                        elif high_count > 0:
                            h_risk_score = min(65 + (high_count - 1) * 3 + med_count * 1.5 + low_count * 0.5, 89)
                        elif med_count > 0:
                            h_risk_score = min(35 + (med_count - 1) * 1.5 + low_count * 0.5, 64)
                        else:
                            h_risk_score = min(15 + (low_count - 1) * 0.5, 34)

                        h_risk_score = int(h_risk_score + 0.5)
                        
                    fleet_hosts.append({
                        "hostname": h,
                        "os_platform": h_os,
                        "latest_snapshot_id": h_snap_id,
                        "latest_snapshot_timestamp": h_timestamp,
                        "unresolved_alerts": len(h_unresolved_sevs),
                        "risk_score": h_risk_score
                    })

                self.send_json({
                    "vault_path": str(db_path),
                    "total_snapshots": total_snapshots,
                    "total_baseline_modules": total_baseline_modules,
                    "total_baseline_users": total_baseline_users,
                    "total_alerts": total_alerts,
                    "unresolved_alerts": unresolved_alerts,
                    "risk_score": risk_score,
                    "latest_snapshot": latest_snapshot,
                    "total_hosts": len(unique_hosts),
                    "fleet_hosts": fleet_hosts
                })
        except Exception as e:
            self.send_error_response(f"Database query failure: {e}")

    def handle_api_alerts(self):
        """Retrieve security events ledger rows."""
        db_path = self.server.db_path
        if not db_path.exists():
            self.send_json([])
            return

        parsed_url = urlparse(self.path)
        query = parse_qs(parsed_url.query)
        host_filter = query.get("host", [None])[0]

        import platform
        storage = OrinStorage(db_path)
        try:
            with storage.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(security_events);")
                columns = {row["name"] for row in cursor.fetchall()}
                
                query_cols = ["id", "timestamp", "event_type", "severity", "description", "raw_details", "resolved"]
                for col in ("notes", "suppressed", "reviewed_at", "attck_technique", "attck_tactic", "attck_url", "hostname"):
                    if col in columns:
                        query_cols.append(col)
                        
                sql = f"SELECT {', '.join(query_cols)} FROM security_events"
                params = []
                if host_filter:
                    sql += " WHERE (hostname = ? OR (hostname IS NULL AND ? = ?))"
                    params.extend([host_filter, host_filter, platform.node() or "unknown_host"])
                sql += " ORDER BY id DESC;"
                
                cursor.execute(sql, params)
                
                alerts = []
                for row in cursor.fetchall():
                    alert_dict = dict(row)
                    for col in ("notes", "suppressed", "reviewed_at", "hostname"):
                        if col not in alert_dict:
                            alert_dict[col] = "" if col in ("notes", "hostname") else (0 if col == "suppressed" else None)
                    for col in ("attck_technique", "attck_tactic", "attck_url"):
                        if col not in alert_dict:
                            alert_dict[col] = None
                    alerts.append(alert_dict)
                self.send_json(alerts)
        except Exception as e:
            self.send_error_response(f"Database query failure: {e}")

    def handle_api_scan(self, post_data):
        """Orchestrate remote fleet scan or remote baseline initialization."""
        host = post_data.get("host")
        user = post_data.get("user")
        key_path = post_data.get("key_path")
        port = post_data.get("port", 22)
        init_flag = post_data.get("init", False)
        
        if not host or not user:
            self.send_error_response("Missing host or user parameters", 400)
            return
            
        db_path = self.server.db_path
        
        if init_flag:
            try:
                current_dir = Path(__file__).resolve().parent
                agent_path = current_dir.parent / "collectors" / "remote_agent.py"
                if not agent_path.exists():
                    self.send_error_response(f"Remote agent script missing at: {agent_path}", 500)
                    return
                    
                remote_agent_code = agent_path.read_text(encoding="utf-8")
                ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no"]
                if port:
                    ssh_cmd.extend(["-p", str(port)])
                if key_path:
                    ssh_cmd.extend(["-i", str(key_path)])
                
                agent_config = {"critical_paths": [], "critical_dirs": []}
                ssh_cmd.extend([f"{user}@{host}", f"python3 - '{json.dumps(agent_config)}'"])
                
                proc = subprocess.Popen(
                    ssh_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = proc.communicate(input=remote_agent_code)
                
                if proc.returncode != 0:
                    self.send_error_response(f"SSH baselining failed: {stderr}", 500)
                    return
                    
                telemetry = json.loads(stdout.strip())
                remote_hostname = telemetry.get("hostname", host)
                
                storage = OrinStorage(db_path)
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
                    
                self.send_json({"status": "success", "message": f"Baseline initialized for remote host {remote_hostname}"})
            except Exception as e:
                self.send_error_response(f"Baselines collection/storage error: {e}", 500)
        else:
            from orin.core.scanner import run_remote_scan
            try:
                metrics = run_remote_scan(
                    host=host,
                    user=user,
                    key_path=key_path,
                    port=port,
                    db_path=db_path
                )
                self.send_json({"status": "success", "metrics": metrics})
            except Exception as e:
                self.send_error_response(f"Remote scan error: {e}", 500)

    def handle_api_correlate(self, data):
        """Invoke local AI correlation and return the Markdown briefing."""
        from orin.analysis.ai import run_ai_correlation
        
        hostnames = data.get("hostnames")
        url = data.get("url", "http://127.0.0.1:11434")
        model = data.get("model", "gemma3:1b")
        
        try:
            briefing = run_ai_correlation(self.server.db_path, hostnames=hostnames, url=url, model=model)
            self.send_json({"status": "success", "briefing": briefing})
        except Exception as e:
            self.send_error_response(f"AI Correlation failed: {e}")

    def handle_api_snapshots(self):
        """Retrieve historical system snapshots ledger."""
        db_path = self.server.db_path
        if not db_path.exists():
            self.send_json([])
            return

        storage = OrinStorage(db_path)
        try:
            with storage.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, timestamp, hostname, os_platform FROM system_snapshots ORDER BY id DESC;")
                snapshots = [dict(row) for row in cursor.fetchall()]
                self.send_json(snapshots)
        except Exception as e:
            self.send_error_response(f"Failed to load snapshots: {e}")

    def handle_api_delta(self, parsed_url):
        """Compute relative telemetry modifications between snapshot IDs."""
        query_params = parse_qs(parsed_url.query)
        base_id = query_params.get("base", [None])[0]
        target_id = query_params.get("target", [None])[0]

        if not base_id or not target_id:
            self.send_error_response("Missing 'base' or 'target' query parameter.", 400)
            return

        db_path = self.server.db_path
        try:
            base_id = int(base_id)
            target_id = int(target_id)
        except ValueError:
            self.send_error_response("Snapshot IDs must be numeric integers.", 400)
            return

        try:
            delta = calculate_snapshot_delta(db_path, base_id, target_id)

            storage = OrinStorage(db_path)
            with storage.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT username, uid, login_shell FROM collected_users WHERE snapshot_id = ?;", (base_id,))
                base_users = {row["username"]: row for row in cursor.fetchall()}
                cursor.execute("SELECT username, uid, login_shell FROM collected_users WHERE snapshot_id = ?;", (target_id,))
                target_users = {row["username"]: row for row in cursor.fetchall()}

                new_users = []
                for username, row in target_users.items():
                    if username not in base_users:
                        new_users.append(dict(row))
                delta["new_users"] = new_users

                cursor.execute("SELECT module_name, memory_size FROM collected_kernel_modules WHERE snapshot_id = ?;", (base_id,))
                base_mods = {row["module_name"]: row for row in cursor.fetchall()}
                cursor.execute("SELECT module_name, memory_size FROM collected_kernel_modules WHERE snapshot_id = ?;", (target_id,))
                target_mods = {row["module_name"]: row for row in cursor.fetchall()}

                new_mods = []
                for mod_name, row in target_mods.items():
                    if mod_name not in base_mods:
                        new_mods.append({"name": row["module_name"], "size": row["memory_size"]})
                delta["new_modules"] = new_mods

                cursor.execute("SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ?;", (base_id,))
                base_files = {row["file_path"]: row["sha256_hash"] for row in cursor.fetchall()}
                cursor.execute("SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ?;", (target_id,))
                target_files = {row["file_path"]: row["sha256_hash"] for row in cursor.fetchall()}

                modified_files = []
                for file_path, current_hash in target_files.items():
                    if file_path not in base_files:
                        modified_files.append({"path": file_path, "status": "added"})
                    elif base_files[file_path] != current_hash:
                        modified_files.append({"path": file_path, "status": "modified"})
                for file_path in base_files:
                    if file_path not in target_files:
                        modified_files.append({"path": file_path, "status": "removed"})
                delta["modified_files"] = modified_files

            self.send_json(delta)
        except Exception as e:
            self.send_error_response(f"Timeline delta calculation failure: {e}")

    # API POST Router Handlers
    def handle_api_collect(self):
        """Execute telemetry collector scans and threat rule audits on demand."""
        db_path = self.server.db_path
        
        class MockArgs:
            def __init__(self, database):
                self.database = str(database)

        try:
            from orin.main import cmd_collect, cmd_analyze
            args = MockArgs(db_path)
            
            cmd_collect(args)
            cmd_analyze(args)

            storage = OrinStorage(db_path)
            latest_id = None
            with storage.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM system_snapshots ORDER BY id DESC LIMIT 1;")
                row = cursor.fetchone()
                if row:
                    latest_id = row["id"]

            self.send_json({"status": "success", "snapshot_id": latest_id})
        except Exception as e:
            self.send_error_response(f"On-demand telemetry capture failed: {e}")

    def handle_api_alert_action(self, data):
        """Process analyst triage annotations or status updates on an alert."""
        alert_id = data.get("alert_id")
        action = data.get("action")

        if not alert_id or not action:
            self.send_error_response("Missing 'alert_id' or 'action' parameter.", 400)
            return

        db_path = self.server.db_path
        storage = OrinStorage(db_path)
        try:
            with storage.get_connection() as conn:
                cursor = conn.cursor()
                now_str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%fZ')

                if action == "acknowledge":
                    cursor.execute("UPDATE security_events SET resolved = 1, reviewed_at = ? WHERE id = ?;", (now_str, alert_id))
                elif action == "unresolve":
                    cursor.execute("UPDATE security_events SET resolved = 0, reviewed_at = NULL WHERE id = ?;", (alert_id,))
                elif action == "suppress":
                    cursor.execute("UPDATE security_events SET suppressed = 1 WHERE id = ?;", (alert_id,))
                elif action == "unsuppress":
                    cursor.execute("UPDATE security_events SET suppressed = 0 WHERE id = ?;", (alert_id,))
                elif action == "update_notes":
                    notes = data.get("notes", "")
                    cursor.execute("UPDATE security_events SET notes = ? WHERE id = ?;", (notes, alert_id))
                elif action == "override_severity":
                    severity = data.get("severity", "").lower()
                    if severity not in ("low", "medium", "high", "critical"):
                        self.send_error_response("Invalid severity value.", 400)
                        return
                    cursor.execute("UPDATE security_events SET severity = ? WHERE id = ?;", (severity, alert_id))
                else:
                    self.send_error_response(f"Unsupported alert action: {action}", 400)
                    return
                
                conn.commit()
            self.send_json({"status": "success"})
        except Exception as e:
            self.send_error_response(f"Failed to update alert state: {e}")

    def handle_api_baseline_refresh(self):
        """Regenerate baseline system configuration logs."""
        db_path = self.server.db_path
        storage = OrinStorage(db_path)
        try:
            baseline_modules = gather_loaded_kernel_modules()
            baseline_accounts = gather_system_accounts()

            with storage.get_connection() as conn:
                if baseline_modules:
                    conn.executemany(
                        "INSERT OR IGNORE INTO baseline_kernel_modules (module_name, memory_size) VALUES (?, ?);",
                        [(m["module_name"], m["memory_size"]) for m in baseline_modules]
                    )
                if baseline_accounts:
                    conn.executemany(
                        """
                        INSERT OR IGNORE INTO baseline_users (username, uid, gid, home_dir, login_shell)
                        VALUES (?, ?, ?, ?, ?);
                        """,
                        [(u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in baseline_accounts]
                    )
                conn.commit()

            self.send_json({"status": "success"})
        except Exception as e:
            self.send_error_response(f"Baseline synchronization routine failed: {e}")

    def handle_api_baseline_add(self, data):
        """Insert a specific user or LKM kernel module into allowlist tables."""
        target_type = data.get("type")
        name = data.get("name")

        if not target_type or not name:
            self.send_error_response("Missing 'type' or 'name' parameter.", 400)
            return

        db_path = self.server.db_path
        storage = OrinStorage(db_path)
        try:
            with storage.get_connection() as conn:
                if target_type == "user":
                    accounts = gather_system_accounts()
                    found = [u for u in accounts if u["username"] == name]
                    
                    if found:
                        u = found[0]
                        conn.execute(
                            "INSERT OR REPLACE INTO baseline_users (username, uid, gid, home_dir, login_shell) VALUES (?, ?, ?, ?, ?);",
                            (u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"])
                        )
                    else:
                        conn.execute(
                            "INSERT OR REPLACE INTO baseline_users (username, uid, gid, home_dir, login_shell) VALUES (?, 1000, 1000, NULL, '/bin/bash');",
                            (name,)
                        )
                elif target_type == "module":
                    mods = gather_loaded_kernel_modules()
                    found = [m for m in mods if m["module_name"] == name]
                    size = found[0]["memory_size"] if found else 16384
                    
                    conn.execute(
                        "INSERT OR REPLACE INTO baseline_kernel_modules (module_name, memory_size) VALUES (?, ?);",
                        (name, size)
                    )
                else:
                    self.send_error_response("Invalid baseline allowlist type.", 400)
                    return
                
                conn.commit()
            self.send_json({"status": "success"})
        except Exception as e:
            self.send_error_response(f"Allowlist registration failed: {e}")

    def handle_api_config_update(self, data):
        """Validate and write configuration updates atomically back to the resolved source path."""
        required_keys = {"expected_ports", "whitelisted_processes", "critical_paths", "critical_dirs"}
        
        if not all(key in data for key in required_keys):
            self.send_error_response("Missing required configuration fields.", 400)
            return

        try:
            data["expected_ports"] = [int(p) for p in data["expected_ports"]]
            data["whitelisted_processes"] = [str(p).strip() for p in data["whitelisted_processes"]]
            data["critical_paths"] = [str(p).strip() for p in data["critical_paths"]]
            data["critical_dirs"] = [str(p).strip() for p in data["critical_dirs"]]
        except Exception as e:
            self.send_error_response(f"Invalid field values or formatting: {e}", 400)
            return

        try:
            # Dynamically import and fetch the active file location source configuration mapping
            from orin.core.config import load_config_with_source
            _, active_config_path = load_config_with_source()
            
            # Write to a temp staging file and rename atomically
            temp_path = active_config_path.with_suffix(".tmp")
            with open(temp_path, "w") as f:
                json.dump(data, f, indent=2)
            temp_path.rename(active_config_path)
            self.send_json({"status": "success"})
        except Exception as e:
            self.send_error_response(f"Atomic configuration serialization failed: {e}")

    def handle_api_schedule_status(self):
        """Return the current cron automation schedule status."""
        result = {"active": False, "mode": None, "cron_entry": None, "interval_minutes": None}

        # Check system-wide file first
        if CRON_D_FILE.exists():
            try:
                content = CRON_D_FILE.read_text().strip()
                result["active"] = True
                result["mode"] = "system"
                result["cron_entry"] = content
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if parts and parts[0].startswith("*/"):
                            try:
                                result["interval_minutes"] = int(parts[0][2:])
                            except ValueError:
                                pass
                        break
            except Exception:
                pass

        if not result["active"]:
            # Check user crontab
            try:
                cron_output = subprocess.check_output(
                    ["crontab", "-l"], stderr=subprocess.DEVNULL
                ).decode()
                for line in cron_output.splitlines():
                    if "orin collect" in line or "orin-collect" in line:
                        result["active"] = True
                        result["mode"] = "user"
                        result["cron_entry"] = line.strip()
                        parts = line.strip().split()
                        if parts and parts[0].startswith("*/"):
                            try:
                                result["interval_minutes"] = int(parts[0][2:])
                            except ValueError:
                                pass
                        break
            except Exception:
                pass

        self.send_json(result)

    def handle_api_schedule_install(self, data):
        """Install or update the cron automation schedule."""
        interval = data.get("interval_minutes", 10)
        try:
            interval = int(interval)
            if interval < 1 or interval > 1440:
                self.send_error_response("Interval must be between 1 and 1440 minutes.", 400)
                return
        except (TypeError, ValueError):
            self.send_error_response("Invalid interval value.", 400)
            return

        try:
            from orin.core.scheduler import install_schedule
            install_schedule(self.server.db_path, interval)
            self.send_json({"status": "success", "interval_minutes": interval})
        except Exception as e:
            self.send_error_response(f"Failed to install schedule: {e}")

    def handle_api_schedule_remove(self):
        """Remove the active cron automation schedule."""
        try:
            from orin.core.scheduler import remove_schedule
            remove_schedule()
            self.send_json({"status": "success"})
        except SystemExit:
            # remove_schedule may call sys.exit(1) on permission errors
            self.send_error_response("Permission denied. Run orin serve as root to manage the system-wide schedule.")
        except Exception as e:
            self.send_error_response(f"Failed to remove schedule: {e}")

    def handle_api_snapshot_telemetry(self, parsed_url: Any) -> None:
        """Fetch all collected telemetry records for a given snapshot ID.

        Parameters
        ----------
        parsed_url : Any
            The parsed request URL.
        """
        from urllib.parse import parse_qs
        query_params = parse_qs(parsed_url.query)
        snap_id_str = query_params.get("id", [None])[0]
        
        db_path = self.server.db_path
        if not db_path.exists():
            self.send_json({})
            return

        storage = OrinStorage(db_path)
        try:
            with storage.get_connection() as conn:
                cursor = conn.cursor()
                
                if not snap_id_str:
                    cursor.execute("SELECT id FROM system_snapshots ORDER BY id DESC LIMIT 1;")
                    row = cursor.fetchone()
                    if not row:
                        self.send_json({})
                        return
                    snap_id = row["id"]
                else:
                    try:
                        snap_id = int(snap_id_str)
                    except ValueError:
                        self.send_error_response("Snapshot ID must be an integer.", 400)
                        return
                
                cursor.execute("SELECT id, timestamp, hostname, os_platform FROM system_snapshots WHERE id = ?;", (snap_id,))
                meta_row = cursor.fetchone()
                if not meta_row:
                    self.send_error_response(f"Snapshot with ID {snap_id} not found.", 404)
                    return
                metadata = dict(meta_row)

                cursor.execute("SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;", (snap_id,))
                processes = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;", (snap_id,))
                ports = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT local_ip, local_port, remote_ip, remote_port, state, process_name FROM collected_outbound_connections WHERE snapshot_id = ?;", (snap_id,))
                outbound = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT module_name, memory_size, instances_loaded FROM collected_kernel_modules WHERE snapshot_id = ?;", (snap_id,))
                kernel_modules = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT user_account, key_type, fingerprint, raw_key_comment FROM collected_ssh_keys WHERE snapshot_id = ?;", (snap_id,))
                ssh_keys = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ?;", (snap_id,))
                users = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ?;", (snap_id,))
                file_hashes = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT pid, exe, sha256, md5, vault_path FROM collected_deleted_binaries WHERE snapshot_id = ?;", (snap_id,))
                deleted_binaries = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT interface, flags, is_promiscuous FROM collected_promisc_interfaces WHERE snapshot_id = ?;", (snap_id,))
                promisc_interfaces = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason FROM collected_wtmp_sessions WHERE snapshot_id = ?;", (snap_id,))
                wtmp_sessions = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT username, uid, line, host, login_time, anomaly_detected, anomaly_reason FROM collected_lastlog_records WHERE snapshot_id = ?;", (snap_id,))
                lastlog_records = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT package, file_path, expected_md5, actual_md5, actual_sha256, status FROM collected_pkg_integrity WHERE snapshot_id = ?;", (snap_id,))
                pkg_integrity = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute("SELECT source, user, schedule, command FROM collected_crontabs WHERE snapshot_id = ?;", (snap_id,))
                crontabs = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT file_path, owner, grp, permissions, sha256 FROM collected_suid_binaries WHERE snapshot_id = ?;", (snap_id,))
                suid_binaries = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT bpf_id, name, type, tag, gpl_compatible FROM collected_ebpf_programs WHERE snapshot_id = ?;", (snap_id,))
                ebpf_programs = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT path, type FROM collected_ebpf_pinned WHERE snapshot_id = ?;", (snap_id,))
                ebpf_pinned = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT line FROM collected_ld_preload WHERE snapshot_id = ?;", (snap_id,))
                ld_preload = [r["line"] for r in cursor.fetchall()]

                cursor.execute("SELECT pid, fd_num, fd_type, resolved_path FROM collected_special_fds WHERE snapshot_id = ?;", (snap_id,))
                special_fds = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT log_line FROM collected_auth_logs WHERE snapshot_id = ?;", (snap_id,))
                auth_logs = [r["log_line"] for r in cursor.fetchall()]

                self.send_json({
                    "metadata": metadata,
                    "processes": processes,
                    "ports": ports,
                    "outbound": outbound,
                    "kernel_modules": kernel_modules,
                    "ssh_keys": ssh_keys,
                    "users": users,
                    "file_hashes": file_hashes,
                    "deleted_binaries": deleted_binaries,
                    "promisc_interfaces": promisc_interfaces,
                    "wtmp_sessions": wtmp_sessions,
                    "lastlog_records": lastlog_records,
                    "pkg_integrity": pkg_integrity,
                    "crontabs": crontabs,
                    "suid_binaries": suid_binaries,
                    "ebpf_programs": ebpf_programs,
                    "ebpf_pinned": ebpf_pinned,
                    "ld_preload": ld_preload,
                    "special_fds": special_fds,
                    "auth_logs": auth_logs
                })
        except Exception as e:
            self.send_error_response(f"Failed to load snapshot telemetry: {e}")

    def handle_api_process_kill(self, data: dict[str, Any]) -> None:
        """Terminate a process on the local node or a remote node over SSH.

        Parameters
        ----------
        data : dict[str, Any]
            The request payload containing process and connection info.
        """
        pid = data.get("pid")
        hostname = data.get("hostname")
        
        if pid is None:
            self.send_error_response("Missing 'pid' parameter.", 400)
            return
            
        try:
            pid = int(pid)
        except ValueError:
            self.send_error_response("Process ID must be an integer.", 400)
            return

        import platform
        local_host = platform.node() or "unknown_host"
        
        if not hostname or hostname == local_host or hostname in ("localhost", "127.0.0.1"):
            import signal
            try:
                os.kill(pid, signal.SIGKILL)
                self.send_json({"status": "success", "message": f"Successfully killed local PID {pid}."})
            except ProcessLookupError:
                self.send_error_response(f"Process with PID {pid} not found.", 404)
            except PermissionError:
                self.send_error_response(f"Permission denied killing PID {pid}.", 403)
            except Exception as e:
                self.send_error_response(f"Failed to kill process locally: {e}")
        else:
            ssh_host = data.get("ssh_host")
            ssh_user = data.get("ssh_user")
            ssh_port = data.get("ssh_port", 22)
            ssh_key = data.get("ssh_key")
            
            if not ssh_host or not ssh_user:
                self.send_error_response("Remote process requires 'ssh_host' and 'ssh_user' parameters.", 400)
                return
                
            import subprocess
            ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no"]
            if ssh_port:
                ssh_cmd.extend(["-p", str(ssh_port)])
            if ssh_key:
                ssh_cmd.extend(["-i", str(ssh_key)])
            
            ssh_cmd.extend([f"{ssh_user}@{ssh_host}", f"kill -9 {pid}"])
            
            try:
                proc = subprocess.Popen(
                    ssh_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = proc.communicate(timeout=10)
                if proc.returncode == 0:
                    self.send_json({"status": "success", "message": f"Successfully killed remote PID {pid} on host {hostname}."})
                else:
                    self.send_error_response(f"Remote command execution failed over SSH (code {proc.returncode}): {stderr.strip()}")
            except subprocess.TimeoutExpired:
                self.send_error_response("SSH connection timed out trying to kill process.", 504)
            except Exception as e:
                self.send_error_response(f"Failed to execute remote SSH command: {e}")


def start_server(db_path, host="127.0.0.1", port=8000, username=None, password=None,
                 cert_path=None, key_path=None, no_auth=False):
    """Initialize and run the blocking HTTPServer loop."""
    db_path = Path(db_path).resolve()

    # Auto-generate a cryptographically random session token unless auth is
    # explicitly disabled (--no-auth) or legacy Basic Auth credentials were supplied.
    # Only the person who ran `sudo orin serve` sees the token in stdout — this is
    # the Jupyter-style protection model.
    session_token = None
    if not no_auth and not (username and password):
        session_token = secrets.token_hex(32)  # 256-bit token, URL-safe hex

    class OrinHTTPServer(HTTPServer):
        def __init__(self, *args, **kwargs):
            self.db_path = db_path
            self.username = username
            self.password = password
            self.session_token = session_token
            self.no_auth = no_auth
            super().__init__(*args, **kwargs)

    server_address = (host, port)
    httpd = OrinHTTPServer(server_address, OrinHTTPHandler)

    if cert_path and key_path:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2  # Add this line
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        proto = "https"
    else:
        proto = "http"

    if db_path.exists():
        try:
            storage = OrinStorage(db_path)
            storage.initialize_db()
        except Exception as e:
            print(f"[!] Warning: Database migration failed on startup: {e}", file=sys.stderr)

    base_url = f"{proto}://{host}:{port}"
    print("[+] Orin Forensic Console bound to local socket interface.")

    if no_auth:
        print("[!] WARNING: Authentication DISABLED. Any user on this host can access the console.")
        print(f"[+] Access: {base_url}/")
    elif session_token:
        access_url = f"{base_url}/?token={session_token}"
        w = max(len(access_url) + 4, 66)
        border = "=" * w
        print("")
        print(f"  {border}")
        print(f"  {'ORIN FORENSIC CONSOLE — SECURE ACCESS TOKEN':^{w}}")
        print(f"  {border}")
        print(f"  {'Open this URL in your browser (token refreshes on restart):':^{w}}")
        print(f"  {border}")
        print(f"  {access_url}")
        print(f"  {border}")
        print(f"  {'Keep this URL private — it grants full console access.':^{w}}")
        print(f"  {border}")
        print("")
    else:
        print(f"[+] Access: {base_url}/  (Basic Auth: {username})")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Orin Forensic Console server...")
        httpd.server_close()
        sys.exit(0)