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
"""
Orin Hub Server - Centralized Air-Gapped Fleet Management
==========================================================
Multi-tenant HTTP server for managing multiple Orin agents across
an air-gapped network with forensic data aggregation capabilities.
"""
import os
import sys
import json
import time
import hmac
import hashlib
import base64
import sqlite3
import threading
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import ssl
import secrets
import uuid

from orin.core.database import OrinStorage
from orin.core.config import load_config


class TenantManager:
    """Manages multi-tenant isolation and access control."""

    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.tenants = {}
        self._load_tenants()

    def _load_tenants(self):
        """Load tenant configurations from database."""
        if not self.db_path.exists():
            return

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Create tenants table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hub_tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                api_key_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_activity TEXT,
                max_hosts INTEGER DEFAULT 100,
                is_active INTEGER DEFAULT 1,
                metadata TEXT
            );
        """)

        # Create host registrations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hub_hosts (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                agent_version TEXT,
                registered_at TEXT NOT NULL,
                last_heartbeat TEXT,
                ip_address TEXT,
                status TEXT DEFAULT 'active',
                metadata TEXT,
                FOREIGN KEY (tenant_id) REFERENCES hub_tenants(id)
            );
        """)

        conn.commit()

        # Load active tenants
        cursor.execute("SELECT * FROM hub_tenants WHERE is_active = 1")
        for row in cursor.fetchall():
            self.tenants[row['id']] = dict(row)

        conn.close()

    def create_tenant(self, name, max_hosts=100, metadata=None):
        """Create a new tenant with API key."""
        tenant_id = str(uuid.uuid4())
        api_key = f"orin_hub_{secrets.token_urlsafe(32)}"
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        created_at = datetime.utcnow().isoformat() + 'Z'

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO hub_tenants (id, name, api_key_hash, created_at, max_hosts, metadata)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (tenant_id, name, api_key_hash, created_at, max_hosts,
                  json.dumps(metadata) if metadata else None))
            conn.commit()

            self.tenants[tenant_id] = {
                'id': tenant_id,
                'name': name,
                'api_key_hash': api_key_hash,
                'created_at': created_at,
                'max_hosts': max_hosts,
                'is_active': 1,
                'metadata': metadata
            }

            return tenant_id, api_key
        finally:
            conn.close()

    def validate_api_key(self, api_key):
        """Validate API key and return tenant info."""
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        for tenant_id, tenant in self.tenants.items():
            if tenant['api_key_hash'] == api_key_hash and tenant['is_active']:
                # Update last activity
                self._update_tenant_activity(tenant_id)
                return tenant

        return None

    def _update_tenant_activity(self, tenant_id):
        """Update tenant's last activity timestamp."""
        if tenant_id not in self.tenants:
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        last_activity = datetime.utcnow().isoformat() + 'Z'
        cursor.execute("""
            UPDATE hub_tenants SET last_activity = ? WHERE id = ?;
        """, (last_activity, tenant_id))
        conn.commit()
        conn.close()

        self.tenants[tenant_id]['last_activity'] = last_activity

    def register_host(self, tenant_id, hostname, agent_version=None, ip_address=None, metadata=None):
        """Register a new host under a tenant."""
        if tenant_id not in self.tenants:
            return None

        tenant = self.tenants[tenant_id]

        # Check host limit
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM hub_hosts WHERE tenant_id = ?", (tenant_id,))
        host_count = cursor.fetchone()[0]

        if host_count >= tenant['max_hosts']:
            conn.close()
            return None

        host_id = f"{tenant_id}_{hostname}_{uuid.uuid4().hex[:8]}"
        registered_at = datetime.utcnow().isoformat() + 'Z'

        try:
            cursor.execute("""
                INSERT INTO hub_hosts (id, tenant_id, hostname, agent_version,
                                      registered_at, ip_address, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (host_id, tenant_id, hostname, agent_version, registered_at,
                  ip_address, json.dumps(metadata) if metadata else None))
            conn.commit()
            return host_id
        finally:
            conn.close()

    def update_host_heartbeat(self, host_id):
        """Update host heartbeat timestamp."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        last_heartbeat = datetime.utcnow().isoformat() + 'Z'
        cursor.execute("""
            UPDATE hub_hosts SET last_heartbeat = ?, status = 'active'
            WHERE id = ?;
        """, (last_heartbeat, host_id))
        conn.commit()
        conn.close()

    def list_hosts(self, tenant_id):
        """List all hosts for a tenant."""
        if tenant_id not in self.tenants:
            return []

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM hub_hosts WHERE tenant_id = ? ORDER BY registered_at DESC;
        """, (tenant_id,))

        hosts = [dict(row) for row in cursor.fetchall()]
        conn.close()

        return hosts

    def get_tenant_stats(self, tenant_id):
        """Get statistics for a tenant."""
        if tenant_id not in self.tenants:
            return None

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                COUNT(*) as total_hosts,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_hosts,
                MAX(last_heartbeat) as last_activity
            FROM hub_hosts
            WHERE tenant_id = ?;
        """, (tenant_id,))

        stats = cursor.fetchone()
        conn.close()

        return {
            'total_hosts': stats[0],
            'active_hosts': stats[1],
            'last_activity': stats[2]
        }


class OrinHubHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Orin Hub server."""

    # Class-level database and tenant manager
    db_path = None
    tenant_manager = None
    vault_passphrase = None
    no_auth = False

    def log_message(self, format, *args):
        """Custom logging with timestamp."""
        timestamp = datetime.utcnow().isoformat() + 'Z'
        sys.stderr.write(f"[{timestamp}] {self.address_string()} - {format % args}\n")

    def _send_json_response(self, data, status=200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _send_error_response(self, message, status=400):
        """Send error response."""
        self._send_json_response({'error': message}, status)

    def _serve_dashboard(self):
        """Serve the main dashboard HTML file."""
        dashboard_path = Path(__file__).parent / 'dashboard.html'

        if not dashboard_path.exists():
            self._send_error_response("Dashboard not found", 404)
            return

        try:
            with open(dashboard_path, 'r', encoding='utf-8') as f:
                content = f.read()

            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; svg-src 'self' data:")
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        except Exception as e:
            self._send_error_response(f"Error loading dashboard: {str(e)}", 500)

    def _authenticate(self):
        """Authenticate request using API key or session token."""
        if self.no_auth:
            return True, None

        # Get API key from header
        api_key = self.headers.get('X-API-Key')
        if not api_key:
            # Try Authorization header
            auth_header = self.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                api_key = auth_header[7:]

        if not api_key:
            return False, "Missing authentication credentials"

        tenant = self.tenant_manager.validate_api_key(api_key)
        if not tenant:
            return False, "Invalid or expired API key"

        return True, tenant

    def _get_request_body(self):
        """Parse JSON request body."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}

        body = self.rfile.read(content_length)
        try:
            return json.loads(body.decode('utf-8'))
        except json.JSONDecodeError:
            return None

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization')
        self.end_headers()

    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)

        # Health check endpoint (no auth required)
        if path == '/health':
            self._send_json_response({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'version': '1.0.0'
            })
            return

        # Serve main dashboard (no auth required for landing page)
        if path == '/' or path == '/dashboard' or path == '/index.html':
            self._serve_dashboard()
            return

        # Authenticate request
        authenticated, result = self._authenticate()
        if not authenticated:
            self._send_error_response(result, 401)
            return

        tenant = result

        # Route handling
        if path == '/api/status':
            self._handle_status(tenant)
        elif path == '/api/hosts':
            self._handle_list_hosts(tenant)
        elif path == '/api/stats':
            self._handle_stats(tenant)
        elif path == '/api/vault/info':
            self._handle_vault_info(tenant)
        elif path == '/api/alerts':
            self._handle_alerts(tenant, query_params)
        elif path == '/api/diff':
            self._handle_diff(tenant, query_params)
        elif path.startswith('/api/telemetry'):
            snapshot_id = path.split('/')[-1] if path != '/api/telemetry' else None
            self._handle_telemetry(tenant, snapshot_id, query_params)
        elif path == '/api/config':
            self._handle_config(tenant)
        elif path.startswith('/api/export/'):
            self._handle_export(tenant, path.split('/')[-1])
        else:
            self._send_error_response("Unknown endpoint", 404)

    def do_POST(self):
        """Handle POST requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        # Authenticate request
        authenticated, result = self._authenticate()
        if not authenticated:
            self._send_error_response(result, 401)
            return

        tenant = result

        # Get request body
        body = self._get_request_body()
        if body is None:
            self._send_error_response("Invalid JSON body", 400)
            return

        # Route handling
        if path == '/api/register':
            self._handle_register(tenant, body)
        elif path == '/api/heartbeat':
            self._handle_heartbeat(tenant, body)
        elif path == '/api/import':
            self._handle_import(tenant, body)
        elif path == '/api/upload':
            self._handle_upload(tenant, body)
        elif path == '/api/tenants':
            self._handle_create_tenant(body)
        else:
            self._send_error_response("Unknown endpoint", 404)

    def _handle_status(self, tenant):
        """Return hub status for tenant."""
        stats = self.tenant_manager.get_tenant_stats(tenant['id'])

        self._send_json_response({
            'tenant_id': tenant['id'],
            'tenant_name': tenant['name'],
            'hub_status': 'online',
            'hosts': stats,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })

    def _handle_list_hosts(self, tenant):
        """List all registered hosts for tenant."""
        hosts = self.tenant_manager.list_hosts(tenant['id'])

        self._send_json_response({
            'hosts': hosts,
            'count': len(hosts)
        })

    def _handle_stats(self, tenant):
        """Return detailed statistics for tenant."""
        stats = self.tenant_manager.get_tenant_stats(tenant['id'])

        # Get additional metrics from vault
        vault_stats = {}
        if self.db_path and Path(self.db_path).exists():
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) FROM system_snapshots;")
                vault_stats['total_snapshots'] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM security_events;")
                vault_stats['total_events'] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM security_events WHERE resolved = 0;")
                vault_stats['unresolved_events'] = cursor.fetchone()[0]

                conn.close()
            except Exception as e:
                vault_stats['error'] = str(e)

        self._send_json_response({
            'tenant': {
                'id': tenant['id'],
                'name': tenant['name'],
                'created_at': tenant['created_at'],
                'last_activity': tenant.get('last_activity')
            },
            'hosts': stats,
            'vault': vault_stats,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })

    def _handle_vault_info(self, tenant):
        """Return vault information."""
        if not self.db_path or not Path(self.db_path).exists():
            self._send_error_response("Vault not initialized", 404)
            return

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get latest snapshot
            cursor.execute("""
                SELECT * FROM system_snapshots ORDER BY timestamp DESC LIMIT 1;
            """)
            latest_snapshot = dict(cursor.fetchone()) if cursor.fetchone else None

            # Get event summary
            cursor.execute("""
                SELECT event_type, severity, COUNT(*) as count
                FROM security_events
                GROUP BY event_type, severity;
            """)
            event_summary = [dict(row) for row in cursor.fetchall()]

            conn.close()

            self._send_json_response({
                'latest_snapshot': latest_snapshot,
                'event_summary': event_summary,
                'path': str(self.db_path)
            })
        except Exception as e:
            self._send_error_response(f"Vault error: {str(e)}", 500)

    def _handle_alerts(self, tenant, query_params):
        """Return security alerts/events from the vault."""
        if not self.db_path or not Path(self.db_path).exists():
            self._send_error_response("Vault not initialized", 404)
            return

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Build query with optional filters
            where_clauses = []
            params = []

            # Filter by severity
            severity = query_params.get('severity', [None])[0]
            if severity:
                where_clauses.append("severity = ?")
                params.append(severity)

            # Filter by event type
            event_type = query_params.get('event_type', [None])[0]
            if event_type:
                where_clauses.append("event_type = ?")
                params.append(event_type)

            # Filter by resolved status
            resolved = query_params.get('resolved', [None])[0]
            if resolved is not None:
                where_clauses.append("resolved = ?")
                params.append(1 if resolved.lower() in ('true', '1', 'yes') else 0)

            # Filter by suppressed status
            suppressed = query_params.get('suppressed', [None])[0]
            if suppressed is not None:
                where_clauses.append("suppressed = ?")
                params.append(1 if suppressed.lower() in ('true', '1', 'yes') else 0)

            # Filter by hostname
            hostname = query_params.get('hostname', [None])[0]
            if hostname:
                where_clauses.append("hostname = ?")
                params.append(hostname)

            # Limit results
            limit = min(int(query_params.get('limit', [100])[0]), 1000)

            where_sql = ""
            if where_clauses:
                where_sql = "WHERE " + " AND ".join(where_clauses)

            cursor.execute(f"""
                SELECT id, timestamp, event_type, severity, description,
                       raw_details, notes, suppressed, resolved,
                       attck_technique, attck_tactic, attck_url, hostname
                FROM security_events
                {where_sql}
                ORDER BY timestamp DESC
                LIMIT ?;
            """, params + [limit])

            alerts = [dict(row) for row in cursor.fetchall()]

            # Get summary counts
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM security_events
                WHERE resolved = 0
                GROUP BY severity;
            """)
            severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}

            conn.close()

            self._send_json_response({
                'alerts': alerts,
                'count': len(alerts),
                'severity_counts': severity_counts,
                'filters_applied': {
                    'severity': severity,
                    'event_type': event_type,
                    'resolved': resolved,
                    'suppressed': suppressed,
                    'hostname': hostname
                }
            })
        except Exception as e:
            self._send_error_response(f"Alerts error: {str(e)}", 500)

    def _handle_diff(self, tenant, query_params):
        """Perform diff analysis between snapshots or against baseline."""
        if not self.db_path or not Path(self.db_path).exists():
            self._send_error_response("Vault not initialized", 404)
            return

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            snapshot_id = query_params.get('snapshot_id', [None])[0]
            baseline_type = query_params.get('baseline_type', ['all'])[0]

            if not snapshot_id:
                # Get latest snapshot
                cursor.execute("SELECT id FROM system_snapshots ORDER BY timestamp DESC LIMIT 1;")
                row = cursor.fetchone()
                if not row:
                    self._send_error_response("No snapshots found", 404)
                    return
                snapshot_id = row['id']

            diffs = {
                'processes': [],
                'kernel_modules': [],
                'users': [],
                'suid_binaries': [],
                'listening_ports': []
            }

            # Compare processes against baseline
            if baseline_type in ('all', 'processes'):
                cursor.execute("""
                    SELECT cp.pid, cp.name, cp.cmdline, cp.exe
                    FROM collected_processes cp
                    WHERE cp.snapshot_id = ?
                    AND NOT EXISTS (
                        SELECT 1 FROM baseline_processes bp
                        WHERE bp.hostname = (SELECT hostname FROM system_snapshots WHERE id = ?)
                        AND bp.name = cp.name
                    );
                """, (snapshot_id, snapshot_id))
                diffs['processes'] = [dict(row) for row in cursor.fetchall()]

            # Compare kernel modules against baseline
            if baseline_type in ('all', 'kernel'):
                cursor.execute("""
                    SELECT ckm.module_name, ckm.memory_size, ckm.holders
                    FROM collected_kernel_modules ckm
                    WHERE ckm.snapshot_id = ?
                    AND NOT EXISTS (
                        SELECT 1 FROM baseline_kernel_modules bkm
                        WHERE bkm.hostname = (SELECT hostname FROM system_snapshots WHERE id = ?)
                        AND bkm.module_name = ckm.module_name
                    );
                """, (snapshot_id, snapshot_id))
                diffs['kernel_modules'] = [dict(row) for row in cursor.fetchall()]

            # Compare users against baseline
            if baseline_type in ('all', 'users'):
                cursor.execute("""
                    SELECT cu.username, cu.uid, cu.gid, cu.home_dir, cu.login_shell
                    FROM collected_users cu
                    WHERE cu.snapshot_id = ?
                    AND NOT EXISTS (
                        SELECT 1 FROM baseline_users bu
                        WHERE bu.hostname = (SELECT hostname FROM system_snapshots WHERE id = ?)
                        AND bu.username = cu.username
                    );
                """, (snapshot_id, snapshot_id))
                diffs['users'] = [dict(row) for row in cursor.fetchall()]

            # Compare SUID binaries against baseline
            if baseline_type in ('all', 'suid'):
                cursor.execute("""
                    SELECT csb.file_path, csb.owner, csb.grp, csb.permissions, csb.sha256
                    FROM collected_suid_binaries csb
                    WHERE csb.snapshot_id = ?
                    AND NOT EXISTS (
                        SELECT 1 FROM baseline_suid_binaries bsb
                        WHERE bsb.hostname = (SELECT hostname FROM system_snapshots WHERE id = ?)
                        AND bsb.file_path = csb.file_path
                    );
                """, (snapshot_id, snapshot_id))
                diffs['suid_binaries'] = [dict(row) for row in cursor.fetchall()]

            # Compare listening ports against baseline
            if baseline_type in ('all', 'ports'):
                cursor.execute("""
                    SELECT cp.port, cp.protocol, cp.process_name
                    FROM collected_ports cp
                    WHERE cp.snapshot_id = ?
                    AND NOT EXISTS (
                        SELECT 1 FROM baseline_listening_ports blp
                        WHERE blp.hostname = (SELECT hostname FROM system_snapshots WHERE id = ?)
                        AND blp.port = cp.port
                        AND blp.protocol = cp.protocol
                    );
                """, (snapshot_id, snapshot_id))
                diffs['listening_ports'] = [dict(row) for row in cursor.fetchall()]

            conn.close()

            # Calculate risk score based on findings
            risk_score = 0
            risk_score += len(diffs['processes']) * 10
            risk_score += len(diffs['kernel_modules']) * 15
            risk_score += len(diffs['users']) * 20
            risk_score += len(diffs['suid_binaries']) * 12
            risk_score += len(diffs['listening_ports']) * 8
            risk_score = min(risk_score, 100)

            self._send_json_response({
                'snapshot_id': snapshot_id,
                'baseline_type': baseline_type,
                'diffs': diffs,
                'risk_score': risk_score,
                'summary': {
                    'new_processes': len(diffs['processes']),
                    'new_kernel_modules': len(diffs['kernel_modules']),
                    'new_users': len(diffs['users']),
                    'new_suid_binaries': len(diffs['suid_binaries']),
                    'new_listening_ports': len(diffs['listening_ports'])
                }
            })
        except Exception as e:
            self._send_error_response(f"Diff analysis error: {str(e)}", 500)

    def _handle_telemetry(self, tenant, snapshot_id, query_params):
        """Return telemetry data for a specific snapshot."""
        if not self.db_path or not Path(self.db_path).exists():
            self._send_error_response("Vault not initialized", 404)
            return

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # If no snapshot_id provided, get latest
            if not snapshot_id or snapshot_id == 'latest':
                cursor.execute("SELECT id FROM system_snapshots ORDER BY timestamp DESC LIMIT 1;")
                row = cursor.fetchone()
                if not row:
                    self._send_error_response("No snapshots found", 404)
                    return
                snapshot_id = row['id']
            else:
                snapshot_id = int(snapshot_id)

            # Get snapshot metadata
            cursor.execute("SELECT * FROM system_snapshots WHERE id = ?;", (snapshot_id,))
            snapshot = dict(cursor.fetchone()) if cursor.fetchone else None

            if not snapshot:
                self._send_error_response("Snapshot not found", 404)
                return

            # Determine which telemetry type to return
            telemetry_type = query_params.get('type', ['summary'])[0]
            limit = min(int(query_params.get('limit', [100])[0]), 1000)

            telemetry_data = {}

            if telemetry_type in ('summary', 'all', 'processes'):
                cursor.execute("""
                    SELECT pid, ppid, name, exe, cmdline, ancestry_path
                    FROM collected_processes
                    WHERE snapshot_id = ?
                    LIMIT ?;
                """, (snapshot_id, limit))
                telemetry_data['processes'] = [dict(row) for row in cursor.fetchall()]

            if telemetry_type in ('summary', 'all', 'ports'):
                cursor.execute("""
                    SELECT port, protocol, process_name, address
                    FROM collected_ports
                    WHERE snapshot_id = ?
                    LIMIT ?;
                """, (snapshot_id, limit))
                telemetry_data['listening_ports'] = [dict(row) for row in cursor.fetchall()]

            if telemetry_type in ('summary', 'all', 'connections'):
                cursor.execute("""
                    SELECT local_address, local_port, remote_address, remote_port,
                           protocol, state, process_name, pid
                    FROM collected_outbound_connections
                    WHERE snapshot_id = ?
                    LIMIT ?;
                """, (snapshot_id, limit))
                telemetry_data['outbound_connections'] = [dict(row) for row in cursor.fetchall()]

            if telemetry_type in ('summary', 'all', 'kernel_modules'):
                cursor.execute("""
                    SELECT module_name, memory_size, holders
                    FROM collected_kernel_modules
                    WHERE snapshot_id = ?
                    LIMIT ?;
                """, (snapshot_id, limit))
                telemetry_data['kernel_modules'] = [dict(row) for row in cursor.fetchall()]

            if telemetry_type in ('summary', 'all', 'users'):
                cursor.execute("""
                    SELECT username, uid, gid, home_dir, login_shell
                    FROM collected_users
                    WHERE snapshot_id = ?
                    LIMIT ?;
                """, (snapshot_id, limit))
                telemetry_data['users'] = [dict(row) for row in cursor.fetchall()]

            if telemetry_type in ('summary', 'all', 'ebpf'):
                cursor.execute("""
                    SELECT program_id, program_type, tag, loaded_at
                    FROM collected_ebpf_programs
                    WHERE snapshot_id = ?
                    LIMIT ?;
                """, (snapshot_id, limit))
                telemetry_data['ebpf_programs'] = [dict(row) for row in cursor.fetchall()]

            conn.close()

            self._send_json_response({
                'snapshot': snapshot,
                'telemetry_type': telemetry_type,
                'data': telemetry_data,
                'counts': {k: len(v) for k, v in telemetry_data.items()}
            })
        except Exception as e:
            self._send_error_response(f"Telemetry error: {str(e)}", 500)

    def _handle_config(self, tenant):
        """Return or update configuration settings."""
        if not self.db_path or not Path(self.db_path).exists():
            self._send_error_response("Vault not initialized", 404)
            return

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Create config table if not exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
            """)

            # Get all config
            cursor.execute("SELECT key, value FROM config;")
            config = {row['key']: row['value'] for row in cursor.fetchall()}

            conn.close()

            # Return default config merged with stored config
            default_config = {
                'retention_days': '30',
                'collection_interval': '300',
                'alert_on_new_process': 'true',
                'alert_on_new_kernel_module': 'true',
                'alert_on_new_user': 'true',
                'alert_on_privilege_escalation': 'true',
                'max_snapshots': '100',
                'enable_ebpf_monitoring': 'false',
                'log_level': 'INFO'
            }

            # Merge defaults with stored config
            final_config = {**default_config, **config}

            self._send_json_response({
                'config': final_config,
                'source': 'merged_defaults_and_stored'
            })
        except Exception as e:
            self._send_error_response(f"Config error: {str(e)}", 500)

    def _handle_register(self, tenant, body):
        """Register a new host."""
        hostname = body.get('hostname')
        agent_version = body.get('agent_version')
        ip_address = body.get('ip_address', self.client_address[0])
        metadata = body.get('metadata')

        if not hostname:
            self._send_error_response("Missing hostname", 400)
            return

        host_id = self.tenant_manager.register_host(
            tenant['id'],
            hostname,
            agent_version,
            ip_address,
            metadata
        )

        if not host_id:
            self._send_error_response("Registration failed (host limit reached?)", 400)
            return

        self._send_json_response({
            'status': 'success',
            'host_id': host_id,
            'tenant_id': tenant['id'],
            'message': 'Host registered successfully'
        })

    def _handle_heartbeat(self, tenant, body):
        """Update host heartbeat."""
        host_id = body.get('host_id')

        if not host_id:
            self._send_error_response("Missing host_id", 400)
            return

        self.tenant_manager.update_host_heartbeat(host_id)

        self._send_json_response({
            'status': 'success',
            'message': 'Heartbeat recorded'
        })

    def _handle_import(self, tenant, body):
        """Import forensic data from air-gapped source."""
        import_type = body.get('type')
        data = body.get('data')
        host_id = body.get('host_id')

        if not import_type or not data:
            self._send_error_response("Missing type or data", 400)
            return

        # Validate and process imported data
        try:
            if import_type == 'snapshot':
                # Process snapshot import
                self._process_snapshot_import(tenant, data, host_id)
            elif import_type == 'events':
                # Process security events import
                self._process_events_import(tenant, data, host_id)
            elif import_type == 'baseline':
                # Process baseline import
                self._process_baseline_import(tenant, data, host_id)
            else:
                self._send_error_response(f"Unknown import type: {import_type}", 400)
                return

            self._send_json_response({
                'status': 'success',
                'message': f'{import_type} imported successfully'
            })
        except Exception as e:
            self._send_error_response(f"Import failed: {str(e)}", 500)

    def _process_snapshot_import(self, tenant, data, host_id):
        """Process snapshot data import."""
        if not self.db_path:
            raise Exception("Vault not initialized")

        storage = OrinStorage(self.db_path)

        with storage.get_connection() as conn:
            # Create snapshot record
            snapshot_id = storage.create_snapshot(conn)

            # Store processes
            if 'processes' in data:
                storage.store_processes(conn, snapshot_id, data['processes'])

            # Store ports
            if 'ports' in data:
                storage.store_ports(conn, snapshot_id, data['ports'])

            # Store kernel modules
            if 'kernel_modules' in data:
                storage.store_kernel_modules(conn, snapshot_id, data['kernel_modules'])

            # Store users
            if 'users' in data:
                storage.store_users(conn, snapshot_id, data['users'])

            # Store security events
            if 'security_events' in data:
                storage.store_privilege_events(conn, snapshot_id, data['security_events'])

            conn.commit()

    def _process_events_import(self, tenant, data, host_id):
        """Process security events import."""
        if not self.db_path:
            raise Exception("Vault not initialized")

        storage = OrinStorage(self.db_path)

        with storage.get_connection() as conn:
            for event in data:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO security_events
                    (timestamp, event_type, severity, description, raw_details, resolved)
                    VALUES (?, ?, ?, ?, ?, 0);
                """, (
                    event.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
                    event.get('event_type'),
                    event.get('severity', 'medium'),
                    event.get('description'),
                    json.dumps(event.get('raw_details', {}))
                ))

            conn.commit()

    def _process_baseline_import(self, tenant, data, host_id):
        """Process baseline data import."""
        if not self.db_path:
            raise Exception("Vault not initialized")

        storage = OrinStorage(self.db_path)
        hostname = data.get('hostname', 'unknown')

        with storage.get_connection() as conn:
            # Store baseline kernel modules
            if 'kernel_modules' in data:
                conn.executemany(
                    "INSERT OR IGNORE INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES (?, ?, ?);",
                    [(hostname, m.get('module_name'), m.get('memory_size'))
                     for m in data['kernel_modules']]
                )

            # Store baseline users
            if 'users' in data:
                conn.executemany(
                    """INSERT OR IGNORE INTO baseline_users
                       (hostname, username, uid, gid, home_dir, login_shell)
                       VALUES (?, ?, ?, ?, ?, ?);""",
                    [(hostname, u.get('username'), u.get('uid'), u.get('gid'),
                      u.get('home_dir'), u.get('login_shell'))
                     for u in data['users']]
                )

            conn.commit()

    def _handle_upload(self, tenant, body):
        """Handle file upload for bulk import."""
        # This would handle multipart file uploads
        # For now, return placeholder
        self._send_json_response({
            'status': 'success',
            'message': 'Upload endpoint ready (implement multipart handling)'
        })

    def _handle_create_tenant(self, body):
        """Create a new tenant (admin only)."""
        # In production, add admin authentication here
        name = body.get('name')
        max_hosts = body.get('max_hosts', 100)
        metadata = body.get('metadata')

        if not name:
            self._send_error_response("Missing tenant name", 400)
            return

        tenant_id, api_key = self.tenant_manager.create_tenant(name, max_hosts, metadata)

        self._send_json_response({
            'status': 'success',
            'tenant_id': tenant_id,
            'api_key': api_key,
            'warning': 'Store this API key securely - it cannot be retrieved later'
        })

    def _handle_export(self, tenant, export_type):
        """Export data for air-gapped transfer."""
        if not self.db_path or not Path(self.db_path).exists():
            self._send_error_response("Vault not initialized", 404)
            return

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            export_data = {}

            if export_type == 'snapshot':
                # Export latest snapshot
                cursor.execute("""
                    SELECT * FROM system_snapshots ORDER BY timestamp DESC LIMIT 1;
                """)
                snapshot = dict(cursor.fetchone()) if cursor.fetchone else None

                if snapshot:
                    snapshot_id = snapshot['id']

                    cursor.execute("SELECT * FROM processes WHERE snapshot_id = ?", (snapshot_id,))
                    export_data['processes'] = [dict(row) for row in cursor.fetchall()]

                    cursor.execute("SELECT * FROM listening_ports WHERE snapshot_id = ?", (snapshot_id,))
                    export_data['ports'] = [dict(row) for row in cursor.fetchall()]

                    cursor.execute("SELECT * FROM kernel_modules WHERE snapshot_id = ?", (snapshot_id,))
                    export_data['kernel_modules'] = [dict(row) for row in cursor.fetchall()]

                export_data['snapshot'] = snapshot

            elif export_type == 'events':
                # Export security events
                cursor.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 1000;")
                export_data['events'] = [dict(row) for row in cursor.fetchall()]

            elif export_type == 'full':
                # Full export (careful with size)
                export_data['export_timestamp'] = datetime.utcnow().isoformat() + 'Z'
                export_data['warning'] = 'Full export may be very large'
                # Add selective tables as needed

            conn.close()

            self._send_json_response({
                'status': 'success',
                'type': export_type,
                'data': export_data
            })
        except Exception as e:
            self._send_error_response(f"Export failed: {str(e)}", 500)


def start_server(db_path=None, host='0.0.0.0', port=8000, username=None,
                 password=None, cert_path=None, key_path=None, no_auth=False,
                 passphrase_file=None, passphrase_prompt=False,
                 passphrase_env_var=None, token_file=None):
    """Start the Orin Hub HTTP server."""

    # Initialize database path
    if db_path is None:
        db_path = Path.home() / '.orin' / 'orin.db'
    else:
        db_path = Path(db_path)

    # Ensure database directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Initialize tenant manager
    tenant_manager = TenantManager(db_path)

    # Configure HTTP server
    OrinHubHTTPHandler.db_path = db_path
    OrinHubHTTPHandler.tenant_manager = tenant_manager
    OrinHubHTTPHandler.no_auth = no_auth

    # Handle vault passphrase
    if passphrase_file:
        with open(passphrase_file, 'r') as f:
            OrinHubHTTPHandler.vault_passphrase = f.read().strip()
    elif passphrase_env_var:
        OrinHubHTTPHandler.vault_passphrase = os.environ.get(passphrase_env_var, '')
    elif passphrase_prompt:
        import getpass
        OrinHubHTTPHandler.vault_passphrase = getpass.getpass('Enter vault passphrase: ')

    # Create HTTP server
    httpd = HTTPServer((host, port), OrinHubHTTPHandler)

    # Setup SSL if certificates provided
    if cert_path and key_path:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        protocol = 'HTTPS'
    else:
        protocol = 'HTTP'

    print(f"[*] Orin Hub Server starting on {host}:{port} ({protocol})")
    print(f"[*] Database vault: {db_path}")
    print(f"[*] Multi-tenant mode: {'Enabled' if not no_auth else 'Disabled (no-auth)'}")
    print(f"[*] Press Ctrl+C to stop")

    # Start server
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Orin Hub Server...")
        httpd.shutdown()
        httpd.server_close()
        print("[*] Server stopped")


# Export for imports
__all__ = ['start_server', 'OrinHubHTTPHandler', 'TenantManager']