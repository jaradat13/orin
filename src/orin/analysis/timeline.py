# orin/analysis/timeline.py
from pathlib import Path
from orin.core.database import OrinStorage

def calculate_snapshot_delta(db_path: Path, base_id: int, target_id: int) -> dict:
    """Computes systemic differences and captures intermediate security alerts."""
    storage = OrinStorage(db_path)
    delta_report = {
        "base_id": base_id,
        "target_id": target_id,
        "new_ports": [],
        "new_processes": [],
        "new_connections": [],
        "triggered_alerts": []
    }

    with storage.get_connection() as conn:
        cursor = conn.cursor()

        # 0. Extract Snapshot timestamps to isolate intermediate events
        cursor.execute("SELECT timestamp FROM system_snapshots WHERE id = ?;", (base_id,))
        base_row = cursor.fetchone()
        cursor.execute("SELECT timestamp FROM system_snapshots WHERE id = ?;", (target_id,))
        target_row = cursor.fetchone()
        
        if base_row and target_row:
            cursor.execute(
                """
                SELECT timestamp, event_type, severity, description FROM security_events
                WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC;
                """,
                (base_row["timestamp"], target_row["timestamp"])
            )
            for r in cursor.fetchall():
                delta_report["triggered_alerts"].append({
                    "timestamp": r["timestamp"], "type": r["event_type"],
                    "severity": r["severity"], "description": r["description"]
                })

        # 1. Evaluate Port Deltas
        cursor.execute("SELECT port, protocol FROM collected_ports WHERE snapshot_id = ?;", (base_id,))
        base_ports = {(r["port"], r["protocol"]) for r in cursor.fetchall()}
        cursor.execute("SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;", (target_id,))
        target_ports = {(r["port"], r["protocol"]): r for r in cursor.fetchall()}
        
        for port_key in (target_ports.keys() - base_ports):
            row = target_ports[port_key]
            delta_report["new_ports"].append({"port": row["port"], "protocol": row["protocol"], "process": row["process_name"]})

        # 2. Evaluate Process Deltas
        cursor.execute("SELECT name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;", (base_id,))
        base_procs = {(r["name"], r["exe"], r["cmdline"]) for r in cursor.fetchall()}
        cursor.execute("SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;", (target_id,))
        for r in cursor.fetchall():
            if (r["name"], r["exe"], r["cmdline"]) not in base_procs:
                delta_report["new_processes"].append({
                    "pid": r["pid"], "ppid": r["ppid"], "name": r["name"], "exe": r["exe"], "cmdline": r["cmdline"]
                })

        # 3. Evaluate Outbound Connection Deltas
        cursor.execute("SELECT remote_ip, remote_port FROM collected_outbound_connections WHERE snapshot_id = ?;", (base_id,))
        base_conns = {(r["remote_ip"], r["remote_port"]) for r in cursor.fetchall()}
        cursor.execute("SELECT remote_ip, remote_port, local_port, state FROM collected_outbound_connections WHERE snapshot_id = ?;", (target_id,))
        for r in cursor.fetchall():
            if (r["remote_ip"], r["remote_port"]) not in base_conns:
                delta_report["new_connections"].append({
                    "remote_ip": r["remote_ip"], "remote_port": r["remote_port"], "local_port": r["local_port"], "state": r["state"]
                })

    return delta_report