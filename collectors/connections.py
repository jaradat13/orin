# Listening sockets tracking interface logic
# orin/collectors/connections.py
import psutil

def gather_listening_ports() -> list[dict]:
    """Retrieves all active listening network ports with strict interface deduplication."""
    ports_data = []
    seen_ports = set()

    try:
        connections = psutil.net_connections(kind="inet")
    except Exception:
        return []

    for conn in connections:
        if conn.status != "LISTEN":
            continue
        
        port = conn.laddr.port
        if port in seen_ports:
            continue
        seen_ports.add(port)

        # Determine protocol type string safely
        protocol = "TCP" if conn.type == 1 else "UDP"

        try:
            proc_name = psutil.Process(conn.pid).name() if conn.pid else "unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc_name = "unknown"

        ports_data.append({
            "port": port,
            "protocol": protocol,
            "process_name": proc_name
        })
    return ports_data

# orin/collectors/connections.py
from pathlib import Path

def parse_proc_net_line(line: str) -> dict | None:
    """Helper to convert hexadecimal /proc/net arrays into standard networking elements."""
    parts = line.strip().split()
    if len(parts) < 4 or parts[0].startswith("local_address"):
        return None
        
    try:
        local_hex, local_port_hex = parts[1].split(":")
        remote_hex, remote_port_hex = parts[2].split(":")
        state_hex = parts[3]
        
        # Parse Little Endian hex values
        local_ip = ".".join(str(int(local_hex[i:i+2], 16)) for i in range(6, -1, -2))
        remote_ip = ".".join(str(int(remote_hex[i:i+2], 16)) for i in range(6, -1, -2))
        
        local_port = int(local_port_hex, 16)
        remote_port = int(remote_port_hex, 16)
        
        return {
            "local_ip": local_ip, "local_port": local_port,
            "remote_ip": remote_ip, "remote_port": remote_port,
            "state": state_hex
        }
    except (ValueError, IndexError):
        return None

def gather_listening_ports() -> list[dict]:
    """Harvests open sockets bound in listening states."""
    ports = []
    proc_tcp = Path("/proc/net/tcp")
    if not proc_tcp.exists():
        return ports
        
    with open(proc_tcp, "r") as f:
        for line in f:
            data = parse_proc_net_line(line)
            if data and data["state"] == "0A":  # TCP_LISTEN state
                ports.append({"port": data["local_port"], "protocol": "TCP", "process_name": "unknown"})
    return ports

def gather_outbound_connections() -> list[dict]:
    """Harvests active outbound connections targeting remote interfaces."""
    connections = []
    proc_tcp = Path("/proc/net/tcp")
    if not proc_tcp.exists():
        return connections
        
    with open(proc_tcp, "r") as f:
        for line in f:
            data = parse_proc_net_line(line)
            # Filter for ESTABLISHED connections (01) that are not targeting local loopbacks
            if data and data["state"] == "01" and data["remote_ip"] != "0.0.0.0" and not data["remote_ip"].startswith("127."):
                connections.append({
                    "local_ip": data["local_ip"],
                    "local_port": data["local_port"],
                    "remote_ip": data["remote_ip"],
                    "remote_port": data["remote_port"],
                    "state": "ESTABLISHED",
                    "process_name": "unknown"
                })
    return connections