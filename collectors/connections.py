# orin/collectors/connections.py
import os
import struct
import socket
from pathlib import Path

PROC_PATH = Path("/proc")

def _get_socket_inode_map() -> dict[str, str]:
    """Scans /proc/[pid]/fd/ to bind socket inodes back to process execution names."""
    inode_to_process = {}
    if not PROC_PATH.exists():
        return inode_to_process

    for pid_dir in PROC_PATH.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue
        
        pid = pid_dir.name
        fd_dir = pid_dir / "fd"
        if not fd_dir.exists():
            continue

        # Extract friendly process string name from the command execution file
        comm_path = pid_dir / "comm"
        process_name = "unknown"
        if comm_path.exists():
            try:
                process_name = comm_path.read_text().strip()
            except (PermissionError, FileNotFoundError):
                pass

        try:
            for fd_link in fd_dir.iterdir():
                try:
                    target = os.readlink(fd_link)
                    # Sockets show up as text descriptors like 'socket:[123456]'
                    if target.startswith("socket:["):
                        inode = target.split("[")[1].split("]")[0]
                        inode_to_process[inode] = f"{process_name} (PID: {pid})"
                except (PermissionError, FileNotFoundError):
                    continue
        except (PermissionError, FileNotFoundError):
            continue

    return inode_to_process

def _parse_hex_endpoint(hex_str: str) -> tuple[str, int]:
    """Translates raw /proc network byte arrays into human-readable IP and Port notation."""
    try:
        ip_hex, port_hex = hex_str.split(":")
        port = int(port_hex, 16)
        ip_bytes = struct.pack("<I", int(ip_hex, 16))
        ip = socket.inet_ntoa(ip_bytes)
        return ip, port
    except (ValueError, struct.error, socket.error):
        return "0.0.0.0", 0

def gather_listening_ports() -> list[dict]:
    """Parses /proc/net/tcp and binds open ports to true process owners."""
    ports_list = []
    tcp_proc = Path("/proc/net/tcp")
    if not tcp_proc.exists():
        return ports_list

    # Map current active system sockets to runtime processes
    inode_map = _get_socket_inode_map()

    try:
        with open(tcp_proc, "r") as f:
            lines = f.readlines()
            
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 10:
                continue
            
            state = parts[3]
            if state == "0A":  # TCP_LISTEN
                local_ip, local_port = _parse_hex_endpoint(parts[1])
                inode = parts[9]
                resolved_process = inode_map.get(inode, "unknown")
                
                if local_port not in [p["port"] for p in ports_list]:
                    ports_list.append({
                        "port": local_port,
                        "protocol": "TCP",
                        "process_name": resolved_process
                    })
    except (FileNotFoundError, PermissionError):
        pass

    return ports_list

def gather_outbound_connections() -> list[dict]:
    """Parses /proc/net/tcp and maps active connections back to process owners."""
    connections = []
    tcp_proc = Path("/proc/net/tcp")
    if not tcp_proc.exists():
        return connections

    inode_map = _get_socket_inode_map()

    try:
        with open(tcp_proc, "r") as f:
            lines = f.readlines()

        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 10:
                continue
            
            state = parts[3]
            if state == "01":  # TCP_ESTABLISHED
                local_ip, local_port = _parse_hex_endpoint(parts[1])
                remote_ip, remote_port = _parse_hex_endpoint(parts[2])
                inode = parts[9]
                resolved_process = inode_map.get(inode, "unknown")
                
                if remote_ip == "127.0.0.1":
                    continue
                    
                connections.append({
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": "ESTABLISHED",
                    "process_name": resolved_process
                })
    except (FileNotFoundError, PermissionError):
        pass

    return connections