# src/orin/collectors/promisc.py
"""
orin.collectors.promisc – Promiscuous Mode Interface Flag Monitor
================================================================
Monitors network interfaces to verify if any are operating in promiscuous mode
by checking kernel device flags from the virtual /sys filesystem.
"""
from pathlib import Path

def gather_promisc_interfaces() -> list[dict]:
    """Inspect network interfaces and check if promiscuous mode is enabled.

    Returns
    -------
    list[dict]
        Each dict contains:
        - interface (str): network interface name (e.g. eth0).
        - flags (str): hexadecimal representation of active interface flags.
        - is_promiscuous (int): 1 if IFF_PROMISC is active, 0 otherwise.
    """
    interfaces = []
    net_path = Path("/sys/class/net")
    if not net_path.exists():
        return interfaces

    for iface_dir in net_path.iterdir():
        if not iface_dir.is_dir():
            continue

        interface_name = iface_dir.name
        flags_file = iface_dir / "flags"

        if not flags_file.exists():
            continue

        try:
            content = flags_file.read_text().strip()
            # Handle potential hex prefixes (e.g., 0x1003)
            flags = int(content, 16)
            is_promiscuous = 1 if (flags & 0x100) != 0 else 0
            
            interfaces.append({
                "interface": interface_name,
                "flags": content,
                "is_promiscuous": is_promiscuous
            })
        except (ValueError, OSError, PermissionError):
            continue

    return interfaces
