# orin/collectors/kernel.py
from pathlib import Path

MODULES_PATH = Path("/proc/modules")

def gather_loaded_kernel_modules() -> list[dict]:
    """Parses /proc/modules to harvest kernel execution signatures offline."""
    modules_list = []
    if not MODULES_PATH.exists():
        return modules_list

    try:
        with open(MODULES_PATH, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                
                # Format layout: name size instances_loaded ...
                modules_list.append({
                    "module_name": parts[0],
                    "memory_size": int(parts[1]),
                    "instances_loaded": int(parts[2])
                })
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    return modules_list