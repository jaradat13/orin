# orin/collectors/kernel.py
"""
orin.collectors.kernel – Linux Kernel Module Harvester
======================================================
Reads ``/proc/modules`` to enumerate every Loadable Kernel Module (LKM)
currently active in the kernel address space.

The analysis engine uses this data in two ways:

1. At ``orin init`` time, the snapshot is stored as an approved baseline in
   ``baseline_kernel_modules``.
2. At subsequent ``orin analyze`` runs, newly appearing modules that are
   absent from the baseline are flagged as untrusted LKMs.
"""
from pathlib import Path

#: Path to the Linux kernel module status file.
MODULES_PATH = Path("/proc/modules")


def gather_loaded_kernel_modules() -> list[dict]:
    """Parse ``/proc/modules`` and return all currently loaded kernel modules.

    Each line in ``/proc/modules`` follows the format::

        <name> <memory_size> <instances_loaded> <dependencies> <state> <offset>

    Only the first three whitespace-delimited fields are captured.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``module_name``       (str) – kernel module identifier.
        - ``memory_size``       (int) – memory footprint of the module in bytes.
        - ``instances_loaded``  (int) – number of loaded instances / use-count.

    Notes
    -----
    Returns an empty list when ``/proc/modules`` is absent (e.g. non-Linux
    environments or containers that hide the pseudo-filesystem).
    """
    modules_list = []
    if not MODULES_PATH.exists():
        return modules_list

    try:
        with open(MODULES_PATH, "r", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                parts = line.strip().split()
                if not parts:
                    continue
                    
                if len(parts) < 3:
                    modules_list.append({
                        "module_name": f"ERROR_LINE_{line_num}",
                        "memory_size": 0,
                        "instances_loaded": 0,
                        "anomaly_detected": 1,
                        "anomaly_reason": f"Malformed kernel module line layout (expected >= 3 fields, got {len(parts)})"
                    })
                    continue
                
                # Real-world defense: Isolate row casting to prevent an anti-forensic string insertion
                # from crashing the remaining data-gathering iterator loop.
                try:
                    modules_list.append({
                        "module_name": parts[0],
                        "memory_size": int(parts[1]),
                        "instances_loaded": int(parts[2])
                    })
                except ValueError as cast_error:
                    modules_list.append({
                        "module_name": f"ERROR_INVALID_CAST_{parts[0]}",
                        "memory_size": 0,
                        "instances_loaded": 0,
                        "anomaly_detected": 1,
                        "anomaly_reason": f"Type validation fault on row {line_num}: {cast_error}"
                    })
                    continue
                    
    except (PermissionError, OSError) as io_error:
        modules_list.append({
            "module_name": "ERROR_PROC_MODULES_IO_FAULT",
            "memory_size": 0,
            "instances_loaded": 0,
            "anomaly_detected": 1,
            "anomaly_reason": f"Failed to access virtual filesystem descriptor node: {io_error}"
        })

    return modules_list
    