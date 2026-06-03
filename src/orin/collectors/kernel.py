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