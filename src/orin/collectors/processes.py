# orin/collectors/processes.py
"""
orin.collectors.processes – Running Process Tree Harvester
=========================================================
Crawls the Linux ``/proc`` virtual filesystem to build a snapshot of every
currently running process, including parent-child relationships.

Data sources per process
------------------------
/proc/[pid]/stat    – parent PID (PPID).
/proc/[pid]/comm    – short process name (up to 15 chars).
/proc/[pid]/exe     – symlink to the executable image on disk.
/proc/[pid]/cmdline – full command line with arguments (NUL-separated).
"""
import os
from pathlib import Path


def gather_active_processes() -> list[dict]:
    """Crawl ``/proc`` and return a structured record for every running process.

    Iterates every numeric subdirectory of ``/proc`` (one per PID) and
    extracts process metadata from the pseudo-files within.  The PPID is
    parsed robustly from ``/proc/[pid]/stat`` by locating the last closing
    parenthesis in the line so that process names containing spaces or
    parentheses are handled correctly.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``pid``     (int) – process identifier.
        - ``ppid``    (int) – parent process identifier.
        - ``name``    (str) – short comm name from ``/proc/[pid]/comm``.
        - ``exe``     (str) – absolute path to the executable, or
          ``"unknown"`` if the symlink cannot be resolved.
        - ``cmdline`` (str) – full command line string; falls back to ``name``
          when ``/proc/[pid]/cmdline`` is empty.

    Notes
    -----
    Kernel threads typically appear with ``exe = "unknown"`` and an empty
    ``cmdline``; they are still included in the output because the analysis
    engine uses them for ancestry-validation checks.
    
    Processes that disappear between the directory scan and the file reads
    (race condition) are silently skipped via broad exception handling.
    """
    process_list = []
    proc_path = Path("/proc")
    
    if not proc_path.exists():
        return process_list

    for pid_dir in proc_path.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue
            
        pid = int(pid_dir.name)
        
        try:
            # 1. Parse PPID out of /proc/[pid]/stat safely
            # Format: pid (name) state ppid ...
            stat_content = (pid_dir / "stat").read_text().strip()
            # Handle cases where process name has spaces or parentheses, locate last close parenthesis
            r_paren_index = stat_content.rfind(")")
            after_name = stat_content[r_paren_index + 2:].split()
            ppid = int(after_name[1]) # The fourth field in stat (index 1 after process name field)

            # 2. Extract Process Comm/Name
            name = (pid_dir / "comm").read_text().strip()

            # 3. Resolve executable path link
            try:
                exe = os.readlink(str(pid_dir / "exe"))
            except (FileNotFoundError, PermissionError):
                exe = "unknown"

            # 4. Extract runtime Command-Line parameters
            cmdline_raw = (pid_dir / "cmdline").read_text()
            cmdline = " ".join(cmdline_raw.split("\x00")).strip() if cmdline_raw else name

            process_list.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "exe": exe,
                "cmdline": cmdline
            })
        except (FileNotFoundError, PermissionError, IndexError, ValueError):
            continue

    return process_list