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
import errno
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
          ``"unknown"`` / error tag if restricted.
        - ``cmdline`` (str) – full command line string; falls back to ``name``.
    """
    process_list = []
    proc_path = Path("/proc")
    
    if not proc_path.exists():
        return process_list

    for pid_dir in proc_path.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue
            
        pid = int(pid_dir.name)
        
        # Initialize fallback variables to ensure partial capture on permission restrictions
        ppid = -1
        name = "unknown"
        exe = "unknown"
        cmdline = ""
        
        try:
            # 1. Parse PPID out of /proc/[pid]/stat safely
            stat_path = pid_dir / "stat"
            try:
                # Real-world defense: Enforce errors="replace" to neutralize anti-forensic encoding attacks
                with open(stat_path, "r", encoding="utf-8", errors="replace") as f:
                    stat_content = f.read().strip()
                
                r_paren_index = stat_content.rfind(")")
                if r_paren_index != -1:
                    after_name = stat_content[r_paren_index + 2:].split()
                    if len(after_name) >= 2:
                        ppid = int(after_name[1])  # Fourth field in stat layout (index 1 after comm)
                else:
                    name = "ERROR: Malformed stat descriptor layout"
            except OSError as e:
                if e.errno == errno.ENOENT:
                    # Natural race condition: process terminated between directory listing and read loop
                    continue
                elif e.errno == errno.EACCES:
                    name = "Permission Denied"
                else:
                    name = f"ERROR: OS read fault: {e.strerror}"

            # 2. Extract Process Comm/Name if not already overwritten by an access fault
            if name in ("unknown", "Permission Denied"):
                comm_path = pid_dir / "comm"
                try:
                    with open(comm_path, "r", encoding="utf-8", errors="replace") as f:
                        name = f.read().strip()
                except OSError as e:
                    if e.errno == errno.ENOENT:
                        continue
                    elif e.errno != errno.EACCES:
                        name = f"ERROR: Comm link block: {e.strerror}"

            # 3. Resolve executable path link safely
            exe_link = pid_dir / "exe"
            try:
                exe = os.readlink(str(exe_link))
            except OSError as e:
                if e.errno == errno.ENOENT:
                    # If /proc/[pid] exists but 'exe' doesn't, it is a kernel thread
                    exe = "unknown"
                elif e.errno == errno.EACCES:
                    exe = "Permission Denied"
                else:
                    exe = f"ERROR: Resolution fault: {e.strerror}"

            # 4. Extract runtime Command-Line parameters securely
            cmdline_path = pid_dir / "cmdline"
            try:
                # Real-world defense: Using open with error replacement blocks an attacker from passing
                # non-UTF-8 trailing garbage parameters to crash the collector iteration step.
                with open(cmdline_path, "r", encoding="utf-8", errors="replace") as f:
                    cmdline_raw = f.read()
                
                if cmdline_raw:
                    cmdline = " ".join(cmdline_raw.split("\x00")).strip()
                else:
                    cmdline = name
            except OSError as e:
                if e.errno == errno.ENOENT:
                    continue
                elif e.errno == errno.EACCES:
                    cmdline = "Permission Denied"
                else:
                    cmdline = f"ERROR: Stream fault: {e.strerror}"

            process_list.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "exe": exe,
                "cmdline": cmdline if cmdline else name
            })
            
        except Exception:
            # Catch-all failsafe to keep the global loop scanning subsequent system nodes resiliently
            continue

    return process_list