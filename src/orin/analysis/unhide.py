# src/orin/analysis/unhide.py
"""
orin.analysis.unhide – Out-of-Band Hidden Process Detector
==========================================================
Identifies processes hidden from /proc directory listings by comparing PIDs
returned by system scheduler signaling (os.kill) against visible /proc entries.
"""
import os
import errno
from pathlib import Path

def detect_hidden_processes() -> list[dict]:
    """Scan the PID space to detect scheduler-active processes hidden from `/proc`.

    Returns
    -------
    list[dict]
        Each dict represents a discovered hidden process:
        - pid (int): PID of the hidden process.
        - status (str): "hidden".
        - reason (str): verification failure details.
    """
    hidden_processes = []
    proc_path = Path("/proc")
    if not proc_path.exists():
        return hidden_processes

    # 1. Gather all visible PIDs and TIDs from /proc listing
    visible_pids = set()
    visible_tids = set()
    for p in proc_path.iterdir():
        if p.is_dir() and p.name.isdigit():
            try:
                pid = int(p.name)
                visible_pids.add(pid)
                # Read all thread IDs (TIDs) under /proc/[pid]/task/
                task_dir = p / "task"
                if task_dir.exists():
                    for t in task_dir.iterdir():
                        if t.name.isdigit():
                            visible_tids.add(int(t.name))
            except (ValueError, OSError):
                pass

    if not visible_pids:
        return hidden_processes

    # 2. Determine bounds of the scanning loop
    max_visible_pid = max(visible_pids)
    
    try:
        pid_max = int(Path("/proc/sys/kernel/pid_max").read_text().strip())
    except Exception:
        pid_max = 32768

    # Scan up to max_visible_pid + 1000, capped at pid_max, with a minimum of 32768
    # to cover standard PID ranges without causing CPU exhaustion.
    scan_limit = min(max(32768, max_visible_pid + 1000), pid_max)

    # 3. Probe each PID
    for pid in range(1, scan_limit + 1):
        if pid in visible_pids or pid in visible_tids:
            continue

        try:
            # Send null signal (0) to check process existence without signaling
            os.kill(pid, 0)
            # If no exception is raised, double check if /proc/{pid} exists right now.
            # This handles race conditions for processes spawned after the initial /proc read.
            if not Path(f"/proc/{pid}").exists():
                # Double check that the process is still running to rule out a process that just exited
                try:
                    os.kill(pid, 0)
                    hidden_processes.append({
                        "pid": pid,
                        "status": "hidden",
                        "reason": "Process responds to signal 0 but is not present in /proc"
                    })
                except OSError:
                    pass
        except OSError as e:
            if e.errno == errno.EPERM:
                # PermissionError: Process exists but current user lacks signal privilege.
                # Double check /proc/{pid} to handle race condition
                if not Path(f"/proc/{pid}").exists():
                    try:
                        os.kill(pid, 0)
                    except OSError as e2:
                        if e2.errno == errno.EPERM:
                            hidden_processes.append({
                                "pid": pid,
                                "status": "hidden",
                                "reason": "Process exists (EPERM) but is not present in /proc"
                            })
            elif e.errno == errno.ESRCH:
                # ProcessLookupError: process does not exist (normal)
                pass

    return hidden_processes
