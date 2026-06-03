# orin/collectors/processes.py
import os
from pathlib import Path

def gather_active_processes() -> list[dict]:
    """Crawls the Linux /proc structure to collect processes with full parent linkages."""
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
            cmdline_raw = (pid_dir / "cmdline").read_bytes()
            cmdline = " ".join(cmdline_raw.decode("utf-8", errors="ignore").split("\x00")).strip() if cmdline_raw else name

            process_list.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "exe": exe,
                "cmdline": cmdline
            })
        except (FileNotFoundError, PermissionError, IndexError, ValueError, UnicodeDecodeError):
            continue

    return process_list