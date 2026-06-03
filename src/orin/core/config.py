# src/orin/core/config.py
import json
from pathlib import Path

DEFAULT_CONFIG_LOCATIONS = [
    Path("orin_config.json"),
    Path("/etc/orin/orin_config.json")
]

DEFAULT_CONFIG = {
    "expected_ports": [22, 80, 443, 631, 3306, 5432, 6379, 8080, 8443],
    "whitelisted_processes": ["code", "antigravity-ide", "language_server"],
    "critical_paths": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config",
        "/etc/sudoers",
        "/etc/crontab"
    ],
    "critical_dirs": [
        "/etc/cron.d",
        "/etc/systemd/system"
    ]
}

def load_config() -> dict:
    """Loads configuration options from a JSON file, falling back to defaults."""
    for loc in DEFAULT_CONFIG_LOCATIONS:
        if loc.exists():
            try:
                with open(loc, "r") as f:
                    data = json.load(f)
                    # Merge to ensure missing keys fallback to defaults
                    merged = DEFAULT_CONFIG.copy()
                    merged.update(data)
                    return merged
            except Exception:
                pass
    return DEFAULT_CONFIG
