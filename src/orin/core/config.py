# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# src/orin/core/config.py
"""
orin.core.config – Configuration Loader
=======================================
Provides a single public entry-point, :func:`load_config`, that reads the
Orin JSON configuration file and merges it with safe built-in defaults.

Search order
------------
1. ``./orin_config.json``  (working-directory local override)
2. ``/etc/orin/orin_config.json``  (system-wide deployment path)

If neither file is found, or if parsing fails, the built-in
``DEFAULT_CONFIG`` dictionary is returned unchanged.
"""
import json
from pathlib import Path

#: Ordered list of filesystem paths that are checked for a user-supplied
#: configuration file.  The first readable file wins.
DEFAULT_CONFIG_LOCATIONS = [
    Path("orin_config.json"),
    Path("/etc/orin/orin_config.json")
]

#: Built-in fallback configuration values used when no config file is found.
#:
#: Keys
#: ----
#: expected_ports       – Port numbers that the analysis engine will *not* flag
#:                        as unexpected listening sockets.
#: whitelisted_processes – Process base-names whose high ephemeral ports are
#:                        excluded from "unexpected port" alerts.
#: critical_paths       – Absolute paths to individual files monitored by the
#:                        File Integrity Monitor (FIM).
#: critical_dirs        – Directories recursively scanned by the FIM.
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
    ],
    # Encryption settings for evidence vault
    "vault_encryption": {
        "enabled": False,
        "passphrase_env": "ORIN_VAULT_PASSPHRASE",
        "min_passphrase_length": 12
    },
    # Structured logging configuration for SIEM integration
    "logging": {
        "enabled": True,
        "level": "INFO",
        "format": "json",
        "output_stderr": True,
        "output_file": None,
        "max_bytes": 10485760,
        "backup_count": 5
    }
}

def load_config_with_source() -> tuple[dict, Path]:
    """Load and return the active configuration dictionary alongside its source path.

    Searches :data:`DEFAULT_CONFIG_LOCATIONS` in order. The first successfully
    parsed JSON file is merged on top of :data:`DEFAULT_CONFIG`.

    Returns
    -------
    tuple[dict, Path]
        A tuple containing:
        - dict: The merged configuration mapping dictionary layout.
        - Path: The actual, validated file path location that was opened.
                Defaults to Path("orin_config.json") if no file exists yet.
    """
    for loc in DEFAULT_CONFIG_LOCATIONS:
        if loc.exists() and loc.is_file():
            try:
                with open(loc, "r") as f:
                    data = json.load(f)
                    # Merge to ensure missing keys fallback to defaults
                    merged = DEFAULT_CONFIG.copy()
                    merged.update(data)
                    return merged, loc
            except Exception:
                pass

    # Default fallback destination if no active configuration layout exists on disk
    return DEFAULT_CONFIG.copy(), Path("orin_config.json")


def load_config() -> dict:
    """Load and return the active Orin configuration dictionary.

    Searches :data:`DEFAULT_CONFIG_LOCATIONS` in order.  The first successfully
    parsed JSON file is merged *on top of* :data:`DEFAULT_CONFIG`, so any keys
    absent from the user file still receive their default values.

    Returns
    -------
    dict
        Merged configuration mapping.  Always contains at minimum all keys
        present in :data:`DEFAULT_CONFIG`.
    """
    config_dict, _ = load_config_with_source()
    return config_dict