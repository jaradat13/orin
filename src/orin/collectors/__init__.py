"""
orin.collectors – System Telemetry Harvesters
==============================================
Each module in this package is responsible for extracting one category of raw
system state data from the Linux kernel interfaces (``/proc``, ``/etc``, …).
All public functions return plain Python lists-of-dicts so results can be
persisted directly into the Orin SQLite vault.

Modules
-------
connections – Listening TCP/UDP ports and active outbound TCP connections.
integrity   – SHA-256 checksums for critical system files and directories.
kernel      – Loaded Linux kernel modules read from ``/proc/modules``.
logs        – Authentication-log parser (brute-force attempts, privilege changes).
persistence – SSH ``authorized_keys`` inventory across all system accounts.
processes   – Full process tree harvested from ``/proc/[pid]`` entries.
users       – System account profiles parsed directly from ``/etc/passwd``.
"""
