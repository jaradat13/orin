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
"""
orin.collectors – System Telemetry Harvesters
==============================================
Each module in this package is responsible for extracting one category of raw
system state data from the Linux kernel interfaces (``/proc``, ``/etc``, …).
All public functions return plain Python lists-of-dicts so results can be
persisted directly into the Orin SQLite vault.

Modules
-------
connections      – Listening TCP/UDP ports and active outbound TCP connections.
crontabs         – User and system crontab schedules and scripts parser.
deleted_binaries – Recover running process executable images flagged as deleted.
integrity        – SHA-256 checksums for critical system files and directories.
kernel           – Loaded Linux kernel modules read from ``/proc/modules``.
logs             – Authentication-log parser (brute-force attempts, privilege changes).
persistence      – SSH ``authorized_keys`` inventory across all system accounts.
pkg_integrity    – Recalculates on-disk binary hashes to compare vs. dpkg records.
processes        – Full process tree harvested from ``/proc/[pid]`` entries.
promisc          – Promiscuous mode interface flags auditor.
session_audit    – Binary login/session auditor parser for wtmp and lastlog structures.
users            – System account profiles parsed directly from ``/etc/passwd``.
"""
