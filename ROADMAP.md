# Orin — Forensic Engine Roadmap

This document outlines the planned updates, upgrades, and upcoming feature enhancements for the Orin offline forensic engine.

---

## 📅 Planned Upgrades & New Features

### 1. Per-User Crontab Persistence Harvester (`orin.collectors.crontabs`)
*   **Problem:** Malware frequently registers cron jobs to maintain persistence, but individual user crontabs under `/var/spool/cron/crontabs/` are not currently harvested.
*   **Solution:** Create a crontab harvester that:
    *   Reads per-user crontabs as well as `/etc/crontab` and `/etc/cron.*` directories.
    *   Saves cron commands and schedules to the vault.
    *   Compares them against baselines to flag unauthorized additions.

### 2. Zero-Dependency Threat Signature Scanner (`orin.analysis.signatures`)
*   **Problem:** Forensics often requires matching known malicious patterns, but installing external dependencies (like YARA bindings) violates Orin's zero-dependency runtime guarantee.
*   **Solution:** Implement a pure-Python, lightweight signature matching engine:
    *   Support JSON-defined rules detailing regex and string patterns.
    *   Scan process environment variables, execution arguments, and FIM target files.
    *   Deduplicate and raise security events with `"suspicious_signature"` severity.

### 3. Background Daemon Mode (`orin watch`)
*   **Problem:** Orin currently runs on-demand, which can allow transient indicators of compromise to be missed.
*   **Solution:** Build a background daemonizing subcommand:
    *   `orin watch --interval <minutes>` runs the collection and analysis loop continuously.
    *   Output alerts to local syslog (`/dev/log`) or write to structured JSON lines in `/var/log/orin/alerts.json` for forwarding.

### 4. Diff & Timeline Reports (`orin report --diff`)
*   **Problem:** Reports currently only reflect the state of a single snapshot. Incident response investigations require clear drift reports over time.
*   **Solution:** Extend the reporter module to support:
    *   `orin report --format html --base <id1> --target <id2>`
    *   Generates a styled offline dashboard highlighting added/removed/modified processes, ports, files, and users.

### 5. In-Place Baseline Management (`orin baseline refresh`)
*   **Problem:** System updates (kernel upgrades or package installations) add new LKMs or system users, forcing the analyst to clear the database to update baselines.
*   **Solution:** Create a baseline manager CLI:
    *   `orin baseline add --user <username>` or `orin baseline add --module <name>`
    *   `orin baseline refresh` to synchronize the trusted baseline with the current system state, leaving historical snapshots intact.

### 6. File Integrity Monitoring (FIM) Performance Tuning
*   **Problem:** Computing SHA-256 hashes for all critical system files on every run can become resource-heavy on slow disks.
*   **Solution:** Introduce metadata-based pre-filtering:
    *   Store file metadata (mtime, size, inode) in the SQLite database.
    *   Skip hashing if the metadata hasn't changed. Only compute SHA-256 for files with modified metadata.

---

## 🧪 Implementation Flow Matrix

```mermaid
graph TD
    A[Telemetry Collector] -->|Crontabs / IPv6 / Volatile Fd| B(SQLite Forensics Vault)
    B -->|Snapshot Data| C[Analysis Engine]
    C -->|Severity Triage| D{Risk Scoring}
    D -->|0-34: Low| E[Posture Report]
    D -->|35-64: Medium| E
    D -->|65-89: High| E
    D -->|90-100: Critical| E
    E -->|Briefing Generation| F[HTML / Markdown Report]
```
