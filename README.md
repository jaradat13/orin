# Orin — Offline Linux Forensics & Integrity Engine

> Host security scanner and forensic triage tool for Linux — built for analysts who trust nothing but the kernel itself.

![CI](https://github.com/jaradat13/orin/actions/workflows/test.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/runtime_deps-psutil-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

Orin takes point-in-time snapshots of critical OS state, compares them against trusted baselines, identifies anomalous behaviour, and produces tamper-evident evidence bundles. One runtime dependency (psutil). No network access. No telemetry.

```bash
# Install
chmod +x install.sh && ./install.sh

# First run
sudo orin init && sudo orin collect && sudo orin analyze && sudo orin report

# Automate collection every 10 minutes via cron
sudo orin schedule --install

# Launch the local web dashboard
sudo orin serve

# Scan a remote host over SSH and baseline it
sudo orin scan --host 192.168.1.50 --user root --init
```

---

## Why Orin?

Most Linux security tools require a persistent daemon, a cloud backend, or a pile of third-party packages. That's a liability on hardened, air-gapped, or forensically sensitive systems.

| | Orin | Falco | osquery | Wazuh |
|---|---|---|---|---|
| **Runtime dependencies** | psutil | Kernel driver / eBPF | Standalone binary | Agent + manager |
| **Network required** | Never | Optional | Optional | Yes |
| **Air-gap safe** | ✅ Out-of-the-box | ⚠️ Complex setup | ⚠️ Complex setup | ❌ Requires manager |
| **Forensic evidence signing** | ✅ HMAC-SHA256 | ❌ | ❌ | ❌ |
| **Reads directly from `/proc`** | ✅ | ✅ | ✅ | ⚠️ Rootcheck only |
| **Anti-forensics detection** | ✅ wtmp/lastlog | ❌ | ❌ | ❌ |

**Orin is built for:** security engineers, forensic analysts, incident responders, and sysadmins who need a lightweight, trustworthy tool they can drop onto any Linux system.

---

## 🛠️ Implemented Capabilities

| # | Module | Description |
|---|--------|-------------|
| 1 | **Process Tree Harvester** | Reads `/proc/[pid]/stat`, `/comm`, `/exe`, `/cmdline` to build a full PPID-linked process tree. |
| 2 | **Network Socket Auditor** | Parses `/proc/net/{tcp,tcp6,udp,udp6}` for IPv4/IPv6 listening ports and outbound connections. |
| 3 | **Kernel Module Monitor** | Reads `/proc/modules` and validates loaded LKMs against an immutable baseline set at `init`. |
| 4 | **User & SSH Key Inventory** | Harvests `/etc/passwd` and all `~/.ssh/authorized_keys` files for account and key fingerprint tracking. |
| 5 | **File Integrity Monitor (FIM)** | SHA-256 checksums for configured critical paths and directories. Uses a stat-based look-back cache — `os.stat()` metadata (mtime, ctime, size) is compared against the previous snapshot before touching the file. Hashing is skipped entirely for unchanged files. |
| 6 | **Auth Log Parser & Sigma Engine** | Scans authentication logs and `journald` records using a zero-dependency, compile-free Sigma rules evaluator with dynamic MITRE ATT&CK tagging. |
| 7 | **In-Memory Executable Recovery** | Resolves `/proc/[pid]/exe` symlinks to detect running processes whose binaries have been deleted from disk, dumps the payload, and logs MD5 & SHA-256 hashes. |
| 8 | **Promiscuous Mode Flag Auditor** | Reads `/sys/class/net/*/flags` and raises alerts when the `IFF_PROMISC` (`0x100`) bit is set. |
| 9 | **Binary Session Auditor** | Parses `/var/log/wtmp` and `/var/log/lastlog` binary structures to track login/logout lifecycles and detect anti-forensic tampering (zeroed records, epoch resets). |
| 10 | **Hidden Process Detector** | Probes scheduler-active PIDs via null signaling (`os.kill(pid, 0)`) and cross-references against `/proc` to expose kernel rootkits. |
| 11 | **Offline Package Integrity Engine** | Verifies on-disk binaries against Debian `/var/lib/dpkg/info/*.md5sums`. Primary pass uses MD5 only; SHA-256 is computed lazily and only on confirmed tamper, eliminating redundant double-hashing on clean binaries. |
| 12 | **Scheduled Task (Crontab) Harvester** | Parses user spool crontabs, `/etc/crontab`, `/etc/cron.d/*`, and timed script directories. Detects cron drift, volatile-path execution, and reverse-shell commands. |
| 13 | **Threat Detection Rules Engine** | Evaluates all collected data against rules for masquerade processes, reverse shells, C2 blocklist hits, SSH persistence, FIM changes, unauthorized accounts, and cron anomalies. Supports per-alert suppression rules and severity overrides. |
| 14 | **Forensic Alert Auto-Resolution** | Automatically closes historical alerts once the anomalous condition is no longer present in subsequent snapshots. |
| 15 | **Cryptographic Evidence Export** | Serialises snapshots to deterministic JSON, signs with HMAC-SHA256, and wraps in a portable `{signature, data}` bundle. |
| 16 | **Markdown & HTML Reporting** | Generates lightweight Markdown briefings and self-contained dark-mode HTML dashboards with tabbed navigation and severity badges. |
| 17 | **Local Web Dashboard (`orin serve`)** | Lightweight stdlib HTTP server serving a single-page forensic console. Features a live risk score gauge, severity-tiered alert feed with triage actions, a Telemetry Explorer tab to inspect all 16 collected forensic datasets (processes, ports, users, FIM, cron jobs, etc.), inline local or remote process termination, and direct timeline delta comparison shortcuts. Zero external JS dependencies. |
| 18 | **Automated Collection Scheduler (`orin schedule`)** | Installs a system-wide cron job (`/etc/cron.d/orin`) or user-level crontab entry that automatically runs `collect → analyze` on a configurable interval (default: every 10 minutes). Logs stream to syslog via `logger`. Falls back to user-level crontab when not running as root. |
| 19 | **Dashboard Auto-Token Security** | On every `orin serve` start, a cryptographically random 256-bit session token (`secrets.token_hex(32)`) is generated and printed to the terminal as a full access URL. Only the user who ran `sudo orin serve` can see it. All API requests are validated via `hmac.compare_digest()` (timing-safe). Token is ephemeral — regenerated on every server restart. |
| 20 | **SUID/SGID Binary Monitor** | Discovers on-disk executables with SUID/SGID bits set and alerts on modified/new ones vs. the baseline. |
| 21 | **Agentless SSH Fleet Scanner** | Profiles remote Linux hosts over SSH using a stdlib-only self-contained remote collection script, saving multi-host snapshots. |
| 22 | **eBPF & File Descriptor Auditor** | Audits loaded eBPF programs, pinned map/prog objects under `/sys/fs/bpf`, dynamic linker preload overrides (`/etc/ld.so.preload`), and suspicious open file descriptors (deleted files, memfd anonymous segments). |
| 23 | **Baseline Manager (`orin baseline`)** | Enables incremental additions (`--user`, `--module`, `--suid`) and comprehensive refreshes (`--force-overwrite`) of system configuration baselines for both local and remote target hosts. |
| 24 | **Local AI Forensic Triage (`orin correlate`)** | Aggregates unresolved security alerts across multiple systems and leverages a local Ollama model to generate context-aware correlation briefs and remediation advice. |

---

## 🛡️ Threat Detection Rules

- **Kernel thread masquerade** — flags processes mimicking kernel workers (`kworker`, `ksoftirqd`, …) with a non-system PPID.
- **Reverse shell detection** — matches dangerous invocation patterns (`python -c`, `bash -i`, `sh -i`).
- **Volatile-directory execution** — processes running from `/tmp`, `/dev/shm`, `/var/tmp`.
- **Known-bad binaries** — `nc`, `ncat`, `netcat`, `socat`, `nmap`, `xmrig`, and more.
- **C2 blocklist** — compares outbound connections against an offline IP blocklist.
- **SSH persistence detection** — new keys appearing between snapshots.
- **File integrity monitoring** — stat-cache accelerated SHA-256 change detection vs. the previous snapshot; unchanged files are skipped without reading from disk.
- **Untrusted kernel modules** — LKMs absent from the baseline captured at `init`.
- **Unauthorized account creation / UID-0 privilege escalation**.
- **In-memory deleted binaries** — monitors virtual symlinks pointing to deleted executables and dumps their payloads to a forensic vault.
- **Promiscuous mode detection** — triggers alerts when a network interface's `IFF_PROMISC` flag is active.
- **Log tampering & anti-forensics** — flags zeroed-out records or epoch timestamp resets in wtmp and lastlog binary log structures.
- **Sigma rules engine** — evaluates system authentication logs and `journald` records against standard rules (SSH brute force, su/sudo privilege escalation, useradd drift) and auto-tags MITRE ATT&CK techniques.
- **Hidden process scanning** — compares scheduler-active PIDs via null signaling with visible `/proc` listings to detect kernel rootkits.
- **Offline package verification** — flags MD5 mismatches between on-disk binaries and dpkg records; forensic SHA-256 computed only on tampered files.
- **Cron job drift detection** — flags newly added cron scheduled tasks.
- **Cron execution anomalies** — flags cron jobs executing commands from volatile directories or containing reverse shell signatures.
- **SUID/SGID privilege anomalies** — alerts on modified or newly created SUID/SGID binary executions.
- **eBPF program & map pin auditing** — audits loaded eBPF programs for non-GPL compatibility or suspicious names, and checks pinned objects under `/sys/fs/bpf` for rootkit patterns.
- **Dynamic Linker preloading hooks** — flags dynamic library preloads registered in `/etc/ld.so.preload`.
- **Memory-only & volatile file descriptor monitoring** — flags processes holding open descriptors pointing to `memfd:` anonymous segments or deleted files in volatile/system directories.
- **Alert suppression & severity override** — analysts can suppress recurring false positives and override alert severity directly from the web dashboard or CLI.
- **Auto-resolution** — automatically resolves historical alerts once the anomalous condition is corrected in a subsequent snapshot.

---

## 📦 Cryptographic Evidence Export

Snapshots are serialised to canonical JSON (keys sorted for determinism), signed with HMAC-SHA256, and wrapped in a portable `{signature, data}` bundle. A compromised bundle is immediately detected by `orin verify`.

---

## ⚡ Performance & Collection Efficiency

* **Stat-Based FIM Cache:** Before computing any SHA-256 hash, the FIM queries `os.stat()` and compares `mtime`, `ctime`, and `size` against the last snapshot. Unchanged files are never read from disk. A full hash is computed only when metadata indicates a change.
* **Lazy SHA-256 in Package Integrity:** MD5 is computed in the primary pass against Debian's `*.md5sums` records. SHA-256 is only computed when an MD5 mismatch is confirmed — zero overhead on clean systems.

---

## 📂 Project Structure

```
orin/
├── orin_config.json          # User configuration (optional)
├── install.sh                # Automated installer
├── pyproject.toml            # Packaging metadata
├── src/
│   └── orin/
│       ├── main.py           # CLI entry point & subcommand router
│       ├── core/
│       │   ├── config.py     # JSON config loader with safe defaults
│       │   ├── crypto.py     # HMAC-SHA256 sign & verify
│       │   ├── database.py   # SQLite schema (OrinStorage ORM)
│       │   ├── scanner.py    # SSH agentless remote scanner orchestrator
│       │   ├── scheduler.py  # Cron automation (orin schedule)
│       │   ├── server.py     # stdlib HTTP server + REST API + auto-token auth (orin serve)
│       │   └── dashboard.html
│       ├── collectors/
│       │   ├── connections.py
│       │   ├── deleted_binaries.py
│       │   ├── integrity.py
│       │   ├── kernel.py
│       │   ├── logs.py
│       │   ├── persistence.py
│       │   ├── pkg_integrity.py
│       │   ├── processes.py
│       │   ├── promisc.py
│       │   ├── remote_agent.py # Stdlib-only remote collection agent script
│       │   ├── session_audit.py
│       │   ├── suid.py       # SUID/SGID binary monitor collector
│       │   ├── crontabs.py
│       │   └── users.py
│       └── analysis/
│           ├── engine.py
│           ├── diff.py
│           ├── timeline.py
│           ├── unhide.py
│           └── reporter.py
└── tests/
```

---

## 🔧 Installation

> Requires **Python ≥ 3.10** and **psutil ≥ 5.9** (installed automatically).

### Method A — Automated installer (recommended)
```bash
chmod +x install.sh
./install.sh
```

### Method B — System-wide (for root forensic workflows)
```bash
sudo pip install . --break-system-packages
```

### Method C — Development mode
```bash
pip install -e .
PYTHONPATH=src python -m orin.main <subcommand>
```

---

## 📖 Usage

All subcommands that read from privileged files produce richer results when run as root.

```
init → collect → analyze → report
        ↓
      delta / diff / export / verify / serve / schedule
```

> [!TIP]
> Use `orin schedule --install` to automate the `collect → analyze` cycle so you never have to call it manually.

### `orin init`
Creates the SQLite vault and records two immutable baselines: trusted kernel modules and trusted user accounts.

### `orin scan`
Executes an agentless remote scan over SSH. Example:
```bash
sudo orin scan --host 192.168.1.50 --user root --init
```

```bash
sudo orin init
```

### `orin collect`
Harvests a full system state snapshot and persists it to the vault.

```bash
sudo orin collect
```

### `orin analyze`
Runs all threat-detection rules against the most recent snapshot. Prints a severity-tiered risk score (0–100).

```bash
sudo orin analyze
```

### `orin report`
Compiles a forensic audit briefing from the latest snapshot and all unresolved alerts.

```bash
sudo orin report --format html --output /tmp/orin_report.html
```

### `orin serve`
Starts a local-only forensic web console on `127.0.0.1:8000`. Generates a one-time session token printed to the terminal — only the user who launched the server sees it.

```bash
sudo orin serve
sudo orin serve --port 9090
sudo orin serve --no-auth   # trusted networks only
```

### `orin schedule`
Installs or removes the automated `collect → analyze` cron job.

```bash
sudo orin schedule --install --interval 10
sudo orin schedule --status
sudo orin schedule --remove
```

### `orin delta` / `orin diff` / `orin export` / `orin verify`
```bash
sudo orin delta --base 1 --target 3
orin diff /backups/orin_day1.db /var/lib/orin/orin_vault.db
sudo orin export --snapshot 2 --secret "passphrase"
orin verify --file orin_export_snap_2.json --secret "passphrase"
```

---

## ⚙️ Configuration

Orin searches for `orin_config.json` in `./` then `/etc/orin/`. Falls back to built-in defaults if neither is found.

```json
{
  "expected_ports": [22, 80, 443, 631, 3306, 5432, 6379, 8080, 8443],
  "whitelisted_processes": ["code", "chrome", "language_server"],
  "critical_paths": ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/crontab"],
  "critical_dirs": ["/etc/cron.d", "/etc/systemd/system"]
}
```

---

## 🧪 Running Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

| Test file | Coverage area |
|-----------|--------------|
| `test_database.py` | Schema creation, connection management, stat-cache migration |
| `test_crypto.py` | HMAC sign/verify, tamper detection |
| `test_connections.py` | IPv4 & IPv6 socket parsing |
| `test_engine.py` | Detection rules, risk scoring, suppression, auto-resolution |
| `test_diff.py` | Snapshot comparator, drift detection |
| `test_reporter.py` | Markdown and HTML report generation |
| `test_server.py` | HTTP routing, API endpoints, Bearer token auth |
| `test_scheduler.py` | Cron install/remove, system vs. user fallback |
| `test_main.py` | CLI subcommand routing, argument parsing |
| `test_unhide.py` | Hidden process detector |
| `test_deleted_binaries.py` | In-memory executable recovery |
| `test_promisc.py` | Promiscuous mode auditing |
| `test_session_audit.py` | wtmp/lastlog parsing |
| `test_pkg_integrity.py` | MD5 mismatch detection, lazy SHA-256 |
| `test_crontabs.py` | Cron line parser edge cases |
| `test_suid.py` | SUID/SGID file discovery, permissions, and hashing |
| `test_scanner.py` | Agentless SSH scanner remote execution mocking |
| `test_ebpf.py` | eBPF programs, pinned map/prog objects, ld.so.preload, and anomalous file descriptor audits |
| `test_baseline.py` | Relational threat scoring correlation rules, baseline CLI commands (add, refresh) |
| `test_ai.py` | Local AI Triage multi-host correlation engine and CLI commands |

---

## 🗄️ Database Schema

Single SQLite file (default: `/var/lib/orin/orin_vault.db`).

```
system_snapshots               — one row per orin collect run
collected_processes            — process list per snapshot
collected_ports                — listening sockets per snapshot
collected_outbound_connections — outbound TCP sessions per snapshot
collected_kernel_modules       — loaded LKMs per snapshot
collected_ssh_keys             — authorized_keys inventory per snapshot
collected_file_hashes          — SHA-256 FIM records (+ mtime, ctime, size for stat-cache)
collected_users                — /etc/passwd accounts per snapshot
collected_deleted_binaries     — unlinked process image dump records per snapshot
collected_promisc_interfaces   — promiscuous network mode flags per snapshot
collected_wtmp_sessions        — parsed binary logins/logouts per snapshot
collected_lastlog_records      — parsed binary lastlogin timestamps per snapshot
collected_pkg_integrity        — dpkg signature mismatch/missing records per snapshot
collected_crontabs             — cron job records per snapshot
collected_suid_binaries        — SUID/SGID binary records per snapshot
collected_auth_logs            — fetched system authentication logs per snapshot
collected_ebpf_programs        — loaded eBPF programs per snapshot
collected_ebpf_pinned          — eBPF program/map pins in /sys/fs/bpf per snapshot
collected_ld_preload           — library preloads listed in /etc/ld.so.preload per snapshot
collected_special_fds          — process open descriptors (memfd, deleted files) per snapshot
security_events                — persistent, deduplicated alert ledger
baseline_kernel_modules        — trusted LKM allowlist (set at init)
baseline_users                 — trusted account allowlist (set at init)
baseline_suid_binaries         — trusted SUID/SGID binary allowlist (set at init)
```

---

## 🗺️ Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features: eBPF rootkit auditing, context-aware relational risk scoring, and local AI triage.

---

## License

MIT — see `LICENSE` for details.