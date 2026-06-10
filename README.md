<p align="center">
  <img src="assets/orin-logo.svg" alt="Orin Logo" width="200">
</p>

# Orin — Offline Linux Forensics & Integrity Engine

> Host security scanner and forensic triage tool for Linux — built for analysts who trust nothing but the kernel itself. **Designed for air-gapped, offline, and forensically sensitive environments.**

[![CI](https://github.com/jaradat13/orin/actions/workflows/test.yml/badge.svg)](https://github.com/jaradat13/orin/actions/workflows/test.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/runtime_deps-psutil,_bcc_(optional)-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux&logoColor=white)
![License](https://img.shields.io/badge/license-AGPLv3-blue)
![Category](https://img.shields.io/badge/category-DFIR-blue)
![MITRE ATT&CK Mapped](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red)
![Coverage](https://img.shields.io/badge/coverage-270%2B_tests-brightgreen)
![Issues](https://img.shields.io/github/issues/jaradat13/orin)
![Stars](https://img.shields.io/github/stars/jaradat13/orin?style=social)


Orin takes point-in-time snapshots of critical OS state, compares them against trusted baselines, identifies anomalous behaviour, and produces tamper-evident evidence bundles. Core runtime dependency: `psutil`. Optional eBPF streaming requires `bcc`/`bpfcc` Python package. **Zero network access required. Zero telemetry. Zero cloud dependencies.** Built from the ground up for air-gapped networks, classified environments, and forensically sensitive systems.

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

# Launch real-time eBPF telemetry streaming (requires bcc package)
sudo orin stream --verbose

# Prune old snapshots to prevent disk exhaustion
sudo orin vault prune --older-than 30

# Launch centralized air-gapped fleet hub for multi-tenant forensic management
sudo orin hub-serve 8000 --host 0.0.0.0 --cert /path/to/cert.pem --key /path/to/key.pem
```

---

## Why Orin?

Most Linux security tools require a persistent daemon, a cloud backend, network connectivity, or a pile of third-party packages. That's a non-starter on hardened, air-gapped, classified, or forensically sensitive systems where **zero external trust** is the requirement.

| | Orin | Falco | osquery | Wazuh |
|---|---|---|---|---|
| **Runtime dependencies** | psutil (+ bcc optional) | Kernel driver / eBPF | Standalone binary | Agent + manager |
| **Network required** | **Never** | Optional | Optional | **Yes (manager)** |
| **Cloud dependencies** | **Zero** | Optional | Optional | **Required** |
| **Air-gap safe** | ✅ **Out-of-the-box** | ⚠️ Complex setup | ⚠️ Complex setup | ❌ Requires manager |
| **Offline threat intel** | ✅ STIX/CSV/TAXII importer | ❌ | ❌ | ❌ |
| **Forensic evidence signing** | ✅ HMAC-SHA256 + AES-256-GCM | ❌ | ❌ | ❌ |
| **Reads directly from `/proc`** | ✅ | ✅ | ✅ | ⚠️ Rootcheck only |
| **Anti-forensics detection** | ✅ wtmp/lastlog | ❌ | ❌ | ❌ |
| **Local AI triage** | ✅ Ollama integration | ❌ | ❌ | ❌ |
| **Real-time eBPF streaming** | ✅ Ring-buffer consumer | ✅ Full IDS | ⚠️ Via extensions | ❌ Agent-based |

**Orin is built for:** security engineers, forensic analysts, incident responders, and sysadmins working in air-gapped environments, SCIFs, classified networks, industrial control systems, and high-security infrastructure where cloud connectivity is prohibited and every byte of telemetry must remain on-premises.

---

## 🛠️ Implemented Capabilities

| # | Module | Description |
|---|--------|-------------|
| 1 | **Process Tree Harvester** | Reads `/proc/[pid]/stat`, `/comm`, `/exe`, `/cmdline` to build a full PPID-linked process tree. |
| 2 | **Network Socket Auditor** | Parses `/proc/net/{tcp,tcp6,udp,udp6}` for IPv4/IPv6 listening ports and outbound connections. |
| 3 | **Kernel Module & Symbol Auditor** | Reads `/proc/modules` for LKM enumeration and `/proc/kallsyms` for kernel symbol analysis. Detects unlinked modules hiding from /proc/modules, suspicious symbol overrides, credential manipulation symbols in third-party modules, and known rootkit patterns. |
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
| 17 | **Local Web Dashboard (`orin serve`)** | Lightweight stdlib HTTP server serving a single-page forensic console. Features a live risk score gauge, severity-tiered alert feed with triage actions, a Telemetry Explorer tab to inspect all collected forensic datasets (including encrypted vault status), inline local or remote process termination, and direct timeline delta comparison shortcuts. Zero external JS dependencies. |
| 18 | **Automated Collection Scheduler (`orin schedule`)** | Installs a system-wide cron job (`/etc/cron.d/orin`) or user-level crontab entry that automatically runs `collect → analyze` on a configurable interval (default: every 10 minutes). Logs stream to syslog via `logger`. Falls back to user-level crontab when not running as root. |
| 19 | **Dashboard Auto-Token Security** | On every `orin serve` start, a cryptographically random 256-bit session token (`secrets.token_hex(32)`) is generated and printed to the terminal as a full access URL. All API requests are validated via `hmac.compare_digest()` (timing-safe). Token is ephemeral — regenerated on every server restart. |
| 20 | **SUID/SGID Binary Monitor** | Discovers on-disk executables with SUID/SGID bits set and alerts on modified/new ones vs. the baseline. |
| 21 | **Agentless SSH Fleet Scanner** | Profiles remote Linux hosts over SSH using a stdlib-only self-contained remote collection script (Python with pure-bash fallback), saving multi-host snapshots. Covers routers, stripped-down containers, and old systems without Python. |
| 22 | **eBPF & File Descriptor Auditor** | Audits loaded eBPF programs, pinned map/prog objects under `/sys/fs/bpf`, dynamic linker preload overrides (`/etc/ld.so.preload`), and suspicious open file descriptors (deleted files, memfd anonymous segments). |
| 23 | **Baseline Manager (`orin baseline`)** | Enables incremental additions (`--user`, `--module`, `--suid`) and comprehensive refreshes (`--force-overwrite`) of system configuration baselines for both local and remote target hosts. |
| 24 | **Local AI Forensic Triage (`orin correlate`)** | Aggregates unresolved security alerts across multiple systems and leverages a local Ollama model to generate context-aware correlation briefs and remediation advice. **Fully offline — no cloud API calls.** |
| 25 | **Offline Threat Intel Importer** | Multi-format IOC importer supporting STIX 2.x JSON/XML, CSV threat feeds, TAXII 2.x collections, and plain text blocklists. Normalizes indicators into a unified format for detection engine consumption. **All processing happens locally with zero network egress.** |
| 26 | **MITRE ATT&CK Mapper** | Zero-dependency static lookup mapping Orin event types to MITRE ATT&CK Technique IDs, tactics, and reference URLs for enriched alert reporting. |
| 27 | **Snapshot Comparator (`orin diff`)** | Compares two point-in-time forensic snapshots from either SQLite vaults or signed JSON exports, producing structured drift reports with authenticated integrity verification. |
| 28 | **Timeline Delta Calculator (`orin delta`)** | Computes structural differences between two named snapshot IDs within the vault, surfacing security events triggered between timestamps and port/process/connection deltas. |
| 29 | **Cryptographically Encrypted Evidence Vault** | AES-256-GCM authenticated encryption at rest for forensic evidence storage. PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations, random salt, and automatic lifecycle management. Enabled via `ORIN_VAULT_PASSPHRASE` environment variable with graceful fallback to unencrypted mode. |
| 30 | **Embedded YARA Core Engine & FIM** | Lightweight offline YARA rules engine executing pattern matching against files and dumped in-memory binaries. Full `.yar` file parsing from `/rules/yara/`, pre-built rule sets for crypto miners, malware tools, rootkits, webshells, and suspicious strings. FIM-accelerated scans only run against modified files. Detailed match reporting with rule metadata, matched strings, and file locations. |
| 31 | **Deep DNS Forensics & Tunneling Detection** | Advanced DNS telemetry harvester detecting DNS tunneling, DGA (Domain Generation Algorithm) domains, and suspicious query patterns. Features Shannon entropy analysis, structural domain analysis, TXT record abuse detection, per-process DNS profiling, IOC matching with subdomain heuristics, and live connection monitoring via `/proc/net`. Full integration with alert reporting and dashboard visualization. |
| 32 | **Triggered PCAP Capture Engine** | Zero-dependency network packet capture system that automatically saves packet data to PCAP files when forensic triggers occur. Supports Scapy-based reconstruction when available, raw PCAP format writing as fallback, automatic empty/error file handling, and full metadata association with trigger events. Enables evidence preservation for active investigations without continuous disk consumption. |
| 33 | **Agent Self-Defense Hardening** | Deploys mandatory access control profiles (AppArmor, SELinux) and syscall filtering (Seccomp-BPF) to restrict Orin's own attack surface. Profiles enforce least-privilege file access, network restrictions, and syscall allowlists. Security profiles stored in `assets/security-profiles/` for deployment during installation. |
| 34 | **Identity, Access & Privilege Tracking** | Complete identity and privilege monitoring system with PAM log parsing, eBPF probe detection, syscall audit log analysis, and credential access tracking. Detects authentication events (session opened/closed, auth failures), sudo executions, SSH logins, privilege escalation syscalls (setuid/setgid/capset/ptrace), and credential dumping attempts. MITRE ATT&CK mapped (T1548, T1078, T1552). Integrated into main collection workflow with 23 unit tests. |
| 35 | **eBPF Ring-Buffer Real-Time Streamer** | Production-ready eBPF telemetry engine streaming real-time security events via kernel ring buffer. Loads BPF programs via BCC Python bindings, attaches to tracepoints (`sys_enter_execve`, `sys_enter_connect`, `sys_enter_openat`), and consumes events asynchronously. Events include PID, UID, comm, filename, and nanosecond timestamps. Queues to local SQLite database with indexed schema for high-throughput ingestion. Supports graceful shutdown, verbose debugging, and automatic database initialization. Invoked via `orin stream` CLI command. Optional dependency: `bcc`/`bpfcc` Python package. |
| 36 | **Read-Only & Ephemeral Modes** | `--read-only` flag prevents any writes to SQLite vault for forensic acquisition on write-protected systems. `--vault-path` option accepts any writable location (USB, tmpfs) decoupling from default paths for ephemeral operation. |
| 37 | **Vault Lifecycle Management** | `orin vault stats` displays database size, snapshot count, and storage utilization. `orin vault prune --older-than <days>` deletes old snapshots with dry-run support and automatic database vacuuming. |
| 38 | **Pruning & Retention Controls** | Scheduled mode auto-pruning via `orin schedule --retention <days>`. Enforces age-based deletion while preserving active alerts. Includes dry-run preview, database vacuuming, and syslog audit logging to prevent disk exhaustion. |
| 39 | **Credential Handling Overhaul** | Secure passphrase methods: `--passphrase-file` (0600 validation), `--passphrase-prompt` (masked input), `--passphrase-env-var`. Dashboard token file storage via `--token-file` with 0600 permissions for secure persistence. |
| 40 | **Tool Self-Verification & Signed Releases** | GPG-signed release manifests with SHA-256 checksums. Embedded SBOM generation via `orin version --sbom`. Runtime self-check via `--self-check` flag verifies critical modules against embedded hashes. |
| 41 | **Centralized Air-Gapped Fleet Hub (`orin hub-serve`)** | Multi-tenant HTTP server for managing multiple Orin agents across air-gapped networks. Features API key authentication, host registration with heartbeat monitoring, forensic data import/export, configurable binding (`--host`, `--port`), HTTPS support (`--cert`, `--key`), flexible credential handling (`--passphrase-file`, `--passphrase-prompt`, `--passphrase-env-var`), and optional auth disable (`--no-auth`). Enables centralized forensic oversight across multiple isolated environments. |
| 42 | **Structured Logging (JSON Output)** | Production-ready logging system with JSON-formatted output to stderr and/or files. Supports severity levels (DEBUG, INFO, WARNING, ERROR, CRITICAL), automatic log rotation, thread-safe operations, and SIEM integration (Splunk, ELK, QRadar). Each log entry includes standardized fields: timestamp, hostname, component, process ID, and structured context. Configurable via JSON config files or command-line arguments. Maintains backward compatibility with existing print statements while offering enhanced parsing and analysis capabilities. |
---

## 🛡️ Threat Detection Rules

- **Kernel thread masquerade** — flags processes mimicking kernel workers (`kworker`, `ksoftirqd`, …) with a non-system PPID.
- **Kernel rootkit symbol detection** — scans `/proc/kallsyms` for suspicious symbols matching known rootkit patterns (diamorphine, reptile), flags credential manipulation symbols (`commit_creds`, `prepare_kernel_cred`) in third-party modules, and detects system call handlers exported by non-kernel modules.
- **Unlinked kernel module detection** — cross-references `/proc/kallsyms` with `/proc/modules` to identify modules hiding from the standard module list but still exporting symbols.
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
- **YARA malware signature scanning** — scans files and memory payloads against embedded YARA rules for crypto miners, malware tools, rootkits, webshells, and suspicious command patterns. FIM-accelerated to only scan modified files.
- **Agent self-defense hardening** — enforces least-privilege execution via AppArmor confinement, SELinux Type Enforcement policies, and Seccomp-BPF syscall filtering to minimize Orin's own attack surface.
- **Identity & privilege tracking** — comprehensive PAM log parsing for authentication events (session opened/closed, auth failures), sudo executions, SSH logins, su commands; eBPF probe detection for privilege escalation syscalls (setuid/setgid/capset/ptrace); syscall audit log analysis; credential access monitoring for /etc/shadow, SSH agent sockets, Kerberos caches. MITRE ATT&CK mapped (T1548, T1078, T1552).
- **eBPF real-time streaming** — live telemetry capture via kernel ring buffer attaching to `execve`, `connect`, and `openat` syscalls. Events streamed to SQLite with nanosecond precision timestamps. Run `orin stream` to launch the consumer. Requires `bcc` Python package.
- **Centralized fleet hub** — multi-tenant HTTP server (`orin hub-serve`) for managing multiple Orin agents across air-gapped networks with API key authentication, host registration, heartbeat monitoring, and forensic data import/export capabilities.

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
> Optional: For real-time eBPF streaming, install `bcc`/`bpfcc`: `sudo apt-get install bpfcc-python` or `pip install bcc`.

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

### Optional: Enable eBPF Real-Time Streaming
```bash
# Debian/Ubuntu
sudo apt-get install bpfcc-python

# Or via pip
pip install bcc

# Verify installation
python3 -c "from bcc import BPF; print('BCC ready')"
```

---

## 📖 Usage

All subcommands that read from privileged files produce richer results when run as root.

```
init → collect → analyze → report
        ↓
      delta / diff / export / verify / serve / schedule / stream
```

> [!TIP]
> Use `orin schedule --install` to automate the `collect → analyze` cycle so you never have to call it manually.
> Use `orin stream` for real-time eBPF telemetry (requires `bcc` package).

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

### `orin stream` (Optional)
Launches the eBPF real-time telemetry consumer. Streams execve, connect, and openat syscall events via kernel ring buffer to the local SQLite database.

```bash
sudo orin stream --verbose
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

### `orin delta` / `orin diff` / `orin export` / `orin verify` / `orin vault`
```bash
sudo orin delta --base 1 --target 3
orin diff /backups/orin_day1.db /var/lib/orin/orin_vault.db
sudo orin export --snapshot 2 --secret "passphrase"
orin verify --file orin_export_snap_2.json --secret "passphrase"
sudo orin vault stats
sudo orin vault prune --older-than 30 --dry-run
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

### 🔐 Encrypted Evidence Vault

Enable AES-256-GCM encryption at rest by setting the `ORIN_VAULT_PASSPHRASE` environment variable:

```bash
# Enable encryption for vault storage
export ORIN_VAULT_PASSPHRASE="your-strong-passphrase-here"
sudo orin init
sudo orin collect

# Encryption is automatic - all snapshot data is encrypted before SQLite storage
# Without passphrase, vault operates in unencrypted mode (backward compatible)
```

**Security features:**
- AES-256-GCM authenticated encryption (confidentiality + integrity)
- PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations
- Random salt per vault instance
- Tamper detection on decryption
- Graceful fallback to unencrypted mode when passphrase not provided

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
| `test_engine.py` | Detection rules, risk scoring, suppression, auto-resolution, YARA scanning |
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
| `test_dns_forensics.py` | DNS tunneling detection, DGA analysis, entropy calculations |
| `test_triggered_pcap.py` | Triggered packet capture, PCAP generation, Scapy integration |
| `test_privilege_audit.py` | PAM log parsing, privilege escalation syscalls, credential access tracking |
| `test_ioc_importer.py` | STIX/TAXII/CSV IOC import, indicator normalization |
| `test_sigma.py` | Sigma rule evaluation, authentication log parsing |
| `test_timeline.py` | Timeline delta calculation, snapshot comparison |
| `test_logs.py` | Log collection, journald parsing |
| `test_persistence.py` | Persistence mechanism detection, config harvesting |
| `test_processes.py` | Process tree harvesting, /proc parsing |
| `test_kernel.py` | Kernel module auditing, rootkit symbol detection |
| `test_integrity.py` | File integrity monitoring, stat-cache acceleration |
| `test_attck.py` | MITRE ATT&CK mapping, technique lookups |
| `test_self_verify.py` | Self-defense verification, integrity checks |
| `test_users.py` | User account enumeration, SSH key inventory |
---

## 🗄️ Database Schema

Single SQLite file (default: `/var/lib/orin/orin_vault.db`).

```
system_snapshots               — one row per orin collect run
collected_processes            — process list per snapshot
collected_ports                — listening sockets per snapshot
collected_outbound_connections — outbound TCP sessions per snapshot
collected_kernel_modules       — loaded LKMs per snapshot
collected_kernel_symbols       — kernel symbol table entries for rootkit analysis
collected_ssh_keys             — authorized_keys inventory per snapshot
collected_file_hashes          — SHA-256 FIM records (+ mtime, ctime, size for stat-cache)
collected_users                — /etc/passwd accounts per snapshot
collected_deleted_binaries     — unlinked process image dump records per snapshot
collected_promisc_interfaces   — promiscuous network mode flags per snapshot
collected_wtmp_sessions        — parsed binary logins/logouts per snapshot
collected_lastlog_records      — parsed binary lastlogin timestamps per snapshot
collected_privilege_events     — privilege escalation and credential access events per snapshot
collected_pkg_integrity        — dpkg signature mismatch/missing records per snapshot
collected_crontabs             — cron job records per snapshot
collected_suid_binaries        — SUID/SGID binary records per snapshot
collected_auth_logs            — fetched system authentication logs per snapshot
collected_ebpf_programs        — loaded eBPF programs per snapshot
collected_ebpf_pinned          — eBPF program/map pins in /sys/fs/bpf per snapshot
collected_ld_preload           — library preloads listed in /etc/ld.so.preload per snapshot
collected_special_fds          — process open descriptors (memfd, deleted files) per snapshot
collected_persistence_configs  — persistence mechanism configurations per snapshot
collected_dns_queries          — DNS query telemetry with tunneling/DGA detection per snapshot
kernel_analysis_summary        — kernel integrity analysis summary per snapshot
kernel_rootkit_indicators      — detected kernel rootkit indicators per snapshot
kernel_hidden_modules          — hidden kernel module detections per snapshot
security_events                — persistent, deduplicated alert ledger
baseline_kernel_modules        — trusted LKM allowlist (set at init)
baseline_users                 — trusted account allowlist (set at init)
baseline_suid_binaries         — trusted SUID/SGID binary allowlist (set at init)
```

---

## License

GNU AGPLv3 — see `LICENSE` for details.