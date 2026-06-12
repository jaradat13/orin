<p align="center">
  <img src="assets/orin-logo.svg" alt="Orin Logo" width="200">
</p>

# Orin — Offline Linux Forensics & Integrity Engine

> Host security scanner and forensic triage tool for Linux — built for analysts who trust nothing but the kernel itself. **Designed for air-gapped, offline, and forensically sensitive environments.**

[![CI](https://github.com/jaradat13/orin/actions/workflows/test.yml/badge.svg)](https://github.com/jaradat13/orin/actions/workflows/test.yml)
![Version](https://img.shields.io/badge/version-v1.2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/runtime_deps-psutil,_libbpf_(optional)-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux&logoColor=white)
![License](https://img.shields.io/badge/license-AGPLv3-blue)
![Category](https://img.shields.io/badge/category-DFIR-blue)
![MITRE ATT&CK Mapped](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red)
[![Coverage](https://img.shields.io/badge/coverage-968_tests_%7C_85.18%25-brightgreen)](https://github.com/jaradat13/orin/actions/workflows/test.yml)
![Issues](https://img.shields.io/github/issues/jaradat13/orin)
![Stars](https://img.shields.io/github/stars/jaradat13/orin?style=social)


Orin takes point-in-time snapshots of critical OS state, compares them against trusted baselines, identifies anomalous behaviour, and produces tamper-evident evidence bundles. Core runtime dependency: `psutil`. Optional eBPF streaming requires the system `libbpf` library. **Zero network access required. Zero telemetry. Zero cloud dependencies.** Built from the ground up for air-gapped networks, classified environments, and forensically sensitive systems. See [STATUS.md](STATUS.md) for supported platforms, assumptions, and known limitations.

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

# Launch real-time eBPF telemetry streaming (requires libbpf)
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
| **Runtime dependencies** | psutil (+ libbpf optional) | Kernel driver / eBPF | Standalone binary | Agent + manager |
| **Network required** | **Never** | Optional | Optional | **Yes (manager)** |
| **Cloud dependencies** | **Zero** | Optional | Optional | **Required** |
| **Air-gap safe** | ✅ **Out-of-the-box** | ⚠️ Complex setup | ⚠️ Complex setup | ❌ Requires manager |
| **Multi-tenant hub** | ✅ Admin auth, rate limiting, audit logs | ❌ | ❌ | ⚠️ Manager-only |
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
| 29 | **Cryptographically Encrypted Evidence Vault** | AES-256-GCM authenticated encryption at rest for forensic evidence storage. PBKDF2-HMAC-SHA256 key derivation with 600,000 iterations (upgraded from 100,000 with backward compatibility for legacy vaults), random salt, and automatic lifecycle management. Enabled via `ORIN_VAULT_PASSPHRASE` environment variable with graceful fallback to unencrypted mode. |
| 30 | **Embedded YARA Core Engine & FIM** | Lightweight offline YARA rules engine executing pattern matching against files and dumped in-memory binaries. Full `.yar` file parsing from `/rules/yara/`, pre-built rule sets for crypto miners, malware tools, rootkits, webshells, and suspicious strings. FIM-accelerated scans only run against modified files. Detailed match reporting with rule metadata, matched strings, and file locations. |
| 31 | **Deep DNS Forensics & Tunneling Detection** | Advanced DNS telemetry harvester detecting DNS tunneling, DGA (Domain Generation Algorithm) domains, and suspicious query patterns. Features Shannon entropy analysis, structural domain analysis, TXT record abuse detection, per-process DNS profiling, IOC matching with subdomain heuristics, and live connection monitoring via `/proc/net`. Full integration with alert reporting and dashboard visualization. |
| 32 | **Triggered PCAP Capture Engine** | Zero-dependency network packet capture system that automatically saves packet data to PCAP files when forensic triggers occur. Supports Scapy-based reconstruction when available, raw PCAP format writing as fallback, automatic empty/error file handling, and full metadata association with trigger events. Enables evidence preservation for active investigations without continuous disk consumption. |
| 33 | **Agent Self-Defense Hardening** | Deploys mandatory access control profiles (AppArmor, SELinux) and syscall filtering (Seccomp-BPF) to restrict Orin's own attack surface. Profiles enforce least-privilege file access, network restrictions, and syscall allowlists. Security profiles stored in `assets/security-profiles/` for deployment during installation. |
| 34 | **Identity, Access & Privilege Tracking** | Complete identity and privilege monitoring system with PAM log parsing, eBPF probe detection, syscall audit log analysis, and credential access tracking. Detects authentication events (session opened/closed, auth failures), sudo executions, SSH logins, privilege escalation syscalls (setuid/setgid/capset/ptrace), and credential dumping attempts. MITRE ATT&CK mapped (T1548, T1078, T1552). Integrated into main collection workflow with 23 unit tests. |
| 35 | **eBPF Ring-Buffer Real-Time Streamer** | Production-ready eBPF telemetry engine streaming real-time security events via kernel ring buffer. Loads BPF programs via system libbpf library, attaches to tracepoints (`sys_enter_execve`, `sys_enter_connect`, `sys_enter_openat`), and consumes events asynchronously. Events include PID, UID, comm, filename, and nanosecond timestamps. Queues to local SQLite database with indexed schema for high-throughput ingestion. Supports graceful shutdown, verbose debugging, and automatic database initialization. Invoked via `orin stream` CLI command. Optional dependency: system `libbpf` library. |
| 36 | **Read-Only & Ephemeral Modes** | `--read-only` flag prevents any writes to SQLite vault for forensic acquisition on write-protected systems. `--vault-path` option accepts any writable location (USB, tmpfs) decoupling from default paths for ephemeral operation. |
| 37 | **Vault Lifecycle Management** | `orin vault stats` displays database size, snapshot count, and storage utilization. `orin vault prune` deletes old snapshots via age-based (`--older-than <days>`) or count-based (`--keep-last <count>`) policies with dry-run support, critical-alert preservation, and automatic database vacuuming. |
| 38 | **Pruning & Retention Controls** | Enforces age-based or count-based deletion while preserving snapshots associated with active critical alerts. Includes dry-run preview, database vacuuming, and syslog audit logging to prevent disk exhaustion. Critical alert preservation can be disabled with `--no-preserve-critical`. |
| 39 | **Credential Handling Overhaul** | Secure passphrase methods: `--passphrase-file` (0600 validation), `--passphrase-prompt` (masked input), `--passphrase-env-var`. Dashboard token file storage via `--token-file` with 0600 permissions for secure persistence. |
| 40 | **Tool Self-Verification & Signed Releases** | GPG-signed release manifests with SHA-256 checksums. Embedded SBOM generation via `orin version --sbom`. Runtime self-check via `--self-check` flag verifies critical modules against embedded hashes. |
| 41 | **Centralized Air-Gapped Fleet Hub (`orin hub-serve`)** | Multi-tenant HTTP server for managing multiple Orin agents across air-gapped networks. Features admin authentication (bcrypt passwords) for tenant creation, API key authentication for hosts, rate limiting (configurable requests/minute), comprehensive audit logging, host registration with heartbeat monitoring, forensic data import/export, configurable binding (`--host`, `--port`), HTTPS support (`--cert`, `--key`), flexible credential handling (`--passphrase-file`, `--passphrase-prompt`, `--passphrase-env-var`). Enables centralized forensic oversight across multiple isolated environments with production-ready security hardening. |
| 42 | **Structured Logging (JSON Output)** | Production-ready logging system with JSON-formatted output to stderr and/or files. Supports severity levels (DEBUG, INFO, WARNING, ERROR, CRITICAL), automatic log rotation, thread-safe operations, and SIEM integration (Splunk, ELK, QRadar). Each log entry includes standardized fields: timestamp, hostname, component, process ID, and structured context. Configurable via JSON config files or command-line arguments. Maintains backward compatibility with existing print statements while offering enhanced parsing and analysis capabilities. |
| 43 | **Agent Script Signing Integration** | HMAC-SHA256 signature enforcement for remote agent deployment over SSH. Automatically signs agent bundles before transmission and verifies integrity on target hosts before execution. Features constant-time comparison to prevent timing attacks, minimum key length enforcement (12 characters), environment variable support (`ORIN_AGENT_SIGNING_KEY`), metadata embedding for audit trails, and optional enforcement mode for testing. Tampered or unsigned agents are rejected with CRITICAL alerts. Integrated into `scanner.run_remote_scan()` with comprehensive logging. |
| 44 | **Dashboard API Endpoints** | Full-featured backend API routes for the local web dashboard including `/api/alerts` (severity-filtered alert feed with triage actions), `/api/diff` (snapshot comparison and drift analysis), `/api/telemetry/{snapshot_id}` (forensic dataset inspection), and `/api/config` (runtime configuration). Frontend JavaScript functions provide real-time data visualization, risk score calculation, process termination, and timeline delta comparison. Zero external JS dependencies. |
| 45 | **SQLite Performance Hardening** | Production-ready database optimization with Write-Ahead Logging (WAL) mode, connection pooling (configurable size, thread-safe, health-checked), batch insert operations with chunking (500-1000 records per transaction), and performance PRAGMAs (64MB cache, 256MB mmap, 30s busy timeout). Reduces transaction overhead by ~90% for large datasets. Includes `optimize_database()` for post-import tuning and `get_pool_stats()` for monitoring. See `SQLITE_PERFORMANCE_HARDENING.md` for details. |
| 46 | **Comprehensive Test Suite** | 968 tests across 52 test files covering all core modules: AI correlation, ATT&CK mapping, baseline management, credentials, network connections, crontabs, crypto/vault operations, database (including extended schema and performance), diff analysis, DNS forensics, eBPF streaming, engine logic, file integrity, fleet hub, IOC importing, kernel auditing, log parsing, package integrity, parallel collection, privilege auditing, process monitoring, promiscuous mode detection, rate limiting, reporting, rootkit detection, scanning, scheduling, self-defense, self-verification, server operations, session auditing, Sigma rules (including extended), SUID monitoring, timeline calculation, triggered PCAP capture, unhide detection, user inventory, and YARA engine. CI enforces a hard 85% coverage gate. |
| 47 | **Parallel Collection Engine** | High-performance concurrent telemetry collection using Python's `ThreadPoolExecutor` for independent collectors. Supports configurable worker pools (`--workers`), per-collector timeouts (`--timeout`), and priority-based scheduling. Reduces collection time from ~15-20s (sequential) to ~1.3s (4 workers) on multi-core systems. Features error resilience (failures don't block others), progress tracking, and automatic fallback to sequential mode on single-core systems. Invoked via `orin collect --parallel` CLI command. |
| 48 | **Remote Agent Script Signing & Verification** | Cryptographic signing and verification system for agentless SSH remote collection scripts. Features HMAC-SHA256 signatures with dual-layer integrity checks (content hash + signature), constant-time comparison to prevent timing attacks, GPG signature integration for stronger guarantees, multi-agent manifest generation, minimum key length enforcement (12 characters), and tamper detection before deployment. Protects against malicious agent injection via compromised control hosts or MITM attacks. Core module: `orin.core.agent_signing`. |
| 49 | **Exception Handling & Atomic Write Safety** | All encryption and decryption operations in `database.py` are wrapped in `try-finally` blocks ensuring temporary plaintext files are securely deleted on error. Atomic write patterns prevent partial-state files from persisting on failure. Consistent exception hierarchy with graceful degradation on non-critical failures. No plaintext evidence is ever left exposed after a collection failure. |
| 50 | **Thread-Safe Connection Pool with Leak Detection** | `ConnectionPool` in `database.py` enforces lock ordering to eliminate deadlocks and connection leaks under concurrent load. Health-checked pool with configurable size, timeout, and background leak detection. Stress-tested via dedicated race-condition test suite (`test_connection_pool_race_conditions.py`) with concurrent reader/writer threads. Parallel collector thread-safety verified in `test_parallel.py`. |
| 51 | **Input Validation & Sanitization Layer** | `validators.py` provides a centralized allowlist-based validation layer for all external inputs: hostname/IP format enforcement, snapshot ID range checks, path sanitization against directory traversal attacks (`../` stripping, symlink-safe resolution), and bounded numeric inputs. All database queries use parameterized statements throughout the ORM. Invalid inputs are rejected at the API boundary before reaching any storage or execution layer. |
| 52 | **Configuration Security & Deep-Copy Isolation** | `config.py` uses deep-copy merging so user-supplied values never mutate the built-in defaults — eliminating a class of subtle shared-reference bugs. All previously hardcoded threat-intel and rules paths are externalized to `orin_config.json`. Database performance PRAGMA constants are documented with their rationale. Config validation rejects out-of-range or type-incorrect values before any collection run. |
| 53 | **Alert Forwarding Framework** | Zero-external-dependency push notification system routing security alerts to analysts without requiring dashboard polling. Supports **Slack Block Kit** webhooks, **Microsoft Teams Adaptive Card** webhooks, and **generic JSON REST** endpoints, plus local **syslog** via the stdlib `syslog` module. Per-channel minimum severity filters, exponential-backoff retry queue (configurable attempts and delay), and an append-only JSONL **notification audit log**. All transports are offline-capable and use only Python stdlib (`urllib.request`). Configured via `orin_config.json` `notifications` block. Dispatched automatically after every `orin analyze` run. Core module: `orin.core.notifier`. |
| 54 | **Health & Readiness Probes** | Kubernetes-style liveness (`GET /health`) and readiness (`GET /ready`) endpoints on both the local dashboard server and fleet hub. `/health` always responds in <1ms with process uptime, version, platform, and vault-exists flag. `/ready` runs four sub-checks — vault exists, vault readable, has ≥1 snapshot, SQLite `PRAGMA integrity_check` — and returns HTTP 200 only when all pass, 503 with a structured reason otherwise. Both endpoints bypass authentication and rate limiting, enabling use with external monitoring stacks (Nagios, Prometheus blackbox, cURL scripts). Core module: `orin.core.health`. |
| 55 | **Operational Metrics Endpoint** | `GET /api/metrics` surfaces a structured JSON snapshot of runtime state: **process** (PID, uptime, version, Python, platform), **vault** (file size, WAL size, snapshot count, host count, date range), **alerts** (total, unresolved, by-severity breakdown, last-7-day count, top-5 event types), **collection** (row counts for all 16 collector output tables), and **performance** (SQLite page size, page count, freelist, journal mode, cache, mmap, WAL autocheckpoint). Available on both the local dashboard server and fleet hub. Zero-dependency, read-only, timeout-bounded. Core module: `orin.core.health`. |
| 56 | **System Services Collector & Auditor** | Gathers systemd unit configurations, states (active, loaded, enabled), and maps service processes back to their owning user accounts. Provides full tabular dashboard rendering with visual status indicators. |
| 57 | **Network Kill Containment & Symbolic SUID Audit** | Enhances the forensic console with one-click process termination directly from split Listening/Active network connection tables, symbolic Unix permission conversion, and dynamic multi-column authentication log triage. |
---

## 🔧 Configuration & Tuning

### SQLite Performance Tuning

Orin includes comprehensive SQLite performance optimizations enabled by default:

```bash
# Initialize with custom pool size
export ORIN_DB_POOL_SIZE=20
export ORIN_DB_TIMEOUT=30

# Run collection with optimized database
sudo orin collect --vault-path /fast/storage/forensics.db
```

**Performance Benefits:**
- **Connection Pooling**: Reuses database connections across threads (default: 10 connections)
- **WAL Mode**: Enables concurrent reads during writes, improving throughput by 3-5x
- **Batch Inserts**: Groups records into chunks of 500-1000, reducing transaction overhead by ~90%
- **Memory-Mapped I/O**: 256MB mmap for faster page access
- **Large Page Cache**: 64MB cache reduces disk I/O for frequently accessed data

For implementation details and migration guide, see `SQLITE_PERFORMANCE_HARDENING.md`.

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
- **eBPF real-time streaming** — live telemetry capture via kernel ring buffer attaching to `execve`, `connect`, and `openat` syscalls. Events streamed to SQLite with nanosecond precision timestamps. Run `orin stream` to launch the consumer. Requires system `libbpf` library.
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
│       │   ├── agent_signing.py  # HMAC-SHA256 remote agent signing & verification
│       │   ├── config.py         # JSON config loader with safe defaults
│       │   ├── credentials.py    # Secure credential handling (passphrase-file, prompt, env)
│       │   ├── crypto.py         # HMAC-SHA256 sign & verify, AES-256-GCM vault encryption
│       │   ├── database.py       # SQLite schema (OrinStorage ORM) + connection pool + WAL
│       │   ├── health.py          # /health + /ready probes + /api/metrics endpoint
│       │   ├── hub_server.py     # Centralized fleet hub server (orin hub-serve)
│       │   ├── logging.py        # JSON structured logging, rotation, SIEM integration
│       │   ├── notifier.py       # Alert forwarding (webhooks, syslog, retry, audit log)
│       │   ├── rate_limiter.py   # SSH rate limiting with exponential backoff
│       │   ├── scanner.py        # SSH agentless remote scanner orchestrator
│       │   ├── scheduler.py      # Cron automation (orin schedule)
│       │   ├── self_defense.py   # Watchdog, AppArmor/SELinux/Seccomp hardening profiles
│       │   ├── self_verify.py    # Runtime self-integrity check & signed release verification
│       │   ├── server.py         # stdlib HTTP server + REST API + auto-token auth (orin serve)
│       │   ├── validators.py     # Input validation & sanitization (hostname, paths, IDs)
│       │   └── dashboard.html    # Single-page forensic console (served by server.py)
│       ├── collectors/
│       │   ├── connections.py        # /proc/net TCP/UDP socket parser
│       │   ├── crontabs.py           # Cron job harvester & anomaly detector
│       │   ├── deleted_binaries.py   # In-memory deleted executable recovery
│       │   ├── dns_forensics.py      # DNS tunneling & DGA detection
│       │   ├── ebpf.py               # eBPF program, pinned map & ld.so.preload auditor
│       │   ├── integrity.py          # SHA-256 FIM with stat-cache acceleration
│       │   ├── kernel.py             # LKM enumeration & kallsyms rootkit analysis
│       │   ├── logs.py               # Auth log & journald collection
│       │   ├── parallel.py           # ThreadPoolExecutor parallel collection engine
│       │   ├── persistence.py        # Persistence mechanism detection
│       │   ├── pkg_integrity.py      # Debian dpkg md5sums verification
│       │   ├── privilege_audit.py    # PAM/eBPF privilege escalation & credential tracking
│       │   ├── processes.py          # /proc process tree harvester
│       │   ├── promisc.py            # IFF_PROMISC flag auditor
│       │   ├── remote_agent.py       # Stdlib-only remote collection agent script (Python)
│       │   ├── remote_agent.sh       # Pure-bash fallback remote collection agent
│       │   ├── session_audit.py      # wtmp/lastlog binary log parser & anti-forensics detector
│       │   ├── suid.py               # SUID/SGID binary discovery & baselining
│       │   ├── triggered_pcap.py     # Zero-dependency PCAP capture on forensic triggers
│       │   └── users.py              # /etc/passwd & SSH authorized_keys inventory
│       └── analysis/
│           ├── diff.py       # Snapshot comparator
│           ├── engine.py     # Threat detection rules engine
│           ├── reporter.py   # Markdown & HTML report generator
│           ├── timeline.py   # Timeline delta calculator
│           └── unhide.py     # Hidden process detector
└── tests/                    # 52 test files, 968 tests, 85.18% coverage
```

---

## 🔧 Installation

> Requires **Python ≥ 3.10** and **psutil ≥ 5.9** (installed automatically).
> Optional: For real-time eBPF streaming, install system `libbpf` library.

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

Setup eBPF runtime dependencies using the automated script:
```bash
sudo ./scripts/setup_ebpf.sh
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
> Use `orin stream` for real-time eBPF telemetry (requires `libbpf` library).

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

# Keep only the last 10 snapshots per host, deleting older ones
sudo orin vault prune --keep-last 10 --execute

# Prune snapshots but disable critical alert preservation (forces deletion of snapshots with active critical alerts)
sudo orin vault prune --keep-last 10 --no-preserve-critical --execute
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
- PBKDF2-HMAC-SHA256 key derivation with 600,000 iterations (OWASP recommendation, with legacy support for 100,000 iteration vaults)
- Best-effort in-memory zeroisation of sensitive secrets, passphrases, and keys immediately after usage
- Secure CLI secret inputs (`--secret-file`, `--secret-prompt`, `--secret-env-var`) for diff/export/verify operations to avoid shell history leakage
- Immediate eviction of vault credentials and secrets from environment variables (`os.environ`) upon retrieval
- Random salt per vault instance
- Tamper detection on decryption
- Graceful fallback to unencrypted mode when passphrase not provided

### 🔒 SSH Security Hardening (v1.1.1)

Orin now includes comprehensive SSH security controls for agentless fleet operations:

**Configurable Host Key Verification:**
```json
{
  "ssh": {
    "strict_host_key_checking": "ask",  // Options: "yes", "ask", "accept-new", "no"
    "known_hosts_file": "/var/lib/orin/ssh_known_hosts",
    "connection_timeout": 30,
    "max_retries": 3
  }
}
```

**Rate Limiting Protection:**
```json
{
  "ssh": {
    "rate_limit": {
      "max_concurrent": 5,
      "delay_between_scans": 1.0,
      "max_scans_per_minute": 10,
      "backoff_factor": 2.0,
      "max_backoff_seconds": 60
    }
  }
}
```

**Benefits:**
- ✅ MITM attack prevention with configurable host key verification
- ✅ Avoids IDS/IPS triggers with intelligent rate limiting
- ✅ Exponential backoff on failures prevents resource exhaustion
- ✅ Per-host rate tracking with thread-safe semaphore control
- ✅ Comprehensive audit logging for all SSH operations

See [`SSH_SECURITY_CONFIGURATION_IMPROVEMENTS.md`](docs/SSH_SECURITY_CONFIGURATION_IMPROVEMENTS.md) and [`SSH_RATE_LIMITING_IMPROVEMENTS.md`](docs/SSH_RATE_LIMITING_IMPROVEMENTS.md) for detailed documentation.

---

### 📡 Alert Forwarding Configuration

Enable push notifications so critical alerts reach analysts without dashboard polling. All transports use Python stdlib — no cloud dependencies required.

```json
{
  "notifications": {
    "enabled": true,
    "min_severity": "high",
    "syslog": {
      "enabled": true,
      "facility": "LOG_LOCAL0",
      "tag": "orin-alert"
    },
    "webhooks": [
      {
        "name": "ops-slack",
        "url": "http://192.168.1.10:8080/slack-webhook",
        "format": "slack",
        "min_severity": "critical",
        "timeout_seconds": 10,
        "enabled": true
      },
      {
        "name": "soc-teams",
        "url": "http://192.168.1.20:9000/teams-webhook",
        "format": "teams",
        "headers": { "X-Auth-Token": "your-token-here" },
        "enabled": true
      },
      {
        "name": "siem-generic",
        "url": "http://192.168.1.30:5000/alerts",
        "format": "generic",
        "enabled": true
      }
    ],
    "retry": {
      "max_attempts": 3,
      "backoff_seconds": 5
    },
    "audit_log": "/var/log/orin/notification_audit.log"
  }
}
```

**Supported formats:** `slack` (Block Kit), `teams` (Adaptive Card), `generic` (flat JSON).
**Per-webhook `min_severity`** overrides the global filter for fine-grained routing.
**All webhook failures are retried** with exponential backoff and written to the audit log — they never abort the analysis cycle.

---

## 🧪 Running Tests

For comprehensive developer onboarding and testing guidelines, see [TESTING.md](docs/TESTING.md).

```bash
# Run full test suite with coverage
venv/bin/pytest --cov=src

# Legacy unittest runner
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

**968 tests · 85.18% line coverage across 52 test files**

| Test file | Coverage area |
|-----------|--------------|
| `test_agent_signing.py` | HMAC-SHA256 agent signing, tamper detection, key enforcement |
| `test_ai.py` | Local AI Triage multi-host correlation engine and CLI commands |
| `test_attck.py` | MITRE ATT&CK mapping, technique lookups |
| `test_baseline.py` | Relational threat scoring correlation rules, baseline CLI commands (add, refresh) |
| `test_config.py` | Config loading, deep-copy isolation, defaults, validation |
| `test_connection_pool_race_conditions.py` | Thread-safe connection pooling, race condition prevention, stress testing |
| `test_connections.py` | IPv4 & IPv6 socket parsing |
| `test_coverage_boost.py` | Branch & edge-case coverage across multiple modules |
| `test_credentials.py` | Secure passphrase handling (file, prompt, env-var), 0600 validation |
| `test_crontabs.py` | Cron line parser edge cases |
| `test_crypto.py` | HMAC sign/verify, AES-256-GCM vault encryption, tamper detection |
| `test_database.py` | Schema creation, connection management, stat-cache migration |
| `test_database_extended.py` | Extended schema paths, ORM edge cases |
| `test_database_performance.py` | WAL mode, batch inserts, connection pool throughput |
| `test_deleted_binaries.py` | In-memory executable recovery |
| `test_diff.py` | Snapshot comparator, drift detection |
| `test_dns_forensics.py` | DNS tunneling detection, DGA analysis, entropy calculations |
| `test_ebpf.py` | eBPF programs, pinned map/prog objects, ld.so.preload, anomalous file descriptor audits |
| `test_encryption_exceptions.py` | Encryption error handling, atomic writes, tamper detection, failure recovery |
| `test_engine.py` | Detection rules, risk scoring, suppression, auto-resolution, YARA scanning |
| `test_health.py` | Health & readiness probes, operational metrics, sub-check logic, error paths |
| `test_hub_server.py` | Fleet hub multi-tenant API, admin auth, rate limiting, audit logging, heartbeats |
| `test_input_validation.py` | Hostname/IP validation, input sanitization, path traversal prevention |
| `test_integrity.py` | File integrity monitoring, stat-cache acceleration |
| `test_ioc_importer.py` | STIX/TAXII/CSV IOC import, indicator normalization |
| `test_ioc_importer_unit.py` | IOC importer unit-level parsing & normalization |
| `test_kernel.py` | Kernel module auditing, rootkit symbol detection |
| `test_logs.py` | Log collection, journald parsing |
| `test_main.py` | CLI subcommand routing, argument parsing |
| `test_notifier.py` | Alert forwarding (Slack/Teams/generic webhooks, syslog, retry, audit log, severity filters) |
| `test_parallel.py` | ThreadPoolExecutor parallel collection, timeouts, error resilience |
| `test_persistence.py` | Persistence mechanism detection, config harvesting |
| `test_pkg_integrity.py` | MD5 mismatch detection, lazy SHA-256 |
| `test_privilege_audit.py` | PAM log parsing, privilege escalation syscalls, credential access tracking |
| `test_processes.py` | Process tree harvesting, /proc parsing |
| `test_promisc.py` | Promiscuous mode auditing |
| `test_rate_limiter.py` | SSH rate limiting, concurrent connection control, exponential backoff |
| `test_reporter.py` | Markdown and HTML report generation |
| `test_rootkit.py` | Hidden module cross-reference, kallsyms pattern matching, unhide integration |
| `test_scanner.py` | Agentless SSH scanner remote execution mocking |
| `test_scheduler.py` | Cron install/remove, system vs. user fallback |
| `test_self_defense.py` | Watchdog service, AppArmor/SELinux/Seccomp profile deployment |
| `test_self_verify.py` | Runtime self-integrity checks, signed release verification |
| `test_server.py` | HTTP routing, API endpoints, Bearer token auth |
| `test_session_audit.py` | wtmp/lastlog parsing, anti-forensics detection |
| `test_sigma.py` | Sigma rule evaluation, authentication log parsing |
| `test_sigma_extended.py` | Extended Sigma rule scenarios, journald integration |
| `test_suid.py` | SUID/SGID file discovery, permissions, and hashing |
| `test_timeline.py` | Timeline delta calculation, snapshot comparison |
| `test_triggered_pcap.py` | Triggered packet capture, PCAP generation, Scapy integration |
| `test_unhide.py` | Hidden process detector |
| `test_users.py` | User account enumeration, SSH key inventory |
| `test_yara_engine.py` | YARA rule parsing, memory & file scanning, pre-built rule sets |
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