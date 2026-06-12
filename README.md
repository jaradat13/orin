<p align="center">
  <img src="assets/orin-logo.svg" alt="Orin Logo" width="200">
</p>

# Orin — Offline Linux Forensics & Integrity Engine

> Host security scanner and forensic triage tool for Linux — built for analysts who trust nothing but the kernel itself. **Designed for air-gapped, offline, and forensically sensitive environments.**

[![CI](https://github.com/jaradat13/orin/actions/workflows/test.yml/badge.svg)](https://github.com/jaradat13/orin/actions/workflows/test.yml)
![Version](https://img.shields.io/badge/version-v1.2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/runtime_deps-stdlib_%2B_libbpf_(optional)-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux&logoColor=white)
![License](https://img.shields.io/badge/license-AGPLv3-blue)
![Category](https://img.shields.io/badge/category-DFIR-blue)
![MITRE ATT&CK Mapped](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red)
![Issues](https://img.shields.io/github/issues/jaradat13/orin)
![Stars](https://img.shields.io/github/stars/jaradat13/orin?style=social)

Orin takes point-in-time snapshots of critical OS state, compares them against trusted
baselines, identifies anomalous behaviour, and produces tamper-evident evidence bundles.
**Zero network access required. Zero telemetry. Zero cloud dependencies.** Built for
air-gapped networks, classified environments, and forensically sensitive systems.

See [docs/STATUS.md](docs/STATUS.md) for supported platforms, deployment assumptions,
and known limitations, and [docs/ROADMAP.md](docs/ROADMAP.md) for project direction.

```bash
# Install
chmod +x install.sh && ./install.sh

# First run — init only needs to be run once, to create the vault and baselines
sudo orin init
sudo orin collect
sudo orin analyze
sudo orin report

# Automate collection every 10 minutes via cron
sudo orin schedule --install

# Launch the local web dashboard
sudo orin serve

# Scan a remote host over SSH and baseline it
# (uses a stdlib-only Python agent; falls back to a pure-Bash agent if Python is absent — see docs/SSH_GUIDE.md)
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

Most Linux security tools require a persistent daemon, a cloud backend, network
connectivity, or a pile of third-party packages. That's a non-starter on hardened,
air-gapped, classified, or forensically sensitive systems where **zero external trust**
is the requirement.

| | Orin | Falco | osquery | Wazuh |
|---|---|---|---|---|
| **Runtime dependencies** | stdlib (+ libbpf optional) | Kernel driver / eBPF | Standalone binary | Agent + manager |
| **Network required** | **Never** | Optional | Optional | **Yes (manager)** |
| **Cloud dependencies** | **Zero** | Optional | Optional | **Required** |
| **Air-gap safe** | ✅ Out-of-the-box | ⚠️ Complex setup | ⚠️ Complex setup | ❌ Requires manager |
| **Multi-tenant hub** | ✅ Admin auth, rate limiting, audit logs | ❌ | ❌ | ⚠️ Manager-only |
| **Offline threat intel** | ✅ STIX/CSV/TAXII importer | ❌ | ❌ | ❌ |
| **Forensic evidence signing** | ✅ HMAC-SHA256 + AES-256-GCM | ❌ | ❌ | ❌ |
| **Reads directly from `/proc`** | ✅ | ✅ | ✅ | ⚠️ Rootcheck only |
| **Anti-forensics detection** | ✅ wtmp/lastlog | ❌ | ❌ | ❌ |
| **Local AI triage** | ✅ Ollama integration | ❌ | ❌ | ❌ |
| **Real-time eBPF streaming** | ✅ Ring-buffer consumer | ✅ Full IDS | ⚠️ Via extensions | ❌ Agent-based |

**Orin is built for:** security engineers, forensic analysts, incident responders, and
sysadmins working in air-gapped environments, SCIFs, classified networks, industrial
control systems, and high-security infrastructure where cloud connectivity is
prohibited and every byte of telemetry must remain on-premises.

---

## 🛠️ Capabilities

| # | Module | Description |
|---|--------|-------------|
| 1 | **Process Tree Harvester** | Reads `/proc/[pid]/stat`, `/comm`, `/exe`, `/cmdline` to build a full PPID-linked process tree. |
| 2 | **Network Socket Auditor** | Parses `/proc/net/{tcp,tcp6,udp,udp6}` for IPv4/IPv6 listening ports and outbound connections. |
| 3 | **Kernel Module & Symbol Auditor** | Reads `/proc/modules` and `/proc/kallsyms`. Detects unlinked modules hiding from `/proc/modules`, suspicious symbol overrides, credential-manipulation symbols in third-party modules, and known rootkit patterns. |
| 4 | **User & SSH Key Inventory** | Harvests `/etc/passwd` and all `~/.ssh/authorized_keys` for account and key fingerprint tracking. |
| 5 | **File Integrity Monitor (FIM)** | SHA-256 checksums for configured critical paths. Stat-cache (`mtime`/`ctime`/`size`) compared against the previous snapshot first — hashing is skipped for unchanged files. |
| 6 | **Auth Log Parser & Sigma Engine** | Scans authentication logs and `journald` records with a zero-dependency Sigma evaluator and dynamic MITRE ATT&CK tagging. |
| 7 | **In-Memory Executable Recovery** | Resolves `/proc/[pid]/exe` symlinks to detect processes whose binaries were deleted from disk, dumps the payload, logs MD5 & SHA-256. |
| 8 | **Promiscuous Mode Flag Auditor** | Reads `/sys/class/net/*/flags`; alerts when `IFF_PROMISC` (`0x100`) is set. |
| 9 | **Binary Session Auditor** | Parses `/var/log/wtmp` and `/var/log/lastlog` to track login/logout lifecycles and detect anti-forensic tampering (zeroed records, epoch resets). |
| 10 | **Hidden Process Detector** | Probes scheduler-active PIDs via null signaling (`os.kill(pid, 0)`) and cross-references `/proc` to expose kernel rootkits. |
| 11 | **Offline Package Integrity Engine** | Verifies binaries against Debian `/var/lib/dpkg/info/*.md5sums`. MD5 first pass; SHA-256 computed lazily only on confirmed tamper. |
| 12 | **Scheduled Task (Crontab) Harvester** | Parses user crontabs, `/etc/crontab`, `/etc/cron.d/*`, and timed script directories. Detects drift, volatile-path execution, reverse-shell commands. |
| 13 | **Threat Detection Rules Engine** | Evaluates collected data for masquerading processes, reverse shells, C2 hits, SSH persistence, FIM changes, unauthorized accounts, cron anomalies. Supports suppression rules and severity overrides. |
| 14 | **Forensic Alert Auto-Resolution** | Closes historical alerts once the anomalous condition no longer appears in later snapshots. |
| 15 | **Cryptographic Evidence Export** | Serialises snapshots to deterministic JSON, signs with HMAC-SHA256, wraps in a portable `{signature, data}` bundle. |
| 16 | **Markdown & HTML Reporting** | Lightweight Markdown briefings and self-contained dark-mode HTML dashboards with tabbed navigation and severity badges. |
| 17 | **Local Web Dashboard (`orin serve`)** | stdlib HTTP server with a live risk gauge, severity-tiered alert feed with triage actions, a Telemetry Explorer, inline process termination (local/remote), and timeline delta shortcuts. Zero JS dependencies. |
| 18 | **Automated Collection Scheduler (`orin schedule`)** | Installs a system or user cron job running `collect → analyze` on a configurable interval (default 10 min). Logs to syslog. |
| 19 | **Dashboard Auto-Token Security** | Each `orin serve` start generates a random 256-bit session token (`secrets.token_hex(32)`), printed to the terminal. Requests validated via `hmac.compare_digest()`. Ephemeral per restart. |
| 20 | **SUID/SGID Binary Monitor** | Discovers on-disk SUID/SGID executables and alerts on modified/new ones vs. baseline. |
| 21 | **Agentless SSH Fleet Scanner** | Profiles remote hosts via a stdlib-only Python agent with pure-Bash fallback. Covers routers, stripped containers, and Python-less systems. See [docs/SSH_GUIDE.md](docs/SSH_GUIDE.md). |
| 22 | **eBPF & File Descriptor Auditor** | Audits loaded eBPF programs, pinned `/sys/fs/bpf` objects, `/etc/ld.so.preload` overrides, and suspicious open FDs (deleted files, anonymous `memfd`). |
| 23 | **Baseline Manager (`orin baseline`)** | Incremental (`--user`, `--module`, `--suid`) or full (`--force-overwrite`) baseline refreshes for local and remote hosts. |
| 24 | **Local AI Forensic Triage (`orin correlate`)** | Aggregates unresolved alerts across hosts and uses a local Ollama model for correlation briefs and remediation advice. Fully offline. |
| 25 | **Offline Threat Intel Importer** | Multi-format IOC importer: STIX 2.x JSON/XML, CSV, TAXII 2.x, plain-text blocklists. Normalizes to a unified format. Zero network egress. |
| 26 | **MITRE ATT&CK Mapper** | Zero-dependency static lookup mapping Orin event types to ATT&CK technique IDs, tactics, and reference URLs. |
| 27 | **Snapshot Comparator (`orin diff`)** | Compares two snapshots (SQLite vaults or signed JSON exports) with structured drift reports and integrity verification. |
| 28 | **Timeline Delta Calculator (`orin delta`)** | Computes structural differences between two snapshot IDs in the vault, surfacing triggered events and port/process/connection deltas. |
| 29 | **Encrypted Evidence Vault** | AES-256-GCM at rest, PBKDF2-HMAC-SHA256 (600,000 iterations, with legacy support for 100,000-iteration vaults), random salt, automatic lifecycle. Enabled via `ORIN_VAULT_PASSPHRASE`, falls back to unencrypted mode gracefully. |
| 30 | **Embedded YARA Engine & FIM** | Offline YARA pattern matching against files and dumped memory binaries. Pre-built rules for miners, malware tools, rootkits, webshells, suspicious strings. FIM-accelerated — only modified files are scanned. |
| 31 | **Deep DNS Forensics & Tunneling Detection** | Detects DNS tunneling and DGA domains via Shannon entropy, structural analysis, TXT-record abuse, per-process profiling, IOC matching, and live `/proc/net` monitoring. |
| 32 | **Triggered PCAP Capture Engine** | Zero-dependency packet capture on forensic triggers; Scapy-based reconstruction when available, raw PCAP fallback otherwise. |
| 33 | **Agent Self-Defense Hardening** | AppArmor/SELinux profiles and Seccomp-BPF syscall filtering restrict Orin's own attack surface. Profiles in `assets/security-profiles/`. |
| 34 | **Identity, Access & Privilege Tracking** | PAM log parsing, eBPF probe detection, syscall audit analysis, and credential-access tracking. Detects auth events, sudo/SSH logins, privilege escalation syscalls, credential dumping. MITRE-mapped (T1548, T1078, T1552). |
| 35 | **eBPF Ring-Buffer Real-Time Streamer** | Streams real-time security events via kernel ring buffer (`sys_enter_execve`, `sys_enter_connect`, `sys_enter_openat`) into SQLite with nanosecond timestamps. Run via `orin stream`. Requires system `libbpf`. See [docs/EBPF_TROUBLESHOOTING.md](docs/EBPF_TROUBLESHOOTING.md). |
| 36 | **Read-Only & Ephemeral Modes** | `--read-only` prevents any vault writes; `--vault-path` allows any writable location (USB, tmpfs) for ephemeral operation. |
| 37 | **Vault Lifecycle Management** | `orin vault stats` shows size, snapshot count, utilization. `orin vault prune` deletes old snapshots by age or count, with dry-run and auto-vacuum. |
| 38 | **Pruning & Retention Controls** | Age- or count-based deletion preserving snapshots tied to active critical alerts (disable with `--no-preserve-critical`). Dry-run preview and syslog audit logging. |
| 39 | **Credential Handling** | `--passphrase-file` (0600-validated), `--passphrase-prompt` (masked), `--passphrase-env-var`. Dashboard tokens persisted via `--token-file` with 0600 permissions. |
| 40 | **Tool Self-Verification & Signed Releases** | GPG-signed release manifests with SHA-256 checksums, embedded SBOM (`orin version --sbom`), and runtime `--self-check` against embedded module hashes. |
| 41 | **Centralized Air-Gapped Fleet Hub (`orin hub-serve`)** | Multi-tenant server: bcrypt admin auth, per-host API keys, rate limiting, audit logging, heartbeat monitoring, data import/export, HTTPS (`--cert`/`--key`), flexible credential handling. |
| 42 | **Structured Logging (JSON)** | JSON logs to stderr/file with severity levels, rotation, thread-safe operation, and SIEM-friendly fields (timestamp, hostname, component, PID, context). |
| 43 | **Agent Script Signing** | HMAC-SHA256 signing/verification for the remote SSH agent. See [docs/AGENT_SIGNING.md](docs/AGENT_SIGNING.md). |
| 44 | **Dashboard API Endpoints** | `/api/alerts`, `/api/diff`, `/api/telemetry/{snapshot_id}`, `/api/config` — real-time visualization, risk scoring, process termination, timeline comparison. Zero external JS. |
| 45 | **SQLite Performance Hardening** | WAL mode, connection pooling, chunked batch inserts, tuned PRAGMAs. See [docs/DATABASE_INTERNALS.md](docs/DATABASE_INTERNALS.md). |
| 46 | **Test Suite** | Tests across core modules: AI correlation, ATT&CK mapping, baselines, crypto/vault, database, diff, DNS forensics, eBPF, engine logic, FIM, fleet hub, IOC import, kernel auditing, logging, package integrity, parallel collection, privilege audit, processes, promiscuous mode, rate limiting, reporting, rootkit detection, scanning, scheduling, self-defense, self-verification, server, session audit, Sigma, SUID, timeline, triggered PCAP, unhide, users, YARA. CI enforces an 85% coverage gate. See [docs/TESTING.md](docs/TESTING.md). |
| 47 | **Parallel Collection Engine** | `ThreadPoolExecutor`-based concurrent collection (`orin collect --parallel`). See [docs/PARALLEL_COLLECTION.md](docs/PARALLEL_COLLECTION.md). |
| 48 | **Remote Agent Signing & Verification** | Dual-layer (hash + HMAC) integrity checks, constant-time comparison, optional GPG layering, multi-agent manifests. Core module: `orin.core.agent_signing`. |
| 49 | **Exception Handling & Atomic Write Safety** | Encryption/decryption wrapped in `try/finally` with atomic temp-file writes; no plaintext evidence left on failure. See [docs/DATABASE_INTERNALS.md](docs/DATABASE_INTERNALS.md). |
| 50 | **Thread-Safe Connection Pool** | Lock-ordered, health-checked pool eliminating deadlocks and leaks under concurrent load. See [docs/DATABASE_INTERNALS.md](docs/DATABASE_INTERNALS.md). |
| 51 | **Input Validation & Sanitization** | `validators.py` provides allowlist-based hostname/IP checks, snapshot ID bounds, path-traversal-safe resolution, and bounded numeric inputs. All queries parameterized. |
| 52 | **Configuration Security & Deep-Copy Isolation** | `config.py` deep-copies defaults so user config never mutates built-in defaults. Threat-intel and rules paths externalized to `orin_config.json`. Validation rejects out-of-range/type-incorrect values before any run. |
| 53 | **Alert Forwarding Framework** | Slack Block Kit, Microsoft Teams Adaptive Cards, generic JSON webhooks, and syslog. Per-channel severity filters, exponential-backoff retry, JSONL audit log. stdlib-only (`urllib.request`). See [Alert Forwarding](#-alert-forwarding) below. |
| 54 | **Health & Readiness Probes** | `GET /health` (always <1ms: uptime, version, platform, vault-exists) and `GET /ready` (vault exists/readable, has snapshots, `PRAGMA integrity_check` — 200 only if all pass, else 503). Unauthenticated, on both dashboard and hub. |
| 55 | **Operational Metrics Endpoint** | `GET /api/metrics`: process, vault (size/WAL/snapshot count/host count/date range), alerts (totals, by severity, recent, top event types), collection row counts, and SQLite performance stats. Read-only, zero-dependency. |
| 56 | **System Services Collector & Auditor** | Gathers systemd unit configs/states (active, loaded, enabled), maps service processes to owning accounts, with dashboard rendering. |
| 57 | **Network Kill Containment & Symbolic SUID Audit** | One-click process termination from connection tables, symbolic Unix permission display, multi-column auth log triage in the dashboard. |

---

## ⚡ Performance Notes

- **Stat-Based FIM Cache** — `os.stat()` (`mtime`, `ctime`, `size`) is compared against
  the last snapshot before any SHA-256 hash is computed; unchanged files are never read.
- **Lazy SHA-256 in Package Integrity** — MD5 is checked first against dpkg records;
  SHA-256 is only computed when an MD5 mismatch is confirmed.

---

## 📂 Project Structure

```
orin/
├── orin_config.json          # User configuration (optional)
├── install.sh                # Automated installer
├── pyproject.toml            # Packaging metadata
├── src/orin/
│   ├── main.py                   # CLI entry point & subcommand router
│   ├── core/
│   │   ├── agent_signing.py      # HMAC-SHA256 remote agent signing & verification
│   │   ├── config.py             # JSON config loader with safe defaults
│   │   ├── credentials.py        # Secure credential handling
│   │   ├── crypto.py             # HMAC-SHA256 signing, AES-256-GCM vault encryption
│   │   ├── database.py           # SQLite ORM, connection pool, WAL
│   │   ├── health.py             # /health, /ready, /api/metrics
│   │   ├── hub_server.py         # Fleet hub server (orin hub-serve)
│   │   ├── logging.py            # JSON structured logging, rotation, SIEM integration
│   │   ├── notifier.py           # Alert forwarding (webhooks, syslog, retry, audit log)
│   │   ├── rate_limiter.py       # SSH rate limiting with exponential backoff
│   │   ├── scanner.py            # SSH agentless scanner orchestrator
│   │   ├── scheduler.py          # Cron automation (orin schedule)
│   │   ├── self_defense.py       # AppArmor/SELinux/Seccomp hardening
│   │   ├── self_verify.py        # Runtime self-integrity check
│   │   ├── server.py             # HTTP server + REST API + auto-token auth (orin serve)
│   │   ├── validators.py         # Input validation & sanitization
│   │   └── dashboard.html        # Single-page forensic console
│   ├── collectors/
│   │   ├── connections.py        # /proc/net TCP/UDP socket parser
│   │   ├── crontabs.py           # Cron job harvester & anomaly detector
│   │   ├── deleted_binaries.py   # In-memory deleted executable recovery
│   │   ├── dns_forensics.py      # DNS tunneling & DGA detection
│   │   ├── ebpf.py               # eBPF program, pinned map & ld.so.preload auditor
│   │   ├── integrity.py          # SHA-256 FIM with stat-cache acceleration
│   │   ├── kernel.py             # LKM enumeration & kallsyms rootkit analysis
│   │   ├── logs.py                # Auth log & journald collection
│   │   ├── parallel.py           # ThreadPoolExecutor parallel collection engine
│   │   ├── persistence.py        # Persistence mechanism detection
│   │   ├── pkg_integrity.py      # dpkg md5sums verification
│   │   ├── privilege_audit.py    # PAM/eBPF privilege escalation & credential tracking
│   │   ├── processes.py          # /proc process tree harvester
│   │   ├── promisc.py            # IFF_PROMISC flag auditor
│   │   ├── remote_agent.py       # Stdlib-only remote collection agent (Python)
│   │   ├── remote_agent.sh       # Pure-bash fallback remote agent
│   │   ├── session_audit.py      # wtmp/lastlog parser & anti-forensics detector
│   │   ├── suid.py                # SUID/SGID discovery & baselining
│   │   ├── triggered_pcap.py     # PCAP capture on forensic triggers
│   │   └── users.py               # /etc/passwd & SSH authorized_keys inventory
│   └── analysis/
│       ├── diff.py            # Snapshot comparator
│       ├── engine.py          # Threat detection rules engine
│       ├── reporter.py        # Markdown & HTML report generator
│       ├── timeline.py        # Timeline delta calculator
│       └── unhide.py          # Hidden process detector
└── tests/                     # see docs/TESTING.md
```

---

## 🔧 Installation

> Requires **Python ≥ 3.10**. Optional: system `libbpf` for real-time eBPF streaming.

**Method A — automated installer (recommended)**
```bash
chmod +x install.sh
./install.sh
```

**Method B — system-wide (for root forensic workflows)**
```bash
sudo pip install . --break-system-packages
```

**Method C — development mode**
```bash
pip install -e .
PYTHONPATH=src python -m orin.main <subcommand>
```

**Optional — enable eBPF real-time streaming**

Target/runtime hosts only need the system `libbpf` shared library
(`libbpf1`/`libbpf0` on Debian/Ubuntu, `libbpf` on RHEL family) — no compiler or
kernel headers required. If you're modifying the eBPF source itself, build with:

```bash
sudo ./scripts/setup_ebpf.sh --build
```

This installs the build toolchain (`clang`, `llvm`, `bpftool`, `libbpf-dev`) and
generates `vmlinux.h`. See [docs/EBPF_TROUBLESHOOTING.md](docs/EBPF_TROUBLESHOOTING.md)
for kernel/BTF requirements and common errors.

---

## 📖 Usage

All subcommands that read privileged files produce richer results when run as root.

```
init → collect → analyze → report
        ↓
      delta / diff / export / verify / serve / schedule / stream
```

> [!TIP]
> Use `orin schedule --install` to automate the `collect → analyze` cycle.
> Use `orin stream` for real-time eBPF telemetry (requires `libbpf`).

### `orin init`
Creates the SQLite vault and records two immutable baselines: trusted kernel modules
and trusted user accounts.

```bash
sudo orin init
```

### `orin scan`
Agentless remote scan over SSH (see [docs/SSH_GUIDE.md](docs/SSH_GUIDE.md)).

```bash
sudo orin scan --host 192.168.1.50 --user root --init
```

### `orin collect`
Harvests a full system state snapshot and persists it to the vault.

```bash
sudo orin collect
sudo orin collect --parallel --workers 4   # see docs/PARALLEL_COLLECTION.md
```

### `orin analyze`
Runs all threat-detection rules against the latest snapshot and prints a
severity-tiered risk score (0-100).

```bash
sudo orin analyze
```

### `orin report`
Compiles a forensic audit briefing from the latest snapshot and unresolved alerts.

```bash
sudo orin report --format html --output /tmp/orin_report.html
```

### `orin stream` (optional)
Launches the eBPF real-time telemetry consumer — streams `execve`, `connect`, and
`openat` events via the kernel ring buffer into SQLite.

```bash
sudo orin stream --verbose
```

### `orin serve`
Starts a local-only forensic web console on `127.0.0.1:8000`, printing a one-time
session token to the terminal.

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

# Keep only the last 10 snapshots per host
sudo orin vault prune --keep-last 10 --execute

# Prune but disable critical-alert preservation
sudo orin vault prune --keep-last 10 --no-preserve-critical --execute
```

---

## ⚙️ Configuration

Orin searches for `orin_config.json` in `./` then `/etc/orin/`, falling back to
built-in defaults. The example below covers the most commonly tuned keys — for the
full reference (all config keys, environment variables, and CLI credential flags),
see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

```json
{
  "expected_ports": [22, 80, 443, 631, 3306, 5432, 6379, 8080, 8443],
  "whitelisted_processes": ["code", "chrome", "language_server"],
  "critical_paths": ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/crontab"],
  "critical_dirs": ["/etc/cron.d", "/etc/systemd/system"]
}
```

### 🔐 Encrypted Evidence Vault

```bash
export ORIN_VAULT_PASSPHRASE="your-strong-passphrase-here"
sudo orin init
sudo orin collect
# All snapshot data is encrypted before SQLite storage.
# Without a passphrase, the vault operates unencrypted (backward compatible).
```

- AES-256-GCM authenticated encryption (confidentiality + integrity)
- PBKDF2-HMAC-SHA256, 600,000 iterations (legacy 100,000-iteration vaults still supported)
- Best-effort in-memory zeroisation of secrets immediately after use
- Secure CLI secret input (`--secret-file`, `--secret-prompt`, `--secret-env-var`) avoids shell-history leakage
- Vault credentials evicted from `os.environ` upon retrieval
- Random salt per vault; tamper detection on decryption; graceful fallback when no passphrase is set

### 🔒 SSH Security & Rate Limiting

See [docs/SSH_GUIDE.md](docs/SSH_GUIDE.md) for host key verification modes and rate
limiting configuration.

### 📡 Alert Forwarding

Push critical alerts to analysts without dashboard polling — Slack, Teams, generic
webhooks, and syslog, all via stdlib `urllib.request`. Example:

```json
{
  "notifications": {
    "enabled": true,
    "min_severity": "high",
    "syslog": { "enabled": true, "facility": "LOG_LOCAL0", "tag": "orin-alert" },
    "webhooks": [
      { "name": "ops-slack", "url": "http://192.168.1.10:8080/slack-webhook", "format": "slack", "min_severity": "critical", "timeout_seconds": 10, "enabled": true },
      { "name": "soc-teams", "url": "http://192.168.1.20:9000/teams-webhook", "format": "teams", "headers": { "X-Auth-Token": "your-token-here" }, "enabled": true },
      { "name": "siem-generic", "url": "http://192.168.1.30:5000/alerts", "format": "generic", "enabled": true }
    ],
    "retry": { "max_attempts": 3, "backoff_seconds": 5 },
    "audit_log": "/var/log/orin/notification_audit.log"
  }
}
```

Formats: `slack` (Block Kit), `teams` (Adaptive Card), `generic` (flat JSON).
Per-webhook `min_severity` overrides the global filter. Failed webhooks retry with
exponential backoff and are written to the audit log — they never abort the analysis
cycle. Dispatched automatically after every `orin analyze`. Core module:
`orin.core.notifier`.

---

## 🛡️ Threat Detection

See [docs/THREAT_DETECTION.md](docs/THREAT_DETECTION.md) for the full rule set.

---

## 🗄️ Database Schema

See [docs/SCHEMA.md](docs/SCHEMA.md).

---

## 🧪 Testing

See [docs/TESTING.md](docs/TESTING.md) for environment setup, running tests, and
coverage requirements.

```bash
ORIN_TEST_FAST=1 pytest --cov=orin --cov-report=term-missing
```

---

## 🤝 Contributing

Contributions are welcome. Before opening a PR:

- Run the test suite (`ORIN_TEST_FAST=1 pytest`) and confirm the 85% coverage gate
  still passes — see [docs/TESTING.md](docs/TESTING.md).
- New test files belong in `tests/`, prefixed `test_*.py`.
- Check [docs/ROADMAP.md](docs/ROADMAP.md) for current priorities and open work before
  starting something large, to avoid duplicated effort.
- Keep collectors stdlib-only where possible — Orin's zero-dependency posture is a
  core design constraint, not an accident.

## 🔒 Security

To report a vulnerability, **do not open a public issue** — see
[docs/SECURITY.md](docs/SECURITY.md) for the private disclosure process and response
timelines.

---

## License

GNU AGPLv3 — see [LICENSE](LICENSE) for details.