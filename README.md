# Orin — Offline Linux Forensics & Integrity Engine

> **Fully offline, zero-dependency** host security scanner and forensic triage tool for Linux systems.

![CI](https://github.com/jaradat13/orin/actions/workflows/test.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/runtime_deps-zero-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center">
  <img src="assets/orin_preview.png" alt="Orin Logo and Terminal Interface" width="600">
</p>

Orin takes point-in-time snapshots of critical OS metrics, compares them against trusted baselines, identifies anomalous behaviour, and produces tamper-evident evidence bundles — all without any external Python packages or network access.

---

## ✨ Features

### 🔬 Low-Level Telemetry Collection
Orin reads directly from Linux kernel interfaces — no shell subprocesses, no third-party libraries.

| Collector | Source | What is captured |
|-----------|--------|-----------------|
| **Processes** | `/proc/[pid]/stat`, `/comm`, `/exe`, `/cmdline` | Full process tree with PPID ancestry |
| **Listening ports** | `/proc/net/{tcp,tcp6,udp,udp6}` | IPv4 & IPv6 TCP/UDP sockets mapped to owning PID |
| **Outbound connections** | `/proc/net/{tcp,tcp6}` | Established non-loopback IPv4 & IPv6 sessions |
| **Kernel modules** | `/proc/modules` | Loaded LKMs (name, size, instance count) |
| **User accounts** | `/etc/passwd` | UID, GID, home directory, login shell |
| **SSH authorised keys** | `~/.ssh/authorized_keys` | Key type, SHA-256 fingerprint, comment |
| **File integrity (FIM)** | Configurable paths & dirs | SHA-256 checksums for critical files |
| **Auth logs** | `/var/log/auth.log` | SSH brute-force IPs, privilege changes |
| **Deleted binaries** | `/proc/[pid]/exe` symlinks | In-memory executable recovery & cryptographic hashes |
| **Promiscuous mode** | `/sys/class/net/[interface]/flags` | Network sniffing interface flag audits |
| **Session audit** | `/var/log/wtmp`, `/var/log/lastlog` | Precise login/logout lifecycles, IP sources, and anti-forensics alerts |
| **Package integrity** | `/var/lib/dpkg/info/*.md5sums` | Core system binaries hash verification vs. dpkg records |

### 🛡️ Threat Detection Rules Engine
- **Kernel thread masquerade** — flags processes mimicking kernel workers (`kworker`, `ksoftirqd`, …) with a non-system PPID.
- **Reverse shell detection** — matches dangerous invocation patterns (`python -c`, `bash -i`, `sh -i`).
- **Volatile-directory execution** — processes running from `/tmp`, `/dev/shm`, `/var/tmp`.
- **Known-bad binaries** — `nc`, `ncat`, `netcat`, `socat`, `nmap`, `xmrig`, and more.
- **C2 blocklist** — compares outbound connections against an offline IP blocklist.
- **SSH persistence detection** — new keys appearing between snapshots.
- **File integrity monitoring** — SHA-256 hash changes vs. the previous snapshot.
- **Untrusted kernel modules** — LKMs absent from the baseline captured at `init`.
- **Unauthorized account creation / UID-0 privilege escalation**.
- **In-memory deleted binaries** — monitors virtual symlinks pointing to deleted executables and dumps their payloads to a forensic vault.
- **Promiscuous mode detection** — triggers alerts when a network interface's promiscuous mode (`IFF_PROMISC` flag) is active.
- **Log tampering & anti-forensics** — flags zeroed-out records or epoch timestamp resets in wtmp and lastlog binary log structures.
- **Hidden process scanning** — compares scheduler-active PIDs via null signaling with visible `/proc` listings to detect kernel rootkits.
- **Offline package verification** — flags mismatches between on-disk binaries and dpkg-registered MD5 signatures.
- **Auto-resolution** — automatically resolves historical alerts (ports, modules, hidden processes, deleted binaries, promiscuous interfaces, package integrity violations, unauthorized users, hijacks, and suspicious process ancestry) once they are corrected or no longer present in a subsequent snapshot.

### 📦 Cryptographic Evidence Export
Snapshots are serialised to canonical JSON (keys sorted for determinism), signed with HMAC-SHA256, and wrapped in a portable `{signature, data}` bundle. A compromised bundle is immediately detected by `orin verify`.

### 📊 Reporting
- **Markdown** — lightweight, version-controllable incident report.
- **HTML** — self-contained dark-mode dashboard with tabbed navigation, severity badges, and metric cards. No CDN dependencies.

---

## 📂 Project Structure

```
orin/
├── orin_config.json          # User configuration (optional)
├── install.sh                # Automated pipx installer
├── setup.py                  # Setuptools packaging (package: orin-engine)
├── src/
│   └── orin/
│       ├── __init__.py
│       ├── main.py           # CLI entry point & subcommand router
│       ├── core/
│       │   ├── config.py     # JSON config loader with safe defaults
│       │   ├── crypto.py     # HMAC-SHA256 sign & verify
│       │   └── database.py   # SQLite schema (OrinStorage ORM)
│       ├── collectors/
│       │   ├── connections.py # Listening ports & outbound TCP
│       │   ├── deleted_binaries.py # In-memory payload recovery & hash check
│       │   ├── integrity.py  # SHA-256 FIM
│       │   ├── kernel.py     # /proc/modules harvester
│       │   ├── logs.py       # auth.log parser
│       │   ├── persistence.py # SSH authorized_keys inventory
│       │   ├── pkg_integrity.py # dpkg offline package MD5 verification
│       │   ├── processes.py  # /proc process tree
│       │   ├── promisc.py    # Promiscuous interface flags auditor
│       │   ├── session_audit.py # binary log session lifecycle parser (wtmp/lastlog)
│       │   └── users.py      # /etc/passwd harvester
│       └── analysis/
│           ├── engine.py     # Threat detection rules engine
│           ├── diff.py       # Cross-file snapshot comparator
│           ├── timeline.py   # Intra-vault snapshot delta
│           ├── unhide.py     # Hidden process scheduler scanner
│           └── reporter.py   # Markdown & HTML report compilers
└── tests/
    ├── test_crypto.py
    ├── test_database.py
    ├── test_diff.py
    ├── test_engine.py
    └── test_reporter.py
```

---

## 🔧 Installation

> Requires **Python ≥ 3.10**. No third-party packages are needed at runtime.

On modern Linux distributions enforcing **PEP 668** (externally-managed environments), choose one of:

### Method A — Automated installer (recommended)
```bash
chmod +x install.sh
./install.sh
```
The script installs Orin via `pipx` into an isolated virtual environment and makes the `orin` command available system-wide.

### Method B — System-wide (for root forensic workflows)
```bash
sudo pip install . --break-system-packages
```

### Method C — Development mode
```bash
pip install -e .
# or run directly without installing:
PYTHONPATH=src python -m orin.main <subcommand>
```

---

## 📖 Usage

All subcommands that read from privileged files (e.g. `/var/log/auth.log`, `/proc/*/fd/`) produce richer results when run as root.

### Workflow overview

```
init → collect → analyze → report
                ↓
              delta / diff / export / verify
```

---

### `orin init`
Creates the SQLite vault and locks two immutable baselines:
- Trusted kernel modules (from the current `/proc/modules`)
- Trusted user accounts (from the current `/etc/passwd`)

```bash
sudo orin init
```

---

### `orin collect`
Harvests a full system state snapshot and persists it to the vault.

```bash
sudo orin collect
```

---

### `orin analyze`
Runs all threat-detection rules against the most recent snapshot and writes findings to the `security_events` table. Prints a severity-tiered risk score (0–100) based on CVSS-like thresholds:
- **Critical anomalies present:** Base score `90` (scales up to `100` for multiple critical events).
- **High anomalies present:** Base score `65` (scales up to `89`).
- **Medium anomalies present:** Base score `35` (scales up to `64`).
- **Low anomalies present:** Base score `15` (scales up to `34`).
- **Clean system:** Risk score `0`.

```bash
sudo orin analyze
```

---

### `orin status`
Prints a dashboard summary: snapshot count, kernel baseline size, total security events, and latest snapshot metadata.

```bash
orin status
```

---

### `orin report`
Compiles a forensic audit briefing from the latest snapshot and all unresolved alerts.

```bash
# Markdown (default)
sudo orin report

# Self-contained HTML dashboard
sudo orin report --format html

# Custom output path
sudo orin report --format html --output /tmp/orin_report.html
```

---

### `orin delta`
Timeline drift analysis between two snapshot IDs stored in the vault. Automatically uses the two most recent snapshots when `--base` / `--target` are omitted.

```bash
sudo orin delta --base 1 --target 3
```

---

### `orin diff`
Compares **any two files** — live SQLite databases or signed JSON exports — and produces a structured drift report. Useful for comparing snapshots from different machines.

```bash
# Compare two vault files
orin diff /backups/orin_day1.db /var/lib/orin/orin_vault.db

# Compare two signed exports (passphrase required)
orin diff baseline.json current.json --secret "YourPassphrase"
```

---

### `orin export`
Serialises a snapshot into a portable, HMAC-signed JSON bundle.

```bash
sudo orin export --snapshot 2 --secret "YourSecurePassphrase"
# Writes: orin_export_snap_2.json
```

---

### `orin verify`
Verifies the integrity of a signed export. Fails loudly if the file has been tampered with.

```bash
orin verify --file orin_export_snap_2.json --secret "YourSecurePassphrase"
```

---

## ⚙️ Configuration

Orin searches for `orin_config.json` in the following order:
1. `./orin_config.json` (working directory)
2. `/etc/orin/orin_config.json` (system-wide)

If neither is found, built-in defaults are used.

```json
{
  "expected_ports": [22, 80, 443, 631, 3306, 5432, 6379, 8080, 8443],
  "whitelisted_processes": ["code", "chrome" "language_server"],
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
```

| Key | Purpose |
|-----|---------|
| `expected_ports` | Ports **not** flagged as unexpected listening sockets |
| `whitelisted_processes` | Process names whose ephemeral ports are excluded from alerts |
| `critical_paths` | Individual files monitored by the FIM |
| `critical_dirs` | Directories recursively scanned by the FIM |

---

## 🧪 Running Tests

Orin's test suite uses Python's built-in `unittest` framework — no test dependencies required.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

| Test file | Coverage area |
|-----------|--------------|
| `test_database.py` | Schema creation, `OrinStorage` connection management |
| `test_crypto.py` | HMAC sign/verify, passphrase validation, tamper detection |
| `test_connections.py` | IPv4 & IPv6 socket parsing, mock proc net file scanning |
| `test_engine.py` | Analysis rules, event deduplication, tiered risk scoring, and alert auto-resolution verification |
| `test_diff.py` | Snapshot comparator, added/removed/modified detection |
| `test_reporter.py` | Markdown and HTML report generation |
| `test_unhide.py` | Out-of-band hidden process scheduler detector verification |
| `test_deleted_binaries.py` | In-memory deleted executable recovery and payload dumping verification |
| `test_promisc.py` | Promiscuous mode interface flags auditing verification |
| `test_session_audit.py` | Binary wtmp/lastlog session audit parsing verification |
| `test_pkg_integrity.py` | Dpkg MD5 hash verification and integrity engine verification |

---

## 🗄️ Database Schema

The vault is a single SQLite file (default: `/var/lib/orin/orin_vault.db`) with the following tables:

```
system_snapshots             — one row per orin collect run
collected_processes          — process list per snapshot
collected_ports              — listening sockets per snapshot
collected_outbound_connections — outbound TCP sessions per snapshot
collected_kernel_modules     — loaded LKMs per snapshot
collected_ssh_keys           — authorized_keys inventory per snapshot
collected_file_hashes        — SHA-256 FIM records per snapshot
collected_users              — /etc/passwd accounts per snapshot
collected_deleted_binaries   — unlinked process image dump records per snapshot
collected_promisc_interfaces — promiscuous network mode flags per snapshot
collected_wtmp_sessions      — parsed binary logins/logouts per snapshot
collected_lastlog_records    — parsed binary lastlogin timestamps per snapshot
collected_pkg_integrity      — dpkg signature mismatch/missing records per snapshot
security_events              — persistent, deduplicated alert ledger
baseline_kernel_modules      — trusted LKM allowlist (set at init)
baseline_users               — trusted account allowlist (set at init)
```

---

## License

MIT — see `LICENSE` for details.
