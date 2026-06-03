# Orin — Offline Linux Forensics & Integrity Engine

> **Fully offline, zero-dependency** host security scanner and forensic triage tool for Linux systems.

Orin takes point-in-time snapshots of critical OS metrics, compares them against trusted baselines, identifies anomalous behaviour, and produces tamper-evident evidence bundles — all without any external Python packages or network access.

---

## ✨ Features

### 🔬 Low-Level Telemetry Collection
Orin reads directly from Linux kernel interfaces — no shell subprocesses, no third-party libraries.

| Collector | Source | What is captured |
|-----------|--------|-----------------|
| **Processes** | `/proc/[pid]/stat`, `/comm`, `/exe`, `/cmdline` | Full process tree with PPID ancestry |
| **Listening ports** | `/proc/net/tcp`, `/proc/net/udp` | TCP/UDP sockets mapped to owning PID |
| **Outbound connections** | `/proc/net/tcp` | Established non-loopback sessions |
| **Kernel modules** | `/proc/modules` | Loaded LKMs (name, size, instance count) |
| **User accounts** | `/etc/passwd` | UID, GID, home directory, login shell |
| **SSH authorised keys** | `~/.ssh/authorized_keys` | Key type, SHA-256 fingerprint, comment |
| **File integrity (FIM)** | Configurable paths & dirs | SHA-256 checksums for critical files |
| **Auth logs** | `/var/log/auth.log` | SSH brute-force IPs, privilege changes |

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
- **Auto-resolution** — events for ports and modules that disappear are automatically closed.

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
│       │   ├── integrity.py  # SHA-256 FIM
│       │   ├── kernel.py     # /proc/modules harvester
│       │   ├── logs.py       # auth.log parser
│       │   ├── persistence.py # SSH authorized_keys inventory
│       │   ├── processes.py  # /proc process tree
│       │   └── users.py      # /etc/passwd harvester
│       └── analysis/
│           ├── engine.py     # Threat detection rules engine
│           ├── diff.py       # Cross-file snapshot comparator
│           ├── timeline.py   # Intra-vault snapshot delta
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
Runs all threat-detection rules against the most recent snapshot and writes findings to the `security_events` table. Prints a risk score (0–100).

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
| `test_engine.py` | Analysis rules, event deduplication, auto-resolution |
| `test_diff.py` | Snapshot comparator, added/removed/modified detection |
| `test_reporter.py` | Markdown and HTML report generation |

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
security_events              — persistent, deduplicated alert ledger
baseline_kernel_modules      — trusted LKM allowlist (set at init)
baseline_users               — trusted account allowlist (set at init)
```

---

## License

MIT — see `LICENSE` for details.
