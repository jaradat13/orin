# Orin: Offline Linux Forensics & Configuration Integrity Engine

Orin is a lightweight, zero-dependency, offline-first host security scanner and forensic triage engine for Linux systems. It monitors configuration drift and validates host integrity over time by taking snapshots of critical OS metrics, comparing them against secure baselines, and identifying anomalous behaviors.

---

## 🚀 Key Features

*   **Zero Dependencies:** Operates without external Python packages (such as `psutil` or shell execution wrappers), utilizing direct `/proc` and system file parsing.
*   **Low-Level Telemetry Collectors:**
    *   **Processes:** Full process tree mapping, command line parameters, and parent-child links.
    *   **Ports & Connections:** Active TCP/UDP listening ports mapped to their PIDs, and established outbound sockets.
    *   **Account Profiles:** Local accounts from `/etc/passwd` and authorized SSH keys mapped to their users with secure SHA-256 fingerprints.
    *   **Kernel modules:** Active Linux Kernel Modules (LKMs).
*   **Recursive File Integrity Monitoring (FIM):** Recursive directory hashing of system persistence vectors (like systemd configurations in `/etc/systemd/system` and cron schedules in `/etc/cron.d`).
*   **Threat Analysis Rules Engine:**
    *   **Kernel Thread Masquerading:** Flags processes pretending to be kernel threads (e.g. `kworker`) with invalid ancestry (PPID not `0` or `2`).
    *   **Reverse Shell Detection:** Identifies typical interactive reverse shell parameters (like `python -c` or `bash -i`).
    *   **Database-Level Event Resolution:** Auto-resolves anomalous events (ports or kernel modules) once they disappear from the system.
*   **Cryptographic Evidence Export:** Serializes collected snapshots and signs them with an HMAC-SHA256 signature using a passphrase to guarantee tamper protection during off-system analysis.
*   **Timeline Drift Engine:** Calculates and reports system drift (ports, processes, and active outbound connections) between any two historical snapshots.

---

## 📂 Project Structure

```
orin/
├── orin_config.json      # Default Configuration file
├── install.sh            # Automated shell installer (for pipx)
├── setup.py              # Packaging Configuration (Setuptools)
├── src/
│   └── orin/             # Package Root
│       ├── __init__.py
│       ├── main.py       # CLI Entrypoint & Subcommands Routing
│       ├── core/
│       │   ├── config.py # Configuration Loader
│       │   ├── crypto.py # HMAC Signature Sign/Verify
│       │   └── database.py # SQLite Schema and Connection Contexts
│       ├── collectors/   # Low-level Telemetry Collectors
│       │   ├── connections.py
│       │   ├── integrity.py
│       │   ├── kernel.py
│       │   ├── logs.py
│       │   ├── persistence.py
│       │   ├── processes.py
│       │   └── users.py
│       └── analysis/     # Analysis & Reporting Engines
│           ├── engine.py
│           ├── timeline.py
│           └── reporter.py
└── tests/                # Self-contained Unittest Suite
    ├── __init__.py
    ├── test_database.py
    ├── test_crypto.py
    └── test_engine.py
```

---

## 🔧 Installation

On modern Linux distributions enforcing **PEP 668** (externally managed environment blocks), choose one of the following methods:

### Method A: Using the Automated Installer (Recommended)
This script handles the `pipx` setup and deploys Orin into an isolated virtual environment:
```bash
chmod +x install.sh
./install.sh
```

### Method B: System-wide Force Install
To install globally for all system users (highly recommended for root-level forensic analyses):
```bash
sudo pip install . --break-system-packages
```

---

## 📖 Usage Guide

All commands modifying or inspecting baseline storage require root/sudo access:

### 1. Initialize Baselines
Captures and locks the initial, trusted configuration of user accounts and loaded kernel modules:
```bash
sudo orin init
```

### 2. Collect Telemetry Snapshot
Harvests current system state indicators (ports, connections, processes, FIM hashes, and SSH keys):
```bash
sudo orin collect
```

### 3. Run Analysis & Scoring
Evaluates the latest snapshot data against baselines and whitelists, reporting active security violations:
```bash
sudo orin analyze
```

### 4. Compile Posture Report
Generates a standalone Markdown summary report (`orin_report_<hostname>.md`) detailing target context and active alerts:
```bash
sudo orin report
```

### 5. Calculate Snapshot Drift
Compares any two historical snapshots to display drifted ports, connections, or processes:
```bash
sudo orin delta --base 1 --target 2
```

### 6. Export Signed Snapshot
Packages a snapshot and signs it with an HMAC-SHA256 signature using a master passphrase:
```bash
sudo orin export --snapshot 1 --secret "YourSecurePassphrase"
```

### 7. Verify Snapshot Evidence Integrity
Verifies the signature of an exported snapshot bundle to ensure it has not been modified:
```bash
orin verify --file orin_export_snap_1.json --secret "YourSecurePassphrase"
```

---

## ⚙️ Configuration

Orin reads its parameters from `orin_config.json` (searched locally in the working directory, or globally at `/etc/orin/orin_config.json`).

Example configuration:
```json
{
  "expected_ports": [22, 80, 443, 631, 8080],
  "whitelisted_processes": [
    "code",
    "antigravity-ide",
    "language_server"
  ],
  "critical_paths": [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/sudoers"
  ],
  "critical_dirs": [
    "/etc/cron.d",
    "/etc/systemd/system"
  ]
}
```

---

## 🧪 Running Tests

Orin utilizes Python's built-in `unittest` framework to execute testing completely offline without external dependencies. 

From the root directory, run:
```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```
