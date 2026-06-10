# Orin Forensic Engine — Full Documentation & Practitioner's Guide

> **Offline Linux Forensics & Integrity Engine**
> Host security scanner and forensic triage tool for Linux — built for analysts who trust nothing but the kernel itself.

**Version:** 1.0.0
**Last Updated:** June 2025
**License:** AGPLv3

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Design Philosophy & Threat Model](#design-philosophy--threat-model)
3. [Architecture Overview](#architecture-overview)
4. [Installation & Deployment](#installation--deployment)
5. [Quick Start Guide](#quick-start-guide)
6. [Core Capabilities Reference](#core-capabilities-reference)
7. [Command-Line Interface Reference](#command-line-interface-reference)
8. [Operational Workflows](#operational-workflows)
9. [Forensic Collection Modules](#forensic-collection-modules)
10. [Threat Detection Engine](#threat-detection-engine)
11. [Cryptographic Evidence Handling](#cryptographic-evidence-handling)
12. [Dashboard & Reporting](#dashboard--reporting)
13. [Fleet Management](#fleet-management)
14. [Advanced Configuration](#advanced-configuration)
15. [Troubleshooting & FAQ](#troubleshooting--faq)
16. [Security Considerations](#security-considerations)
17. [Appendix A: Database Schema](#appendix-a-database-schema)
18. [Appendix B: MITRE ATT&CK Mapping](#appendix-b-mitre-attck-mapping)
19. [Appendix C: Rule Syntax Reference](#appendix-c-rule-syntax-reference)

---

## Executive Summary

**Orin** is a zero-dependency, offline-first forensic acquisition and threat detection engine designed for Linux systems operating in air-gapped, classified, or forensically sensitive environments. Unlike traditional EDR/XDR platforms that require cloud connectivity, persistent daemons, or extensive third-party dependencies, Orin operates entirely from userspace with minimal runtime requirements (`psutil` + optional `bcc` for eBPF).

### Key Differentiators

| Feature | Orin | Traditional EDR |
|---------|------|-----------------|
| Network Requirement | **Never** | Required for telemetry |
| Cloud Dependencies | **Zero** | Mandatory |
| Runtime Footprint | ~5MB (stdlib) | 100MB+ |
| Daemon Required | **No** (on-demand) | Yes (persistent) |
| Air-Gap Compatible | ✅ Native | ❌ Complex workarounds |
| Evidence Encryption | ✅ AES-256-GCM | ⚠️ Vendor-dependent |
| Tamper-Evident Export | ✅ HMAC-SHA256 signed | ⚠️ Proprietary formats |

### Primary Use Cases

1. **Classified Networks (SCIFs)** — Forensic data collection where no external connectivity is permitted
2. **Industrial Control Systems (ICS/SCADA)** — Passive monitoring without network exposure
3. **Incident Response** — Point-in-time snapshot acquisition for post-compromise analysis
4. **Compliance Auditing** — Cryptographically verifiable evidence chains for regulatory requirements
5. **Threat Hunting** — Offline correlation of security events across isolated infrastructure
6. **Secure Enclaves** — Deployment in environments with strict data sovereignty requirements

---

## Design Philosophy & Threat Model

### Core Principles

Orin adheres to four non-negotiable design principles:

1. **Zero Network Egress**
   No outbound connections, no telemetry phone-home, no cloud API calls. All processing occurs locally on the target system.

2. **Zero External Trust**
   Minimal dependencies (`psutil` for process/network enumeration, optional `bcc` for eBPF). No kernel modules, no drivers, no proprietary agents.

3. **Tamper-Evident Storage**
   All forensic evidence is cryptographically signed (HMAC-SHA256) and optionally encrypted at rest (AES-256-GCM with PBKDF2 key derivation).

4. **Self-Contained Operation**
   Can run indefinitely without external updates, internet connectivity, or vendor support infrastructure.

### Threat Model

**Assumed Adversary Capabilities:**
- Root-level access to target system
- Ability to modify userspace binaries
- Kernel-level rootkit deployment
- Anti-forensic techniques (log clearing, timestamp manipulation)

**Out of Scope:**
- Hardware-level attacks (DMA, JTAG)
- Compromised kernel (Orin reads from `/proc`; a fully compromised kernel can lie)
- Physical access attacks

**Mitigations Provided:**
- Cross-view differential analysis (compare `/proc` vs. scheduler-active PIDs)
- Kernel symbol integrity verification
- Binary session audit (wtmp/lastlog tampering detection)
- Cryptographic evidence binding (cannot be modified post-collection without detection)

---

## Architecture Overview

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     Orin Forensic Engine                        │
├─────────────────────────────────────────────────────────────────┤
│  CLI Interface (main.py)                                        │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────────┐  │
│  │ init     │ collect  │ analyze  │ report   │ serve        │  │
│  │ scan     │ baseline │ diff     │ delta    │ hub-serve    │  │
│  │ schedule │ stream   │ vault    │ rules    │ correlate    │  │
│  └──────────┴──────────┴──────────┴──────────┴──────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  Collectors (src/orin/collectors/)                              │
│  ┌─────────────┬──────────────┬─────────────┬────────────────┐ │
│  │ processes   │ connections  │ kernel      │ users          │ │
│  │ integrity   │ crontabs     │ logs        │ deleted_bins   │ │
│  │ suid        │ ebpf         │ promisc     │ session_audit  │ │
│  │ dns_forensics│ privilege   │ triggered_pcap│ remote_agent │ │
│  └─────────────┴──────────────┴─────────────┴────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│  Analysis Engine (src/orin/analysis/)                           │
│  ┌─────────────┬──────────────┬─────────────┬────────────────┐ │
│  │ engine      │ sigma        │ yara_engine │ attck          │ │
│  │ rootkit     │ unhide       │ timeline    │ reporter       │ │
│  │ ai          │ diff         │             │                │ │
│  └─────────────┴──────────────┴─────────────┴────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│  Core Services (src/orin/core/)                                 │
│  ┌─────────────┬──────────────┬─────────────┬────────────────┐ │
│  │ database    │ crypto       │ server      │ hub_server     │ │
│  │ scanner     │ scheduler    │ self_verify │ credentials    │ │
│  │ self_defense│ config       │ dashboard   │                │ │
│  └─────────────┴──────────────┴─────────────┴────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│  Intelligence (src/orin/intel/)                                 │
│  │ ioc_importer (STIX, TAXII, CSV, blocklists)                 │ │
│  └─────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│  SQLite Vault (orin_vault.db)                                   │
│  - Encrypted via AES-256-GCM (optional)                         │
│  - HMAC-SHA256 signed exports                                   │
│  - Automatic lifecycle management (prune, vacuum)               │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Collection Phase** (`orin collect`)
   - Reads directly from `/proc`, `/sys`, `/var/log`, `/etc`
   - No modifications to system state
   - Stores normalized telemetry in SQLite vault

2. **Analysis Phase** (`orin analyze`)
   - Applies threat detection rules
   - Cross-references against baselines
   - Computes risk score and generates alerts

3. **Reporting Phase** (`orin report`)
   - Generates Markdown or HTML briefings
   - Exports signed JSON bundles
   - Dashboard visualization via `orin serve`

---

## Installation & Deployment

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Linux (kernel 4.4+) | Linux 5.4+ |
| Python | 3.10+ | 3.11+ |
| RAM | 256MB | 512MB+ |
| Disk | 100MB + vault space | 1GB+ for vault |
| Dependencies | `psutil` | `psutil` + `bcc` (eBPF) |

### Method A: Automated Installer (Recommended)

```bash
chmod +x install.sh && ./install.sh
```

This script:
- Installs Python dependencies (`psutil`, optional `bcc`)
- Creates system user `orin` (if running as root)
- Sets up default configuration in `/etc/orin/`
- Installs CLI entry point to `/usr/local/bin/orin`

### Method B: Manual System-Wide Installation

```bash
# Clone repository
git clone https://github.com/jaradat13/orin.git
cd orin

# Install as root for system-wide forensic workflows
pip install .

# Verify installation
orin version
```

### Method C: Development Mode

```bash
# For contributors and custom deployments
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

### Optional: Enable eBPF Real-Time Streaming

For real-time syscall telemetry via eBPF ring buffers:

```bash
# Debian/Ubuntu
apt-get install bpfcc-tools python3-bcc

# RHEL/CentOS
yum install bcc-tools python3-bcc

# Verify eBPF availability
python3 -c "from bcc import BPF; print('eBPF OK')"
```

---

## Quick Start Guide

### First-Time Setup

```bash
# Step 1: Initialize forensic vault
sudo orin init

# Output:
# [*] Initializing Orin forensic vault at: /var/lib/orin/orin_vault.db
# [*] Recording pristine system configuration baselines...
# 🟢 Success: Baseline initialized. Recorded 47 modules, 32 accounts, and 12 SUID/SGID binaries.
```

### Basic Workflow

```bash
# Step 2: Collect telemetry snapshot
sudo orin collect

# Step 3: Analyze against threat models
sudo orin analyze

# Step 4: Generate human-readable report
sudo orin report -o /tmp/orin_report.html -f html

# Step 5: Launch local dashboard
sudo orin serve
# Access URL printed to terminal: http://127.0.0.1:8000/?token=<ephemeral_token>
```

### Remote Host Scanning

```bash
# Scan a remote host over SSH (no agent required)
sudo orin scan --host 192.168.1.50 --user root --key ~/.ssh/id_ed25519

# Initialize baseline for remote host
sudo orin scan --host 192.168.1.50 --user root --init
```

### Automated Collection

```bash
# Schedule collection every 10 minutes with 30-day retention
sudo orin schedule --install --interval 10 --retention 30d

# Check scheduling status
sudo orin schedule --status
```

---

## Core Capabilities Reference

Orin implements **41 distinct forensic capabilities** organized into logical modules:

### Process & Execution Monitoring

| # | Capability | Description | Data Source |
|---|------------|-------------|-------------|
| 1 | Process Tree Harvester | Full PPID-linked process enumeration | `/proc/[pid]/stat`, `/comm`, `/exe`, `/cmdline` |
| 7 | In-Memory Executable Recovery | Detect & dump deleted binaries still executing | `/proc/[pid]/exe` symlinks |
| 10 | Hidden Process Detector | Expose kernel rootkit-hidden processes | `os.kill(pid, 0)` cross-reference |
| 20 | SUID/SGID Binary Monitor | Track privileged executables | `find / -perm /6000` |

### Network Telemetry

| # | Capability | Description | Data Source |
|---|------------|-------------|-------------|
| 2 | Network Socket Auditor | IPv4/IPv6 listening ports & connections | `/proc/net/{tcp,tcp6,udp,udp6}` |
| 8 | Promiscuous Mode Auditor | Detect NICs in promiscuous mode | `/sys/class/net/*/flags` (IFF_PROMISC) |
| 31 | DNS Forensics & Tunneling Detection | Shannon entropy analysis, DGA detection | `/proc/net`, resolver logs |
| 32 | Triggered PCAP Capture | Packet capture on forensic triggers | Raw socket + Scapy fallback |

### Kernel Integrity

| # | Capability | Description | Data Source |
|---|------------|-------------|-------------|
| 3 | Kernel Module & Symbol Auditor | LKM enumeration, rootkit symbol detection | `/proc/modules`, `/proc/kallsyms` |
| 22 | eBPF & FD Auditor | Loaded eBPF programs, suspicious file descriptors | `/sys/fs/bpf`, `/proc/[pid]/fd` |
| 34 | Identity & Privilege Tracking | PAM events, sudo executions, credential access | `/var/log/auth.log`, eBPF probes |

### Persistence Mechanisms

| # | Capability | Description | Data Source |
|---|------------|-------------|-------------|
| 4 | User & SSH Key Inventory | Account enumeration, authorized_keys fingerprinting | `/etc/passwd`, `~/.ssh/authorized_keys` |
| 12 | Scheduled Task Harvester | Crontab parsing, reverse-shell detection | `/var/spool/cron/*`, `/etc/cron.*` |
| 21 | Agentless SSH Fleet Scanner | Multi-host profiling without agent deployment | SSH protocol + bash fallback |

### File Integrity

| # | Capability | Description | Data Source |
|---|------------|-------------|-------------|
| 5 | File Integrity Monitor (FIM) | SHA-256 checksums with stat-based caching | Configured paths + metadata cache |
| 11 | Package Integrity Engine | Verify binaries against dpkg md5sums | `/var/lib/dpkg/info/*.md5sums` |

### Log Analysis

| # | Capability | Description | Data Source |
|---|------------|-------------|-------------|
| 6 | Auth Log Parser & Sigma Engine | Zero-dependency Sigma rule evaluator | `/var/log/auth.log`, `journalctl` |
| 9 | Binary Session Auditor | wtmp/lastlog parsing, anti-forensic detection | `/var/log/wtmp`, `/var/log/lastlog` |

### Advanced Features

| # | Capability | Description |
|---|------------|-------------|
| 13 | Threat Detection Rules Engine | Multi-signal correlation with MITRE ATT&CK tagging |
| 14 | Forensic Alert Auto-Resolution | Close resolved alerts in subsequent snapshots |
| 15 | Cryptographic Evidence Export | HMAC-SHA256 signed JSON bundles |
| 16 | Markdown & HTML Reporting | Self-contained dark-mode dashboards |
| 17 | Local Web Dashboard | Live risk score, triage actions, telemetry explorer |
| 18 | Automated Scheduler | Cron-based recurring collection |
| 19 | Dashboard Auto-Token Security | Ephemeral 256-bit session tokens |
| 23 | Baseline Manager | Incremental additions & comprehensive refreshes |
| 24 | Local AI Triage | Ollama integration for alert correlation |
| 25 | Offline Threat Intel Importer | STIX, TAXII, CSV, blocklist normalization |
| 26 | MITRE ATT&CK Mapper | Static technique ID enrichment |
| 27 | Snapshot Comparator | Diff two forensic snapshots |
| 28 | Timeline Delta Calculator | Structural differences between snapshot IDs |
| 29 | Encrypted Evidence Vault | AES-256-GCM with PBKDF2 (100k iterations) |
| 30 | Embedded YARA Engine | Pattern matching against files & dumped binaries |
| 33 | Agent Self-Defense | AppArmor, SELinux, Seccomp-BPF profiles |
| 35 | eBPF Ring-Buffer Streamer | Real-time syscall telemetry |
| 36 | Read-Only & Ephemeral Modes | Write-protected & USB/tmpfs operation |
| 37 | Vault Lifecycle Management | Stats, pruning, vacuum operations |
| 38 | Retention Controls | Age-based deletion with dry-run preview |
| 39 | Credential Handling Overhaul | Passphrase file/prompt/env, token file storage |
| 40 | Tool Self-Verification | GPG-signed releases, SBOM, runtime self-check |
| 41 | Centralized Fleet Hub | Multi-tenant HTTP server for air-gapped management |

---

## Command-Line Interface Reference

### Engine Core Commands

#### `orin init`

Initialize forensic vault and register system baselines.

```bash
orin init [--read-only]

Options:
  --read-only    Prevent any writes to vault (forensic acquisition mode)
```

**Example:**
```bash
sudo orin init
# Or for write-protected systems:
sudo orin init --read-only
```

---

#### `orin collect`

Execute telemetry acquisition sequence.

```bash
orin collect [--read-only] [--vault-path VAULT_PATH]

Options:
  --read-only              No data stored to vault (reference only)
  --vault-path PATH        Override default vault location
```

**Example:**
```bash
# Standard collection
sudo orin collect

# Read-only forensics on USB drive
sudo orin collect --read-only --vault-path /mnt/usb/evidence.db
```

---

#### `orin analyze`

Evaluate current snapshot against threat models.

```bash
orin analyze
```

**Output:** Risk score, alert count, MITRE ATT&CK coverage summary.

---

#### `orin report`

Generate human-readable briefings.

```bash
orin report -o OUTPUT [-f {markdown,html}]

Required:
  -o, --output    Target file path

Optional:
  -f, --format    Output format (default: markdown)
```

**Example:**
```bash
sudo orin report -o /tmp/brief.md -f markdown
sudo orin report -o /tmp/dashboard.html -f html
```

---

#### `orin serve`

Launch local HTTP dashboard.

```bash
orin serve [port] [-H HOST] [--cert CERT] [--key KEY]
           [--username USER] [--password PASS] [--no-auth]
           [--passphrase-file FILE] [--passphrase-prompt]
           [--passphrase-env-var VAR] [--token-file FILE]

Positional:
  port          Binding port (default: 8000)

Options:
  -H, --host              Bind address (default: 127.0.0.1)
  --cert, --key           SSL certificate/key for HTTPS
  --username, --password  Basic auth credentials
  --no-auth               Disable authentication
  --passphrase-file       Vault passphrase from file
  --passphrase-prompt     Interactive passphrase prompt
  --passphrase-env-var    Custom env var for passphrase
  --token-file            Save/load session token (0600)
```

**Example:**
```bash
# Default (ephemeral token, localhost only)
sudo orin serve

# HTTPS with certificate
sudo orin serve 8443 --cert /etc/ssl/orin.crt --key /etc/ssl/orin.key

# Persistent token file
sudo orin serve --token-file /etc/orin/session.token
```

---

#### `orin hub-serve`

Launch centralized fleet management server.

```bash
orin hub-serve [port] [-H HOST] [--cert CERT] [--key KEY]
               [--no-auth] [--passphrase-file FILE]
               [--passphrase-prompt] [--token-file FILE]

Options: Same as `orin serve` plus:
  -H, --host    Bind address (default: 0.0.0.0 for fleet access)
```

**Example:**
```bash
# Multi-tenant fleet hub on all interfaces
sudo orin hub-serve 8000 -H 0.0.0.0 --cert cert.pem --key key.pem
```

---

#### `orin schedule`

Manage automated collection scheduling.

```bash
orin schedule [--install | --remove | --status]
              [-i INTERVAL] [--retention RETENTION]

Options:
  --install             Install cron job
  --remove              Remove scheduled tasks
  --status              Show current schedule
  -i, --interval        Minutes between collections (default: 10)
  --retention           Auto-prune policy (e.g., '30d')
```

**Example:**
```bash
# Install with 15-minute interval and 60-day retention
sudo orin schedule --install --interval 15 --retention 60d

# Check status
sudo orin schedule --status
```

---

#### `orin scan`

Agentless remote SSH scanning.

```bash
orin scan --host HOST --user USER [--key KEY] [-p PORT]
          [--init] [--no-strict-host-keys]
          [--known-hosts-file FILE]

Required:
  --host      Target hostname/IP
  --user      SSH username

Optional:
  --key       Private key path
  -p, --port  SSH port (default: 22)
  --init      Initialize baseline instead of drift scan
  --no-strict-host-keys    Skip host key verification
  --known-hosts-file       Custom known_hosts path
```

**Example:**
```bash
# Drift scan against baseline
sudo orin scan --host 192.168.1.50 --user root --key ~/.ssh/id_ed25519

# Initialize new remote baseline
sudo orin scan --host 192.168.1.50 --user root --init
```

---

#### `orin baseline`

Manage trusted baselines.

```bash
orin baseline {add | refresh} ...

Subcommands:
  add       Add specific resource to baseline
  refresh   Refresh baseline from latest snapshot
```

**Example:**
```bash
# Add new authorized user to baseline
sudo orin baseline add --user admin

# Refresh all baselines from current state
sudo orin baseline refresh --force-overwrite
```

---

#### `orin diff`

Compare two snapshot files.

```bash
orin diff BASE_FILE TARGET_FILE [--secret SECRET] [-v]

Positional:
  base_file     Base snapshot (.db or .json)
  target_file   Target snapshot (.db or .json)

Options:
  --secret    Passphrase for signed JSON
  -v, --verbose    Full report output
```

**Example:**
```bash
orin diff snapshot_1.json snapshot_2.json --secret mypassphrase -v
```

---

#### `orin delta`

Compare two snapshots by ID within vault.

```bash
orin delta --base BASE_ID --target TARGET_ID
           [--database DB_PATH] [-v]

Required:
  --base      Base snapshot ID
  --target    Target snapshot ID

Optional:
  --database  Vault path (default: configured path)
  -v, --verbose    Full diff output
```

**Example:**
```bash
orin delta --base 1 --target 5 -v
```

---

#### `orin export`

Export snapshot to signed JSON.

```bash
orin export --snapshot ID --secret SECRET [--output FILE]
            [--database DB_PATH]

Required:
  --snapshot    Snapshot ID to export
  --secret      Signing passphrase

Optional:
  -o, --output    Output file path
  --database      Vault path
```

**Example:**
```bash
orin export --snapshot 42 --secret "strong-passphrase" -o evidence_42.json
```

---

#### `orin verify`

Verify signed export bundle.

```bash
orin verify --file FILE --secret SECRET

Required:
  -f, --file    Export file to verify
  --secret      Verification passphrase
```

**Example:**
```bash
orin verify --file evidence_42.json --secret "strong-passphrase"
```

---

#### `orin vault`

Manage vault lifecycle.

```bash
orin vault {stats | prune} ...

Subcommands:
  stats              Display vault statistics
  prune              Delete old snapshots
```

**Examples:**
```bash
# Show vault size, snapshot count, age distribution
orin vault stats

# Prune snapshots older than 30 days (dry-run first)
orin vault prune --older-than 30 --dry-run
orin vault prune --older-than 30
```

---

#### `orin rules`

Manage Sigma and YARA rules.

```bash
orin rules {update | list | validate}

Subcommands:
  update      Load rules from offline directory
  list        Show active rules with descriptions
  validate    Check rule syntax and schema
```

**Example:**
```bash
# List all active detection rules
orin rules list

# Validate custom rule files
orin rules validate /custom/rules/
```

---

#### `orin correlate`

Local AI multi-host triage.

```bash
orin correlate [--host HOST [HOST ...]] [--url URL]
               [--model MODEL] [-o OUTPUT]

Options:
  --host      Specific hostnames to correlate
  --url       Ollama API base URL (default: http://127.0.0.1:11434)
  --model     Ollama model name (default: llama3)
  -o, --output    Save Markdown report to file
```

**Example:**
```bash
# Correlate all hosts using local Ollama
orin correlate -o correlation_report.md

# Specific hosts with custom model
orin correlate --host web01 db01 --model mistral -o triage.md
```

---

#### `orin stream`

Launch eBPF real-time telemetry streaming.

```bash
orin stream [--verbose]

Options:
  -v, --verbose    Debug output
```

**Requirements:** `bcc`/`bpfcc` Python package installed.

---

#### `orin self-defense`

Deploy agent hardening profiles.

```bash
orin self-defense [--action ACTION] [--socket SOCKET]
                  [--interval INTERVAL] [--output-dir DIR]

Options:
  --action    watchdog | heartbeat | generate-profiles | status
  --socket    Unix socket for watchdog
  --interval  Health check interval (seconds)
  --output-dir    Profile output directory
```

**Example:**
```bash
# Generate AppArmor/SELinux profiles
orin self-defense --action generate-profiles --output-dir /etc/orin/profiles
```

---

#### `orin version`

Display version and perform self-verification.

```bash
orin version [--sbom] [--self-check] [--generate-manifest]
             [--sign-manifest PATH] [--verify-manifest PATH]

Options:
  --sbom              Show Software Bill of Materials
  --self-check        Verify critical modules against embedded hashes
  --generate-manifest    Create release manifest with SHA-256
  --sign-manifest     GPG-sign a manifest
  --verify-manifest   Verify manifest signature
```

**Example:**
```bash
orin version --sbom
orin version --self-check
```

---

## Operational Workflows

### Workflow 1: Initial Baseline Creation

**Scenario:** Deploying Orin on a newly provisioned system for continuous monitoring.

```bash
# 1. Install Orin
chmod +x install.sh && ./install.sh

# 2. Initialize vault and capture baselines
sudo orin init

# 3. Perform first collection
sudo orin collect

# 4. Analyze for immediate threats
sudo orin analyze

# 5. Generate initial report
sudo orin report -o baseline_report.html -f html

# 6. Schedule ongoing collection
sudo orin schedule --install --interval 10 --retention 90d

# 7. Launch dashboard for ongoing monitoring
sudo orin serve --token-file /etc/orin/dashboard.token
```

---

### Workflow 2: Incident Response Triage

**Scenario:** Suspected compromise on production server; need rapid forensic acquisition.

```bash
# 1. Connect to affected system (out-of-band if possible)

# 2. Initialize vault on external USB (preserves disk state)
sudo orin init --vault-path /mnt/usb_evidence/vault.db

# 3. Collect in read-only mode (no writes to suspect disk)
sudo orin collect --read-only --vault-path /mnt/usb_evidence/vault.db

# 4. Analyze collected telemetry
sudo orin analyze

# 5. Export signed evidence bundle
sudo orin export --snapshot 1 --secret "IR-Case-2025-001" \
                 -o /mnt/usb_evidence/evidence_bundle.json

# 6. Generate executive briefing
sudo orin report -o /mnt/usb_evidence/incident_brief.md -f markdown

# 7. Verify evidence integrity before chain-of-custody transfer
sudo orin verify --file /mnt/usb_evidence/evidence_bundle.json \
                 --secret "IR-Case-2025-001"
```

---

### Workflow 3: Air-Gapped Fleet Assessment

**Scenario:** Audit 50 isolated servers in a SCIF environment.

```bash
# On jump host (air-gapped network):

# 1. Set up centralized hub
sudo orin hub-serve 8000 -H 10.0.0.1 --cert hub.crt --key hub.key

# 2. On each target server (via physical access or isolated SSH):
for host in $(cat scif_hosts.txt); do
    # Scan and collect from each host
    sudo orin scan --host $host --user root --key /root/scif_key

    # Import findings to hub
    curl -k -X POST https://10.0.0.1:8000/api/v1/import \
         -H "Authorization: Bearer $HUB_TOKEN" \
         -F "vault=@/var/lib/orin/orin_vault.db"
done

# 3. Correlate findings across fleet
orin correlate --host $(cat scif_hosts.txt) -o fleet_triage.md

# 4. Generate consolidated dashboard
sudo orin serve 8443 --cert dashboard.crt --key dashboard.key
```

---

### Workflow 4: Continuous Compliance Monitoring

**Scenario:** Maintain PCI-DSS compliance evidence for quarterly audits.

```bash
# 1. Configure retention policy (retain 1 year of snapshots)
sudo orin schedule --install --interval 60 --retention 365d

# 2. Enable encrypted vault
export ORIN_VAULT_PASSPHRASE="compliance-master-key-2025"

# 3. Configure FIM for cardholder data paths
cat >> /etc/orin/config.toml <<EOF
[integrity]
paths = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/var/www/html",
    "/opt/payment_processor"
]
EOF

# 4. Generate monthly compliance report
sudo orin report -o /var/reports/$(date +%Y-%m).html -f html

# 5. Export signed evidence for auditors
sudo orin export --snapshot latest --secret "audit-key" \
                 -o /var/reports/evidence_$(date +%Y-%m).json
```

---

## Forensic Collection Modules

### Process Tree Harvester

**Purpose:** Enumerate all running processes with parent-child relationships.

**Data Sources:**
- `/proc/[pid]/stat` — Process state, PPID, start time
- `/proc/[pid]/comm` — Command name
- `/proc/[pid]/exe` — Executable symlink
- `/proc/[pid]/cmdline` — Full command line arguments

**Detection Logic:**
```python
# Pseudocode from collectors/processes.py
for pid in os.listdir('/proc'):
    if not pid.isdigit(): continue
    try:
        stat = read_proc_stat(pid)
        ppid = stat['ppid']
        comm = read_proc_comm(pid)
        exe = os.readlink(f'/proc/{pid}/exe')
        cmdline = read_proc_cmdline(pid)

        processes.append({
            'pid': int(pid),
            'ppid': ppid,
            'comm': comm,
            'exe': exe,
            'cmdline': cmdline,
            'state': stat['state']
        })
    except (FileNotFoundError, PermissionError):
        continue  # Process exited during enumeration
```

**Alert Conditions:**
- PPID points to non-existent process
- `comm` differs significantly from `exe` basename (masquerading)
- Kernel thread names (`kworker/*`, `ksoftirqd/*`) with userspace PPID

---

### Network Socket Auditor

**Purpose:** Map all network endpoints (listening ports, active connections).

**Data Sources:**
- `/proc/net/tcp`, `/proc/net/tcp6` — TCP sockets
- `/proc/net/udp`, `/proc/net/udp6` — UDP sockets
- `/proc/[pid]/fd` — Socket inode resolution

**Parsing Format:**
```
sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
0:  0B00007F:1F92 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 47854 1 ffff8a3c12345678
```

**Fields Decoded:**
- `local_address`: Hex IP:PORT (little-endian)
- `st`: Socket state (0A = LISTEN)
- `inode`: Socket inode for process correlation

**Alert Conditions:**
- Listening ports not in baseline
- Outbound connections to known C2 IPs
- Sockets bound to 0.0.0.0 (all interfaces) on sensitive services

---

### Kernel Module & Symbol Auditor

**Purpose:** Detect loadable kernel modules and rootkit indicators.

**Data Sources:**
- `/proc/modules` — Loaded module list
- `/proc/kallsyms` — Kernel symbol table
- `/sys/module/*/sections/*` — Module memory sections

**Rootkit Detection Techniques:**

1. **Unlinked Module Detection**
   ```python
   # Compare kallsyms symbols against /proc/modules
   modules_from_proc = set(m['name'] for m in gather_modules())
   modules_from_kallsyms = extract_module_names_from_symbols()

   hidden_modules = modules_from_kallsyms - modules_from_proc
   if hidden_modules:
       alert("UNLINKED_MODULE", hidden_modules)
   ```

2. **Suspicious Symbol Patterns**
   ```python
   ROOTKIT_SYMBOLS = [
       'diamorphine', 'reptile', 'rootkit',
       'commit_creds', 'prepare_kernel_cred'  # Cred manipulation
   ]

   for sym in kallsyms:
       if any(pattern in sym['name'] for pattern in ROOTKIT_SYMBOLS):
           alert("ROOTKIT_SYMBOL", sym)
   ```

3. **Syscall Handler Overrides**
   ```python
   # Check if syscall_table entries point to non-kernel modules
   for syscall in syscall_table:
       handler_addr = syscall['address']
       module = find_module_for_address(handler_addr)
       if module and module not in KERNEL_MODULES:
           alert("SYSCALL_HOOK", syscall, module)
   ```

---

### File Integrity Monitor (FIM)

**Purpose:** Detect unauthorized file modifications.

**Implementation:**
- **Primary Hash:** SHA-256
- **Optimization:** Stat-based look-back cache (skip hashing if mtime/ctime/size unchanged)
- **Baseline Comparison:** Compare against trusted baseline or previous snapshot

**Configuration:**
```toml
# /etc/orin/config.toml
[integrity]
paths = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/boot/",
    "/usr/bin/",
    "/usr/sbin/"
]

exclude_patterns = [
    "*.log",
    "*.tmp",
    "/var/cache/*"
]
```

**Performance Characteristics:**
- Initial scan: ~10,000 files/min (depends on I/O)
- Incremental scan: ~100,000 files/min (cache hits skip hashing)

---

### Binary Session Auditor

**Purpose:** Parse wtmp/lastlog for login session tracking and anti-forensic detection.

**Binary Structures:**

**wtmp Entry (384 bytes):**
```c
struct utmp {
    short ut_type;           // LOGIN_PROCESS, USER_PROCESS, DEAD_PROCESS
    pid_t ut_pid;
    char ut_line[32];        // tty/pts
    char ut_id[4];
    char ut_user[32];        // Username
    struct timeval ut_tv;    // Timestamp
    int32_t ut_addr_v6[4];   // Remote IP
};
```

**lastlog Entry (292 bytes per UID):**
```c
struct lastlog {
    ll_time_t ll_time;       // Last login timestamp
    char ll_line[8];         // TTY
    char ll_host[16];        // Remote host
};
```

**Anti-Forensic Detection:**
- Zeroed records (indicates log clearing)
- Timestamp anomalies (epoch resets, future dates)
- Missing logout records for active sessions

---

### DNS Forensics & Tunneling Detection

**Purpose:** Identify DNS-based data exfiltration and C2 channels.

**Detection Techniques:**

1. **Shannon Entropy Analysis**
   ```python
   def shannon_entropy(domain):
       freq = Counter(domain)
       length = len(domain)
       return -sum((count/length) * log2(count/length)
                   for count in freq.values())

   # High entropy (>4.0) suggests DGA or encoded data
   if entropy(subdomain) > 4.0:
       alert("HIGH_ENTROPY_DNS", domain)
   ```

2. **Structural Domain Analysis**
   - Subdomain length > 50 characters
   - Numeric patterns (base32/base64 encoding)
   - Unusual TLDs associated with malware

3. **TXT Record Abuse**
   - Excessive TXT queries to single domain
   - Large TXT response sizes (>512 bytes)

4. **Per-Process DNS Profiling**
   - Correlate DNS queries with originating process
   - Flag unexpected processes making DNS requests

---

### Triggered PCAP Capture

**Purpose:** Preserve network packet evidence when forensic triggers occur.

**Trigger Conditions:**
- Reverse shell detection
- C2 beacon pattern match
- Suspicious outbound connection to blocklisted IP
- DNS tunneling alert

**Implementation:**
```python
# When trigger fires:
if trigger_event in ['reverse_shell', 'c2_beacon', 'dns_tunnel']:
    pcap_path = f"/var/lib/orin/pcaps/{trigger_id}.pcap"

    if HAS_SCAPY:
        # Reconstruct packets with Scapy
        packets = sniff(filter=f"host {suspicious_ip}",
                       count=1000, timeout=30)
        wrpcap(pcap_path, packets)
    else:
        # Raw socket capture fallback
        capture_raw_pcap(pcap_path, suspicious_ip)

    # Associate PCAP with alert in database
    associate_pcap_with_alert(alert_id, pcap_path)
```

**Storage Management:**
- Automatic deletion after 7 days (configurable)
- Size limit: 100MB per capture
- Compression: gzip for archives >7 days old

---

## Threat Detection Engine

### Rule Evaluation Pipeline

```
┌─────────────────┐
│ Collected Data  │
│ (Snapshot N)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Baseline Diff   │
│ (vs Snapshot 1) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Sigma Rules     │
│ (Log Patterns)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ YARA Rules      │
│ (Binary/File)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Heuristic Rules │
│ (Behavioral)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ MITRE ATT&CK    │
│ Tagging         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Alert Generation│
│ (Risk Score)    │
└─────────────────┘
```

### Built-In Detection Rules

#### Kernel Thread Masquerade (T1014)

**Logic:**
```python
KERNEL_THREAD_PREFIXES = ['kworker', 'ksoftirqd', 'kcompactd', 'khungtaskd']

for proc in processes:
    if any(proc['comm'].startswith(prefix)
           for prefix in KERNEL_THREAD_PREFIXES):
        if proc['ppid'] != 0 and proc['ppid'] != 2:
            alert(
                event_type='KERNEL_THREAD_MASQUERADE',
                severity='CRITICAL',
                details={
                    'pid': proc['pid'],
                    'ppid': proc['ppid'],
                    'comm': proc['comm'],
                    'cmdline': proc['cmdline']
                },
                mitre=['T1014']  # Rootkit
            )
```

**Rationale:** Legitimate kernel threads have PID 0 (idle) or PPID 2 (kthreadd). Userspace-spawned processes with kernel thread names indicate masquerading.

---

#### Reverse Shell Detection (T1059.004)

**Logic:**
```python
REVERSE_SHELL_PATTERNS = [
    r'/bin/(ba)?sh\s+-i\s*>\s*&\s*\d+\s*<\s*&\s*(\d+)\s*\|\s*(\d+)',
    r'nc\s+(-e\s+)?(/bin/(ba)?sh)',
    r'python.*socket.*connect',
    r'perl\s+.*Socket.*connect',
    r'ruby.*require.*socket.*TCPSocket',
]

for proc in processes:
    cmdline = proc['cmdline']
    if any(re.search(pattern, cmdline, re.IGNORECASE)
           for pattern in REVERSE_SHELL_PATTERNS):
        alert(
            event_type='REVERSE_SHELL',
            severity='CRITICAL',
            details={'pid': proc['pid'], 'cmdline': cmdline},
            mitre=['T1059.004']  # Command and Scripting Interpreter
        )
```

---

#### SSH Persistence (T1098.004)

**Logic:**
```python
# Check for new authorized_keys entries
current_keys = gather_ssh_authorized_keys()
baseline_keys = load_baseline_ssh_keys()

new_keys = current_keys - baseline_keys
if new_keys:
    alert(
        event_type='SSH_PERSISTENCE',
        severity='HIGH',
        details={
            'new_keys': list(new_keys),
            'affected_users': [k['user'] for k in new_keys]
        },
        mitre=['T1098.004']  # Account Manipulation: SSH Authorized Keys
    )
```

---

#### Cron Drift Detection (T1053.003)

**Logic:**
```python
CRON_PATHS = [
    '/var/spool/cron/',
    '/etc/crontab',
    '/etc/cron.d/',
    '/etc/cron.daily/',
    '/etc/cron.hourly/',
    '/etc/cron.weekly/',
    '/etc/cron.monthly/'
]

VOLATILE_PATHS = ['/tmp', '/var/tmp', '/dev/shm']

for cron_entry in parse_all_crontabs():
    # Check for volatile path execution
    if any(volatile in cron_entry['command']
           for volatile in VOLATILE_PATHS):
        alert(
            event_type='CRON_VOLATILE_PATH',
            severity='MEDIUM',
            details=cron_entry,
            mitre=['T1053.003']  # Scheduled Task: Cron
        )

    # Check for reverse shell commands
    if matches_reverse_shell_pattern(cron_entry['command']):
        alert(
            event_type='CRON_REVERSE_SHELL',
            severity='CRITICAL',
            details=cron_entry,
            mitre=['T1053.003', 'T1059.004']
        )
```

---

### Sigma Rule Format

Orin supports a subset of Sigma rules for log pattern matching:

```yaml
title: SSH Brute Force Attempt
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
level: high
description: Detects multiple failed SSH login attempts
author: Orin Project
date: 2025/01/15
references:
    - https://attack.mitre.org/techniques/T1110/001/
tags:
    - attack.credential_access
    - attack.t1110.001
logsource:
    category: authentication
    product: linux
    service: sshd
detection:
    selection:
        EventID: 'failed-password'
        Keyword: 'sshd'
    condition: selection | count() > 5 timespan 5m
falsepositives:
    - Legitimate forgotten password attempts
```

**Sigma Rule Locations:**
- System rules: `/etc/orin/rules/sigma/`
- Custom rules: `/opt/orin-custom/rules/`

---

### YARA Rule Integration

Orin includes an embedded YARA engine for pattern matching:

```yara
rule CryptoMiner_XMRig {
    meta:
        description = "Detects XMRig cryptocurrency miner"
        author = "Orin Project"
        severity = "high"
        mitre = "T1496"  # Resource Hijacking

    strings:
        $str1 = "xmrig" ascii wide
        $str2 = "donate level" ascii
        $str3 = "pool.us" ascii
        $hex1 = { 4D 6F 6E 65 72 6F 00 }  // "Monero"

    condition:
        2 of them
}
```

**Rule Locations:**
- Default rules: `/etc/orin/rules/yara/`
- Custom rules: `/opt/orin-custom/yara/`

**Scanning Targets:**
- Dumped in-memory binaries (from deleted processes)
- Files matching FIM changes
- Executables in suspicious paths (`/tmp`, `/dev/shm`)

---

## Cryptographic Evidence Handling

### Vault Encryption

**Algorithm:** AES-256-GCM
**Key Derivation:** PBKDF2-HMAC-SHA256 (100,000 iterations)
**Salt:** 16 bytes random per vault

**Enable Encryption:**
```bash
# Option 1: Environment variable
export ORIN_VAULT_PASSPHRASE="my-secure-passphrase"
sudo orin collect

# Option 2: Passphrase file (recommended for automation)
echo "my-secure-passphrase" > /etc/orin/vault.pass
chmod 600 /etc/orin/vault.pass
sudo orin collect --passphrase-file /etc/orin/vault.pass

# Option 3: Interactive prompt
sudo orin collect --passphrase-prompt

# Option 4: Custom environment variable name
export CUSTOM_ORIN_PASS="my-passphrase"
sudo orin collect --passphrase-env-var CUSTOM_ORIN_PASS
```

**Encryption Flow:**
```
Passphrase → PBKDF2 (100k iterations, random salt) → 256-bit AES key
                                               ↓
SQLite data → AES-256-GCM encrypt → Encrypted blob + 16-byte tag
```

---

### Signed Export Bundles

**Format:** JSON with HMAC-SHA256 signature

**Structure:**
```json
{
  "version": "1.0",
  "algorithm": "hmac-sha256",
  "timestamp": "2025-06-10T14:32:15Z",
  "snapshot_id": 42,
  "hostname": "prod-web-01",
  "signature": "<base64-encoded-hmac>",
  "data": {
    "processes": [...],
    "connections": [...],
    "alerts": [...],
    ...
  }
}
```

**Export:**
```bash
orin export --snapshot 42 --secret "signing-key" -o evidence.json
```

**Verify:**
```bash
orin verify --file evidence.json --secret "signing-key"

# Output:
# ✓ Signature valid
# ✓ Data integrity confirmed
# ✓ Timestamp: 2025-06-10T14:32:15Z
```

---

### Chain of Custody

For legal admissibility, maintain:

1. **Original Evidence:** Never modify original vault/export
2. **Hash Verification:** Document SHA-256 of all exports
3. **Access Log:** Record all `orin verify` operations
4. **Passphrase Custody:** Store signing keys separately from evidence

**Example Chain-of-Custody Record:**
```
Case: IR-2025-001
Evidence File: evidence_snapshot_42.json
SHA-256: a1b2c3d4e5f67890...
Export Time: 2025-06-10T14:32:15Z
Exported By: analyst@example.com
Verified By: supervisor@example.com (2025-06-10T15:00:00Z)
Storage Location: /evidence/IR-2025-001/original/
```

---

## Dashboard & Reporting

### Local Dashboard (`orin serve`)

**Features:**
- Live risk score gauge (0-100)
- Severity-tiered alert feed with triage actions
- Telemetry Explorer tab (inspect all collected datasets)
- Inline process termination (local or remote)
- Timeline delta comparison shortcuts
- Encrypted vault status indicator

**Access Control:**
- **Default:** Ephemeral 256-bit token (regenerated per restart)
- **Persistent:** Token file (`--token-file`)
- **Basic Auth:** Username/password (`--username`, `--password`)
- **mTLS:** Client certificate validation
- **Unix Socket:** Local-only access (`--host unix:///var/run/orin.sock`)

**Example Sessions:**

```bash
# Ephemeral token (most secure)
sudo orin serve
# Output: Access URL: http://127.0.0.1:8000/?token=abc123def456...

# Persistent token file
sudo orin serve --token-file /etc/orin/dashboard.token
# Token saved with 0600 permissions

# Basic authentication
sudo orin serve --username admin --password "SecureP@ss"

# Unix socket (no network exposure)
sudo orin serve --host unix:///var/run/orin.sock
# Access via: curl --unix-socket /var/run/orin.sock http://localhost/
```

---

### Report Formats

#### Markdown Briefing

**Use Case:** Executive summaries, email attachments, ticketing systems.

```bash
orin report -o briefing.md -f markdown
```

**Sections:**
1. Executive Summary (risk score, alert count)
2. Critical Alerts (with MITRE ATT&CK mapping)
3. Process Anomalies
4. Network Changes
5. File Integrity Violations
6. Recommendations

#### HTML Dashboard

**Use Case:** Interactive investigation, SOC displays.

```bash
orin report -o dashboard.html -f html
```

**Features:**
- Dark-mode theme (SOC-friendly)
- Tabbed navigation (Overview, Alerts, Processes, Network, Files)
- Severity badges (Critical, High, Medium, Low, Info)
- Collapsible alert details
- Search/filter functionality
- Zero external JavaScript dependencies

---

## Fleet Management

### Centralized Hub (`orin hub-serve`)

**Purpose:** Multi-tenant forensic management across air-gapped networks.

**Capabilities:**
- API key authentication per host
- Host registration with heartbeat monitoring
- Forensic data import/export
- Configurable binding (host/port)
- HTTPS support
- Flexible credential handling

**Deployment:**

```bash
# Generate API keys for each host
for host in web01 web02 db01; do
    api_key=$(openssl rand -hex 32)
    echo "$host:$api_key" >> /etc/orin/hub_api_keys.txt
    chmod 600 /etc/orin/hub_api_keys.txt
done

# Launch hub server
sudo orin hub-serve 8000 -H 0.0.0.0 \
    --cert /etc/ssl/hub.crt \
    --key /etc/ssl/hub.key \
    --passphrase-file /etc/orin/vault.pass
```

**Agent Registration:**

On each target host:
```bash
# Register with hub
curl -k -X POST https://hub.example.com:8000/api/v1/register \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "hostname": "web01",
        "ip": "10.0.1.50",
        "os": "Ubuntu 22.04",
        "orin_version": "1.0.0"
    }'

# Upload forensic vault
curl -k -X POST https://hub.example.com:8000/api/v1/import \
    -H "Authorization: Bearer $API_KEY" \
    -F "vault=@/var/lib/orin/orin_vault.db"
```

---

### Agentless SSH Scanning

**Use Case:** Scan routers, containers, legacy systems without installing Orin.

**Mechanism:**
1. Establish SSH connection
2. Upload self-contained Python collector (or bash fallback)
3. Execute remotely, capture stdout
4. Parse and store in local vault

**Requirements:**
- SSH access (key-based recommended)
- Python 3.6+ on target (falls back to pure bash if unavailable)
- No persistent installation on target

**Example:**
```bash
# Scan remote host
sudo orin scan --host 192.168.1.100 \
    --user admin \
    --key ~/.ssh/orin_scan_key \
    -p 2222

# Initialize baseline for future drift detection
sudo orin scan --host 192.168.1.100 \
    --user admin \
    --key ~/.ssh/orin_scan_key \
    --init
```

---

## Advanced Configuration

### Configuration File

**Location:** `/etc/orin/config.toml`

```toml
# Global settings
[global]
log_level = "INFO"
log_file = "/var/log/orin/orin.log"
vault_path = "/var/lib/orin/orin_vault.db"

# Vault encryption
[vault]
encryption_enabled = true
passphrase_env_var = "ORIN_VAULT_PASSPHRASE"
key_derivation_iterations = 100000

# Collection settings
[collection]
parallel_collectors = 4
timeout_seconds = 300
skip_deleted_binary_dump = false

# File Integrity Monitoring
[integrity]
paths = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/boot/",
    "/usr/bin/",
    "/usr/sbin/"
]
exclude_patterns = ["*.log", "*.tmp", "/var/cache/*"]
hash_algorithm = "sha256"
enable_stat_cache = true

# Threat detection
[detection]
enable_sigma = true
enable_yara = true
sigma_rules_dir = "/etc/orin/rules/sigma/"
yara_rules_dir = "/etc/orin/rules/yara/"
ioc_importer_dirs = ["/etc/orin/ioc/"]

# MITRE ATT&CK mapping
[attck]
enabled = true
include_urls = true

# Alert suppression
[alerts]
auto_resolve = true
suppression_rules_file = "/etc/orin/suppression.toml"
default_severity = "medium"

# Dashboard
[dashboard]
bind_host = "127.0.0.1"
bind_port = 8000
enable_https = false
session_timeout_minutes = 60

# Scheduler
[scheduler]
enabled = false
interval_minutes = 10
retention_days = 90
prune_on_collection = true

# eBPF streaming
[ebpf]
enabled = false
ring_buffer_size_kb = 1024
tracepoints = [
    "sys_enter_execve",
    "sys_enter_connect",
    "sys_enter_openat"
]

# AI correlation
[ai]
enabled = false
ollama_url = "http://127.0.0.1:11434"
model = "llama3"
max_context_hosts = 10

# Self-defense
[self_defense]
enable_watchdog = false
enable_seccomp = false
enable_apparmor = false
enable_selinux = false
```

---

### Suppression Rules

**Purpose:** Reduce alert noise from known-good anomalies.

**Location:** `/etc/orin/suppression.toml`

```toml
# Suppress alerts from specific processes
[[suppress]]
event_type = "KERNEL_THREAD_MASQUERADE"
condition = "pid == 1234"
expires = "2025-12-31T23:59:59Z"
reason = "Known monitoring agent"

# Suppress alerts for specific network connections
[[suppress]]
event_type = "OUTBOUND_C2_CONNECTION"
condition = "remote_ip == '10.0.0.1' and remote_port == 443"
reason = "Legitimate internal update server"

# Suppress FIM alerts for expected changes
[[suppress]]
event_type = "FIM_MODIFIED"
condition = "path.startswith('/var/log/')"
reason = "Expected log rotation"
```

---

### Custom Detection Rules

**Adding Custom Sigma Rules:**

1. Create rule file: `/etc/orin/rules/sigma/custom_suspicious_login.yml`
```yaml
title: Suspicious Login Time
id: custom-001
status: experimental
level: medium
description: Detects logins outside business hours
logsource:
    category: authentication
    product: linux
detection:
    selection:
        EventID: 'session-opened'
    timeframe:
        start: "22:00"
        end: "06:00"
    condition: selection
```

2. Validate syntax:
```bash
orin rules validate /etc/orin/rules/sigma/custom_suspicious_login.yml
```

3. Reload rules:
```bash
orin rules update
```

**Adding Custom YARA Rules:**

1. Create rule file: `/etc/orin/rules/yara/custom_backdoor.yar`
```yara
rule Custom_Backdoor {
    meta:
        description = "Detects custom backdoor pattern"
        severity = "critical"

    strings:
        $backdoor_sig = "BACKDOOR_INIT_SEQ" ascii
        $c2_marker = { DE AD BE EF CA FE BA BE }

    condition:
        all of them
}
```

2. Validate and reload:
```bash
orin rules validate /etc/orin/rules/yara/
orin rules update
```

---

## Troubleshooting & FAQ

### Common Issues

#### Issue: "Database locked" error during collection

**Cause:** Concurrent access to vault (e.g., `orin serve` running during `orin collect`).

**Solution:**
```bash
# Stop dashboard during collection
sudo systemctl stop orin-dashboard  # If using systemd

# Or use WAL mode for concurrent reads
sqlite3 /var/lib/orin/orin_vault.db "PRAGMA journal_mode=WAL;"
```

---

#### Issue: eBPF streaming fails with "permission denied"

**Cause:** Kernel lockdown or missing capabilities.

**Solution:**
```bash
# Check lockdown status
cat /sys/kernel/security/lockdown

# If 'integrity' or 'confidentiality', disable in GRUB:
# Edit /etc/default/grub, add:
GRUB_CMDLINE_LINUX="lockdown=0"
update-grub && reboot

# Or ensure CAP_BPF capability:
setcap cap_bpf+ep /usr/bin/python3
```

---

#### Issue: High CPU usage during collection

**Cause:** Large number of files in FIM paths.

**Solution:**
```toml
# /etc/orin/config.toml
[integrity]
# Exclude high-churn directories
exclude_patterns = [
    "*.log",
    "/var/cache/*",
    "/tmp/*",
    "/var/spool/*"
]

# Reduce parallelism
[collection]
parallel_collectors = 2
```

---

#### Issue: False positive "Kernel Thread Masquerade" alerts

**Cause:** Legitimate userspace process with kernel-like name.

**Solution:**
```toml
# /etc/orin/suppression.toml
[[suppress]]
event_type = "KERNEL_THREAD_MASQUERADE"
condition = "comm == 'kworker-custom' and ppid == 1"
reason = "Known legitimate process"
```

---

#### Issue: Dashboard won't start on port 8000

**Cause:** Port already in use.

**Solution:**
```bash
# Find conflicting process
sudo lsof -i :8000

# Use alternative port
sudo orin serve 8080

# Or kill conflicting process
sudo kill <PID>
```

---

### FAQ

**Q: Does Orin work on containers?**
A: Yes, but with limitations. Orin can enumerate processes and network connections inside containers if run with sufficient privileges (`--privileged` or specific capabilities: `CAP_SYS_PTRACE`, `CAP_NET_RAW`). However, kernel-level visibility (modules, kallsyms) reflects the host kernel, not container-isolated state.

**Q: Can Orin detect kernel rootkits?**
A: Orin employs multiple detection techniques:
- Cross-view differential (compare `/proc/modules` vs `/proc/kallsyms`)
- Kernel symbol integrity checks
- Hidden process detection via scheduler probing
However, a fully compromised kernel can potentially evade all userspace detection. Orin's approach is "trust but verify" — anomalies are flagged for manual investigation.

**Q: Is the SQLite vault encrypted by default?**
A: No. Encryption must be explicitly enabled via `ORIN_VAULT_PASSPHRASE` environment variable or `--passphrase-*` flags. This design allows Orin to operate in environments where encryption keys cannot be safely stored.

**Q: How long does a typical collection take?**
A: On a standard Ubuntu 22.04 server:
- Process/network enumeration: <5 seconds
- FIM scan (10,000 files): 30-60 seconds (faster with cache hits)
- Kernel module analysis: <2 seconds
- Log parsing: 5-10 seconds
**Total:** ~1-2 minutes for full collection.

**Q: Can I run Orin without root?**
A: Partially. Non-root execution limits visibility:
- Cannot read `/proc/[pid]/exe` for other users
- Cannot access `/proc/kallsyms` (kernel symbols)
- Cannot parse `/var/log/wtmp` (binary session logs)
- Cannot detect promiscuous mode
For full forensic capability, root (or equivalent capabilities) is required.

**Q: Does Orin modify the system?**
A: No. Orin is strictly read-only during collection. The only writes are:
- SQLite vault (to configured path)
- Optional PCAP captures (to `/var/lib/orin/pcaps/`)
- Log files (if configured)
No system binaries, configurations, or logs are modified.

**Q: How do I upgrade Orin?**
A: For air-gapped environments:
1. Download release package on internet-connected system
2. Verify GPG signature: `gpg --verify orin-X.Y.Z.tar.gz.sig`
3. Transfer via USB to air-gapped system
4. Run installer: `./install.sh`
5. Verify self-integrity: `orin version --self-check`

---

## Security Considerations

### Threats to Orin Itself

1. **Privilege Escalation via Dashboard**
   **Mitigation:** Dashboard binds to localhost by default. Use `--no-auth` only on trusted networks. Enable mTLS or Unix socket for high-security deployments.

2. **Passphrase Exposure**
   **Mitigation:** Use `--passphrase-file` with 0600 permissions instead of environment variables (visible in `ps`, `/proc/[pid]/environ`).

3. **Vault Theft**
   **Mitigation:** Enable AES-256-GCM encryption. Store passphrase separately from vault file.

4. **Rule Tampering**
   **Mitigation:** Store rules in immutable filesystem (e.g., squashfs). Use `orin rules validate` periodically.

5. **Time-of-Check-Time-of-Use (TOCTOU)**
   **Mitigation:** Orin collects atomically where possible. For critical investigations, run multiple rapid collections and compare.

### Hardening Recommendations

**For Production Deployments:**

```bash
# 1. Run Orin as dedicated user
useradd -r -s /sbin/nologin orin
chown -R orin:orin /var/lib/orin /etc/orin

# 2. Apply AppArmor profile
orin self-defense --action generate-profiles --output-dir /etc/apparmor.d/
systemctl restart apparmor

# 3. Enable seccomp filtering
orin self-defense --action watchdog --socket /var/run/orin/watchdog.sock

# 4. Restrict vault permissions
chmod 600 /var/lib/orin/orin_vault.db
chattr +i /var/lib/orin/orin_vault.db  # Immutable flag (remove for updates)

# 5. Use Unix socket for dashboard
sudo -u orin orin serve --host unix:///var/run/orin/dashboard.sock
```

---

## Appendix A: Database Schema

### Core Tables

**`system_snapshots`**
```sql
CREATE TABLE system_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    hostname TEXT NOT NULL,
    kernel_version TEXT,
    orin_version TEXT,
    collection_duration_ms INTEGER,
    encrypted INTEGER DEFAULT 0
);
```

**`processes`**
```sql
CREATE TABLE processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER NOT NULL,
    comm TEXT,
    exe TEXT,
    cmdline TEXT,
    state TEXT,
    uid INTEGER,
    gid INTEGER,
    start_time TEXT,
    FOREIGN KEY (snapshot_id) REFERENCES system_snapshots(id)
);
```

**`network_connections`**
```sql
CREATE TABLE network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    protocol TEXT,  -- tcp, udp, tcp6, udp6
    local_ip TEXT,
    local_port INTEGER,
    remote_ip TEXT,
    remote_port INTEGER,
    state TEXT,
    pid INTEGER,
    FOREIGN KEY (snapshot_id) REFERENCES system_snapshots(id)
);
```

**`kernel_modules`**
```sql
CREATE TABLE kernel_modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    module_name TEXT NOT NULL,
    memory_size INTEGER,
    FOREIGN KEY (snapshot_id) REFERENCES system_snapshots(id)
);
```

**`alerts`**
```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,  -- critical, high, medium, low, info
    description TEXT,
    details_json TEXT,
    mitre_techniques TEXT,  -- JSON array of technique IDs
    status TEXT DEFAULT 'open',  -- open, resolved, suppressed
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    FOREIGN KEY (snapshot_id) REFERENCES system_snapshots(id)
);
```

**`baseline_kernel_modules`**, **`baseline_users`**, **`baseline_suid_binaries`**
```sql
CREATE TABLE baseline_kernel_modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    module_name TEXT NOT NULL,
    memory_size INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE baseline_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    username TEXT NOT NULL,
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL,
    home_dir TEXT,
    login_shell TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE baseline_suid_binaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    file_path TEXT NOT NULL,
    owner TEXT,
    grp TEXT,
    permissions TEXT,
    sha256 TEXT,
    created_at TEXT NOT NULL
);
```

**`encrypted_vault_metadata`** (when encryption enabled)
```sql
CREATE TABLE encrypted_vault_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    salt BLOB NOT NULL,  -- 16 bytes
    iterations INTEGER NOT NULL,
    algorithm TEXT NOT NULL,  -- 'aes-256-gcm'
    created_at TEXT NOT NULL
);
```

---

## Appendix B: MITRE ATT&CK Mapping

Orin maps detected events to MITRE ATT&CK Enterprise Matrix (Linux platform):

| Orin Event Type | MITRE Technique ID | Tactic |
|-----------------|-------------------|--------|
| `KERNEL_THREAD_MASQUERADE` | T1014 | Defense Evasion |
| `ROOTKIT_SYMBOL_DETECTED` | T1014 | Defense Evasion |
| `UNLINKED_MODULE` | T1014 | Defense Evasion |
| `REVERSE_SHELL` | T1059.004 | Execution |
| `SSH_PERSISTENCE` | T1098.004 | Persistence |
| `CRON_REVERSE_SHELL` | T1053.003, T1059.004 | Persistence, Execution |
| `CRON_VOLATILE_PATH` | T1053.003 | Persistence |
| `HIDDEN_PROCESS` | T1014 | Defense Evasion |
| `PROMISC_MODE_ENABLED` | T1040 | Discovery |
| `DELETED_BINARY_EXECUTING` | T1027.009 | Defense Evasion |
| `SUID_DRIFT` | T1548.001 | Privilege Escalation |
| `USER_ACCOUNT_ADDED` | T1136.001 | Persistence |
| `SSH_KEY_ADDED` | T1098.004 | Persistence |
| `DNS_TUNNEL_HIGH_ENTROPY` | T1071.004 | Command and Control |
| `C2_CONNECTION_DETECTED` | T1071 | Command and Control |
| `PACKAGE_TAMPERED` | T1565.001 | Impact |
| `FIM_MODIFIED_CRITICAL` | T1565.001 | Impact |
| `WTMP_TAMPERING` | T1070.002 | Defense Evasion |
| `PRIVILEGE_ESCALATION_SYSCALL` | T1548 | Privilege Escalation |
| `CREDENTIAL_ACCESS_ATTEMPT` | T1552 | Credential Access |

**Full MITRE ATT&CK Navigator Layer:**
Export compatible layer files via:
```bash
orin report -o attck_layer.json --format attck-nav-layer
```

---

## Appendix C: Rule Syntax Reference

### Sigma Rule Schema (Supported Subset)

```yaml
title: <string>              # Rule title (required)
id: <uuid>                   # Unique identifier (required)
status: <string>             # stable | test | experimental
level: <string>              # critical | high | medium | low | informational
description: <string>        # Human-readable description
author: <string>             # Rule author
date: <YYYY/MM/DD>           # Creation date
references:                  # Optional URLs
    - <url>
tags:                        # Optional MITRE tags
    - attack.<tactic>
    - attack.<technique_id>
logsource:                   # Log source definition
    category: <string>       # authentication | process_creation | file_event
    product: <string>        # linux | windows | macos
    service: <string>        # sshd | auditd | syslog
detection:
    selection:               # Detection logic
        <field>: <value>     # Field-value pairs
        EventID: <string>
        Keyword: <string>
    condition: <string>      # Boolean expression (e.g., "selection")
falsepositives:              # Optional list
    - <description>
```

**Condition Expressions:**
```yaml
# Simple match
condition: selection

# Multiple selections
detection:
    selection1:
        EventID: 'failed-password'
    selection2:
        EventID: 'invalid-user'
    condition: selection1 or selection2

# Aggregation (count threshold)
detection:
    selection:
        EventID: 'failed-password'
    timeframe: 5m
    condition: selection | count() > 5 timespan 5m
```

---

### YARA Rule Schema

```yara
rule <RuleName> {
    meta:
        description = "<string>"
        author = "<string>"
        severity = "<string>"     # critical | high | medium | low
        mitre = "<technique_id>"  # Optional MITRE mapping
        date = "<YYYY-MM-DD>"
        hash = "<sha256>"         # Optional reference hash

    strings:
        $identifier = "<string>" [modifiers]
        $hex_string = { <hex_bytes> }
        $regex = /<regular_expression>/ [modifiers]

    modifiers:
        ascii           # ASCII string
        wide            # UTF-16LE encoding
        nocase          # Case-insensitive
        fullword        # Word boundary match
        xor             # XOR-encoded (1-255)
        base64          # Base64-encoded
        base64wide      # Base64 with wide chars
        private         # Exclude from reporting

    condition:
        <boolean_expression>
        # Examples:
        # all of them
        # any of them
        # 2 of ($*)
        # $string1 and $hex_string
        # filesize < 1MB
}
```

**Example: Multi-String Detection**
```yara
rule Suspicious_Python_Shell {
    meta:
        description = "Detects Python-based shell spawning"
        severity = "high"
        mitre = "T1059.006"

    strings:
        $py1 = "import subprocess" ascii
        $py2 = "subprocess.call" ascii
        $py3 = "/bin/sh" ascii
        $py4 = "-c" ascii

    condition:
        $py1 and $py2 and any of ($py3, $py4)
}
```

---

## Contributing

For development guidelines, testing procedures, and contribution workflows, refer to:
- `CONTRIBUTING.md` (if available)
- GitHub Issues: https://github.com/jaradat13/orin/issues
- Test Suite: `pytest tests/ -v`

---

## License

**AGPLv3** — See `LICENSE` file for full terms.

**Summary:**
- Free to use, modify, and distribute
- Modifications must be released under same license
- Network use counts as distribution (must provide source)
- No warranty provided

---

## Support & Community

- **Documentation:** This guide + `README.md`
- **Issues:** https://github.com/jaradat13/orin/issues
- **Discussions:** https://github.com/jaradat13/orin/discussions
- **Security Reports:** security@orin-project.org (PGP: see `SECURITY.md`)

---

**Document Version:** 1.0.0
**Last Revised:** June 2025
**Maintained By:** Orin Project Contributors