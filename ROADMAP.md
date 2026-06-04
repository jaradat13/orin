# Orin — Forensic & Threat Detection Roadmap

This document outlines the strategic roadmap for the **Orin Forensic Engine**, detailing recently integrated features and planning upcoming next-generation capabilities. 

> [!IMPORTANT]
> **Orin operates strictly offline and locally.** The engine does not connect to any cloud services, external APIs, or remote servers. All telemetry collection, signature matching, and timeline analysis run entirely on the local system to guarantee absolute privacy and integrity of forensic evidence.

---

## ✅ Recently Integrated Capabilities

The following baseline forensic capabilities have been fully implemented, verified, and integrated into the core engine:

1. **In-Memory Executable Recovery (`orin.collectors.deleted_binaries`)**
   * Automatically monitors virtual `/proc/[pid]/exe` symlinks for unlinked execution images, dumps the active payload directly to the secure local vault (`/var/lib/orin/vault/`), and logs cryptographic hashes (MD5 and SHA-256) for offline reputation checkups.
2. **Promiscuous Mode Interface Flag Monitor (`orin.collectors.promisc`)**
   * Audits interface flags directly in the kernel via `/sys/class/net/*/flags` to flag interfaces placed in promiscuous mode (`IFF_PROMISC` / `0x100`) for network packet sniffing.
3. **Binary Login and Session Auditor (`orin.collectors.session_audit`)**
   * Uses binary structure parsing on `/var/log/wtmp` and `/var/log/lastlog` to track login/logout lifecycles and raise critical events on zeroed-out records or epoch timestamp resets (anti-forensic tampering).
4. **Out-of-Band Hidden Process Detector (`orin.analysis.unhide`)**
   * Probes active scheduler processes via null signaling (`os.kill(pid, 0)`) and cross-references them against visible `/proc` directories, utilizing double-check path validation to eliminate race-condition false-positives on transient processes.
5. **Offline Package Integrity Engine (`orin.collectors.pkg_integrity`)**
   * Verifies on-disk system binary hashes against registered Debian `/var/lib/dpkg/info/*.md5sums` records to locate missing or modified packages on disk.
6. **Forensic Alert Auto-Resolution (`orin.analysis.engine`)**
   * Keeps the local alert ledger clean by automatically marking historic events (ports, modules, users, hidden processes, deleted execution images, promiscuous interfaces, and cron anomalies) as resolved once the anomalous states return to baseline.
7. **Per-User & System Crontab Persistence Harvester (`orin.collectors.crontabs`)**
   * Parses and audits all scheduled cron tasks from user spool directories (`/var/spool/cron/crontabs/*`), system-wide `/etc/crontab`, configuration snippets in `/etc/cron.d/*`, and timed script directories (`/etc/cron.hourly`, `.daily`, `.weekly`, `.monthly`). The rules engine detects newly added cron jobs (drift), execution from volatile directories (`/tmp`, `/dev/shm`), and reverse-shell command signatures (`bash -i`, `nc`, `xmrig`). All cron events support automatic resolution once the malicious entries are removed.
8. **First-Run False-Positive Guard (`orin.analysis.engine`)**
   * The `new_cron_job` drift rule now skips comparison on any snapshot where the previous snapshot had zero crontab records (e.g. the first collection cycle after a schema upgrade). This eliminates false positive storms when upgrading the engine on a system with an existing vault.

---

## 🔭 Next-Generation Capabilities & Future Features

To solve major gaps in the Linux forensics industry while maintaining a strict offline boundary, our upcoming feature pipeline is organized into five strategic pillars:

### 1. Secure, Local AI Triage & Multi-Host Correlation

Analyzing raw forensic evidence using external servers or SaaS platforms introduces massive privacy and compliance risks. Orin will introduce local, secure multi-host correlation.

* **Planned Feature: Local AI Timeline Correlator (`orin.analysis.ai_correlator`)**
  * **Objective:** Correlate signed JSON snapshot exports from multiple systems (e.g., a developer workstation, an application server, and a database) on the analyst's machine.
  * **Implementation:** Feed consolidated timelines through a local, context-optimized model (running locally on the workstation via ONNX or Ollama). The engine will automatically map lateral movement, identify shared Indicators of Compromise (IoCs), and output a unified multi-host incident brief.
* **Planned Feature: Cross-Snapshot Drift Reports (`orin report --diff`)**
  * **Objective:** Allow analysts to run comparative differentials between snapshots locally.
  * **Implementation:** CLI parameters `orin report --format html --base <id1> --target <id2>` will build a self-contained offline comparison dashboard highlighting additions, modifications, and removals of processes, ports, files, and users.

### 2. Forensic Auditing for eBPF-Based Rootkits

Stealthy eBPF-based rootkits (such as LinkPro, TripleCross, and ebpfkit) run sandboxed inside the kernel's virtual machine, making them completely invisible to traditional LKM and file integrity scanners.

* **Planned Feature: eBPF Subsystem Auditor (`orin.collectors.ebpf`)**
  * **Objective:** Audit the state of the local eBPF subsystem to expose malicious filters and rootkits.
  * **Implementation:** Enumerate loaded BPF programs, track pinned objects under `/sys/fs/bpf`, detect dynamic linker preload overrides, and raise alerts when administrative tools like `bpftool` are used to rewrite policy maps or detach security filters.
* **Planned Feature: Open File Descriptor Harvester (`orin.collectors.file_descriptors`)**
  * **Objective:** Audit open process descriptors to expose fileless malware.
  * **Implementation:** Walk `/proc/[pid]/fd/` and flag anonymous memory-backed file descriptors (`memfd:`) and unexpected hidden Unix socket streams.

### 3. Lightweight Linux Log Triage via Sigma Rules

Linux log auditing (`syslog`, `auditd`, `journald`) lacks a lightweight, standardized local scanner equivalent to Windows-centric log-parsing standards.

* **Planned Feature: Sigma Log Parser & Rules Matcher (`orin.analysis.sigma`)**
  * **Objective:** Ingest standardized Sigma rules to triage Linux log files directly on the compromised host.
  * **Implementation:** Implement a compile-free, zero-dependency Sigma rule evaluator that scans `/var/log/auth.log` and raw journald records, instantly flagging MITRE ATT&CK patterns with precise timestamps.
* **Planned Feature: Auth Log Lateral Movement Enrichment (`orin.collectors.logs`)**
  * **Objective:** Extend log parsing to identify lateral movement techniques.
  * **Implementation:** Harvest and parse `sudo` command logs and `su` session switches from system logs, alerting on sensitive execution targets (`bash`, `python`, `find`, `vim`) run via sudo.

### 4. Agentless Drift Detection for Diverse Linux Fleets

Installing intrusive kernel agents on legacy systems, operational technology (OT) appliances, and resource-constrained embedded nodes introduces severe stability and performance risks.

* **Planned Feature: Remote SSH Agentless Scanner (`orin.remote.profiler`)**
  * **Objective:** Profile and monitor diverse Linux fleets without installing any runtime code on target endpoints.
  * **Implementation:** Deploy a controller script that connects to remote targets over SSH, queries system state (active ports, users, kernel modules, file hashes), pulls the metadata, and runs drift analysis against local baselines.
* **Planned Feature: SUID/SGID Binary Monitor (`orin.collectors.suid`)**
  * **Objective:** Scan and detect newly introduced SUID/SGID binaries on the system.
  * **Implementation:** Walk the filesystem, index binaries with SUID/SGID bits set, and alert if new setuid files appear between snapshots.

### 5. Relational and Temporal Compliance Risk Scoring

Traditional compliance checkers evaluate configuration check-lists in isolation, leading to high false-positive rates.

* **Planned Feature: Context-Aware Compliance Risk Engine (`orin.analysis.context_scorer`)**
  * **Objective:** Transition risk calculations from simple checklists to an interconnected network of events.
  * **Implementation:** Escalate risk scores based on relational threat patterns. For example, a loosely configured `sudoers` rule on a host will escalate to critical severity only if paired with disabled auditing (`auditd`) or active anomalous system process events.
* **Planned Feature: In-Place Baseline Manager (`orin baseline refresh`)**
  * **Objective:** Support baseline evolution without losing historical snapshot data.
  * **Implementation:** Support adding individual users (`orin baseline add --user <username>`) or kernel modules (`orin baseline add --module <name>`) to the trusted ledger, and implement `orin baseline refresh` to synchronize the baseline database after package upgrades.

---

## 🧪 Implementation Flow Matrix

```mermaid
graph TD
    A[Telemetry Collectors] -->|Crontabs / Ports / eBPF / Processes| B(SQLite Forensics Vault)
    B -->|Snapshot Canonical JSON| C[Local AI / Sigma Rules Engine]
    C -->|Relational Threat Analysis| D{Context Scoring}
    D -->|0-34: Low| E[Posture Report]
    D -->|35-64: Medium| E
    D -->|65-89: High| E
    D -->|90-100: Critical| E
    E -->|Briefing Generation| F[HTML / Markdown Report]
```
