# Orin — Forensic & Threat Detection Roadmap

This document outlines the **next-generation capabilities** planned for the Orin Forensic Engine. For a full list of everything already implemented, see [README.md](README.md).

> [!IMPORTANT]
> **Orin operates strictly offline and locally.** The engine does not connect to any cloud services, external APIs, or remote servers. All telemetry collection, signature matching, and timeline analysis run entirely on the local system to guarantee absolute privacy and integrity of forensic evidence.

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
