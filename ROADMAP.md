# Orin — Roadmap

Planned features and future engineering milestones for the Orin Forensic Engine. For implemented features, see [README.md](README.md).

## Current Implementation Status

**✅ Fully Implemented (100%)**: All 24 capabilities in README.md are complete and functional.

**🟡 Partially Implemented (Foundation Only)**: Basic versions exist but lack advanced capabilities described below.

**🔴 Not Implemented (0%)**: Features with no code implementation yet.

---

### Status Legend
- 🔴 **Not Implemented** - No code exists; full development required
- 🟡 **Partially Implemented** - Basic foundation exists; advanced features pending
- ✅ **Fully Implemented** - Complete and production-ready

### 🛡️ Phase 1: Trust, Survival & Core Architecture
*Before Orin can detect threats, it must ensure its own survival and guarantee the integrity of the data it collects.*

**1. Cryptographically Encrypted Evidence Vault** 🔴 *Not Implemented*
* **Status:** Currently uses plain SQLite with HMAC-SHA256 signing only. No AES-256 encryption at rest.
* **Description:** Ensure collected snapshot data, alerts, and dumped memory payloads are tamper-resistant from rootkits with high-privilege access.
* **Key Tasks:** Support SQLCipher/transparent AES-256 payload encryption; sign snapshot entries with hardware-backed keys (e.g., local TPM chips).
* **Gap:** Zero implementation of SQLCipher, AES-256 file encryption, or TPM integration.

**1.2. Evidence Chain-of-Custody (CoC) Manifest** ✅ *Fully Implemented*
* **Status:** Complete implementation as of v1.0.0.
* **Description:** Automatically generates legally defensible Chain-of-Custody manifests during export operations, containing SHA256 hashes of all evidence items, timestamps, system information, and collector metadata.
* **Key Features:**
  - Auto-generated manifest ID with timestamp
  - Complete inventory of collected file hashes, deleted binaries, and package integrity records
  - Self-hashing manifest for integrity verification
  - JSON format for easy parsing and archival
* **Implementation:** `generate_coc_manifest()` function in `orin/core/crypto.py`; automatically invoked during `orin export` command.

**2. Agent Self-Defense & Resilience** 🔴 *Not Implemented*
* **Status:** No self-protection mechanisms exist.
* **Description:** Protect the Orin agent from being killed, debugged, or modified by a compromised root user or advanced persistent threat (APT).
* **Key Tasks:**
  * Implement an Out-of-Band Watchdog (a separate micro-service or secure systemd socket) to monitor the main Orin process and trigger critical "Agent Tampered" alerts if it dies.
  * Apply strict `seccomp` profiles and AppArmor/SELinux policies to restrict what the root user can do to Orin binaries, config files, and memory space.
* **Gap:** No watchdog service, no seccomp profiles, no AppArmor/SELinux policies implemented.

---

### 👁️ Phase 2: Deep Kernel & System Visibility
*Establishing the foundational telemetry required to see what is happening at the lowest levels of the operating system.*

**3. Advanced Memory & Kernel Integrity Auditing** 🟡 *Partially Implemented*
* **Status:** Reads `/proc/modules` for LKM listing only. No kernel symbol analysis.
* **Description:** Detect advanced kernel rootkits, unlinked modules, and kernel-level symbol overrides.
* **Key Tasks:** Cross-reference `/proc/kallsyms` with standard kernel system maps; audit dynamic kernel patching in memory structures; implement heuristics for identifying unlinked LKMs hiding from `/proc/modules`.
* **Gap:** Missing `/proc/kallsyms` analysis, kernel symbol override detection, and unlinked LKM heuristics.

**4. eBPF Ring-Buffer Real-Time Streamer** 🟡 *Partially Implemented*
* **Status:** Uses `bpftool` CLI for static enumeration only. No real-time streaming.
* **Description:** Augment point-in-time snapshots with a real-time event recorder using lightweight, zero-dependency eBPF kernel probes.
* **Key Tasks:** Deploy kprobes/tracepoints for `execve`, `tcp_connect`, and file opens; buffer events in a secure, local database queue for asynchronous threat engine analysis.
* **Gap:** No real-time ring-buffer streaming, no kprobes/tracepoints deployment, no async event buffering.

---

### 🧠 Phase 3: Identity, Context & Persistence
*Moving beyond "what happened" to "who did it" and "how are they staying on the system."*

**5. Identity, Access & Privilege Tracking** 🔴 *Not Implemented*
* **Status:** Binary parsing of wtmp/lastlog only. No PAM hooks or syscall monitoring.
* **Description:** Track human and service identities, authentication events, and privilege boundary crossings.
* **Key Tasks:**
  * Hook PAM (Pluggable Authentication Modules) to track logins, SSH sessions, and `sudo` transitions.
  * Use eBPF to monitor `setuid`, `setgid`, `capset` (capability changes), and `ptrace` (process injection/debugging) system calls.
  * Detect credential dumping by monitoring access to `/etc/shadow`, SSH agent memory, or Kerberos ticket caches.
* **Gap:** No PAM integration, no eBPF syscall probes for privilege escalation, no credential dump detection.

**6. Semantic Persistence Analyzer** ✅ *Fully Implemented*
* **Status:** Monitors SSH `authorized_keys`, crontabs, systemd service/timer units, udev rules, sysctl configurations, and shell initialization files (`~/.bashrc`).
* **Description:** Understand the *intent* behind file changes by specifically monitoring locations used by malware to maintain persistence across reboots.
* **Key Tasks:**
  * Parse and monitor high-value persistence vectors: Systemd service/timer files, crontabs, `udev` rules, and shell profiles (`~/.bashrc`).
  * Track SSH `authorized_keys` modifications.
  * Implement configuration drift detection (comparing active `sysctl` or `iptables` rules against a known-good baseline).
* **Implementation:** Complete implementation with file hashing, database storage, and drift detection for all major persistence vectors.

**7. Process Genealogy Tracker** ✅ *Fully Implemented*
* **Status:** Complete implementation with full ancestry path tracking from init to leaf processes.
* **Description:** Track parent-child relationships between processes to build complete process lineage chains for forensic analysis and attack chain reconstruction.
* **Key Tasks:**
  * Enhance process collector to build ancestry paths showing complete genealogy.
  * Store ancestry_path field in collected_processes table for historical analysis.
  * Implement cycle detection and maximum depth limits to handle edge cases.
* **Implementation:** Two-pass algorithm in `processes.py`: first collects all processes, second builds ancestry paths by traversing PPID chain. Database schema updated with `ancestry_path` column. Format: `"init(1) -> bash(123) -> python(456)"`.

---

### 📦 Phase 4: Modern Environment Support
*Adapting Orin to understand the abstractions of modern infrastructure (containers and cloud).*

**7. Container & Namespace Forensic Harvester** 🔴 *Not Implemented*
* **Status:** No container introspection capabilities exist.
* **Description:** Extend `/proc` mapping and socket collection to support containerized environments (Docker, Podman, Kubernetes).
* **Key Tasks:** Retrieve namespace context (`/proc/[pid]/ns/`) for network/mount/PID isolation; query local container runtime Unix sockets to map processes to container IDs/pod names; profile overlay filesystems for escape signals.
* **Gap:** Zero implementation of namespace introspection, container runtime queries, or overlay filesystem analysis.

**8. Cloud & Orchestrator API Context** 🔴 *Not Implemented*
* **Status:** No cloud metadata or Kubernetes audit log integration.
* **Description:** Correlate host-level telemetry with control-plane events to provide macro-level context for cloud and Kubernetes environments.
* **Key Tasks:**
  * Ingest Kubernetes Audit Logs to correlate host eBPF events with control-plane events (e.g., a pod spawned with `privileged: true`).
  * Automatically pull Cloud Provider Metadata (AWS/GCP/Azure Instance ID, VPC, Security Groups, IAM roles) to enrich the forensic context of the compromised node.
* **Gap:** No K8s audit log ingestion, no cloud provider metadata APIs integrated.

---

### 🎯 Phase 5: Detection Engine & Threat Intel
*Applying rules, signatures, and external intelligence to the collected telemetry to find actual threats.*

**9. Embedded YARA Core Engine & FIM** 🔴 *Not Implemented*
* **Status:** Zero YARA rule support. No `.yar` file parsing or memory payload scanning.
* **Description:** Integrate a lightweight, offline YARA rules engine to execute pattern matching against files and dumped in-memory binaries.
* **Key Tasks:** Support `.yar` files from `/etc/orin/signatures/`; scan memory payloads from unlinked binaries; add FIM-accelerated scans (only run YARA against modified files).
* **Gap:** No YARA library integration, no `.yar` file support, no memory payload pattern matching.

**10. Offline Threat Intelligence & IOC Importer** 🟡 *Partially Implemented*
* **Status:** Simple IP blocklist (`intel_blocklist.txt`) only. No structured threat intel formats.
* **Description:** Enable security teams to import offline threat intelligence feeds to screen target systems for known C2 infrastructure.
* **Key Tasks:** Ingest STIX/TAXII XML/JSON/CSV IOCs locally; match outbound network logs against offline blocklists; compare file metadata against lists of compromised cryptographic signatures.
* **Gap:** No STIX/TAXII support, no hash-based IOCs, no domain-based IOCs, only basic IP blocklist exists.

**11. Deep Network Forensics & Triggered PCAP** 🔴 *Not Implemented*
* **Status:** Basic socket enumeration only. No DNS tracking or payload capture.
* **Description:** Capture deep network payloads and DNS telemetry for active investigations without consuming massive amounts of disk space.
* **Key Tasks:**
  * Track DNS queries/responses via eBPF uprobes on `libc`/`musl` to detect DNS tunneling or DGAs.
  * Implement a triggered PCAP ring-buffer that captures actual network payloads *only* when a specific YARA rule or IOC is triggered.
* **Gap:** No DNS query/response tracking, no DNS tunneling/DGA detection, no triggered PCAP ring-buffer.

---

### ⚡ Phase 6: Response, Integration & Enterprise Scale
*Taking action on threats and integrating Orin into the broader enterprise security ecosystem.*

**12. Active Response & Automated Remediation** 🔴 *Not Implemented*
* **Status:** No active response capabilities exist. Detection is passive only.
* **Description:** Transition Orin from a passive detector to an active defender capable of stopping attacks in real-time.
* **Key Tasks:**
  * Safely terminate (`SIGKILL`) or suspend (`SIGSTOP`) malicious processes identified by the detection engine.
  * Dynamically inject rules into `nftables`/`iptables` or eBPF TC to block malicious IPs or isolate the host from the network.
  * Move confirmed malicious files to a secure, hashed quarantine directory.
* **Gap:** No process termination, no dynamic firewall injection, no network isolation, no file quarantine capabilities.

**13. SIEM/SOAR Integration & Standardized Export** 🔴 *Not Implemented*
* **Status:** Only basic syslog mention in scheduler. No standardized export pipelines.
* **Description:** Ensure Orin telemetry can be seamlessly ingested by existing enterprise SOC tools (Splunk, Elastic, Sentinel).
* **Key Tasks:**
  * Build native export pipelines for Kafka, Redis Pub/Sub, and Syslog.
  * Normalize all alerts and telemetry into standard formats like **CEF** (Common Event Format), **LEEF**, or **ECS** (Elastic Common Schema) for out-of-the-box SIEM parsing.
* **Gap:** No Kafka/Redis pipelines, no CEF/LEEF/ECS normalization, no SIEM integration.

**14. Multi-Host Visualizer & Centralized Console** 🔴 *Not Implemented*
* **Status:** Single-host only. No fleet management or cross-host correlation.
* **Description:** Extend the single-host console to support multi-node visual correlation, configuration distribution, and cluster-wide drift tracking.
* **Key Tasks:** Consolidate telemetry reports from multiple remote scan profiles into a single dashboard view; sync timelines of distinct systems to pinpoint lateral movement and coordinated credential abuse.
* **Gap:** No centralized console, no multi-host telemetry consolidation, no lateral movement tracking across hosts.

---

## Summary: Implementation Progress by Phase

| Phase | Feature Count | 🔴 Not Implemented | 🟡 Partially Implemented | ✅ Fully Implemented | Completion |
|-------|---------------|--------------------|---------------------------|----------------------|------------|
| **Phase 1** | Trust, Survival & Core Architecture | 2 (Vault, Self-Defense) | 0 | 0 | 0% |
| **Phase 2** | Deep Kernel & System Visibility | 0 | 2 (Kernel Audit, eBPF Streamer) | 0 | ~30% |
| **Phase 3** | Identity, Context & Persistence | 1 (Identity Tracking) | 0 | 2 (Persistence Analyzer, Genealogy Tracker) | ~65% |
| **Phase 4** | Modern Environment Support | 2 (Container, Cloud) | 0 | 0 | 0% |
| **Phase 5** | Detection Engine & Threat Intel | 2 (YARA, Network Forensics) | 1 (Threat Intel) | 0 | ~15% |
| **Phase 6** | Response, Integration & Enterprise Scale | 3 (Active Response, SIEM, Fleet) | 0 | 0 | 0% |
| **TOTAL** | **15 Features** | **9 (60%)** | **3 (20%)** | **2 (13%)** | **~23%** |

### Current State Assessment
The codebase is a **solid single-host static forensic scanner** with 100% of basic collection features (README.md) fully implemented. Two advanced roadmap features are now complete: **Semantic Persistence Analyzer** and **Process Genealogy Tracker**. Remaining roadmap targets transformation into a **real-time EDR/XDR platform** requiring significant additional development in:

- Real-time streaming telemetry (eBPF ring-buffer)
- Advanced threat detection (YARA, STIX/TAXII)
- Active defense capabilities (process kill, network isolation)
- Enterprise integration (SIEM export, fleet management)
- Modern infrastructure support (containers, cloud)
- Deep kernel visibility (kallsyms, syscall hooks)
- Agent hardening (seccomp, AppArmor, watchdog)

---

## System Architecture

```mermaid
graph TD
    subgraph Ingestion [🟢 Layer 1: Telemetry & Context Ingestion]
        EBPF[eBPF Streamer & Kernel Audit]
        K8S[Container & K8s Harvester]
        NET[Deep Network & DNS Tracker]
        ID[Identity & Privilege Tracker]
        PERS[Semantic Persistence Analyzer]
        CLOUD[Cloud API Context Ingestor]
    end

    subgraph Core [🔵 Layer 2: Secure Storage & Self-Defense]
        VAULT[(Encrypted SQLite Vault)]
        TPM[TPM Hardware Signer]
        FIM[Stat-Cache / FIM]
        WATCHDOG[Out-of-Band Watchdog]
    end

    subgraph Analysis [🟡 Layer 3: Detection & Scoring Engine]
        YARA[Embedded YARA Engine]
        SIGMA[Sigma / ATT&CK Engine]
        IOC[Offline IOC Matcher]
        AI[Context Scoring & Local AI]
    end

    subgraph Action [🔴 Layer 4: Active Response]
        RESP[Remediation Engine]
        NETBLOCK[Network Isolation / nftables]
        PROCKILL[Process Kill & Quarantine]
    end

    subgraph Egress [🟣 Layer 5: Egress & Enterprise Integration]
        DASH[Local Web Dashboard]
        FLEET[Multi-Host Fleet Visualizer]
        SIEM[SIEM/SOAR Exporter]
        REP[Report Generator]
    end

    %% Layer 1 to Layer 2
    EBPF -->|Process/Net Events| VAULT
    K8S -->|Namespace Context| VAULT
    NET -->|Triggered PCAP/DNS| VAULT
    ID -->|Auth/Cred Events| VAULT
    PERS -->|Config Drift| VAULT
    CLOUD -->|K8s/Cloud Metadata| VAULT

    %% Layer 2 Internals
    VAULT <-->|SQLCipher AES-256| TPM
    FIM -->|Skip Unchanged Files| VAULT
    WATCHDOG -.->|Heartbeat & Tamper Alerts| VAULT

    %% Layer 2 to Layer 3
    VAULT -->|Dumped Payloads/Files| YARA
    VAULT -->|Normalized Telemetry| SIGMA
    VAULT -->|Network/Hash Logs| IOC

    %% Layer 3 Internals & Output
    YARA -->|Signature Matches| AI
    SIGMA -->|Relational Analysis| AI
    IOC -->|Threat Intel Hits| AI

    %% Layer 3 to Layer 4 & 5
    AI -->|Scores 0-100| DASH
    AI -->|High/Critical Alerts| RESP

    %% Layer 4 Internals
    RESP -->|Execute eBPF TC| NETBLOCK
    RESP -->|SIGKILL / Move File| PROCKILL

    %% Layer 2/3 to Layer 5
    VAULT -->|Snapshots & Timelines| DASH
    DASH -->|Triage Actions| VAULT
    VAULT -->|Agentless SSH Sync| FLEET
    AI -->|CEF / ECS / Syslog| SIEM
    DASH -->|Briefings| REP
```