# Orin — Roadmap

Planned features and future engineering milestones for the Orin Forensic Engine. For implemented features, see [README.md](README.md).

## Design Philosophy: Air-Gapped First

Orin is designed from the ground up for **air-gapped, offline, and forensically sensitive environments**. Every feature must adhere to these principles:

- **Zero Network Egress**: No outbound connections, no telemetry, no cloud API calls
- **Zero External Dependencies**: All processing happens locally with stdlib or minimal trusted packages
- **Tamper-Evident Storage**: All evidence is cryptographically signed and optionally encrypted
- **Self-Contained Operation**: Can run indefinitely without external connectivity or updates

## Current Implementation Status

**✅ Complete (100%)**: All 34 capabilities in README.md are complete and functional.

**🟡 Foundation Only**: Basic versions exist but lack advanced capabilities described below.

**🔴 Not Started**: Features with no code implementation yet.

---


---

### Milestone 1: Deep Kernel & System Visibility
*Establishing the foundational telemetry required to see what is happening at the lowest levels of the operating system.*

**3. Advanced Memory & Kernel Integrity Auditing** ✅ *Complete*
* **Status:** Complete implementation with `/proc/kallsyms` parsing, kernel symbol analysis, and unlinked module detection.
* **Description:** Detect advanced kernel rootkits, unlinked modules, and kernel-level symbol overrides.
* **Key Features:**
  - Cross-reference `/proc/kallsyms` with standard kernel system maps
  - Audit dynamic kernel patching in memory structures
  - Implement heuristics for identifying unlinked LKMs hiding from `/proc/modules`
  - Detect suspicious symbols matching known rootkit patterns (diamorphine, reptile, etc.)
  - Flag credential manipulation symbols (`commit_creds`, `prepare_kernel_cred`) in third-party modules
  - Identify system call handlers exported by non-kernel modules
* **Implementation:** `gather_kernel_symbols()`, `analyze_kernel_symbol_overrides()`, and `check_for_unlinked_modules()` in `orin/collectors/kernel.py`; database tables `collected_kernel_symbols`, `kernel_analysis_summary`, and `kernel_rootkit_indicators` in `orin/core/database.py`; integrated into `orin collect` workflow.

**4. eBPF Ring-Buffer Real-Time Streamer** 🟡 *Foundation Only*
* **Status:** Uses `bpftool` CLI for static enumeration only. No real-time streaming.
* **Description:** Augment point-in-time snapshots with a real-time event recorder using lightweight, zero-dependency eBPF kernel probes.
* **Key Tasks:** Deploy kprobes/tracepoints for `execve`, `tcp_connect`, and file opens; buffer events in a secure, local database queue for asynchronous threat engine analysis.
* **Gap:** No real-time ring-buffer streaming, no kprobes/tracepoints deployment, no async event buffering.

---


---

## Summary: Implementation Progress by Phase

| Phase | Feature Count | 🔴 Not Started | 🟡 Foundation Only | ✅ Complete | Completion |
|-------|---------------|--------------------|---------------------------|----------------------|------------|
| **Milestone 1** | Deep Kernel & System Visibility | 0 | 1 (eBPF Streamer) | 1 (Kernel Audit) | ~65% |


### Current State Assessment
The codebase is a **production-ready, air-gapped forensic scanner** with 100% of README.md capabilities fully implemented. Eleven advanced roadmap features are complete: **Cryptographically Encrypted Evidence Vault**, **Evidence Chain-of-Custody Manifest**, **Agent Self-Defense & Resilience**, **Advanced Memory & Kernel Integrity Auditing**, **Identity, Access & Privilege Tracking**, **Semantic Persistence Analyzer**, **Process Genealogy Tracker**, **Embedded YARA Core Engine & FIM**, **Offline Threat Intelligence & IOC Importer**, **Deep Network Forensics & Triggered PCAP**, and **Active Response & Manual Remediation**.

**Remaining In-Scope Roadmap:**
- Real-time eBPF ring-buffer streaming (currently static `bpftool` enumeration only)

Orin prioritizes **trustworthiness over convenience**, **forensic integrity over automation**, and **air-gap purity over enterprise integration**.

---


**Architecture Notes:**
- **Zero Network Egress**: All components operate entirely offline with no outbound connections
- **No TPM/HSM**: Cryptographic operations use PBKDF2 key derivation from user passphrase (no hardware dependencies)
- **No SQLCipher**: Custom AES-256-GCM implementation using stdlib `cryptography` primitives
- **Host-Only Focus**: Bare-metal and VM forensics only, maintaining minimal attack surface
- **Manual Evidence Export**: All data stays local; signed JSON bundles for offline manual transfer
- **Local-Only Dashboard**: Web UI binds strictly to `127.0.0.1` with ephemeral token authentication

---

## Use Cases: Where Orin Excels

Orin is specifically designed for:

✅ **Classified Networks (SCIFs)**: No network egress, no telemetry, zero cloud dependencies
✅ **Air-Gapped Industrial Control Systems (ICS/SCADA)**: Minimal footprint, no external connectivity required
✅ **Forensic Incident Response**: Tamper-evident evidence collection with cryptographic signing
✅ **Compliance Auditing**: Point-in-time snapshots with baseline comparison for regulatory requirements
✅ **Offline Threat Hunting**: Local YARA scanning, IOC matching, and AI-assisted triage without internet
✅ **Secure Enclaves**: Self-contained operation with optional encrypted vault storage
✅ **Manual Remediation**: Human-in-the-loop process termination for critical incident response

Orin prioritizes **trustworthiness over convenience**, **forensic integrity over automation**, and **air-gap purity over enterprise integration**.