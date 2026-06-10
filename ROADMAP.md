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

### Current State Assessment
The codebase is a **production-ready, air-gapped forensic scanner** with 100% of README.md capabilities fully implemented. Twelve advanced roadmap features are complete: **Cryptographically Encrypted Evidence Vault**, **Evidence Chain-of-Custody Manifest**, **Agent Self-Defense & Resilience**, **Advanced Memory & Kernel Integrity Auditing**, **eBPF Ring-Buffer Real-Time Streamer**, **Identity, Access & Privilege Tracking**, **Semantic Persistence Analyzer**, **Process Genealogy Tracker**, **Embedded YARA Core Engine & FIM**, **Offline Threat Intelligence & IOC Importer**, **Deep Network Forensics & Triggered PCAP**, and **Active Response & Manual Remediation**.



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

- ✅ **Classified Networks (SCIFs)**: No network egress, no telemetry, zero cloud dependencies
- ✅ **Air-Gapped Industrial Control Systems (ICS/SCADA)**: Minimal footprint, no external connectivity required
- ✅ **Forensic Incident Response**: Tamper-evident evidence collection with cryptographic signing
- ✅ **Compliance Auditing**: Point-in-time snapshots with baseline comparison for regulatory requirements
- ✅ **Offline Threat Hunting**: Local YARA scanning, IOC matching, and AI-assisted triage without internet
- ✅ **Secure Enclaves**: Self-contained operation with optional encrypted vault storage
- ✅ **Manual Remediation**: Human-in-the-loop process termination for critical incident response

Orin prioritizes **trustworthiness over convenience**, **forensic integrity over automation**, and **air-gap purity over enterprise integration**.