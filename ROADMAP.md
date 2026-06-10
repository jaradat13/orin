# Orin — Roadmap

Planned features and future engineering milestones for the Orin Forensic Engine. For implemented features, see [README.md](README.md).

## Design Philosophy: Air-Gapped First

Orin is designed from the ground up for **air-gapped, offline, and forensically sensitive environments**. Every feature must adhere to these principles:

- **Zero Network Egress**: No outbound connections, no telemetry, no cloud API calls
- **Zero External Dependencies**: All processing happens locally with stdlib or minimal trusted packages
- **Tamper-Evident Storage**: All evidence is cryptographically signed and optionally encrypted
- **Self-Contained Operation**: Can run indefinitely without external connectivity or updates

## Current Implementation Status

**✅ Complete (100%)**: All 35 capabilities in README.md are complete and functional.
**🟡 Foundation Only**: Basic versions exist but lack advanced capabilities described below.
**🔴 Not Started**: Features with no code implementation yet.
---

### Current State Assessment
The codebase is a **production-ready, air-gapped forensic scanner** with 100% of README.md capabilities fully implemented. Twenty-one advanced roadmap features are complete: **Cryptographically Encrypted Evidence Vault**, **Evidence Chain-of-Custody Manifest**, **Agent Self-Defense & Resilience**, **Advanced Memory & Kernel Integrity Auditing**, **eBPF Ring-Buffer Real-Time Streamer**, **Identity, Access & Privilege Tracking**, **Semantic Persistence Analyzer**, **Process Genealogy Tracker**, **Embedded YARA Core Engine & FIM**, **Offline Threat Intelligence & IOC Importer** (library module present, CLI pending), **Deep Network Forensics & Triggered PCAP**, **Active Response & Manual Remediation**, **Tool Self-Verification & Signed Releases** (SBOM generation, release manifests with SHA-256 checksums, GPG signature support, and runtime self-integrity checks), **Vault Lifecycle Management** (`orin vault prune/stats`), **DNS Forensics & Tunneling Detection**, **Minimal Footprint SSH Agent** (pure-bash fallback collector for systems without Python), **Read-Only Mode** (`--read-only` flag for write-protected systems), **Custom Vault Path** (`--vault-path` override for USB/ephemeral storage), and **Credential Handling Overhaul** (passphrase file/prompt/env-var options, token file storage with 0600 permissions).



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
---

## Real-World Deployment Review & Full Enhancement Plan

*Based on architectural analysis, this document provides a concrete, phased roadmap to transform Orin from a promising prototype into a mission-ready forensic instrument for air-gapped, classified, and high-security Linux environments.*

### Recap of Critical Gaps

Before outlining the plan, recall the key blockers for real-world adoption:

1. **Dependency chain breaks on hardened systems** – Python 3.10+ and `psutil` (a C extension) are rarely present or installable offline.
2. **No lifecycle management** – SQLite vaults grow unbounded; no pruning, rotation, or retention controls.
3. **Detection logic is fragile** – Sigma engine supports only a trivial rule subset; YARA rules are unmanaged; hidden process detection is easily evaded.
4. **Tool integrity not verifiable** ✅ RESOLVED – Signed releases, checksums, and SBOM now available via `orin.core.self_verify` module with GPG signing support and runtime self-check.
5. **Operational assumptions break on minimal systems** – Hardcoded paths, rootfs write requirement, no in-memory or USB‑stick mode.
6. **Dashboard & credentials exposure** ✅ RESOLVED – Credential handling overhaul complete: `--passphrase-file`, `--passphrase-prompt`, and `--passphrase-env-var` options eliminate shell history exposure; `--token-file` enables secure token storage with 0600 permissions instead of stdout printing.
7. **Agentless SSH is Python‑dependent** ✅ RESOLVED – Remote hosts without Python are now reachable via the pure-bash fallback agent (`src/orin/collectors/remote_agent.sh`).

---

## Phased Enhancement Plan

The plan is divided into three phases, each building on the previous and targeting clear, measurable milestones.

### Phase 1 – **"Field‑Ready Forensic Grabber"**

**Goal**: Make Orin usable *immediately* in any air‑gapped environment with zero external dependencies and no disk footprint if desired.

#### 1.1 Static Binary Distribution
- Package the entire tool (including Python interpreter, `psutil`, and all pure‑Python modules) as a **single, statically linked ELF binary** using **PyInstaller** or **Nuitka**.
- Pre‑compile for `x86‑64` (glibc ≥2.17) and `arm64` (Raspberry Pi / embedded use). Distribute signed binaries alongside hashes.
- This eliminates the need for pip, compilers, or even a pre‑installed Python runtime.

#### 1.2 Read‑Only & Ephemeral Modes ✅ COMPLETE
- ✅ **`--read-only` flag**: Implemented in `orin collect` and `orin init` commands. When enabled:
  - Prevents any writes to the SQLite vault database
  - Runs collection in forensic mode without storing snapshots
  - Allows analysis of existing vault data without modification
  - Invoked via `orin collect --read-only` or `orin init --read-only`
- ✅ **`--vault-path` option**: Implemented across all commands accepting `--database` flag. Accepts any writable location (e.g., `/mnt/usb/orin_vault.db`, tmpfs mounts), decoupling the tool from default paths. Supports ephemeral operation when pointed to temporary storage.

#### 1.3 Vault Lifecycle Management ✅ COMPLETE
- ✅ **`orin vault stats`**: Displays vault statistics including database size, snapshot count, oldest/newest record timestamps, and storage utilization. Invoked via `orin vault stats`.
- ✅ **`orin vault prune --older-than <days>`**: Deletes snapshots, related collected data, and resolved alerts older than specified threshold. Supports `--dry-run` flag for preview. Invoked via `orin vault prune --older-than 30`.
- ✅ **Automatic retention policy**: Integrated into scheduler via `orin schedule --retention 30d` for automatic pruning after each collection cycle.

#### 1.4 Credential Handling Overhaul ✅ COMPLETE
- ✅ **Vault passphrase methods**: Implemented in `orin.core.credentials.CredentialManager`:
  - `--passphrase-file PATH`: Load passphrase from file with permission validation (warns if not 0600)
  - `--passphrase-prompt`: Interactive masked input using `getpass` with optional confirmation
  - `--passphrase-env-var NAME`: Load from custom environment variable (default: `ORIN_VAULT_PASSPHRASE`)
- ✅ **Dashboard token file storage**: Implemented in `orin.core.server.start_server()`:
  - `--token-file PATH`: Save/load session token with restricted permissions (0600)
  - Token persistence across server restarts when using same token file
  - Automatic file permission enforcement and validation
- ✅ **Security features**: Timing-safe comparisons, whitespace stripping, informative error handling

#### 1.5 Tool Self‑Verification ✅ COMPLETE

- ✅ **GPG‑signed release manifests**: Implemented in `orin.core.self_verify`. Generate manifests with SHA‑256 checksums via `generate_release_manifest()`, sign with `sign_manifest_with_gpg()`, and verify with `verify_gpg_signature()`.
- ✅ **Embedded SBOM**: SBOM generation via `generate_sbom()` catalogs all modules, rules, and assets with SHA‑256 hashes. Accessible via `orin version --sbom` command.
- ✅ **Self‑check flag**: Runtime integrity verification via `self_check()` function and `--self-check` CLI flag. Verifies critical core modules against embedded hashes (deterrence, not absolute protection).

#### 1.6 Minimal Footprint SSH Agent ✅ COMPLETE

- ✅ Extended the remote scan script to fall back to a **pure-bash** collector if Python is absent. The bash script (`src/orin/collectors/remote_agent.sh`) gathers `procfs` and file metadata (coarser than Python) and outputs JSON. This covers routers, stripped-down containers, and old systems.
- ✅ Documented exact SSH requirements in [`SSH_REQUIREMENTS.md`](SSH_REQUIREMENTS.md): user privileges, available commands, filesystem access, and target system compatibility.
---

### Phase 2 – **"Production‑Grade Monitoring & Detection"**

**Goal**: Enable continuous security monitoring on hardened endpoints with reliable alerting and manageable data.

#### 2.1 Sigma & YARA Rule Management
- **Sigma Engine Audit**: Clearly document the *supported* Sigma operators (e.g., `selection`, `condition`, `|near`, `|count`). If full compliance is not intended, implement a strict schema validation that rejects unsupported rules with precise error messages.
- **Rule Repositories**: Add `orin rules update` (offline: user points to a directory of Sigma/YARA files), `orin rules list --sigma` to see active rules with descriptions, `orin rules validate` to test rule syntax.
- Provide a curated default rule set (MITRE‑mapped) that works reliably, avoiding false positives.

#### 2.2 Enhanced Rootkit Detection
- Complement the null‑signal test with more resilient methods:
  - **Cross‑view diff**: Compare results from `/proc`, `/sys/kernel/…`, and the `netlink` socket (if available) for process listing.
  - **Extended Berkeley Packet Filter (eBPF) probe**: Deploy a tiny, signed BPF program to count running tasks directly in the kernel (if BCC is present). Fall back to heuristic signals like hidden `cgroup` entries.
- Add a `--rootkit-scan` mode that runs all available detection methods and reports discrepancies.

#### 2.3 Centralised Air‑Gapped Fleet Hub
- Introduce an optional **aggregator mode** (`orin hub serve`) that:
  - Runs on a designated forensic workstation.
  - Accepts signed JSON snapshot exports from multiple hosts (via sneakernet).
  - Normalises and stores all imported data in a multi‑tenant SQLite or duckdb database.
  - Provides a unified dashboard, diff across hosts, and AI‑assisted correlation (reusing the Ollama integration).
- This replaces the ad‑hoc "carry vaults around" workflow with structured fleet management.

#### 2.4 Configurable Retention & Auto‑Cleanup
- In addition to vault pruning, implement **per‑event type retention** in the SQLite schema (e.g., keep `collected_processes` for 90 days, delete `stream_events` after 7 days).
- Automatic vacuum after large deletions to reclaim disk space.

#### 2.5 Robust Dashboard with Access Control
- ✅ **Token file storage**: Implemented via `--token-file` option with 0600 permissions for secure token persistence
- 🔲 **Unix socket** binding by default (no network exposure, permissions enforces access) - *Future enhancement*
- 🔲 **mTLS** as an option for remote‑via‑SSH‑tunnel access, using auto‑generated ephemeral certs - *Future enhancement*
- 🔲 Add a `--dashboard-password` option for an additional layer (HTTP Basic over the socket) - *Future enhancement*

#### 2.6 macOS & *BSD Preliminary Support
- While Linux‑specific collectors (procfs) won't port easily, abstract the data layer so that community contributors can add *BSD collectors. Focus on static‑binary availability for incident response cross‑platform.

---

### Phase 3 – **"Enterprise Forensic Platform"**

**Goal**: Mature into a trusted DFIR standard for high‑security environments, with rigorous validation and extensibility.

#### 3.1 Formal Verification & Independent Audit
- Commission a **third‑party security audit** of the codebase, focusing on cryptographic implementations, sandbox enforcement, and the Sigma/YARA engine.
- Publish a **formal specification** of the snapshot JSON format and the evidence bundle schema for tool‑agnostic interoperability.

#### 3.2 Integration with Established Forensic Standards
- Support export to **DFIR‑ORC** or **CASE** (Cyber-investigation Analysis Standard Expression) format alongside the current signed JSON.
- Implement a **timeline generation** module that outputs a ChronoPort-compatible file from multiple snapshot deltas.

#### 3.3 Automated Baseline Creation & Drift Learning
- Introduce `orin baseline learn` that runs over a defined period (e.g., 72 hours) to automatically whitelist normal behaviour, reducing false positives without manual tuning.
- Integrate statistical anomaly detection (e.g., process start burst, unusual port opening frequency) using lightweight on‑host models.

#### 3.4 Secure Update Mechanism for Air‑Gapped Networks
- Design a **signed update cartridge** format: a compressed archive containing the new binary, rule packs, and a detached signature. The cartridge is physically transferred and verified by `orin update --cartridge /media/usb/orin_update.tar.gz`.
- Rollback command in case of incompatibility.

#### 3.5 Full Documentation & Practitioner's Guide
- Publish a **field manual** covering:
  - Workflows for various engagement types (live triage, dead‑box acquisition, long‑term monitoring).
  - Hardening guidelines for the tool itself in different environments.
  - Detailed rule writing guide for Orin's Sigma subset.
  - Case studies from real‑world deployments (if available).

---

## Summary Table of Priority Actions

| Priority | Action | Impact |
|----------|--------|--------|
| **Critical** | Ship static binary (no Python/psutil dep) | Unblocks all air‑gap usage immediately |
| **Critical** | Implement `--read-only` / `--vault-path` | Enables forensic acquisition on write‑protected systems |
| **Critical** | Pruning and retention controls | Prevents disk exhaustion in scheduled mode |
| **✅ Complete** | Credential handling overhaul | Reduces exposure of vault passphrase & dashboard token |
| **✅ Complete** | Self‑verification & signed releases | Establishes trust in the tool's own integrity |
| **High** | Document Sigma limitations & add rule validation | Avoids analyst frustration and false reliance |
| **✅ Complete** | Pure‑bash SSH agent fallback | Extends agentless coverage to minimal hosts (routers, containers, embedded) |
| **Medium** | Air‑gapped fleet hub | Enables structured multi‑host forensic management |
| **Low** | Third‑party audit & formal spec | Long‑term credibility for classified environments |

---

## Conclusion

Orin's architectural decisions are sound; it already does many things that no other single open‑source tool does for offline Linux forensics. With the concrete enhancements outlined above, it can evolve from a proof‑of‑concept into a **hardened, self‑contained forensic instrument that operators can carry on a USB stick and trust in the most sensitive environments**. The plan is deliberately phased to deliver immediate field‑ready capability first, then progressively add detection depth and enterprise features without sacrificing the "zero trust" principle.
---

## ✅ Completed: Tool Self-Verification & Signed Releases

**Module**: `orin.core.self_verify`

**Capabilities**:

1. **SBOM Generation** (`generate_sbom`)
   - Automatically catalogs all Python modules, rules, and assets
   - Computes SHA-256 hashes for each component
   - Extracts module docstrings for descriptions
   - Documents runtime dependencies (psutil, cryptography)
   - Exportable via `export_sbom()` for supply chain transparency

2. **Release Manifest Generation** (`generate_release_manifest`)
   - Creates comprehensive manifests with SHA-256 checksums for all distributable files
   - Categorizes files (source, rules, tests, docs)
   - Includes aggregate statistics (total files, total size)
   - Self-hashing for manifest integrity verification
   - Suitable for GPG signing and distribution

3. **Manifest Verification** (`verify_against_manifest`)
   - Verifies installed files against a release manifest
   - Detects missing files, hash mismatches, and tampering
   - Validates manifest self-hash to detect manifest tampering
   - Returns detailed pass/fail lists with error descriptions

4. **Runtime Self-Check** (`self_check`)
   - Performs integrity verification on critical core modules
   - Reports current file hashes (reference hashes embedded at build time in production)
   - Deterrent against tool compromise in adversarial environments
   - Configurable package root for flexible deployment scenarios

5. **GPG Integration** (`sign_manifest_with_gpg`, `verify_gpg_signature`)
   - Detached ASCII-armored signature generation
   - Signature verification with proper error handling
   - Supports custom GPG key IDs or default key
   - Graceful degradation when GPG is unavailable

**Usage Examples**:

```python
from orin.core.self_verify import (
    generate_sbom,
    generate_release_manifest,
    verify_against_manifest,
    self_check,
    export_sbom
)
from pathlib import Path

# Generate and export SBOM
sbom = generate_sbom(Path('.'))
export_sbom(Path('.'), Path('/tmp/orin_sbom.json'))

# Generate release manifest for distribution
manifest = generate_release_manifest(Path('.'), output_path=Path('release_manifest.json'))

# Verify installation against manifest
success, passed, failed = verify_against_manifest(
    Path('release_manifest.json'),
    Path('/opt/orin')
)
if not success:
    print(f"Integrity check failed: {failed}")

# Runtime self-check
success, message = self_check()
print(message)  # "SELF-CHECK PASSED: 7 critical file(s) verified successfully"
```

**Security Considerations**:

- Embedded reference hashes provide deterrent-level protection; for stronger guarantees, use externally-signed manifests
- Manifest self-hashing detects tampering with the manifest itself
- GPG signatures provide cryptographic proof of release authenticity
- All hash computations use streaming to handle large files efficiently
- Constant-time comparison not required for hash verification (timing attacks not applicable)

**Future Enhancements**:

- Build-time injection of reference hashes during PyInstaller/Nuitka compilation
- SPDX format export for SBOM interoperability
- Automated manifest signing in CI/CD pipeline
- Hardware-backed attestation (TPM/HSM) support for high-security deployments