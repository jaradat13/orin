# 🚦 Project Status, Assumptions & Limitations

**Version:** 1.2.0  
**Project Status:** Production-Capable  
**Last Updated:** June 2026

---

## 1. Project Status Summary

Orin is currently a **production-capable offline forensic snapshot and integrity engine** for Linux environments. The core CLI commands (`init`, `collect`, `analyze`, `report`, `serve`, `hub-serve`, `schedule`, `scan`, `baseline`, `diff`, `delta`, `vault`, `rules`) are fully implemented and verified via automated test suites. 

All core collectors (Process, Network, Kernel, Users, FIM, Crontabs, Package Integrity, Logs, and Privilege Auditing) are stable and do not require external network access or SaaS dependencies.

---

## 2. Supported Platform Matrix

Orin targets Linux operating systems. The platform requirements and validation status are detailed below:

### Operating System Compatibility

| Distribution | Version | Compatibility | Notes |
| :--- | :--- | :--- | :--- |
| **Ubuntu** | 20.04 LTS, 22.04 LTS, 24.04 LTS | 🟢 Fully Supported | Target CI test environment. |
| **Debian** | 11 (Bullseye), 12 (Bookworm) | 🟢 Fully Supported | Package integrity checked via `dpkg`. |
| **RHEL / Rocky / Alma** | 8.x, 9.x | 🟢 Fully Supported | Verified with standard Python 3.10+ environments. |
| **Fedora** | 38+ | 🟢 Fully Supported | Fully functional. |
| **Arch Linux** | Latest | 🟡 Partially Supported | Functional, but package integrity checking does not support Pacman database formats out of the box (Debian/Ubuntu `dpkg` only). |
| **macOS / Windows** | Any | ❌ Not Supported | Host-level forensics are deeply tied to Linux kernel interfaces (`/proc`, `/sys`). Porting is an explicit non-goal. |

### System & Architecture Prerequisites

*   **Processor Architectures:** `x86_64`, `aarch64` (ARM64).
*   **Linux Kernel:** Version `4.4` or higher. Kernel `5.4+` is recommended to support all eBPF features and ring-buffer streaming.
*   **Python:** Version `3.10` or higher (fully validated on Python `3.10`, `3.11`, and `3.12`).
*   **Runtime Memory:** Minimal footprint. Execution requires less than **50 MB** of free RAM under standard configurations (up to **256 MB** during concurrent parallel collection or large YARA scans).
*   **Storage Space:** A baseline installation requires less than **100 MB** of disk space. Vault database storage (`orin_vault.db`) size varies depending on snapshot frequency, active file changes, and retention policies.

---

## 3. Deployment Assumptions

Before deploying Orin, the following operational assumptions must be understood:

1.  **Administrative Privileges:** Orin must be run as `root` (via `sudo` or as a system service) to perform complete forensic collection. Non-privileged execution is supported as a fallback but cannot access restricted logs (e.g. `/var/log/auth.log`), audit descriptors of other users, promiscuous NIC flags, or perform hidden process signaling.
2.  **Air-Gapped / Isolated Infrastructure:** Orin is designed under the assumption that the target host or fleet network has **zero external internet connectivity**. All threat signature files (Sigma, YARA) and intelligence feeds (IOCs) must be imported offline from local directories.
3.  **Local Storage Availability:** The host filesystem must have a writable path (local disk, USB media, or memory-backed `tmpfs`) to store the SQLite evidence vault. If write access to the host disk is completely restricted, Orin must be executed with the `--read-only` flag or configured with an external `--vault-path`.

---

## 4. Known Limitations

While Orin provides comprehensive forensic acquisition, practitioners should be aware of the following system limits:

### ⚠️ eBPF Streaming Prerequisites
*   **Limitation:** Real-time event streaming (`orin stream`) requires a kernel built with BTF (BPF Type Format) enabled and the system `libbpf` library.
*   **Impact:** If prerequisites are missing, real-time streaming will fail to load the BPF program. Periodic collection (`orin collect`) remains fully functional as it relies on `/proc` parsing instead of eBPF.

### ⚠️ Default YARA Scanning Scope
*   **Limitation:** The embedded YARA engine performs FIM-accelerated file-integrity scans but is restricted by default to scanning temporary paths (e.g. `/tmp`, `/dev/shm`, `/var/tmp`) and dumped memory executables.
*   **Impact:** Scanning the entire root directory (`/`) for YARA signatures is disabled by default to prevent substantial I/O performance degradation and disk bottlenecks. Full-directory sweeps must be manually configured in `orin_config.json`.

### ⚠️ Triggered PCAP Requirements
*   **Limitation:** Automatic packet capture on threat rules trigger requires the `scapy` Python package to reconstruct packets.
*   **Impact:** If `scapy` is absent, Orin falls back to writing raw socket buffers directly. While functional, the raw format does not include high-level protocol reconstruction.

### ⚠️ Container Namespace Isolation
*   **Limitation:** Orin executes within the host network, pid, and mount namespaces.
*   **Impact:** It does not inspect container-isolated namespaces (e.g. Docker, Podman, Kubernetes pods) dynamically. It reports container processes running on the host but does not associate them with specific container IDs or pod metadata out of the box.

### ⚠️ Compromised Kernel Defense Boundary
*   **Limitation:** Orin reads process state, network socket information, and loaded modules from `/proc` and `/sys`. If an attacker has successfully loaded a malicious kernel rootkit that intercept syscalls or hooks the virtual filesystem, the kernel itself may return falsified data to Orin.
*   **Mitigation:** Orin attempts to expose rootkits by cross-referencing scheduler-active PIDs via null signaling (`os.kill(pid, 0)`) against `/proc` listings and auditing unlinked kernel symbols, but a fully compromised kernel remains a fundamental barrier to userspace integrity tools.

---

## 5. Security & Trust Model

*   **Evidence Integrity:** Evidentiary snapshots exported via `orin export` are cryptographically signed with HMAC-SHA256 to prevent post-collection modification. The SQLite vault itself can be encrypted using AES-256-GCM.
*   **Agent Confinement:** Installation packages include AppArmor and SELinux templates located in [assets/security-profiles/](file:///home/musa/orin/assets/security-profiles/) to confine Orin's execution path, restricting it to required system directories and preventing arbitrary network egress.