# 🗺️ Orin Roadmap

**Version:** 1.2.0
**Project Status:** Production-capable offline forensic snapshot platform for Linux
**Last Updated:** June 2026

---

# Vision

Orin is an **offline-first, air-gapped forensic snapshot and incident investigation platform** designed for Linux environments where reliability, transparency, and forensic integrity matter more than feature volume.

The project prioritizes:

* Zero-telemetry operation
* Tamper-evident evidence collection
* Cryptographic integrity verification
* Minimal and auditable dependencies
* Offline deployment capability
* Honest documentation of capabilities and limitations

The long-term objective is to become the most trustworthy open-source offline forensic platform for Linux systems.

---

# Current State (v1.2)

## Production-Ready Components

The following functionality is considered stable and suitable for production deployment.

| Module                                      | Status   |
| ------------------------------------------- | -------- |
| Process Collection                          | ✅ Stable |
| Network Collection                          | ✅ Stable |
| Kernel Collection                           | ✅ Stable |
| User & Account Collection                   | ✅ Stable |
| Cron & Persistence Collection               | ✅ Stable |
| File Integrity Monitoring (SHA-256 + cache) | ✅ Stable |
| Encrypted Evidence Vault (AES-256-GCM)      | ✅ Stable |
| Signed JSON Exports (HMAC-SHA256)           | ✅ Stable |
| Local Dashboard (`orin serve`)              | ✅ Stable |
| Agentless SSH Collection                    | ✅ Stable |
| Bash Fallback Collection                    | ✅ Stable |
| Alert Forwarding                            | ✅ Stable |
| Health & Readiness APIs                     | ✅ Stable |
| Structured JSON Logging                     | ✅ Stable |
| Agent Script Signing & Verification         | ✅ Stable |
| Detection Rules Engine                      | ✅ Stable |
| Sigma Rule Evaluation (Subset)              | ✅ Stable |
| Offline Threat Intel Importer               | ✅ Stable |
| SUID / SGID Monitoring                      | ✅ Stable |

---

## Partial / Experimental Components

These features function but require additional setup, dependencies, or operational knowledge.

| Component                 | Limitation                                         | Status          |
| ------------------------- | -------------------------------------------------- | --------------- |
| eBPF Real-Time Streaming  | Requires BTF-enabled kernel and setup via scripts/setup_ebpf.sh | ✅ Supported   |
| YARA Scanning             | Limited to temporary directories by default        | ⚠️ Partial      |
| Triggered PCAP Collection | Requires Scapy installation                        | ⚠️ Partial      |
| AI Correlation            | Requires external Ollama deployment                | ⚠️ Optional     |

---

## Not Included

The following capabilities are intentionally absent or scheduled for future releases.

| Feature                       | Status      |
| ----------------------------- | ----------- |
| Full Public Test Suite        | Planned     |
| PostgreSQL Backend            | Planned     |
| Multi-Node Scaling            | Planned     |
| Windows Support               | Not Planned |
| macOS Support                 | Not Planned |
| Container Namespace Isolation | Not Planned |

---

# Strategic Roadmap

## Phase 1 — Documentation & Transparency ✅ COMPLETED (v1.2.1)

**Target Release:** v1.2.1
**Estimated Timeline:** Completed June 2026

### Objectives

Improve transparency and reduce documentation drift.

### Tasks

* [x] Reduce README scope to verified functionality
* [x] Move future ideas into `ROADMAP.md`
* [x] Publish `STATUS.md`
* [x] Add explicit limitation documentation
* [x] Add deployment assumptions
* [x] Add supported platform matrix

### Known Limitations To Document

* eBPF streaming requires manual setup
* YARA scans temporary directories only by default
* Triggered PCAP requires Scapy
* Container boundaries are not respected
* Linux-only platform support

### Success Criteria

* No README feature overclaims
* Every documented feature can be demonstrated
* All experimental features clearly marked

---

# Phase 2 — Reliability & Production Readiness

**Target Release:** v1.3
**Estimated Timeline:** 2–3 Months

## Priority 1: eBPF Streaming

### Goal

Provide a reproducible deployment experience.

### Tasks

* [x] Add `scripts/setup_ebpf.sh`
* [x] Automate `vmlinux.h` generation
* [x] Validate kernel prerequisites
* [x] Improve error reporting
* [x] Document troubleshooting procedures

### Alternative Paths

1. Retain libbpf implementation with automated setup
2. Migrate to BCC inline compilation
3. Officially classify feature as experimental

---

## Priority 2: End-to-End Testing

### Goal

Ensure the complete workflow executes successfully on clean systems.

### Tasks

* [ ] Create Ubuntu 22.04 CI environment
* [ ] Install Orin from source
* [ ] Execute:

  * `orin init`
  * `orin collect`
  * `orin analyze`
  * `orin report`
* [ ] Validate generated reports
* [ ] Publish test artifacts

### Deliverables

* Automated CI pipeline
* E2E regression tests
* Reproducible installation validation

---

## Priority 3: Public Test Suite

### Goal

Improve confidence and contributor onboarding.

### Tasks

* [ ] Publish current internal tests
* [ ] Add pytest coverage reporting
* [ ] Add clickable coverage badge
* [ ] Publish testing guidelines

### Success Criteria

* Coverage visible in CI
* Contributors can run tests locally
* Major workflows validated automatically

---

## Operational Improvements

### Database Migrations

* [ ] Schema version tracking
* [ ] Upgrade compatibility validation
* [ ] Migration rollback support

### Snapshot Retention

* [x] Age-based retention
* [x] Count-based retention
* [x] Critical-alert preservation

### Offline Update Cartridges

* [ ] Signed update bundles
* [ ] Offline rule updates
* [ ] Offline intelligence updates
* [ ] Offline binary upgrades

---

# Phase 3 — Operational Excellence

**Target Release:** v1.4
**Estimated Timeline:** 3–6 Months

### Dashboard Enhancements

* [x] Live WebSocket alert feed
* [x] Real-time dashboard updates
* [x] Alert acknowledgement workflow

### Platform Diagnostics

* [x] `orin doctor`
* [x] Dependency validation
* [x] Permission validation
* [x] Configuration validation

### Investigation Enhancements

* [x] `orin diff`
* [x] Snapshot comparison engine
* [x] Timeline delta reporting
* [x] Alert drift analysis

### Collector Framework

* [x] Capability registry
* [x] Privilege requirements
* [x] Runtime impact scoring
* [x] Collector metadata reporting

---

# Phase 4 — Scale & Enterprise Operations

**Target Release:** v2.0
**Estimated Timeline:** 6–12 Months

## Storage Layer

* [ ] PostgreSQL backend
* [ ] Migration tooling
* [ ] Large-scale retention support

## Distributed Operations

* [ ] Multi-node hub
* [ ] Centralized aggregation
* [ ] Distributed collection orchestration

## Packaging

* [ ] Standalone binary releases
* [ ] PyInstaller distribution
* [ ] Offline installer bundles

## Security Hardening

* [x] Full credential memory zeroisation
* [x] Enhanced secret handling
* [x] Expanded cryptographic review

---

# Phase 5 — Trust & Ecosystem

**Target Release:** v3.0
**Estimated Timeline:** Long-Term

### Security Assurance

* [ ] Independent security audit
* [ ] Secure development review
* [ ] Threat model publication

### Platform Expansion

* [ ] Evaluate Windows support
* [ ] Evaluate macOS support
* [ ] Community feasibility assessment

### Ecosystem Integration

* [ ] Native SIEM connectors
* [ ] Native SOAR integrations
* [ ] Automated investigation workflows

---

# v1.3 Exit Criteria

A first-time user should be able to:

1. Clone the repository
2. Execute `./install.sh`
3. Run:

```bash
sudo orin init
sudo orin collect
sudo orin analyze
sudo orin report
```

4. Generate a valid HTML report
5. Review findings through the dashboard

Additionally:

* CI must pass consistently
* Test coverage must be publicly visible
* eBPF streaming must either:

  * work through documented automation, or
  * clearly identify itself as experimental
* Documentation must accurately reflect shipped functionality

---

# Explicit Non-Goals

The following items are intentionally outside the project's scope.

### Container Isolation

Orin is a host-focused forensic platform and will not attempt complex namespace-aware collection.

### Windows and macOS Support

Linux remains the sole supported platform unless long-term contributors commit to maintaining additional operating systems.

### Kernel Modules

Orin will not ship custom kernel modules. eBPF provides a safer and more maintainable observability path.

---

# Strategic Goal

Build the most trustworthy offline forensic snapshot platform for Linux.

The objective is not maximum feature count. The objective is dependable collection, verifiable evidence, transparent limitations, and predictable operation in disconnected environments.

**Offline First. Secure by Default. Forensically Sound. Honest About Limits.**
