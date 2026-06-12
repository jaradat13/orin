# Orin Roadmap

**Version:** 1.2.0
**Status:** Production-capable offline forensic snapshot platform for Linux
**Last Updated:** June 2026

---

## Vision

Orin is an **offline-first, air-gapped forensic snapshot and incident investigation platform** designed for Linux environments where reliability, transparency, and forensic integrity matter more than feature volume.

The project prioritizes:

- Zero-telemetry operation
- Tamper-evident evidence collection
- Cryptographic integrity verification
- Minimal, auditable dependencies
- Offline deployment capability
- Honest documentation of capabilities and limitations

The long-term objective is to become the most trustworthy open-source offline forensic platform for Linux.

---

## Current State (v1.2)

### Production-Ready Components

| Module | Status |
|---|---|
| Process Collection | ✅ Stable |
| Network Collection | ✅ Stable |
| Kernel Collection | ✅ Stable |
| User & Account Collection | ✅ Stable |
| Cron & Persistence Collection | ✅ Stable |
| File Integrity Monitoring (SHA-256 + stat cache) | ✅ Stable |
| Encrypted Evidence Vault (AES-256-GCM) | ✅ Stable |
| Signed JSON Exports (HMAC-SHA256) | ✅ Stable |
| Local Dashboard (`orin serve`) | ✅ Stable |
| Agentless SSH Collection | ✅ Stable |
| Bash Fallback Collection Agent | ✅ Stable |
| Alert Forwarding (Slack, Teams, syslog) | ✅ Stable |
| Health & Readiness APIs | ✅ Stable |
| Structured JSON Logging | ✅ Stable |
| Agent Script Signing & Verification | ✅ Stable |
| Threat Detection Rules Engine | ✅ Stable |
| Sigma Rule Evaluation (Subset) | ✅ Stable |
| Offline Threat Intel Importer | ✅ Stable |
| SUID/SGID Monitoring | ✅ Stable |

### Partial / Experimental Components

| Component | Limitation | Status |
|---|---|---|
| eBPF Real-Time Streaming | Requires a BTF-enabled kernel and setup via `scripts/setup_ebpf.sh` | ✅ Supported |
| YARA Scanning | Restricted to temporary directories by default | ⚠️ Partial |
| Triggered PCAP Collection | Requires Scapy for protocol reconstruction | ⚠️ Partial |
| AI Correlation | Requires a local Ollama deployment | ⚠️ Optional |

### Not Included

| Feature | Status |
|---|---|
| Full Public Test Suite | Planned |
| PostgreSQL Backend | Planned |
| Multi-Node Scaling | Planned |
| Windows Support | Not Planned |
| macOS Support | Not Planned |
| Container Namespace Isolation | Not Planned |

---

## Phase 1 — Documentation & Transparency ✅ Completed (v1.2.1)

**Target:** v1.2.1 · **Completed:** June 2026

### Objectives

Improve transparency and eliminate documentation drift between stated and shipped functionality.

### Completed Tasks

- [x] Reduce README scope to verified functionality only
- [x] Move aspirational features into ROADMAP.md
- [x] Publish STATUS.md with explicit platform matrix and deployment assumptions
- [x] Document all known limitations
- [x] Mark all experimental features clearly

### Success Criteria Met

- No README feature overclaims
- Every documented feature is demonstrable
- All experimental features are clearly labelled

---

## Phase 2 — Reliability & Production Readiness

**Target:** v1.3 · **Estimated Timeline:** 2–3 months

### Priority 1: eBPF Streaming

**Goal:** Provide a reproducible, documented deployment experience for eBPF streaming.

- [x] Add `scripts/setup_ebpf.sh`
- [x] Automate `vmlinux.h` generation
- [x] Validate kernel prerequisites at runtime
- [x] Improve error reporting and surface actionable messages
- [x] Document troubleshooting procedures in EBPF_TROUBLESHOOTING.md

### Priority 2: End-to-End Testing

**Goal:** Ensure the complete workflow executes successfully on clean systems.

- [ ] Create Ubuntu 22.04 CI environment
- [ ] Install Orin from source in CI
- [ ] Execute and validate the full `init → collect → analyze → report` cycle
- [ ] Publish CI artifacts and test results

### Priority 3: Public Test Suite

**Goal:** Increase contributor confidence and improve onboarding experience.

- [ ] Publish current internal tests
- [ ] Add pytest coverage reporting to CI
- [ ] Add clickable coverage badge to README
- [ ] Publish testing guidelines in TESTING.md

### Operational Improvements

**Database migrations:**
- [ ] Schema version tracking
- [ ] Upgrade compatibility validation
- [ ] Migration rollback support

**Offline update cartridges:**
- [ ] Signed offline update bundles
- [ ] Offline rule and intelligence updates
- [ ] Offline binary upgrade packages

**Snapshot retention (completed):**
- [x] Age-based retention
- [x] Count-based retention
- [x] Critical-alert preservation during pruning

---

## Phase 3 — Operational Excellence

**Target:** v1.4 · **Estimated Timeline:** 3–6 months

- [x] Live WebSocket alert feed in dashboard
- [x] Real-time dashboard updates
- [x] Alert acknowledgement workflow
- [x] `orin doctor` — dependency, permission, and configuration validation
- [x] `orin diff` — snapshot comparison engine
- [x] Timeline delta reporting and alert drift analysis
- [x] Collector capability registry with privilege requirements and runtime impact scoring

---

## Phase 4 — Scale & Enterprise Operations

**Target:** v2.0 · **Estimated Timeline:** 6–12 months

**Storage layer:**
- [ ] PostgreSQL backend
- [ ] Migration tooling from SQLite
- [ ] Large-scale snapshot retention

**Distributed operations:**
- [ ] Multi-node fleet hub
- [ ] Centralized alert aggregation
- [ ] Distributed collection orchestration

**Packaging:**
- [ ] Standalone binary releases via PyInstaller
- [ ] Offline installer bundles

**Security hardening (completed):**
- [x] Full credential memory zeroization
- [x] Enhanced secret handling
- [x] Expanded cryptographic review

---

## Phase 5 — Trust & Ecosystem

**Target:** v3.0 · **Estimated Timeline:** Long-term

- [ ] Independent security audit
- [ ] Published threat model
- [ ] Evaluate Windows and macOS support (community feasibility assessment)
- [ ] Native SIEM connectors
- [ ] Native SOAR integrations
- [ ] Automated investigation workflows

---

## v1.3 Exit Criteria

A first-time user must be able to:

1. Clone the repository
2. Run `./install.sh`
3. Execute the full workflow:
   ```bash
   sudo orin init
   sudo orin collect
   sudo orin analyze
   sudo orin report
   ```
4. Receive a valid HTML report
5. Browse findings in the dashboard

Additionally:
- CI must pass consistently
- Test coverage must be publicly visible
- eBPF streaming must either work via documented automation or clearly identify itself as experimental
- Documentation must accurately reflect all shipped functionality

---

## Explicit Non-Goals

**Container Namespace Isolation**
Orin is a host-focused forensic platform. Complex namespace-aware collection is out of scope.

**Windows and macOS Support**
Linux remains the sole supported platform unless long-term contributors commit to maintaining additional OS targets.

**Custom Kernel Modules**
Orin will not ship custom kernel modules. eBPF provides a safer and more maintainable observability path.

---

## Strategic Goal

Build the most trustworthy offline forensic snapshot platform for Linux.

The objective is not maximum feature count. It is dependable collection, verifiable evidence, transparent limitations, and predictable operation in disconnected environments.

**Offline First. Secure by Default. Forensically Sound. Honest About Limits.**