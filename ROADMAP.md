# 🗺️ Orin Roadmap

**Version:** 1.0
**Status:** Production-Capable Linux Forensic Platform
**Last Updated:** June 2026

---

# Vision

Orin aims to become the leading **offline-first, air-gapped forensic and incident response platform** for Linux environments.

The project focuses on:

* Zero-telemetry operation
* Forensic integrity
* Secure fleet collection
* Minimal external dependencies
* Enterprise-grade deployment in disconnected environments

The current release delivers a robust foundation for single-host investigations and small fleet operations. The roadmap below outlines the remaining work required to achieve large-scale, unattended, and enterprise-class deployment.

---

# Current State

## Production Ready

### Forensic Collection Engine

* 40+ forensic collectors
* Parallel collection framework
* Vault encryption
* Signed evidence exports
* Chain-of-custody tracking
* Timeline generation
* Differential analysis

### Dashboard

* Alert management
* Telemetry explorer
* Configuration management
* Diff analysis viewer
* Authentication support
* REST API

### Fleet Hub

* Multi-tenant architecture
* API key authentication
* Administrator accounts
* Audit logging
* Rate limiting
* mTLS support
* Basic authentication

### Security Hardening

* AppArmor profiles
* SELinux policies
* Seccomp sandboxing
* Watchdog protection
* Tamper-evident exports

### Performance

* SQLite WAL mode
* Connection pooling
* Batch inserts
* Parallel collectors

---

# Roadmap Overview

| Phase   | Target                     | Priority  |
| ------- | -------------------------- | --------- |
| Phase 1 | Secure Fleet Operations    | Critical  |
| Phase 2 | Enterprise Automation      | High      |
| Phase 3 | Scalability & Distribution | High      |
| Phase 4 | Platform Expansion         | Medium    |
| Phase 5 | Compliance & Ecosystem     | Long-Term |

---

# Phase 1 — Secure Fleet Operations

**Goal:** Eliminate remaining high-risk operational gaps.

## 1. Agent Script Signing Integration

### Status

🔴 Critical

### Problem

Remote agent signing exists but is not currently enforced during agentless SSH deployments.

Current flow:

```
Control Node
    ↓
remote_agent.py
    ↓
SSH Transfer
    ↓
Target Host
```

Desired flow:

```
Control Node
    ↓
Verify Signature
    ↓
SSH Transfer
    ↓
Verify Again
    ↓
Execute
```

### Deliverables

* Integrate signature verification into `scanner.run_remote_scan()`
* Refuse execution of unsigned agents
* Refuse execution of tampered agents
* Signed bundle format
* Signature verification logging

### Success Criteria

* Every remote execution path requires signature validation
* Tampered payloads are rejected automatically

---

## 2. Alert Forwarding Framework

### Status

🟠 High Priority

### Deliverables

* Generic webhook notifier
* Syslog forwarding
* Critical severity forwarding
* Retry queue
* Notification audit log

### Planned Integrations

* Slack-compatible webhooks
* Microsoft Teams webhooks
* Generic REST endpoints
* Local syslog collectors

### Success Criteria

* Critical alerts can reach analysts without dashboard polling

---

## 3. Collector Capability Documentation

### Status

🟡 Medium

### Deliverables

Per-collector documentation showing:

* Required privileges
* Required Linux capabilities
* Expected runtime impact
* Data sources accessed

### Success Criteria

Operators can deploy least-privilege configurations confidently.

---

# Phase 2 — Enterprise Automation

**Goal:** Improve maintainability in air-gapped deployments.

## 1. Offline Update Cartridges

### Status

🟠 High Priority

### Deliverables

* Signed update bundles
* Offline verification
* Incremental updates
* Rollback support

### Example

```bash
orin update --bundle update.bin
```

### Success Criteria

Entire fleets can be updated without internet connectivity.

---

## 2. Health & Readiness Monitoring

### Deliverables

* Enhanced `/health`
* Kubernetes-style `/ready`
* Collector health reporting
* Database health checks
* Hub synchronization status

### Success Criteria

External monitoring systems can determine operational readiness automatically.

---

## 3. Operational Metrics

### Deliverables

* Collection duration metrics
* Collector performance statistics
* Database performance metrics
* Fleet-wide operational dashboard

### Success Criteria

Administrators can identify bottlenecks and failures quickly.

---

# Phase 3 — Scalability & Distribution

**Goal:** Support larger environments and simplify deployment.

## 1. Static Binary Distribution

### Status

🟠 High Priority

### Deliverables

* PyInstaller build
* Nuitka build
* Single-file deployment
* Embedded dependencies

### Benefits

* No Python installation required
* Simplified deployment
* Consistent runtime behavior

---

## 2. PostgreSQL Backend

### Status

🟡 Medium Priority

### Motivation

SQLite remains excellent for:

* Single-host deployments
* Small fleets
* Air-gapped environments

PostgreSQL becomes valuable for:

* Large fleets
* Multi-user environments
* High event volume

### Deliverables

* Database abstraction layer
* PostgreSQL backend
* Migration tooling

---

## 3. Horizontal Hub Scaling

### Deliverables

* Shared database support
* Worker separation
* Queue-based ingestion
* Multi-node deployments

### Success Criteria

Thousands of managed endpoints can be supported.

---

# Phase 4 — Platform Expansion

**Goal:** Expand supported environments.

## Windows Support

### Potential Components

* Event Log collection
* Registry acquisition
* Scheduled task analysis
* Service auditing
* PowerShell activity tracking

### Status

⚪ Future

---

## macOS Support

### Potential Components

* Unified Logging
* LaunchAgent inspection
* TCC analysis
* Security framework telemetry

### Status

⚪ Future

---

## Container Visibility

### Deliverables

* Docker inspection
* Podman support
* Kubernetes artifact collection
* Runtime anomaly detection

### Status

⚪ Future

---

# Phase 5 — Compliance & Ecosystem

**Goal:** Achieve enterprise trust and ecosystem integration.

## Third-Party Security Audit

### Deliverables

* Independent code review
* Threat modeling assessment
* Cryptographic review
* Secure deployment guidance

### Target Standards

* FIPS-oriented environments
* Common Criteria-aligned environments
* Government deployments

---

## SOAR Integration

### Deliverables

* REST API enhancements
* Webhook actions
* Playbook integration

### Planned Targets

* TheHive
* Cortex
* Shuffle
* Generic SOAR platforms

---

## SIEM Integrations

### Deliverables

* Native Splunk support
* Elastic integrations
* OpenSearch integrations
* Sigma rule mapping

---

# Research & Innovation

Future research tracks under consideration:

## eBPF Expansion

* Continuous telemetry streaming
* Advanced kernel event monitoring
* Runtime behavioral analytics

## Threat Intelligence

* Offline IOC bundles
* Signed intelligence packs
* YARA distribution

## Behavioral Analytics

* UEBA-style baselining
* User behavior anomaly scoring
* Lateral movement detection

## Autonomous Triage

* Local LLM-assisted investigation
* Offline evidence correlation
* Automated incident summarization

---

# Release Priorities

## Version 1.1

* Agent signing enforcement
* Alert forwarding
* Capability documentation
* Health/readiness improvements

## Version 1.2

* Offline update cartridges
* Static binary builds
* Operational metrics

## Version 2.0

* PostgreSQL support
* Large fleet scalability
* Enhanced hub architecture

## Version 3.0

* Cross-platform expansion
* SOAR ecosystem integration
* Formal security audit

---

# Success Criteria

Orin will be considered fully mature when it can:

* Securely manage large air-gapped fleets
* Enforce signed remote execution
* Deliver automated alerting
* Update entirely offline
* Scale beyond SQLite when required
* Pass independent security assessment
* Integrate with enterprise incident response workflows

---

# Strategic Goal

Build the most trusted open-source forensic platform for disconnected and security-sensitive Linux environments while preserving the project's core principles:

**Offline First. Secure by Default. Forensically Sound.**
