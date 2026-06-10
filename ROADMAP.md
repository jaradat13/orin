# 🗺️ Orin Roadmap

**Version:** 1.1
**Status:** Production-Capable Linux Forensic Platform
**Last Updated:** January 2026

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

| Phase   | Target                           | Priority  |
| ------- | -------------------------------- | --------- |
| Phase 0 | Code Quality & Security Hardening| Critical  |
| Phase 1 | Secure Fleet Operations          | Critical  |
| Phase 2 | Enterprise Automation            | High      |
| Phase 3 | Scalability & Distribution       | High      |
| Phase 4 | Platform Expansion               | Medium    |
| Phase 5 | Compliance & Ecosystem           | Long-Term |

---

# Phase 0 — Code Quality & Security Hardening

**Goal:** Address critical code quality issues and security vulnerabilities identified in code review.

**Priority:** Critical

**Status:** 🟠 In Progress

---

## 1. Exception Handling & Error Recovery

### Status

🔴 Critical Priority

### Issues

* Missing error handling in `database.py` encryption operations could leave plaintext files exposed
* Inconsistent logging with mix of stderr writes and exceptions
* No cleanup on failure paths

### Deliverables

* Wrap all encryption/decryption operations in try-finally blocks
* Ensure temporary files are securely deleted on error
* Implement consistent exception hierarchy
* Add error recovery mechanisms for partial failures

### Success Criteria

* No plaintext evidence left exposed on collection failure
* All error paths logged consistently
* Graceful degradation on non-critical failures

---

## 2. Race Condition Fixes

### Status

🔴 Critical Priority

### Issues

* ConnectionPool lock acquisition timing could cause connection leaks
* Potential race conditions in parallel collection framework

### Deliverables

* Audit all threading primitives
* Fix ConnectionPool lock ordering
* Add stress tests for concurrent access
* Implement connection leak detection

### Success Criteria

* Zero connection leaks under load
* Thread-safe operations verified by stress tests

---

## 3. Input Validation & Sanitization

### Status

🔴 Critical Priority

### Issues

* Missing validation on `snapshot_id` and `host` parameters
* Potential injection vulnerabilities in database queries
* No bounds checking on user-provided values

### Deliverables

* Validate all external inputs (snapshot_id, host, paths)
* Implement allowlist-based validation where possible
* Add parameterized queries throughout
* Sanitize file paths to prevent directory traversal

### Success Criteria

* All user inputs validated before use
* SQL injection prevented via parameterized queries
* Path traversal attacks blocked

---

## 4. SSH Security Hardening

### Status

🔴 Critical Priority

### Issues

* `StrictHostKeyChecking=no` is dangerous in production
* No rate limiting for SSH scanning
* Missing host key verification options

### Deliverables

* Make StrictHostKeyChecking configurable
* Implement known_hosts management
* Add rate limiting for SSH operations
* Document SSH security best practices

### Success Criteria

* Production deployments can enforce host key verification
* SSH scanning respects rate limits
* Clear guidance on SSH security configuration

---

## 5. Configuration Security

### Status

🔴 High Priority

### Issues

* Shallow copy bug in `config.py` - nested dicts share references between default and user configs
* Hardcoded paths in `engine.py` - threat intel paths should be configurable
* Magic numbers in database pragmas with no explanation

### Deliverables

* Fix config merging to use deep copy
* Externalize all hardcoded paths to configuration
* Document all configuration constants
* Add validation for configuration values

### Success Criteria

* User config changes don't affect defaults
* All paths configurable via environment or config file
* No unexplained magic numbers in code

---

## 6. Memory Security

### Status

🔴 High Priority

### Issues

* Ineffective memory zeroization in `SecureCredential._zeroize()` - currently does nothing
* Sensitive data may persist in memory

### Deliverables

* Implement proper memory clearing using ctypes or specialized libraries
* Audit all credential handling code
* Minimize sensitive data lifetime in memory
* Add tests to verify memory zeroization

### Success Criteria

* Credentials securely wiped from memory after use
* No sensitive data lingering in process memory

---

## 7. Type Safety & Code Quality

### Status

🟡 Medium Priority

### Issues

* Incomplete type hints - many functions lack proper annotations
* Code duplication in database store methods
* Missing docstrings on public APIs

### Deliverables

* Add comprehensive type hints throughout
* Refactor duplicated database methods into base classes
* Complete API documentation
* Enable strict mypy checking in CI

### Success Criteria

* 100% type coverage on public APIs
* DRY principles applied to database layer
* Type checking passes in CI pipeline

---

## 8. Test Coverage Improvement

### Status

🔴 Critical Priority

### Issues

* Test coverage is only 6% (target is 85%)
* Missing tests for critical security functions
* No integration tests for end-to-end workflows

### Deliverables

* Unit tests for all collectors
* Integration tests for collection workflows
* Security-focused tests (crypto, auth, validation)
* Performance regression tests
* Achieve 85%+ line coverage

### Success Criteria

* 85%+ code coverage
* All critical paths tested
* CI fails on coverage regression

---

## 9. Logging & Observability

### Status

🟡 Medium Priority

### Issues

* Mix of stderr writes and exceptions for logging
* Missing structured logging context
* Inconsistent log levels

### Deliverables

* Standardize on Python logging module
* Add structured logging with context (host, snapshot_id, collector)
* Implement log correlation IDs
* Define log level guidelines

### Success Criteria

* All logs via standard logging facility
* Structured logs with consistent fields
* Easy correlation of related events

---

## 10. Dependency Management

### Status

🟡 Medium Priority

### Issues

* Dependency versions not pinned
* No automated vulnerability scanning
* Missing dependency audit process

### Deliverables

* Pin all dependency versions
* Add automated dependency scanning (pip-audit, safety)
* Document dependency update process
* Implement SBOM generation

### Success Criteria

* Reproducible builds with pinned dependencies
* Automated vulnerability alerts
* Complete software bill of materials

---

# Phase 1 — Secure Fleet Operations

**Goal:** Eliminate remaining high-risk operational gaps.

## 1. Agent Script Signing Integration ✅ COMPLETED

### Status

✅ **Production Ready** (v1.1)

### Implementation

Remote agent signing is now fully enforced during agentless SSH deployments with HMAC-SHA256 signatures.

Current flow:

```
Control Node
    ↓
Sign Agent Bundle (HMAC-SHA256)
    ↓
SSH Transfer
    ↓
Target Host Verifies Signature
    ↓
Execute (or Reject if Tampered)
```

### Deliverables (All Complete)

* ✅ Integrated signature verification into `scanner.run_remote_scan()`
* ✅ Automatic refusal of unsigned agents
* ✅ Automatic refusal of tampered agents with CRITICAL alerts
* ✅ Signed bundle format with metadata embedding
* ✅ Comprehensive signature verification logging
* ✅ Environment variable support (`ORIN_AGENT_SIGNING_KEY`)
* ✅ Constant-time comparison for timing attack prevention
* ✅ Minimum key length enforcement (12 characters)
* ✅ Optional enforcement mode for testing

### Success Criteria

* ✅ Every remote execution path requires signature validation
* ✅ Tampered payloads are rejected automatically
* ✅ Clear audit trail in logs for signing operations

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

## Version 1.1 ✅ Released

* ✅ Agent signing enforcement (HMAC-SHA256, production ready)
* 🟠 Alert forwarding (in progress)
* 🟡 Capability documentation (planned)
* 🟡 Health/readiness improvements (planned)

## Version 1.1.1 — Security Hardening Patch (Immediate)

* 🔴 Critical exception handling fixes in database.py
* 🔴 Race condition fixes in ConnectionPool
* 🔴 Input validation for snapshot_id and host parameters
* 🔴 SSH StrictHostKeyChecking configuration
* 🔴 Secure credential zeroization implementation

## Version 1.2

* 🟠 All Phase 0 critical items (test coverage, config security, memory security)
* 🟠 Alert forwarding framework completion
* 🟡 Offline update cartridges
* 🟡 Static binary builds
* 🟡 Operational metrics
* 🟡 Logging standardization
* 🟡 Dependency pinning and SBOM generation

## Version 1.3

* 🟡 Type safety improvements (100% type coverage)
* 🟡 Code duplication refactoring
* 🟡 Collector capability documentation
* 🟡 Enhanced health/readiness endpoints

## Version 2.0

* PostgreSQL support
* Large fleet scalability
* Enhanced hub architecture
* Horizontal scaling capabilities

## Version 3.0

* Cross-platform expansion (Windows/macOS)
* SOAR ecosystem integration
* Formal security audit
* Container visibility features

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