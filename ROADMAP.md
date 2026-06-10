# Orin — Roadmap

Planned features and future engineering milestones for the Orin Forensic Engine.  
For implemented features, see `README.md`.

---

## Design Philosophy: Air-Gapped First

Orin is designed from the ground up for air‑gapped, offline, and forensically sensitive environments. Every feature must adhere to these principles:

- **Zero Network Egress** – No outbound connections, no telemetry, no cloud API calls.
- **Zero External Dependencies** – All processing happens locally with stdlib or minimal trusted packages.
- **Tamper‑Evident Storage** – All evidence is cryptographically signed and optionally encrypted.
- **Self‑Contained Operation** – Can run indefinitely without external connectivity or updates.

---

## Current Implementation Status

| Status | Description |
|--------|-------------|
| ✅ **Core Capabilities** | All 35 capabilities listed in `README.md` are fully functional. |
| 🟡 **Advanced Features** | 21 advanced features planned; some complete (encrypted vault, chain‑of‑custody, eBPF streaming, YARA engine), others in progress (see Phase 2). |
| 🔴 **Phase 3 Features** | No code yet – enterprise platform features are not started (see Phase 3). |

**Architecture notes** (all implemented):
- Zero network egress – all components operate entirely offline.
- No TPM/HSM – uses PBKDF2 from user passphrase.
- No SQLCipher – custom AES‑256‑GCM with stdlib crypto.
- Host‑only focus – bare metal and VM forensics.
- Manual evidence export – signed JSON bundles for offline transfer.
- Local‑only dashboard – binds to 127.0.0.1 with ephemeral token.

**Use cases where Orin excels**:
✅ Classified networks (SCIFs)  
✅ Air‑gapped ICS/SCADA  
✅ Forensic incident response  
✅ Compliance auditing  
✅ Offline threat hunting  
✅ Secure enclaves  
✅ Manual remediation

---

## Real‑World Deployment Review & Enhancement Plan

Based on architectural analysis, the following phased roadmap transforms Orin into a mission‑ready forensic instrument for air‑gapped, classified, and high‑security Linux environments.

### Recap of Critical Gaps (Resolved or Pending)

| Gap | Status |
|-----|--------|
| Dependency chain breaks on hardened systems (Python 3.10+, psutil) | 🔴 **Pending (Phase 1.1)** |
| No lifecycle management (SQLite vault unbounded) | ✅ **Complete** (pruning, retention, vacuum) |
| Fragile detection logic (Sigma subset, unmanaged YARA) | 🟡 **Partial (Phase 2.1 & 2.2)** |
| Tool integrity not verifiable | ✅ **Complete** (signed releases, SBOM, self‑check) |
| Hardcoded paths, no USB / in‑memory mode | ✅ **Complete** (`--vault-path`, `--read-only`) |
| Dashboard & credential exposure | ✅ **Complete** (passphrase file/prompt/env, token file) |
| Agentless SSH requires Python | ✅ **Complete** (pure‑bash fallback agent) |

---

## Phased Enhancement Plan

### Phase 1 – “Field‑Ready Forensic Grabber”

**Goal:** Make Orin usable immediately in any air‑gapped environment with zero external dependencies and no disk footprint if desired.

| Feature | Status |
|---------|--------|
| 1.1 Static binary distribution (PyInstaller/Nuitka, x86_64 + arm64) | 🔴 Not Started |
| 1.2 Read‑only & ephemeral modes (`--read-only`, `--vault-path`) | ✅ Complete |
| 1.3 Vault lifecycle management (`prune`, `stats`, retention) | ✅ Complete |
| 1.4 Credential handling overhaul (passphrase file/prompt/env, token file) | ✅ Complete |
| 1.5 Tool self‑verification (SBOM, manifests, GPG signatures, self‑check) | ✅ Complete |
| 1.6 Minimal footprint SSH agent (pure‑bash fallback) | ✅ Complete |

---

### Phase 2 – “Production‑Grade Monitoring & Detection”

**Goal:** Enable continuous security monitoring on hardened endpoints with reliable alerting and manageable data.

| Feature | Status |
|---------|--------|
| 2.1 Sigma & YARA rule management (validation, list, offline update) | 🟡 Foundation exists (YARA embedded); Sigma validation missing |
| 2.2 Enhanced rootkit detection (cross‑view diff, eBPF probe) | 🟡 Basic null‑signal test exists; advanced methods pending |
| 2.3 Centralised air‑gapped fleet hub (`orin hub serve`, multi‑tenant import) | 🔴 Not Started |
| 2.4 Configurable retention & auto‑cleanup (per‑event type) | ✅ Basic pruning complete; granular per‑type planned |
| 2.5 Robust dashboard with access control (Unix socket, mTLS, HTTP Basic) | 🟡 Token file complete; socket/mTLS/Basic pending |
| 2.6 macOS & *BSD preliminary support | 🔴 Not Started |

---

### Phase 3 – “Enterprise Forensic Platform”

**Goal:** Mature into a trusted DFIR standard for high‑security environments.

| Feature | Status |
|---------|--------|
| 3.1 Formal verification & independent audit | 🔴 Not Started |
| 3.2 Integration with established forensic standards (DFIR‑ORC, CASE, ChronoPort) | 🔴 Not Started |
| 3.3 Automated baseline creation & drift learning | 🔴 Not Started |
| 3.4 Secure update mechanism for air‑gapped networks (signed cartridge) | 🔴 Not Started |
| 3.5 Full documentation & practitioner’s guide | 🔴 Not Started |

---

## Summary Table of Priority Actions

| Priority | Action | Impact |
|----------|--------|--------|
| **Critical** | Ship static binary (no Python/psutil dep) | Unblocks all air‑gap usage immediately |
| **Critical** | Enhanced rootkit detection (cross‑view, eBPF) | Improves evaded‑process detection |
| **High** | Document Sigma limitations & add rule validation | Avoids analyst frustration |
| **High** | Centralised fleet hub | Enables multi‑host forensic management |
| **Medium** | Dashboard access control (Unix socket, mTLS) | Reduces network exposure |
| **Low** | Third‑party audit & formal spec | Long‑term credibility for classified environments |