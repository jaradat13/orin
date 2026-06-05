# Orin — Roadmap

Planned features for the Orin Forensic Engine. For what's already built, see [README.md](README.md).

> [!IMPORTANT]
> Orin operates strictly offline. No cloud services, no external APIs, no remote servers — ever.

> **Status key:** ✅ Completed &nbsp;|&nbsp; 🔄 In Progress &nbsp;|&nbsp; 🗓️ Planned

---


All planned milestones have been completed.

---


## Implementation Flow

```mermaid
graph TD
    A[Telemetry Collectors] -->|Crontabs / Ports / eBPF / Processes| B(SQLite Forensics Vault)
    B -->|orin serve ✅| C[Local Web Dashboard]
    C -->|Alert Triage & Annotations| B
    C -->|Snapshot Timeline Explorer| B
    B -->|Snapshot Canonical JSON| D[Sigma / ATT&CK Engine]
    D -->|Relational Threat Analysis| E{Context Scoring}
    E -->|0-34: Low| F[Posture Report]
    E -->|35-64: Medium| F
    E -->|65-89: High| F
    E -->|90-100: Critical| F
    F -->|Briefing Generation| G[HTML / Markdown Report]
    B -->|SSH Agentless| H[Fleet Scanner]
    H -->|Multi-Host Drift| B
    D -->|Long-Term| I[Local AI Correlator]
    B -->|Stat-Cache ✅| J[FIM Skip Unchanged Files]
```