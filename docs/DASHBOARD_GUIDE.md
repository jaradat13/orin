# Orin Dashboard - Complete Functionality Guide

## Executive Summary

The Orin Forensic Investigation Console is a production-grade, single-page application (SPA) dashboard that provides real-time visibility into system security posture, forensic telemetry, threat detection alerts, and fleet management capabilities. This document provides comprehensive coverage of **all available user functions**, their backend API integrations, and operational workflows.

---

## Table of Contents

1. [Dashboard Architecture Overview](#dashboard-architecture-overview)
2. [Navigation & Layout Structure](#navigation--layout-structure)
3. [Core Functional Areas](#core-functional-areas)
   - [3.1 Posture Pane - Forensic Alert Feed](#31-posture-pane---forensic-alert-feed)
   - [3.2 Telemetry Explorer](#32-telemetry-explorer)
   - [3.3 Timeline Delta Analysis](#33-timeline-delta-analysis)
   - [3.4 Settings Panel](#34-settings-panel)
   - [3.5 AI Triage Briefing](#35-ai-triage-briefing)
4. [Left Sidebar Functions](#left-sidebar-functions)
   - [4.1 Risk Assessment Gauge](#41-risk-assessment-gauge)
   - [4.2 Recent Snapshots Ledger](#42-recent-snapshots-ledger)
   - [4.3 Baseline Administration](#43-baseline-administration)
   - [4.4 Fleet Dashboard Overview](#44-fleet-dashboard-overview)
   - [4.5 Remote SSH Scan Configuration](#45-remote-ssh-scan-configuration)
5. [API Endpoint Reference](#api-endpoint-reference)
6. [JavaScript Function Reference](#javascript-function-reference)
7. [User Workflows](#user-workflows)
8. [Security Considerations](#security-considerations)
9. [Troubleshooting](#troubleshooting)

---

## Dashboard Architecture Overview

### Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Frontend | Vanilla JavaScript + CSS3 | Zero-dependency SPA |
| Styling | Custom CSS Variables | Dark theme, responsive design |
| Icons | Lucide Icons (via data attributes) | Consistent iconography |
| Backend API | Python HTTP Server (hub_server.py) | RESTful API endpoints |
| Data Storage | SQLite (OrinStorage) | Forensic data persistence |
| Authentication | API Key / Bearer Token | Multi-tenant isolation |

### Communication Flow

```
┌─────────────────┐      HTTPS/API      ┌──────────────────┐
│   Browser       │ ◄─────────────────► │  Hub Server      │
│   (dashboard.html) │  JSON Responses    │  (port 8443)     │
└─────────────────┘                     └──────────────────┘
                                               │
                                               ▼
                                      ┌──────────────────┐
                                      │  SQLite Vault    │
                                      │  (forensic DB)   │
                                      └──────────────────┘
```

---

## Navigation & Layout Structure

### Header Bar Components

| Element | ID/Class | Function |
|---------|----------|----------|
| Logo Section | `.logo-section` | Brand identity with shield icon |
| Host Badge | `#badge-host` | Displays current hostname |
| OS Badge | `#badge-os` | Shows operating system details |
| Vault Badge | `#badge-vault` | Indicates active vault name |
| Tab Navigation | `.nav-tabs` | Switch between main panes |
| Capture Button | `.btn` (Capture Telemetry) | Triggers on-demand collection |

### Main Layout Grid

The dashboard uses a **two-column layout**:

- **Left Column** (320px fixed width): Risk metrics, snapshots, baseline controls, fleet overview, remote scan config
- **Right Column** (flexible): Active pane content (Posture/Telemetry/Diff/Settings/AI)

### Tab System

| Tab Button | Target Pane ID | Description |
|------------|----------------|-------------|
| Posture | `#pane-posture` | Security alert feed with filtering |
| Telemetry Explorer | `#pane-telemetry` | Deep-dive into system state |
| Timeline delta | `#pane-diff` | Comparative snapshot analysis |
| Settings | `#pane-config` | Configuration management |
| AI Triage | `#pane-ai` | AI-powered executive summaries |

---

## Core Functional Areas

### 3.1 Posture Pane - Forensic Alert Feed

**Purpose:** Centralized view of all security events, alerts, and forensic findings with advanced filtering capabilities.

#### UI Components

| Component | ID/Class | Interaction |
|-----------|----------|-------------|
| Host Filter Dropdown | `#filter-host` | Filter alerts by specific host |
| Severity Pills | `.sev-pills` | Filter by severity level (ALL/CRITICAL/HIGH/MEDIUM/LOW) |
| Show Resolved Toggle | `#chk-resolved` | Include/exclude resolved alerts |
| Show Suppressed Toggle | `#chk-suppressed` | Include/exclude suppressed alerts |
| Alert Feed Content | `#alert-feed-content` | Dynamic alert list rendering |

#### Available Functions

##### `loadAlertsLedger()`

**Purpose:** Fetches and renders security alerts from the backend.

**Implementation Required:**
```javascript
async function loadAlertsLedger() {
    const hostFilter = document.getElementById('filter-host').value;
    const showResolved = document.getElementById('chk-resolved').checked;
    const showSuppressed = document.getElementById('chk-suppressed').checked;
    const severityFilter = currentSeverityFilter; // Set by setSeverityFilter()

    try {
        const response = await fetch('/api/alerts?' + new URLSearchParams({
            host: hostFilter,
            resolved: showResolved,
            suppressed: showSuppressed,
            severity: severityFilter
        }), {
            headers: { 'X-API-Key': getApiKey() }
        });

        const data = await response.json();
        renderAlertFeed(data.alerts);
    } catch (error) {
        showToast('Failed to load alerts: ' + error.message, 'error');
    }
}
```

**Backend Endpoint:** `GET /api/alerts` (to be implemented in hub_server.py)

**Response Schema:**
```json
{
  "alerts": [
    {
      "id": "evt_abc123",
      "timestamp": "2026-06-10T14:30:00Z",
      "host": "forensic-server-01",
      "severity": "CRITICAL",
      "category": "privilege_escalation",
      "title": "Sudo Abuse Detected",
      "description": "User 'john' executed sudo with suspicious arguments",
      "mitre_attack": ["T1548.003"],
      "resolved": false,
      "suppressed": false,
      "evidence": {...}
    }
  ],
  "total_count": 42,
  "filtered_count": 15
}
```

##### `setSeverityFilter(level)`

**Purpose:** Sets the active severity filter and refreshes the alert feed.

**Current Implementation:**
```javascript
function setSeverityFilter(level) {
    document.querySelectorAll('.sev-pill').forEach(el => el.classList.remove('active'));
    event.target.classList.add('active');
    currentSeverityFilter = level;
    loadAlertsLedger(); // Should trigger reload
}
```

**Severity Levels:**
- `ALL` - No filtering
- `CRITICAL` - Immediate action required (risk score impact: +25)
- `HIGH` - Serious threats (risk score impact: +15)
- `MEDIUM` - Moderate concerns (risk score impact: +8)
- `LOW` - Informational (risk score impact: +2)

#### Alert Detail Modal

Clicking an alert opens a modal with:
- Full event timeline
- Related processes and users
- MITRE ATT&CK mapping
- Recommended remediation steps
- Evidence artifacts (file hashes, network connections)

---

### 3.2 Telemetry Explorer

**Purpose:** Interactive exploration of captured system state snapshots across multiple forensic domains.

#### Snapshot Selection

| Component | ID | Function |
|-----------|----|--------|
| Snapshot Dropdown | `#telemetry-snapshot-select` | Select snapshot run to explore |

**Population Logic:**
```javascript
async function populateSnapshotDropdown() {
    const response = await fetch('/api/snapshots', {
        headers: { 'X-API-Key': getApiKey() }
    });
    const data = await response.json();

    const select = document.getElementById('telemetry-snapshot-select');
    select.innerHTML = '<option value="">Select a snapshot...</option>';

    data.snapshots.forEach(snap => {
        const option = document.createElement('option');
        option.value = snap.id;
        option.textContent = `${snap.timestamp} - ${snap.hostname}`;
        select.appendChild(option);
    });
}
```

#### Telemetry Categories

The sidebar provides navigation between 7 telemetry domains:

| Tab Button | Content ID | Data Source | Collector Module |
|------------|-----------|-------------|------------------|
| Processes | `#telemetry-processes` | `processes` table | `collectors/processes.py` |
| Network Connections | `#telemetry-network` | `connections` table | `collectors/connections.py` |
| File Changes | `#telemetry-files` | `integrity_events` table | `collectors/integrity.py` |
| User Sessions | `#telemetry-users` | `sessions` table | `collectors/session_audit.py` |
| Kernel Modules | `#telemetry-kernel` | `kernel_modules` table | `collectors/kernel.py` |
| Services | `#telemetry-services` | `services` table | `collectors/persistence.py` |
| Packages | `#telemetry-packages` | `packages` table | `collectors/pkg_integrity.py` |

#### Data Loading Functions

##### `loadTelemetry(snapshotId)`

**Purpose:** Fetches and displays telemetry data for the selected snapshot.

**Implementation Required:**
```javascript
async function loadTelemetry(snapshotId) {
    if (!snapshotId) return;

    const activeTab = document.querySelector('.telemetry-menu-btn.active').dataset.tab;
    const dataType = activeTab.replace('telemetry-', '');

    try {
        const response = await fetch(`/api/telemetry/${dataType}?snapshot_id=${snapshotId}`, {
            headers: { 'X-API-Key': getApiKey() }
        });
        const data = await response.json();

        renderTelemetryTable(dataType, data.records);
    } catch (error) {
        showToast('Failed to load telemetry: ' + error.message, 'error');
    }
}
```

##### `switchTelemetryTab(tabId)`

**Purpose:** Switches between telemetry categories and reloads data.

**Current Implementation:**
```javascript
function switchTelemetryTab(tabId) {
    document.querySelectorAll('.telemetry-tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.telemetry-menu-btn').forEach(el => el.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    event.target.classList.add('active');

    // Reload data for new tab
    const snapshotId = document.getElementById('telemetry-snapshot-select').value;
    if (snapshotId) {
        loadTelemetry(snapshotId);
    }
}
```

#### Table Rendering Specifications

Each telemetry category has specific column requirements:

**Processes Table:**
| Column | Field | Sortable |
|--------|-------|----------|
| PID | `pid` | Yes |
| Command | `cmdline` | Yes |
| User | `username` | Yes |
| CPU% | `cpu_percent` | Yes |
| Mem% | `memory_percent` | Yes |
| Status | `status` | Yes |

**Network Connections Table:**
| Column | Field | Sortable |
|--------|-------|----------|
| Protocol | `protocol` (TCP/UDP) | Yes |
| Local Address | `local_addr` | Yes |
| Foreign Address | `remote_addr` | Yes |
| State | `state` (LISTEN/ESTABLISHED/etc) | Yes |
| Process | `process_name` | Yes |

**File Changes Table:**
| Column | Field | Sortable |
|--------|-------|----------|
| Path | `file_path` | Yes |
| Action | `change_type` (CREATED/MODIFIED/DELETED) | Yes |
| Timestamp | `timestamp` | Yes |
| Size | `file_size` | Yes |
| Checksum | `sha256_hash` | Yes |

---

### 3.3 Timeline Delta Analysis

**Purpose:** Comparative analysis between two snapshots to identify system changes, drift, and potential compromise indicators.

#### UI Components

| Component | ID | Function |
|-----------|----|--------|
| Baseline Dropdown | `#diff-base-snapshot` | Select reference snapshot |
| Comparison Dropdown | `#diff-comp-snapshot` | Select target snapshot |
| Analyze Button | `.btn` (Analyze Differences) | Trigger diff analysis |
| Results Container | `#diff-results-content` | Display comparative results |

#### Diff Analysis Workflow

1. User selects baseline snapshot (e.g., known-good state)
2. User selects comparison snapshot (e.g., post-incident capture)
3. Click "Analyze Differences" button
4. Backend computes delta across all telemetry domains
5. Results displayed grouped by category with color coding:
   - 🟢 Green: Expected/benign changes
   - 🟡 Yellow: Suspicious modifications
   - 🔴 Red: Critical/high-risk changes

##### `performDiffAnalysis()`

**Implementation Required:**
```javascript
async function performDiffAnalysis() {
    const baseSnapshot = document.getElementById('diff-base-snapshot').value;
    const compSnapshot = document.getElementById('diff-comp-snapshot').value;

    if (!baseSnapshot || !compSnapshot) {
        showToast('Please select both baseline and comparison snapshots', 'error');
        return;
    }

    if (baseSnapshot === compSnapshot) {
        showToast('Baseline and comparison must be different snapshots', 'error');
        return;
    }

    // Show loading state
    document.getElementById('diff-results-content').innerHTML = `
        <div class="secured-state">
            <span data-icon="loader" class="spinner" data-size="28"></span>
            <div class="secured-title">Analyzing Differences</div>
            <div class="secured-desc">Comparing snapshots across all forensic domains...</div>
        </div>
    `;

    try {
        const response = await fetch('/api/diff', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': getApiKey()
            },
            body: JSON.stringify({
                baseline_snapshot: baseSnapshot,
                comparison_snapshot: compSnapshot
            })
        });

        const data = await response.json();
        renderDiffResults(data);
    } catch (error) {
        showToast('Diff analysis failed: ' + error.message, 'error');
    }
}
```

**Backend Endpoint:** `POST /api/diff`

**Request Body:**
```json
{
  "baseline_snapshot": "snap_abc123",
  "comparison_snapshot": "snap_def456"
}
```

**Response Schema:**
```json
{
  "summary": {
    "total_changes": 47,
    "critical_changes": 3,
    "suspicious_changes": 8,
    "benign_changes": 36
  },
  "by_category": {
    "processes": {
      "added": [...],
      "removed": [...],
      "modified": [...]
    },
    "network": {
      "new_connections": [...],
      "closed_connections": [...]
    },
    "files": {
      "created": [...],
      "deleted": [...],
      "modified": [...]
    },
    "users": {...},
    "kernel_modules": {...},
    "services": {...},
    "packages": {...}
  },
  "risk_indicators": [
    {
      "type": "new_suid_binary",
      "path": "/tmp/.hidden/backdoor",
      "severity": "CRITICAL",
      "description": "New SUID binary detected in temporary directory"
    }
  ]
}
```

---

### 3.4 Settings Panel

**Purpose:** Configure Orin agent behavior, notification settings, retention policies, and AI integration.

#### Configuration Fields

| Field | ID | Type | Default | Validation |
|-------|----|------|---------|------------|
| Telemetry Collection Interval | `#cfg-interval` | Number (seconds) | 300 | 60-86400 |
| Alert Notification Webhook | `#cfg-webhook` | Text (URL) | empty | Valid HTTPS URL |
| Max Historical Snapshots | `#cfg-max-snapshots` | Number | 50 | 1-1000 |
| Log Level | `#cfg-log-level` | Select | INFO | INFO/DEBUG/WARN/ERROR |
| Data Retention Period | `#cfg-retention` | Number (days) | 90 | 1-3650 |
| AI Triage API Endpoint | `#cfg-ai-api` | Text (URL) | empty | Valid HTTP/HTTPS URL |

#### Configuration Functions

##### `loadConfig()`

**Purpose:** Fetches current configuration from backend and populates form fields.

**Implementation Required:**
```javascript
async function loadConfig() {
    try {
        const response = await fetch('/api/config', {
            headers: { 'X-API-Key': getApiKey() }
        });
        const config = await response.json();

        document.getElementById('cfg-interval').value = config.collection_interval || 300;
        document.getElementById('cfg-webhook').value = config.webhook_url || '';
        document.getElementById('cfg-max-snapshots').value = config.max_snapshots || 50;
        document.getElementById('cfg-log-level').value = config.log_level || 'INFO';
        document.getElementById('cfg-retention').value = config.retention_days || 90;
        document.getElementById('cfg-ai-api').value = config.ai_api_endpoint || '';

        showToast('Configuration loaded', 'info');
    } catch (error) {
        showToast('Failed to load config: ' + error.message, 'error');
    }
}
```

##### `saveConfig()`

**Purpose:** Validates and saves configuration changes to backend.

**Current Implementation (Enhanced):**
```javascript
async function saveConfig() {
    const config = {
        collection_interval: parseInt(document.getElementById('cfg-interval').value),
        webhook_url: document.getElementById('cfg-webhook').value.trim(),
        max_snapshots: parseInt(document.getElementById('cfg-max-snapshots').value),
        log_level: document.getElementById('cfg-log-level').value,
        retention_days: parseInt(document.getElementById('cfg-retention').value),
        ai_api_endpoint: document.getElementById('cfg-ai-api').value.trim()
    };

    // Validation
    if (config.collection_interval < 60 || config.collection_interval > 86400) {
        showToast('Collection interval must be between 60 and 86400 seconds', 'error');
        return;
    }

    if (config.webhook_url && !config.webhook_url.startsWith('https://')) {
        showToast('Webhook URL must use HTTPS', 'error');
        return;
    }

    try {
        const response = await fetch('/api/config', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': getApiKey()
            },
            body: JSON.stringify(config)
        });

        if (response.ok) {
            showToast('Configuration saved successfully', 'success');
        } else {
            const error = await response.json();
            showToast('Save failed: ' + error.message, 'error');
        }
    } catch (error) {
        showToast('Save failed: ' + error.message, 'error');
    }
}
```

**Backend Endpoint:**
- `GET /api/config` - Retrieve current configuration
- `PUT /api/config` - Update configuration

---

### 3.5 AI Triage Briefing

**Purpose:** Generate AI-powered executive summaries of current security findings for rapid incident comprehension and decision-making.

#### UI Components

| Component | ID | Function |
|-----------|----|--------|
| Context Snapshot | `#ai-context-snapshot` | Select specific snapshot for analysis |
| Generate Button | `.btn` (Generate Executive Summary) | Request AI briefing |
| Output Container | `#ai-output-content` | Display AI-generated report |

#### AI Integration Workflow

1. User optionally selects a specific snapshot (defaults to latest findings)
2. Click "Generate Executive Summary"
3. Backend aggregates current alerts, telemetry anomalies, and risk indicators
4. Structured prompt sent to configured AI endpoint
5. Markdown-formatted briefing returned and rendered

##### `requestAIInsight()`

**Implementation Required:**
```javascript
async function requestAIInsight() {
    const snapshotId = document.getElementById('ai-context-snapshot').value;

    // Show loading state
    document.getElementById('ai-output-content').innerHTML = `
        <div class="secured-state">
            <span data-icon="loader" class="spinner" data-size="28"></span>
            <div class="secured-title">Generating AI Briefing</div>
            <div class="secured-desc">Analyzing forensic data and composing executive summary...</div>
        </div>
    `;

    try {
        const response = await fetch('/api/ai/triage', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': getApiKey()
            },
            body: JSON.stringify({
                snapshot_id: snapshotId || null,
                include_mitre_mapping: true,
                include_remediation_steps: true
            })
        });

        const data = await response.json();
        renderAIBriefing(data.briefing);
    } catch (error) {
        showToast('AI analysis failed: ' + error.message, 'error');
    }
}
```

**Backend Endpoint:** `POST /api/ai/triage`

**Request Body:**
```json
{
  "snapshot_id": "snap_abc123",
  "include_mitre_mapping": true,
  "include_remediation_steps": true
}
```

**Response Schema:**
```json
{
  "briefing": "# Executive Security Briefing\n\n## Threat Summary\nDetected 3 critical and 8 high-severity events...\n\n## Key Findings\n- Privilege escalation attempt via sudo abuse\n- Suspicious outbound connection to known C2 IP\n- New kernel module loaded without signature\n\n## MITRE ATT&CK Mapping\n- T1548.003: Sudo and Sudo Caching Abuse\n- T1071.001: Application Layer Protocol: Web Protocols\n\n## Recommended Actions\n1. Isolate affected host immediately\n2. Preserve forensic evidence\n3. Review user 'john' activity...",
  "generated_at": "2026-06-10T15:45:00Z",
  "model_used": "local-llama-3.1",
  "confidence_score": 0.87
}
```

**Markdown Rendering:**
```javascript
function renderAIBriefing(markdownText) {
    // Simple markdown-to-HTML conversion
    let html = markdownText
        .replace(/^# (.*$)/gim, '<h1>$1</h1>')
        .replace(/^## (.*$)/gim, '<h2>$1</h2>')
        .replace(/^### (.*$)/gim, '<h3>$1</h3>')
        .replace(/^\- (.*$)/gim, '<li>$1</li>')
        .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
        .replace(/\`(.*?)\`/gim, '<code>$1</code>');

    // Wrap lists
    html = html.replace(/(<li>.*<\/li>)/gis, '<ul>$1</ul>');

    document.getElementById('ai-output-content').innerHTML =
        `<div class="ai-briefing-md">${html}</div>`;
}
```

---

## Left Sidebar Functions

### 4.1 Risk Assessment Gauge

**Purpose:** Visual representation of overall system security posture based on aggregated alert severity and anomaly detection.

#### Components

| Element | ID | Description |
|---------|----|-------------|
| Gauge SVG | `#gauge-risk-fill` | Animated circular progress indicator |
| Score Value | `#gauge-risk-val` | Numeric risk score (0-100) |
| Status Pill | `#status-pill` | Text status indicator |
| Stats Grid | `.stats-grid` | Four key metrics display |

#### Risk Score Calculation

**Formula:**
```
risk_score = MIN(100, SUM(alert_severity_weights) + anomaly_bonus)

Where:
- CRITICAL alerts: +25 points each
- HIGH alerts: +15 points each
- MEDIUM alerts: +8 points each
- LOW alerts: +2 points each
- Anomaly bonus: +10 if >50% deviation from baseline
```

**Status Thresholds:**
| Score Range | Status | Color |
|-------------|--------|-------|
| 0 | Healthy | Green (#10B981) |
| 1-39 | Monitor | Blue (#38BDF8) |
| 40-59 | Medium Risk | Orange (#F59E0B) |
| 60-79 | High Risk | Orange (#F59E0B) |
| 80-100 | Critical | Red (#EF4444) |

##### `updateRiskGauge(score)`

**Current Implementation (Functional):**
```javascript
function updateRiskGauge(score) {
    const fillElement = document.getElementById('gauge-risk-fill');
    const textElement = document.getElementById('gauge-risk-val');
    const statusPill = document.getElementById('status-pill');

    let normalizedScore = Math.min(Math.max(score, 0), 100);
    textElement.textContent = Math.round(normalizedScore);

    const circumference = 2 * Math.PI * 60; // r=60
    const offset = circumference - (normalizedScore / 100) * circumference;
    fillElement.style.strokeDashoffset = offset;

    if (normalizedScore >= 80) {
        fillElement.style.stroke = 'var(--critical)';
        statusPill.textContent = 'Critical';
        statusPill.style.background = 'rgba(239, 68, 68, 0.1)';
        statusPill.style.color = 'var(--critical)';
        statusPill.style.borderColor = 'rgba(239, 68, 68, 0.2)';
    } else if (normalizedScore >= 60) {
        fillElement.style.stroke = 'var(--warning)';
        statusPill.textContent = 'High Risk';
        statusPill.style.background = 'rgba(245, 158, 11, 0.1)';
        statusPill.style.color = 'var(--warning)';
        statusPill.style.borderColor = 'rgba(245, 158, 11, 0.2)';
    } else if (normalizedScore >= 40) {
        fillElement.style.stroke = 'var(--warning)';
        statusPill.textContent = 'Medium Risk';
        statusPill.style.background = 'rgba(245, 158, 11, 0.1)';
        statusPill.style.color = 'var(--warning)';
        statusPill.style.borderColor = 'rgba(245, 158, 11, 0.2)';
    } else if (normalizedScore > 0) {
        fillElement.style.stroke = 'var(--primary)';
        statusPill.textContent = 'Monitor';
        statusPill.style.background = 'rgba(56, 189, 248, 0.1)';
        statusPill.style.color = 'var(--primary)';
        statusPill.style.borderColor = 'rgba(56, 189, 248, 0.2)';
    } else {
        fillElement.style.stroke = 'var(--success)';
        statusPill.textContent = 'Healthy';
    }
}
```

**Backend Integration (Required):**
```javascript
async function refreshRiskAssessment() {
    try {
        const response = await fetch('/api/risk/score', {
            headers: { 'X-API-Key': getApiKey() }
        });
        const data = await response.json();

        updateRiskGauge(data.risk_score);
        document.getElementById('stat-snapshots').textContent = data.snapshots_count;
        document.getElementById('stat-alerts').textContent = data.active_alerts;
        document.getElementById('stat-modules').textContent = data.kernel_modules;
        document.getElementById('stat-users').textContent = data.user_count;
    } catch (error) {
        console.error('Failed to refresh risk assessment:', error);
    }
}
```

---

### 4.2 Recent Snapshots Ledger

**Purpose:** Quick-access list of most recent forensic snapshot captures for rapid navigation.

#### UI Component
- Container: `#recent-snapshots-list`
- Max Height: 250px with scrollable overflow

**Implementation Required:**
```javascript
async function loadRecentSnapshots() {
    try {
        const response = await fetch('/api/snapshots/recent?limit=10', {
            headers: { 'X-API-Key': getApiKey() }
        });
        const data = await response.json();

        const container = document.getElementById('recent-snapshots-list');
        container.innerHTML = '';

        if (data.snapshots.length === 0) {
            container.innerHTML = '<div style="text-align: center; color: var(--text-muted); font-size: 0.8rem;">No snapshots available</div>';
            return;
        }

        data.snapshots.forEach(snap => {
            const item = document.createElement('div');
            item.className = 'timeline-item';
            item.style.cursor = 'pointer';
            item.onclick = () => {
                document.getElementById('telemetry-snapshot-select').value = snap.id;
                switchTab('pane-telemetry');
                loadTelemetry(snap.id);
            };

            item.innerHTML = `
                <div style="flex: 1;">
                    <div style="font-weight: 600; font-size: 0.85rem;">${snap.hostname}</div>
                    <div style="font-size: 0.75rem; color: var(--text-secondary);">${snap.timestamp}</div>
                </div>
                <span class="badge ${getSeverityBadge(snap.risk_level)}">${snap.risk_level}</span>
            `;

            container.appendChild(item);
        });
    } catch (error) {
        document.getElementById('recent-snapshots-list').innerHTML =
            '<div style="text-align: center; color: var(--critical); font-size: 0.8rem;">Failed to load snapshots</div>';
    }
}
```

---

### 4.3 Baseline Administration

**Purpose:** Manage trusted baseline allowlists for users and kernel modules to reduce false positives.

#### Functions

##### `triggerBaselineRefresh()`

**Purpose:** Force re-calculation of baseline statistics.

**Current Implementation (Placeholder):**
```javascript
function triggerBaselineRefresh() {
    showToast("Refreshing baseline ledger...", "info");
}
```

**Enhanced Implementation:**
```javascript
async function triggerBaselineRefresh() {
    try {
        const response = await fetch('/api/baseline/refresh', {
            method: 'POST',
            headers: { 'X-API-Key': getApiKey() }
        });

        if (response.ok) {
            showToast('Baseline ledger refreshed', 'success');
            loadRecentSnapshots();
        } else {
            showToast('Refresh failed', 'error');
        }
    } catch (error) {
        showToast('Refresh failed: ' + error.message, 'error');
    }
}
```

##### `addToAllowlist(type, inputId)`

**Purpose:** Add users or kernel modules to trusted allowlist.

**Current Implementation (Placeholder):**
```javascript
function addToAllowlist(type, inputId) {
    const input = document.getElementById(inputId);
    if (input.value.trim()) {
        showToast(`Added ${type} '${input.value}' to allowlist.`, "success");
        input.value = '';
    } else {
        showToast("Please enter a valid value.", "error");
    }
}
```

**Enhanced Implementation:**
```javascript
async function addToAllowlist(type, inputId) {
    const input = document.getElementById(inputId);
    const value = input.value.trim();

    if (!value) {
        showToast("Please enter a valid value.", "error");
        return;
    }

    try {
        const response = await fetch('/api/baseline/allowlist', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': getApiKey()
            },
            body: JSON.stringify({
                type: type, // 'user' or 'module'
                value: value
            })
        });

        if (response.ok) {
            showToast(`Added ${type} '${value}' to allowlist`, "success");
            input.value = '';
        } else {
            const error = await response.json();
            showToast(`Add failed: ${error.message}`, "error");
        }
    } catch (error) {
        showToast(`Add failed: ${error.message}`, "error");
    }
}
```

**Backend Endpoint:** `POST /api/baseline/allowlist`

---

### 4.4 Fleet Dashboard Overview

**Purpose:** Multi-host visibility for fleet-wide security monitoring (Hub Server mode).

#### UI Component
- Container: `#fleet-list`

**Implementation Required:**
```javascript
async function loadFleetOverview() {
    try {
        const response = await fetch('/api/hosts', {
            headers: { 'X-API-Key': getApiKey() }
        });
        const data = await response.json();

        const container = document.getElementById('fleet-list');
        container.innerHTML = '';

        if (data.hosts.length === 0) {
            container.innerHTML = '<div style="text-align: center; color: var(--text-muted); font-size: 0.8rem;">No hosts registered</div>';
            return;
        }

        data.hosts.forEach(host => {
            const item = document.createElement('div');
            item.className = 'timeline-item';
            item.style.cursor = 'pointer';
            item.onclick = () => switchToHost(host.id);

            const statusColor = host.status === 'active' ? 'var(--success)' : 'var(--text-muted)';
            const lastSeen = new Date(host.last_heartbeat).toLocaleString();

            item.innerHTML = `
                <div style="flex: 1;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="width: 8px; height: 8px; border-radius: 50%; background: ${statusColor};"></span>
                        <span style="font-weight: 600; font-size: 0.85rem;">${host.hostname}</span>
                    </div>
                    <div style="font-size: 0.75rem; color: var(--text-secondary);">
                        ${host.ip_address} • Last seen: ${lastSeen}
                    </div>
                </div>
                <span class="badge ${getSeverityBadge(host.risk_level)}">${host.risk_level || 'N/A'}</span>
            `;

            container.appendChild(item);
        });

        // Populate host filter dropdown in alert feed
        populateHostFilter(data.hosts);
    } catch (error) {
        document.getElementById('fleet-list').innerHTML =
            '<div style="text-align: center; color: var(--critical); font-size: 0.8rem;">Failed to load fleet</div>';
    }
}

function populateHostFilter(hosts) {
    const select = document.getElementById('filter-host');
    select.innerHTML = '<option value="">All Hosts</option>';

    hosts.forEach(host => {
        const option = document.createElement('option');
        option.value = host.id;
        option.textContent = host.hostname;
        select.appendChild(option);
    });
}
```

---

### 4.5 Remote SSH Scan Configuration

**Purpose:** Initiate forensic scans on remote hosts via SSH for distributed deployment scenarios.

#### Form Fields

| Field | ID | Type | Example |
|-------|----|------|---------|
| Target Host | `#scan-host` | Text | 192.168.1.50 |
| SSH Username | `#scan-user` | Text | root |
| SSH Port | `#scan-port` | Number | 22 |
| Private Key Path | `#scan-key` | Text | /root/.ssh/id_rsa |

#### Action Buttons

| Button | Text | Function |
|--------|------|----------|
| Init Baseline | `Init Baseline` | Create initial trusted baseline on remote host |
| Scan Host | `Scan Host` | Perform one-time forensic scan |

##### `triggerRemoteScan(isBaseline)`

**Current Implementation (Placeholder):**
```javascript
function triggerRemoteScan(isBaseline) {
    const action = isBaseline ? "initializing baseline" : "scanning";
    showToast(`Initiating remote SSH host ${action}...`, "info");
}
```

**Enhanced Implementation:**
```javascript
async function triggerRemoteScan(isBaseline) {
    const host = document.getElementById('scan-host').value.trim();
    const username = document.getElementById('scan-user').value.trim();
    const port = document.getElementById('scan-port').value;
    const keyPath = document.getElementById('scan-key').value.trim();

    // Validation
    if (!host || !username) {
        showToast('Host and username are required', 'error');
        return;
    }

    const payload = {
        target_host: host,
        ssh_username: username,
        ssh_port: parseInt(port) || 22,
        private_key_path: keyPath || null,
        operation: isBaseline ? 'init_baseline' : 'scan'
    };

    try {
        const response = await fetch('/api/scan/remote', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': getApiKey()
            },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            const data = await response.json();
            showToast(`Remote ${payload.operation} initiated (Task ID: ${data.task_id})`, 'success');

            // Clear form
            document.getElementById('scan-host').value = '';
            document.getElementById('scan-key').value = '';
        } else {
            const error = await response.json();
            showToast(`Scan failed: ${error.message}`, 'error');
        }
    } catch (error) {
        showToast(`Scan failed: ${error.message}`, 'error');
    }
}
```

**Backend Endpoint:** `POST /api/scan/remote`

---

## API Endpoint Reference

### Authentication

All API endpoints (except `/health` and `/`) require authentication via:
- `X-API-Key` header, or
- `Authorization: Bearer <token>` header

### Endpoints Summary

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/health` | Health check | No |
| GET | `/` | Serve dashboard | No |
| GET | `/api/status` | Hub status for tenant | Yes |
| GET | `/api/hosts` | List registered hosts | Yes |
| GET | `/api/stats` | Tenant statistics | Yes |
| GET | `/api/vault/info` | Vault metadata | Yes |
| GET | `/api/export/{type}` | Export forensic data | Yes |
| POST | `/api/register` | Register new host | Yes |
| POST | `/api/heartbeat` | Host heartbeat | Yes |
| POST | `/api/import` | Import forensic data | Yes |
| POST | `/api/upload` | Upload snapshot archive | Yes |
| POST | `/api/tenants` | Create tenant | No |
| GET | `/api/alerts` | Query security alerts | Yes |
| GET | `/api/snapshots` | List snapshots | Yes |
| GET | `/api/telemetry/{type}` | Get telemetry data | Yes |
| POST | `/api/diff` | Compare snapshots | Yes |
| GET | `/api/config` | Get configuration | Yes |
| PUT | `/api/config` | Update configuration | Yes |
| POST | `/api/ai/triage` | Request AI briefing | Yes |
| GET | `/api/risk/score` | Calculate risk score | Yes |
| POST | `/api/baseline/refresh` | Refresh baseline | Yes |
| POST | `/api/baseline/allowlist` | Add to allowlist | Yes |
| POST | `/api/scan/remote` | Initiate remote scan | Yes |

---

## JavaScript Function Reference

### Global Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `switchTab(tabId)` | `tabId: string` | void | Switch active pane |
| `triggerOnDemandCollect()` | none | void | Trigger telemetry collection |
| `triggerBaselineRefresh()` | none | void | Refresh baseline ledger |
| `addToAllowlist(type, inputId)` | `type: string`, `inputId: string` | void | Add to allowlist |
| `triggerRemoteScan(isBaseline)` | `isBaseline: boolean` | void | Initiate remote scan |
| `loadAlertsLedger()` | none | void | Load alert feed |
| `setSeverityFilter(level)` | `level: string` | void | Set severity filter |
| `loadTelemetry(snapshotId)` | `snapshotId: string` | void | Load telemetry data |
| `switchTelemetryTab(tabId)` | `tabId: string` | void | Switch telemetry tab |
| `performDiffAnalysis()` | none | void | Run diff analysis |
| `loadConfig()` | none | void | Load configuration |
| `saveConfig()` | none | void | Save configuration |
| `requestAIInsight()` | none | void | Request AI briefing |
| `closeModal()` | none | void | Close detail modal |
| `showToast(message, type)` | `message: string`, `type: string` | void | Show notification |
| `updateRiskGauge(score)` | `score: number` | void | Update risk gauge |

### Utility Functions (Required Implementation)

| Function | Purpose |
|----------|---------|
| `getApiKey()` | Retrieve stored API key from localStorage or cookie |
| `renderAlertFeed(alerts)` | Render alert list HTML |
| `renderTelemetryTable(type, records)` | Render telemetry table |
| `renderDiffResults(data)` | Render diff analysis results |
| `renderAIBriefing(markdown)` | Render AI briefing markdown |
| `getSeverityBadge(level)` | Get CSS class for severity badge |
| `populateSnapshotDropdown()` | Populate snapshot selectors |
| `switchToHost(hostId)` | Switch context to different host |

---

## User Workflows

### Workflow 1: Initial Dashboard Setup

1. **Access Dashboard:** Navigate to `https://<hub-ip>:8443/`
2. **Authentication:** Enter API key (provided during tenant creation)
3. **Context Verification:** Confirm host, OS, and vault badges display correctly
4. **Baseline Check:** Verify risk gauge shows initial assessment
5. **First Snapshot:** Click "Capture Telemetry" to initiate first collection

### Workflow 2: Incident Response

1. **Alert Discovery:** View Posture pane for new CRITICAL/HIGH alerts
2. **Filtering:** Apply severity filter and host filter as needed
3. **Detail Review:** Click alert to open modal with full context
4. **Telemetry Dive:** Switch to Telemetry Explorer, select relevant snapshot
5. **Process Analysis:** Review Processes tab for suspicious PIDs
6. **Network Correlation:** Check Network Connections for C2 communication
7. **Timeline Comparison:** Use Timeline Delta to compare pre/post incident
8. **AI Summary:** Generate AI Triage briefing for executive reporting
9. **Remediation:** Document actions taken, mark alerts as resolved

### Workflow 3: Baseline Management

1. **Initial Baseline:** After clean OS install, click "Init Baseline" via SSH scan
2. **Allowlist Population:** Add known-good users and kernel modules
3. **Periodic Refresh:** Click "Refresh Baseline Ledger" monthly
4. **Drift Detection:** Monitor Timeline Delta for unauthorized changes
5. **Investigation:** Investigate any unexpected drift indicators

### Workflow 4: Fleet Monitoring

1. **Fleet Overview:** Review left sidebar fleet list for host statuses
2. **Risk Aggregation:** Identify hosts with elevated risk scores
3. **Drill-Down:** Click host to switch context
4. **Comparative Analysis:** Compare risk profiles across hosts
5. **Bulk Operations:** Use remote scan for fleet-wide assessments

---

## Security Considerations

### Authentication & Authorization

- **API Key Rotation:** Keys should be rotated every 90 days
- **Multi-Tenant Isolation:** Tenants cannot access other tenants' data
- **Session Timeout:** Implement 30-minute idle timeout for dashboard sessions

### CSP Headers

The dashboard enforces strict Content Security Policy:
```
default-src 'self'
script-src 'self' 'unsafe-inline'
style-src 'self' 'unsafe-inline'
font-src 'self'
img-src 'self' data:
connect-src 'self'
frame-ancestors 'none'
base-uri 'self'
form-action 'self'
svg-src 'self' data:
```

### Data Protection

- All API communications should use TLS 1.3
- Sensitive data (credentials, keys) never transmitted to frontend
- Audit logs maintained for all dashboard interactions

---

## Troubleshooting

### Common Issues

| Issue | Symptom | Resolution |
|-------|---------|------------|
| Dashboard not loading | Blank page | Check browser console for CSP violations |
| API calls failing | Toast errors | Verify API key validity and network connectivity |
| Risk gauge stuck at 0 | No updates | Check backend `/api/risk/score` endpoint |
| Snapshot dropdown empty | No options | Ensure snapshots exist in database |
| AI briefing timeout | Loading spinner forever | Verify AI API endpoint accessibility |

### Debug Mode

Enable debug logging in browser console:
```javascript
localStorage.setItem('orin_debug', 'true');
location.reload();
```

### Backend Logs

Check hub server logs for API errors:
```bash
journalctl -u orin-hub -f
# or
tail -f /var/log/orin/hub_server.log
```

---

## Appendix A: CSS Variable Reference

| Variable | Default Value | Usage |
|----------|---------------|-------|
| `--bg-primary` | #0A0D1A | Main background |
| `--bg-secondary` | #0E1225 | Secondary backgrounds |
| `--bg-card` | #121832 | Card backgrounds |
| `--text-primary` | #F8FAFC | Primary text |
| `--text-secondary` | #8E9BAE | Secondary text |
| `--primary` | #38BDF8 | Primary accent color |
| `--success` | #10B981 | Success states |
| `--warning` | #F59E0B | Warning states |
| `--critical` | #EF4444 | Error/critical states |

---

## Appendix B: Icon Reference

Icons use Lucide icon names via `data-icon` attribute:

| Icon Name | Usage Context |
|-----------|---------------|
| `shield-alert` | Logo, security contexts |
| `alert-triangle` | Warnings, alerts |
| `database` | Telemetry, data |
| `git-compare` | Diff analysis |
| `settings` | Configuration |
| `bot` | AI features |
| `refresh-cw` | Refresh actions |
| `check-circle` | Success toasts |
| `alert-circle` | Error toasts |
| `info` | Info toasts |
| `loader` | Loading spinners |
| `x` | Close buttons |

---

**Document Version:** 1.0
**Last Updated:** June 10, 2026
**Maintainer:** Orin Development Team