# SSH Remote Scanning Guide

Orin's agentless scanner (`orin scan`) connects to remote Linux hosts over SSH and runs a
self-contained collection script (Python, with a pure-Bash fallback). This guide covers
connection requirements, security configuration, and rate limiting.

---

## Connectivity Requirements

- An OpenSSH-compatible daemon on the target host, default port 22.
- SSH key authentication (recommended) or an `ssh-agent` with a loaded key. Password auth
  is not handled directly — use `sshpass` or configure key-based auth.

## Privilege Levels

| Data category | Non-root | Root |
|---|---|---|
| Process list | Own processes only | Full, with cmdline/exe paths |
| Listening ports / connections | Yes | Yes, with accurate socket→PID mapping |
| Promiscuous interfaces | Yes | Yes |
| User accounts (`/etc/passwd`) | Yes | Yes |
| SSH keys | Own `~/.ssh` only | All users' keys |
| Crontabs | Own + `/etc/crontab` | All user crontabs |
| SUID/SGID binaries | Yes (via `find`) | Yes |
| File integrity hashes | Readable files only | All configured paths |
| Auth logs | Often restricted | Full access |
| Kernel modules / `kallsyms` | Often restricted | Full access |

For complete telemetry — including kernel symbol rootkit analysis, full auth log review,
and accurate socket-to-process mapping — run as root or via passwordless sudo:

```bash
ssh -i /path/to/key root@host
```

If direct root login is disabled, grant the scanning account passwordless sudo on the
target:

```
# /etc/sudoers
orin_scanner ALL=(ALL) NOPASSWD: /bin/bash
```

## Agent Requirements

**Python agent (primary)** — needs only Python 3.6+ standard library
(`os, sys, json, stat, errno, struct, socket, re, hashlib, pwd, grp, platform, pathlib, datetime`).
Verify with:

```bash
ssh user@host "python3 -c 'import os,sys,json,stat,errno,struct,socket,re,hashlib,pwd,grp,platform; print(\"OK\")'"
```

**Bash agent (fallback)** — used when Python is unavailable. Needs Bash 4.0+ and common
coreutils (`hostname`, `uname`, `cat`, `readlink`, `stat`, `find`, `awk`, `grep`, `tail`,
a SHA-256/MD5 tool, `ps`, `ss`/`netstat`, `ip`, `lsmod`), each with graceful fallbacks if
missing. Suitable for routers, Alpine/distroless containers, and embedded systems.

### Platform compatibility

| System | Python agent | Bash agent |
|---|---|---|
| Ubuntu / Debian / RHEL / Fedora / Alpine | ✅ | ✅ |
| BusyBox / OpenWrt / embedded | ❌ | ✅ |
| Docker containers | ✅ | ✅ (depends on base image) |
| macOS / Windows | ❌ | ❌ — not supported |

Known limitations: SELinux/AppArmor may restrict `/proc` access even for root; container
namespaces limit host process visibility; kernels older than 3.x may have incomplete
`/proc` interfaces.

---

## Host Key Verification

Configure under `ssh` in `orin_config.json`:

```json
{
  "ssh": {
    "strict_host_key_checking": "ask",
    "known_hosts_file": null,
    "connection_timeout": 30,
    "max_retries": 3
  }
}
```

| Option | Default | Description |
|---|---|---|
| `strict_host_key_checking` | `"ask"` | `"yes"` (strict, requires pre-populated known_hosts), `"accept-new"` (auto-trust new hosts), `"ask"` (interactive), `"no"` (no verification — isolated/CI use only) |
| `known_hosts_file` | `null` | Custom known_hosts path; `null` uses `~/.ssh/known_hosts` |
| `connection_timeout` | `30` | Seconds before connection attempt times out |
| `max_retries` | `3` | Maps to SSH `ConnectionAttempts` |

**Production:** use `"yes"` with a centrally managed `known_hosts_file`, populated via
`ssh-keyscan -H target >> /etc/orin/known_hosts`.

**Development:** `"accept-new"` trusts new hosts on first connect and remembers them.

**`"no"`** disables host key checking entirely. This is vulnerable to MITM and should
only be used on isolated/trusted networks or ephemeral CI environments — never in
production.

---

## Rate Limiting

To avoid overwhelming targets, triggering IDS alerts, or appearing as a DoS pattern,
configure rate limiting under `ssh.rate_limit`:

```json
{
  "ssh": {
    "rate_limit": {
      "enabled": true,
      "max_concurrent_connections": 5,
      "delay_between_scans": 1.0,
      "max_scans_per_minute": 10,
      "backoff_factor": 2.0,
      "max_backoff_delay": 60.0
    }
  }
}
```

| Setting | Description |
|---|---|
| `max_concurrent_connections` | Semaphore-bounded concurrent SSH connections |
| `delay_between_scans` | Minimum seconds between any two scan initiations |
| `max_scans_per_minute` | Per-host scan rate cap |
| `backoff_factor` / `max_backoff_delay` | Exponential backoff on connection failures, reset on success |

### Example profiles

**Production (conservative):**
```json
{ "max_concurrent_connections": 3, "delay_between_scans": 2.0, "max_scans_per_minute": 5, "backoff_factor": 2.0, "max_backoff_delay": 120.0 }
```

**Lab (aggressive):**
```json
{ "max_concurrent_connections": 10, "delay_between_scans": 0.1, "max_scans_per_minute": 60, "backoff_factor": 1.5, "max_backoff_delay": 10.0 }
```

**Disabled (trusted internal network only):**
```json
{ "enabled": false }
```

All shared state in the rate limiter is thread-safe and supports independent per-host
tracking.

---

## Best Practices

- Use a dedicated scanning account with minimal privileges where possible.
- Constrain SSH keys: `command="...",no-port-forwarding,no-X11-forwarding,no-agent-forwarding`.
- Enable SSH access logging on targets.
- Rotate scanning keys periodically.
- Scan from a dedicated management network segment.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Permission denied` | Check key permissions (`chmod 600`), target shell access, sudo config |
| `python3: command not found` | Scanner falls back to Bash agent automatically; if both fail, install Python or ensure Bash 4+ |
| Incomplete telemetry | Usually a privilege issue — connect as root, check SELinux/AppArmor |
| JSON parse errors | Check stderr on the target; verify Bash version supports required features |

Debug a connection directly:
```bash
ssh -vvv -i /path/to/key user@host
ssh user@host "cat /proc/net/tcp | head -5"
```