# SSH Requirements for Orin Remote Scanner

This document details the exact SSH requirements, user privileges, and available commands needed for the Orin remote security scanner to function correctly.

## Overview

Orin uses an agentless SSH-based scanning approach. It connects to remote Linux hosts via SSH and executes a self-contained telemetry collection script (Python with Bash fallback) that gathers security-relevant system information.

## SSH Connection Requirements

### Basic Connectivity

- **SSH Server**: OpenSSH or compatible SSH daemon must be running on the target host
- **Port**: Default port 22 (configurable)
- **Protocol**: SSH-2 recommended
- **Host Key Verification**: Disabled by default (`StrictHostKeyChecking=no`) for automation purposes

### Authentication Methods

The scanner supports the following authentication methods:

1. **SSH Key Authentication** (Recommended)
   ```bash
   ssh -i /path/to/private_key user@host
   ```
   - Private key must be in PEM or OpenSSH format
   - Key should not require a passphrase for automated scans, or passphrase must be loaded in ssh-agent

2. **SSH Agent Forwarding**
   - Keys loaded in `ssh-agent` will be used automatically
   - Ensure `SSH_AUTH_SOCK` environment variable is set

3. **Password Authentication** (Not directly supported)
   - For password-based auth, use `sshpass` wrapper or configure key-based auth

## User Privilege Requirements

### Minimum Privileges (Non-Root User)

A standard unprivileged user account can gather **basic telemetry**:

| Data Category | Requires Root? | Notes |
|--------------|----------------|-------|
| Process List | No | Can read `/proc/[pid]/` for own processes; limited visibility into others |
| Listening Ports | No | Can read `/proc/net/tcp`, `/proc/net/udp` |
| Network Connections | No | Established connections visible without root |
| Promiscuous Interfaces | No | Can read `/sys/class/net/*/flags` |
| User Accounts | No | `/etc/passwd` is world-readable |
| SSH Keys | Partial | Can only read keys in user's home directory |
| Crontabs | Partial | Can read `/etc/crontab` and own crontab |
| SUID Binaries | No | Can use `find` to locate SUID files |
| File Integrity (Hashes) | No | Can hash readable files |
| Auth Logs | Partial | May not have read access to `/var/log/auth.log` |

**Limitations without root:**
- Cannot see all process details (cmdline, exe links may be restricted)
- Cannot associate network sockets with processes accurately
- Cannot read `/etc/shadow` or other sensitive files
- Limited visibility into other users' SSH keys and crontabs
- Cannot read kernel modules list (`/proc/modules`) on some systems
- Cannot access `/proc/kallsyms` for kernel symbol analysis

### Recommended Privileges (Root User)

For **complete telemetry coverage**, root access is strongly recommended:

```bash
ssh -i /path/to/key root@host
# OR
ssh -i /path/to/key sudo_user@host sudo bash -s
```

**Benefits of root access:**
- Full process visibility including all cmdlines and executable paths
- Accurate socket-to-process mapping via `/proc/[pid]/fd/`
- Access to all user SSH keys and crontabs
- Kernel module enumeration
- Kernel symbol analysis for rootkit detection
- Complete auth log access
- Ability to detect deleted binaries and file integrity across all paths
- eBPF program enumeration
- Special file descriptor analysis

### Using Sudo for Privilege Escalation

If direct root login is disabled, configure passwordless sudo for the scan command:

1. Add to `/etc/sudoers` on target host:
   ```
   orin_scanner ALL=(ALL) NOPASSWD: /bin/bash
   ```

2. Connect with sudo wrapper:
   ```bash
   ssh -i /path/to/key orin_scanner@host "sudo bash -s"
   ```

## Required Commands and Utilities

### Python Agent (Primary Method)

The Python agent requires **only Python 3 standard library** - no external dependencies.

**Minimum Python Version**: 3.6+

**Required Python Modules** (all part of standard library):
- `os`, `sys`, `json`
- `stat`, `errno`, `struct`
- `socket`, `re`
- `hashlib`
- `pwd`, `grp`
- `platform`
- `pathlib`
- `datetime`

**Verification Command**:
```bash
ssh user@host "python3 --version && python3 -c 'import os, sys, json, stat, errno, struct, socket, re, hashlib, pwd, grp, platform; print(\"OK\")'"
```

### Bash Agent (Fallback Method)

When Python is unavailable, the scanner falls back to a pure Bash script.

**Required Shell**: Bash 4.0+ (for associative arrays and regex features)

**Required External Commands** (with fallbacks):

| Command | Purpose | Fallback if Missing |
|---------|---------|---------------------|
| `hostname` | Get system hostname | Uses "unknown_host" |
| `uname` | Get OS information | Uses "Linux" |
| `cat` | Read files | Essential (busybox usually has it) |
| `readlink` | Resolve symlinks | Limited functionality |
| `stat` | Get file permissions/mtime | Uses defaults |
| `find` | Locate SUID binaries | Skips SUID detection |
| `awk` | Text processing | Limited parsing capability |
| `grep` | Pattern matching | Reduced filtering |
| `tail` | Read log files | Skips auth logs |
| `sha256sum` or `shasum` or `md5sum` | File hashing | No file integrity data |
| `ps` | Process listing (fallback) | Uses /proc directly |
| `ss` or `netstat` | Network connections (fallback) | Uses /proc/net directly |
| `ip` | Interface info (fallback) | Uses /sys/class/net |
| `lsmod` | Kernel modules (fallback) | Uses /proc/modules |

**Minimal System Compatibility**:
The Bash agent is designed to work on:
- Routers (OpenWrt, DD-WRT)
- Stripped-down containers (Alpine, distroless)
- Old/embedded systems
- Systems without Python installed

**Verification Command**:
```bash
ssh user@host "bash --version && echo 'OK'"
```

## Filesystem Access Requirements

### Read Access Needed

The scanner requires read access to the following paths:

**Critical System Files**:
```
/etc/passwd          # User accounts (world-readable)
/etc/shadow          # Password hashes (root only)
/etc/group           # Group memberships (world-readable)
/etc/ssh/sshd_config # SSH configuration (root only)
/etc/sudoers         # Sudo configuration (root only)
/etc/crontab         # System crontab (world-readable)
```

**System Directories**:
```
/etc/cron.d/         # Additional cron configs (root only)
/etc/systemd/system/ # Systemd units (varies)
/var/log/            # Log files (varies by distro)
/var/spool/cron/     # User crontabs (root only)
```

**Procfs and Sysfs**:
```
/proc/[pid]/         # Process information
/proc/net/           # Network stack info
/proc/modules        # Loaded kernel modules
/proc/kallsyms       # Kernel symbols (restricted)
/sys/class/net/      # Network interface info
```

**Binary Directories** (for SUID detection):
```
/bin/, /sbin/
/usr/bin/, /usr/sbin/
/usr/local/bin/, /usr/local/sbin/
/lib/, /lib64/
/usr/lib/, /usr/lib64/
```

**SSH Key Locations**:
```
/etc/ssh/                    # System SSH keys
/home/*/.ssh/                # User SSH keys (requires access)
/root/.ssh/                  # Root SSH keys (root only)
```

### Vault Directory

The scanner may write to a vault directory for evidence collection:
```
/var/lib/orin/vault/    # Default vault path (configurable)
```

This requires write permissions if deleted binary recovery is enabled.

## Network Requirements

### Outbound Connectivity

The scanner host needs outbound SSH access to target systems:
- TCP port 22 (or custom SSH port)
- No special firewall rules needed beyond SSH

### Inbound Connectivity

No inbound connections are required on the scanner host. All communication is initiated outbound via SSH.

## Target System Compatibility

### Tested and Supported Systems

| System Type | Python Agent | Bash Agent | Notes |
|-------------|--------------|------------|-------|
| Ubuntu 18.04+ | ✅ | ✅ | Full support |
| Debian 9+ | ✅ | ✅ | Full support |
| CentOS/RHEL 7+ | ✅ | ✅ | Full support |
| Fedora | ✅ | ✅ | Full support |
| Alpine Linux | ✅ | ✅ | Minimal deps |
| BusyBox | ❌ | ✅ | Bash agent only |
| OpenWrt | ❌ | ✅ | Bash agent recommended |
| Docker Containers | ✅ | ✅ | Depends on base image |
| Embedded Linux | ❌ | ✅ | Bash agent for stripped systems |

### Known Limitations

1. **Non-Linux Systems**: The scanner is Linux-specific. macOS, BSD, and Windows are not supported.

2. **SELinux/AppArmor**: Security modules may restrict access to certain `/proc` entries even for root. Consider temporarily setting permissive mode or configuring policies.

3. **Containerized Environments**:
   - Some `/proc` views may be namespaced/limited
   - Host process visibility depends on container privileges
   - Consider running with `--privileged` or specific capabilities

4. **Old Kernels**: Systems with kernels older than 3.x may have incomplete procfs interfaces.

## Configuration Examples

### Minimal SSH Config

Create `~/.ssh/config`:
```
Host orin-targets
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    IdentityFile ~/.ssh/orin_scanner_key
    User root
    Port 22
```

### Scanner Invocation

```python
from orin.core.scanner import run_remote_scan

results = run_remote_scan(
    host="192.168.1.100",
    user="root",
    key_path="/home/scanner/.ssh/orin_key",
    port=22,
    db_path=Path("orin_vault.db")
)
```

### Bash-Only Target

For systems without Python:
```bash
# Manual execution test
ssh root@target "bash -s" < src/orin/collectors/remote_agent.sh
```

## Troubleshooting

### Common Issues

1. **"Permission denied" errors**
   - Verify SSH key permissions: `chmod 600 ~/.ssh/id_rsa`
   - Check target user has proper shell access
   - Verify sudo configuration if using privilege escalation

2. **"python3: command not found"**
   - Scanner should automatically fall back to bash agent
   - If bash also fails, install Python or ensure bash is available

3. **Incomplete telemetry**
   - Likely a privilege issue - try connecting as root
   - Check if security modules (SELinux) are blocking access
   - Verify filesystem paths exist on target system

4. **JSON parse errors**
   - Target system may have non-standard output
   - Check stderr for error messages
   - Verify bash version supports required features

### Debug Mode

Enable verbose SSH output for troubleshooting:
```bash
ssh -vvv -i /path/to/key user@host
```

Test individual collectors manually:
```bash
ssh user@host "cat /proc/net/tcp | head -5"
ssh user@host "ls -la /proc/1/exe"
```

## Security Considerations

### Best Practices

1. **Use Dedicated Scanner Account**: Create a dedicated user account for scanning with minimal required privileges.

2. **Restrict SSH Key Scope**: Use SSH key constraints:
   ```
   command="/usr/bin/true",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-rsa AAAA...
   ```

3. **Audit Logging**: Enable SSH logging on target systems to track scanner access.

4. **Network Segmentation**: Scan from a dedicated management network segment.

5. **Regular Key Rotation**: Rotate SSH keys used for scanning periodically.

### Data Sensitivity

The scanner collects potentially sensitive information:
- User account details
- SSH public keys
- Network topology
- Running processes and connections
- System configuration

Ensure proper handling and encryption of collected telemetry data.

## Summary

| Requirement | Python Agent | Bash Agent |
|-------------|--------------|------------|
| SSH Access | ✅ Required | ✅ Required |
| Root Privileges | Recommended | Recommended |
| Python 3.6+ | ✅ Required | ❌ Not needed |
| Bash 4.0+ | ❌ Not needed | ✅ Required |
| Standard Unix Tools | ❌ Minimal | ✅ Multiple tools |
| Coverage | Complete | Coarse/Basic |
| Best For | Modern Linux | Embedded/Legacy |

For optimal results, use the Python agent with root access. The Bash agent provides essential coverage for systems where Python is unavailable.