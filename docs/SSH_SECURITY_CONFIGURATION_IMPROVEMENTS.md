# SSH StrictHostKeyChecking Configuration Improvements

## Overview

This document describes the implementation of configurable SSH security settings to replace the hardcoded `StrictHostKeyChecking=no` option that was previously used across all SSH operations in Orin.

## Security Issue Addressed

**Original Problem:** All SSH connections were using `StrictHostKeyChecking=no`, which:
- Disables host key verification completely
- Makes the system vulnerable to man-in-the-middle (MITM) attacks
- Accepts any host key without validation
- Violates security best practices for production environments

## Implementation Details

### 1. Configuration Schema (`src/orin/core/config.py`)

Added new `ssh` section to `DEFAULT_CONFIG`:

```python
"ssh": {
    "strict_host_key_checking": "ask",  # Options: "yes", "no", "ask", "accept-new"
    "known_hosts_file": None,  # None uses default ~/.ssh/known_hosts
    "connection_timeout": 30,
    "max_retries": 3
}
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `strict_host_key_checking` | string | `"ask"` | SSH StrictHostKeyChecking mode. Options: `"yes"` (strict), `"no"` (insecure), `"ask"` (prompt), `"accept-new"` (auto-accept new) |
| `known_hosts_file` | string/null | `None` | Custom path to known_hosts file. `None` uses SSH default (`~/.ssh/known_hosts`) |
| `connection_timeout` | integer | `30` | Connection timeout in seconds |
| `max_retries` | integer | `3` | Maximum connection attempts (via ConnectionAttempts) |

### 2. Updated SSH Command Construction

Modified three locations where SSH commands are constructed:

#### a. `src/orin/core/scanner.py` - `run_remote_scan()`

**Before:**
```python
ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no"]
if port:
    ssh_cmd.extend(["-p", str(port)])
if key_path:
    ssh_cmd.extend(["-i", str(key_path)])
```

**After:**
```python
# Load SSH security configuration from config
ssh_config = config.get("ssh", {}) if config else {}
strict_host_checking = ssh_config.get("strict_host_key_checking", "ask")
known_hosts_file = ssh_config.get("known_hosts_file")
connection_timeout = ssh_config.get("connection_timeout", 30)
max_retries = ssh_config.get("max_retries", 3)

# Construct the SSH subprocess execution command list with configurable security options
ssh_cmd = ["ssh", "-o", f"StrictHostKeyChecking={strict_host_checking}"]

# Add custom known_hosts file if specified
if known_hosts_file:
    ssh_cmd.extend(["-o", f"UserKnownHostsFile={known_hosts_file}"])

# Add connection timeout
ssh_cmd.extend(["-o", f"ConnectTimeout={connection_timeout}"])

# Add retry limit (via ConnectionAttempts)
ssh_cmd.extend(["-o", f"ConnectionAttempts={max_retries}"])

if port:
    ssh_cmd.extend(["-p", str(port)])
if key_path:
    ssh_cmd.extend(["-i", str(key_path)])
```

#### b. `src/orin/core/server.py` - `run_remote_scan_or_baseline()`

Same pattern as scanner.py, with additional import:
```python
from orin.core.config import load_config
config = load_config()
```

#### c. `src/orin/main.py` - Remote baseline initialization

Same pattern as server.py.

### 3. SSH Option Mapping

The implementation maps configuration values to SSH command-line options:

| Config Key | SSH Option | Example |
|------------|-----------|---------|
| `strict_host_key_checking` | `-o StrictHostKeyChecking=<value>` | `-o StrictHostKeyChecking=ask` |
| `known_hosts_file` | `-o UserKnownHostsFile=<path>` | `-o UserKnownHostsFile=/etc/orin/known_hosts` |
| `connection_timeout` | `-o ConnectTimeout=<seconds>` | `-o ConnectTimeout=30` |
| `max_retries` | `-o ConnectionAttempts=<count>` | `-o ConnectionAttempts=3` |

## Usage Examples

### Production Environment (Secure)

```json
{
  "ssh": {
    "strict_host_key_checking": "yes",
    "known_hosts_file": "/etc/orin/known_hosts",
    "connection_timeout": 30,
    "max_retries": 3
  }
}
```

**Behavior:**
- Requires pre-existing host keys in known_hosts file
- Rejects unknown hosts (prevents MITM)
- Uses centralized known_hosts file for consistency

### Development Environment (Convenient)

```json
{
  "ssh": {
    "strict_host_key_checking": "accept-new",
    "known_hosts_file": null,
    "connection_timeout": 60,
    "max_retries": 5
  }
}
```

**Behavior:**
- Automatically accepts new host keys on first connection
- Stores them in default `~/.ssh/known_hosts`
- More tolerant of network issues (longer timeout, more retries)

### Automated/CI Environment (Controlled)

```json
{
  "ssh": {
    "strict_host_key_checking": "no",
    "known_hosts_file": null,
    "connection_timeout": 10,
    "max_retries": 2
  }
}
```

**⚠️ Warning:** Only use in isolated, trusted networks where MITM risk is negligible.

**Behavior:**
- No host key verification (fastest, least secure)
- Suitable for ephemeral CI/CD environments
- Should never be used in production

## Security Benefits

### 1. **MITM Attack Prevention**
- Default `"ask"` mode requires user verification for unknown hosts
- `"yes"` mode enforces strict host key validation
- Prevents silent acceptance of malicious host keys

### 2. **Configurable Security Posture**
- Organizations can choose appropriate security level for their environment
- Supports compliance requirements for host key verification
- Enables gradual migration from insecure to secure configurations

### 3. **Centralized Known Hosts Management**
- Custom `known_hosts_file` enables enterprise-wide host key management
- Supports read-only known_hosts files for enhanced security
- Facilitates automated host key distribution

### 4. **Connection Reliability**
- Configurable timeouts prevent hanging connections
- Retry limits balance reliability with resource consumption
- Prevents indefinite blocking on network issues

### 5. **Audit Trail**
- Host key acceptance/rejection is logged by SSH
- Custom known_hosts files enable better audit control
- Configuration changes are tracked in config file

## Migration Guide

### Step 1: Assess Current Risk

If you're currently using the hardcoded `StrictHostKeyChecking=no`:
- Identify all environments where this is used
- Evaluate MITM risk in each environment
- Plan migration to secure configuration

### Step 2: Choose Configuration Mode

**For Production:**
```json
{
  "ssh": {
    "strict_host_key_checking": "yes",
    "known_hosts_file": "/etc/orin/known_hosts"
  }
}
```

**For Development:**
```json
{
  "ssh": {
    "strict_host_key_checking": "accept-new"
  }
}
```

### Step 3: Populate Known Hosts (for `"yes"` mode)

```bash
# Collect host keys from all target systems
ssh-keyscan -H target1.example.com >> /etc/orin/known_hosts
ssh-keyscan -H target2.example.com >> /etc/orin/known_hosts

# Set appropriate permissions
chmod 644 /etc/orin/known_hosts
chown root:root /etc/orin/known_hosts
```

### Step 4: Test Configuration

```bash
# Test connection with new configuration
python -m orin --host target.example.com --user admin --init

# Verify host key is being checked
# Should fail if host key not in known_hosts (for "yes" mode)
```

### Step 5: Monitor and Adjust

- Monitor logs for connection failures
- Adjust timeout/retry values based on network conditions
- Update known_hosts file as infrastructure changes

## Testing

All modified modules have been tested for:
- ✅ Successful import without errors
- ✅ Correct configuration loading
- ✅ Proper SSH command construction
- ✅ Backward compatibility (defaults work without config)

## Future Enhancements

Potential future improvements:
1. **Host Key Rotation Support**: Automatic handling of rotated host keys
2. **Certificate-Based Authentication**: Support for SSH certificates
3. **ProxyJump Configuration**: Configurable SSH proxy jumps
4. **Connection Pooling**: Reuse SSH connections for multiple operations
5. **Rate Limiting**: Prevent SSH scanning abuse (already on roadmap)

## References

- [SSH StrictHostKeyChecking Documentation](https://man.openbsd.org/ssh_config#StrictHostKeyChecking)
- [SSH Security Best Practices](https://www.ssh.com/academy/ssh/best-practices)
- [OWASP Secure Configuration Guide](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Configuration_Cheat_Sheet.html)

## Related Roadmap Items

This implementation addresses item **#4: SSH Security Hardening** from Phase 0 of the Orin improvement roadmap.

Related items:
- ✅ **Exception Handling** (Item #1) - Completed
- ✅ **Race Condition Fixes** (Item #2) - Completed
- ✅ **Input Validation** (Item #3) - Completed
- ✅ **SSH Security Configuration** (Item #4) - **Completed**
- ⏳ **Rate Limiting** (Item #4 continued) - Pending
- ⏳ **Test Coverage** (Item #5) - In Progress