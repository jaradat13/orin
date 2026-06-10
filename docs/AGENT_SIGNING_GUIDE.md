# Agent Script Signing Integration Guide

## Overview

Orin now includes **HMAC-SHA256 agent script signing** to ensure that only trusted, unmodified remote agent code is deployed during forensic scans. This critical security feature prevents tampering and man-in-the-middle attacks on the telemetry collection agent.

## Features

- **HMAC-SHA256 signatures** for agent script integrity verification
- **Automatic verification** before SSH transmission
- **Tamper detection** with clear error messages
- **Environment variable support** for secret key management
- **Optional enforcement** (can be disabled for testing)
- **Metadata embedding** in signature bundles

## Configuration

### Method 1: Environment Variable (Recommended)

Set the `ORIN_AGENT_SIGNING_KEY` environment variable:

```bash
export ORIN_AGENT_SIGNING_KEY="your-secure-passphrase-here"
```

**Requirements:**
- Minimum length: 12 characters
- Should be stored securely (e.g., in a secrets manager)
- Never commit to version control

### Method 2: Function Parameter

Pass the signing secret directly to the scanner:

```python
from orin.core.scanner import run_remote_scan

result = run_remote_scan(
    host="target.example.com",
    user="forensic-user",
    signing_secret="your-secure-passphrase-here",
    verify_signature=True
)
```

## Usage Examples

### Basic Scan with Signing Enabled

```python
import os
from pathlib import Path
from orin.core.scanner import run_remote_scan

# Set signing key
os.environ["ORIN_AGENT_SIGNING_KEY"] = "my-secure-key-12345"

# Execute scan with automatic signing verification
result = run_remote_scan(
    host="192.168.1.100",
    user="root",
    key_path="/home/user/.ssh/id_ed25519",
    db_path=Path("forensic_vault.db")
)
```

### Disable Signing (Testing Only)

```python
# For testing environments only
result = run_remote_scan(
    host="test-host",
    user="test",
    verify_signature=False  # Disables signing verification
)
```

### Explicit Signing Secret

```python
result = run_remote_scan(
    host="secure-target",
    user="admin",
    signing_secret="explicit-secret-key",  # Takes precedence over env var
    verify_signature=True
)
```

## How It Works

1. **Before Scan Execution:**
   - The scanner loads the `remote_agent.py` script
   - If signing is enabled, it creates an HMAC-SHA256 signature bundle
   - The signature is immediately verified locally

2. **Signature Bundle Contents:**
   ```json
   {
     "version": "1.0.0",
     "signed_at": "2026-01-15T10:30:00Z",
     "agent_name": "remote_agent.py",
     "agent_hash": "<sha256-hash>",
     "algorithm": "sha256",
     "metadata": {
       "source_path": "/path/to/agent",
       "scan_target": "hostname",
       "initiated_by": "user"
     },
     "content": "<agent script content>",
     "signature": "<hmac-sha256-signature>"
   }
   ```

3. **Verification Process:**
   - Content hash is recomputed and compared
   - HMAC signature is recomputed and verified
   - Constant-time comparison prevents timing attacks
   - Failure results in immediate scan abortion

4. **Transmission:**
   - Only verified, signed content is transmitted via SSH
   - The signed content is piped directly to the remote Python interpreter

## Security Considerations

### Key Management

- **Minimum Length:** 12 characters (enforced by validation)
- **Recommended:** Use 32+ character randomly generated keys
- **Storage:** Use environment variables or secrets managers
- **Rotation:** Periodically rotate signing keys

### Protection Against

✅ **Code Tampering:** Detects any modification to agent script
✅ **Man-in-the-Middle:** Signature verification before transmission
✅ **Unauthorized Agents:** Only signed agents can be deployed
✅ **Replay Attacks:** Metadata includes timestamp and target info

### Limitations

⚠️ **Not Encryption:** Signing provides integrity, not confidentiality
⚠️ **Key Security:** Compromised key allows signing malicious agents
⚠️ **Local Verification:** Signature is verified locally before transmission

For stronger guarantees, combine with:
- GPG-signed release manifests
- Secure key storage (HSM, Vault, etc.)
- Network-level encryption (SSH, TLS)

## Error Messages

| Message | Cause | Resolution |
|---------|-------|------------|
| `Signing passphrase is too short` | Key < 12 characters | Use longer key |
| `Agent signature verification failed` | Internal verification error | Check key integrity |
| `CRITICAL: Agent content hash mismatch` | File corruption/tampering | Restore original agent |
| `CRITICAL: Signature verification failed` | Wrong key or tampering | Verify key matches |
| `WARNING: Agent signing disabled` | No key provided | Set `ORIN_AGENT_SIGNING_KEY` |

## API Reference

### `run_remote_scan()` Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | str | required | Target hostname/IP |
| `user` | str | required | SSH username |
| `key_path` | str | None | SSH private key path |
| `port` | int | 22 | SSH port |
| `db_path` | Path | `orin_vault.db` | SQLite database path |
| `config` | dict | None | Configuration overrides |
| `signing_secret` | str | None | HMAC signing key |
| `verify_signature` | bool | `True` | Enable signing verification |

### Related Functions

- `sign_agent_script()`: Sign an agent script file
- `verify_agent_signature()`: Verify a signature bundle
- `AgentSigner`: High-level signing interface class
- `save_signed_bundle()`: Persist bundle to JSON file
- `load_signed_bundle()`: Load bundle from JSON file
- `extract_verified_agent()`: Verify and extract agent content

## Testing

```python
from pathlib import Path
from orin.core.agent_signing import AgentSigner

# Test signing
signer = AgentSigner(secret_key="test-key-12345")
bundle = signer.sign(Path("src/orin/collectors/remote_agent.py"))

# Test verification
is_valid, message = signer.verify(bundle)
assert is_valid, f"Verification failed: {message}"

# Test tamper detection
tampered = bundle.copy()
tampered["content"] += "\n# MALICIOUS CODE"
is_valid, _ = signer.verify(tampered)
assert not is_valid, "Tamper detection failed!"
```

## Compliance

This implementation supports:
- **Forensic Integrity:** Chain of custody for agent code
- **Audit Trail:** Metadata tracks scan initiation details
- **Security Hardening:** Meets roadmap Phase 1 requirements

---

**Version:** 1.0
**Last Updated:** June 2026
**Status:** Production Ready ✅