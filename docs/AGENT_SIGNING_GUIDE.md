# Remote Agent Script Signing & Verification Guide

## Overview

Orin now supports cryptographic signing and verification of remote agent scripts before deployment. This feature ensures that only trusted, unmodified agent code is executed on target systems during SSH-based scans.

## Security Benefits

1. **Tamper Detection**: Detects any modifications to agent scripts before execution
2. **Integrity Assurance**: Cryptographically verifies agent authenticity
3. **Supply Chain Security**: Prevents unauthorized code injection in the deployment pipeline
4. **Audit Trail**: Signed bundles provide evidence of code integrity for compliance

## Architecture

```
┌─────────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Agent Script       │────▶│  Signer Module   │────▶│  Signed Bundle  │
│  (remote_agent.py)  │     │  (HMAC-SHA256)   │     │  (JSON format)  │
└─────────────────────┘     └──────────────────┘     └─────────────────┘
                                                         │
                                                         ▼
                                                ┌──────────────────┐
                                                │  Verification    │
                                                │  Before Execution│
                                                └──────────────────┘
```

## API Reference

### Core Functions

#### `sign_agent_script(agent_path, secret_key, algorithm="sha256", metadata=None)`

Sign a remote agent script and generate a signature bundle.

**Parameters:**
- `agent_path` (Path): Path to the agent script file
- `secret_key` (str): HMAC passphrase (minimum 12 characters)
- `algorithm` (str): Hash algorithm ("sha256" or "sha512")
- `metadata` (dict, optional): Additional metadata to include

**Returns:**
- `dict`: Signature bundle containing content, hash, and signature

**Example:**
```python
from orin.core.agent_signing import sign_agent_script
from pathlib import Path

bundle = sign_agent_script(
    Path("src/orin/collectors/remote_agent.py"),
    secret_key="my-secure-passphrase-here",
    metadata={"version": "1.0", "author": "security-team"}
)
```

#### `verify_agent_signature(bundle, secret_key)`

Verify the signature of a signed agent bundle.

**Parameters:**
- `bundle` (dict): The signature bundle to verify
- `secret_key` (str): HMAC passphrase used for signing

**Returns:**
- `Tuple[bool, str]`: Verification result and message

**Example:**
```python
from orin.core.agent_signing import verify_agent_signature

is_valid, message = verify_agent_signature(
    bundle,
    secret_key="my-secure-passphrase-here"
)

if not is_valid:
    raise RuntimeError(f"Agent verification failed: {message}")
```

#### `extract_verified_agent(bundle, secret_key, output_path=None)`

Verify a bundle and extract the agent content if valid.

**Parameters:**
- `bundle` (dict): The signature bundle
- `secret_key` (str): HMAC passphrase
- `output_path` (Path, optional): Where to save the extracted agent

**Returns:**
- `Tuple[bool, str, Optional[str]]`: Result, message, and content

**Example:**
```python
from orin.core.agent_signing import extract_verified_agent

is_valid, message, content = extract_verified_agent(
    bundle,
    secret_key="my-secure-passphrase-here",
    output_path=Path("/tmp/verified_agent.py")
)
```

### Bundle Persistence

#### `save_signed_bundle(bundle, output_path)`

Save a signed bundle to a JSON file.

```python
from orin.core.agent_signing import save_signed_bundle

save_signed_bundle(bundle, Path("/path/to/bundle.json"))
```

#### `load_signed_bundle(bundle_path)`

Load a signed bundle from a JSON file.

```python
from orin.core.agent_signing import load_signed_bundle

bundle = load_signed_bundle(Path("/path/to/bundle.json"))
```

### Multi-Agent Manifest

#### `generate_agent_manifest(agent_paths, secret_key, output_path=None)`

Generate a manifest with signatures for multiple agent scripts.

```python
from orin.core.agent_signing import generate_agent_manifest
from pathlib import Path

manifest = generate_agent_manifest(
    [
        Path("src/orin/collectors/remote_agent.py"),
        Path("src/orin/collectors/remote_agent.sh")
    ],
    secret_key="manifest-key-here",
    output_path=Path("agent_manifest.json")
)
```

### High-Level Interface: AgentSigner Class

The `AgentSigner` class provides a convenient object-oriented interface:

```python
from orin.core.agent_signing import AgentSigner
from pathlib import Path

# Initialize signer
signer = AgentSigner(secret_key="my-secure-passphrase-here")

# Sign an agent
bundle = signer.sign(Path("remote_agent.py"))

# Verify a bundle
is_valid, message = signer.verify(bundle)

# Save bundle
signer.save(bundle, Path("bundle.json"))

# Load bundle
loaded = signer.load(Path("bundle.json"))

# Extract verified agent
is_valid, message, content = signer.extract(
    bundle,
    output_path=Path("verified_agent.py")
)
```

## GPG Integration

For stronger guarantees, combine HMAC signing with GPG signatures:

### Sign Bundle with GPG

```python
from orin.core.agent_signing import sign_bundle_with_gpg, save_signed_bundle

# First create HMAC-signed bundle
bundle = sign_agent_script(agent_path, secret_key="hmac-key")
bundle_path = Path("bundle.json")
save_signed_bundle(bundle, bundle_path)

# Then add GPG signature
sig_path = sign_bundle_with_gpg(bundle_path, gpg_key_id="your-key-id")
```

### Verify GPG Signature

```python
from orin.core.agent_signing import verify_gpg_signature_on_bundle

is_valid = verify_gpg_signature_on_bundle(
    Path("bundle.json"),
    signature_path=Path("bundle.json.sig")
)
```

## Bundle Format

A signed bundle has the following JSON structure:

```json
{
  "version": "1.0.0",
  "signed_at": "2026-06-10T15:00:00+00:00",
  "agent_name": "remote_agent.py",
  "agent_hash": "sha256_hex_digest_of_content",
  "algorithm": "sha256",
  "metadata": {},
  "content": "#!/usr/bin/env python3\n...",
  "signature": "hmac_sha256_signature"
}
```

## Security Considerations

### Key Management

1. **Secret Key Storage**: Store signing keys securely (e.g., hardware security modules, secure vaults)
2. **Key Rotation**: Implement regular key rotation policies
3. **Access Control**: Limit access to signing keys to authorized personnel only
4. **Never Transmit Keys**: The signing key must never be transmitted to target systems

### Signature Verification

1. **Verify Before Execution**: Always verify signatures before deploying agents
2. **Fail Secure**: Reject any agent that fails verification
3. **Constant-Time Comparison**: Uses `hmac.compare_digest()` to prevent timing attacks
4. **Dual Verification**: Consider combining HMAC with GPG for defense in depth

### Threat Model

This feature protects against:
- ✅ Accidental file corruption during transfer
- ✅ Malicious modification of agent scripts
- ✅ Unauthorized code injection
- ✅ Supply chain tampering

This feature does NOT protect against:
- ❌ Compromised signing keys
- ❌ Runtime attacks after verification
- ❌ Social engineering to bypass verification

## Usage Patterns

### Pattern 1: Pre-Deployment Verification

```python
from orin.core.agent_signing import AgentSigner
from pathlib import Path

def deploy_verified_agent(agent_path, secret_key):
    """Deploy agent only if signature verifies."""
    signer = AgentSigner(secret_key=secret_key)

    # Sign the agent
    bundle = signer.sign(agent_path)

    # Verify before deployment
    is_valid, message = signer.verify(bundle)
    if not is_valid:
        raise RuntimeError(f"Deployment blocked: {message}")

    # Proceed with deployment
    return bundle["content"]
```

### Pattern 2: CI/CD Pipeline Integration

```yaml
# Example GitHub Actions workflow
- name: Sign Release Agents
  run: |
    python -c "
    from orin.core.agent_signing import generate_agent_manifest
    from pathlib import Path

    manifest = generate_agent_manifest(
        ['src/orin/collectors/remote_agent.py',
         'src/orin/collectors/remote_agent.sh'],
        secret_key='${{ secrets.AGENT_SIGNING_KEY }}',
        output_path='release/agent_manifest.json'
    )
    "
```

### Pattern 3: Runtime Verification in Scanner

```python
# Integration with scanner module (future enhancement)
from orin.core.agent_signing import AgentSigner

class SecureScanner:
    def __init__(self, signing_key):
        self.signer = AgentSigner(secret_key=signing_key)

    def scan(self, host, user, agent_path):
        # Sign and verify before each scan
        bundle = self.signer.sign(agent_path)
        is_valid, _ = self.signer.verify(bundle)

        if not is_valid:
            raise SecurityError("Agent verification failed")

        # Proceed with SSH deployment
        # ...
```

## Testing

Run the test suite to verify functionality:

```bash
pytest tests/test_agent_signing.py -v
```

Tests cover:
- Secret validation
- Hash computation (SHA256, SHA512)
- Signing operations
- Signature verification (valid and tampered)
- Bundle persistence (save/load)
- Agent extraction
- Multi-agent manifests
- GPG integration
- Error handling

## Integration with Existing Crypto Module

The agent signing module complements the existing `orin.core.crypto` module:

- `crypto.py`: Focuses on snapshot export signing for forensic data
- `agent_signing.py`: Focuses on agent script integrity before deployment

Both use similar HMAC-SHA256 patterns but serve different security purposes in the Orin architecture.

## Future Enhancements

Potential improvements for future versions:

1. **Automatic Key Rotation**: Scheduled key rotation with versioned signatures
2. **Hardware Security Module (HSM) Support**: Integration with AWS KMS, Azure Key Vault
3. **Multi-Signature Schemes**: Require multiple signatures for critical deployments
4. **Timestamp Authority Integration**: RFC 3161 timestamps for non-repudiation
5. **Certificate-Based Signing**: X.509 certificate support for enterprise PKI
6. **Automatic Scanner Integration**: Built-in verification in `orin.core.scanner`

## Troubleshooting

### "Passphrase is too short" Error

Ensure your signing key is at least 12 characters:

```python
# ❌ Too short
AgentSigner(secret_key="short")

# ✅ Valid length
AgentSigner(secret_key="secure-passphrase-123")
```

### "Signature verification failed" Error

This indicates the bundle has been modified. Re-sign the agent:

```python
# Re-create the bundle
bundle = sign_agent_script(agent_path, secret_key)
```

### "Unsupported algorithm" Error

Use only supported algorithms:

```python
# ✅ Supported
sign_agent_script(agent_path, secret_key, algorithm="sha256")
sign_agent_script(agent_path, secret_key, algorithm="sha512")

# ❌ Not supported
sign_agent_script(agent_path, secret_key, algorithm="md5")
```

## References

- HMAC-SHA256: RFC 2104
- Constant-Time Comparison: `hmac.compare_digest()` documentation
- Related: `orin.core.crypto` for snapshot signing
- Related: `orin.core.self_verify` for tool self-verification