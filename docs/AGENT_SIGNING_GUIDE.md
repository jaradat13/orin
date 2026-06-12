# Agent Script Signing

Orin signs the remote collection agent script with HMAC-SHA256 before transmitting it
over SSH, ensuring the target host only ever executes unmodified, trusted code.

## Configuration

**Recommended — environment variable:**

```bash
export ORIN_AGENT_SIGNING_KEY="your-secure-passphrase-here"
```

Requirements: minimum 12 characters; store in a secrets manager; never commit to
version control.

**Alternative — explicit parameter:**

```python
from orin.core.scanner import run_remote_scan

result = run_remote_scan(
    host="target.example.com",
    user="forensic-user",
    signing_secret="your-secure-passphrase-here",  # takes precedence over env var
    verify_signature=True,
)
```

Disable for testing only:

```python
result = run_remote_scan(host="test-host", user="test", verify_signature=False)
```

## How It Works

1. Before each scan, the scanner loads `remote_agent.py` and (if signing is enabled)
   builds a signature bundle, verifying it locally first.
2. Bundle contents:

   ```json
   {
     "version": "1.0.0",
     "signed_at": "2026-01-15T10:30:00Z",
     "agent_name": "remote_agent.py",
     "agent_hash": "<sha256-hash>",
     "algorithm": "sha256",
     "metadata": { "source_path": "...", "scan_target": "...", "initiated_by": "..." },
     "content": "<agent script content>",
     "signature": "<hmac-sha256-signature>"
   }
   ```

3. Verification recomputes the content hash and HMAC signature using a constant-time
   comparison; any mismatch aborts the scan immediately.
4. Only verified, signed content is piped to the remote Python interpreter via SSH.

## Protects Against

- Code tampering — any modification to the agent script is detected.
- MITM — signature is verified before transmission.
- Unauthorized agents — only correctly signed agents are deployed.
- Replay — bundle metadata includes timestamp and target info.

## Limitations

- Signing provides integrity, not confidentiality.
- A compromised signing key allows signing malicious agents.
- Verification happens locally before transmission, not independently on the remote
  host. For stronger guarantees, combine with GPG-signed release manifests, HSM/secrets
  manager key storage, and SSH/TLS transport encryption.

## Error Reference

| Message | Cause | Fix |
|---|---|---|
| `Signing passphrase is too short` | Key < 12 characters | Use a longer key |
| `Agent signature verification failed` | Internal verification error | Check key integrity |
| `CRITICAL: Agent content hash mismatch` | File corruption/tampering | Restore original agent |
| `CRITICAL: Signature verification failed` | Wrong key or tampering | Verify key matches |
| `WARNING: Agent signing disabled` | No key provided | Set `ORIN_AGENT_SIGNING_KEY` |

## API Reference

### `run_remote_scan()` parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `host` | str | required | Target hostname/IP |
| `user` | str | required | SSH username |
| `key_path` | str | `None` | SSH private key path |
| `port` | int | `22` | SSH port |
| `db_path` | Path | `orin_vault.db` | SQLite database path |
| `config` | dict | `None` | Configuration overrides |
| `signing_secret` | str | `None` | HMAC signing key |
| `verify_signature` | bool | `True` | Enable signing verification |

### Related functions / classes

- `sign_agent_script()` — sign an agent script file
- `verify_agent_signature()` — verify a signature bundle
- `AgentSigner` — high-level signing interface
- `save_signed_bundle()` / `load_signed_bundle()` — persist/load bundles as JSON
- `extract_verified_agent()` — verify and extract agent content

## Testing

```python
from pathlib import Path
from orin.core.agent_signing import AgentSigner

signer = AgentSigner(secret_key="test-key-12345")
bundle = signer.sign(Path("src/orin/collectors/remote_agent.py"))

is_valid, message = signer.verify(bundle)
assert is_valid, f"Verification failed: {message}"

tampered = bundle.copy()
tampered["content"] += "\n# MALICIOUS CODE"
is_valid, _ = signer.verify(tampered)
assert not is_valid, "Tamper detection failed!"
```