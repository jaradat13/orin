# Configuration Reference

Orin searches for `orin_config.json` in `./` then `/etc/orin/`, falling back to
built-in defaults if neither is found. `config.py` deep-copies defaults so
user-supplied values never mutate the built-in default object.

This page consolidates every config key and environment variable referenced across
Orin's docs. For narrative detail, follow the links to the relevant guide.

---

## Top-Level Config Keys

```json
{
  "expected_ports": [22, 80, 443, 631, 3306, 5432, 6379, 8080, 8443],
  "whitelisted_processes": ["code", "chrome", "language_server"],
  "critical_paths": ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/crontab"],
  "critical_dirs": ["/etc/cron.d", "/etc/systemd/system"],
  "ssh": { "...": "see SSH section below" },
  "notifications": { "...": "see Alert Forwarding section below" }
}
```

| Key | Type | Purpose |
|---|---|---|
| `expected_ports` | array of int | Listening ports considered normal; unexpected open ports raise alerts |
| `whitelisted_processes` | array of string | Process names excluded from masquerade/anomaly checks |
| `critical_paths` | array of string | Individual files monitored by FIM |
| `critical_dirs` | array of string | Directories monitored by FIM |
| `ssh` | object | Host key verification and rate limiting — see [SSH_GUIDE.md](SSH_GUIDE.md) |
| `notifications` | object | Alert forwarding — see [Alert Forwarding](#alert-forwarding) below |

YARA full-directory sweeps (disabled by default, restricted to `/tmp`, `/dev/shm`,
`/var/tmp`) and alert suppression rules are also configured via `orin_config.json`,
though their exact key structure is not documented here — see
[STATUS.md](STATUS.md) and [THREAT_DETECTION.md](THREAT_DETECTION.md).

---

## SSH Configuration

```json
{
  "ssh": {
    "strict_host_key_checking": "ask",
    "known_hosts_file": null,
    "connection_timeout": 30,
    "max_retries": 3,
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

Full explanation of each field, security implications, and recommended profiles for
production/lab/CI: see [SSH_GUIDE.md](SSH_GUIDE.md).

---

## Alert Forwarding

```json
{
  "notifications": {
    "enabled": true,
    "min_severity": "high",
    "syslog": { "enabled": true, "facility": "LOG_LOCAL0", "tag": "orin-alert" },
    "webhooks": [
      {
        "name": "ops-slack",
        "url": "http://192.168.1.10:8080/slack-webhook",
        "format": "slack",
        "min_severity": "critical",
        "timeout_seconds": 10,
        "enabled": true
      }
    ],
    "retry": { "max_attempts": 3, "backoff_seconds": 5 },
    "audit_log": "/var/log/orin/notification_audit.log"
  }
}
```

| Key | Type | Purpose |
|---|---|---|
| `enabled` | bool | Master switch for alert forwarding |
| `min_severity` | string | Global minimum severity (`low`/`medium`/`high`/`critical`) |
| `syslog.enabled` | bool | Send alerts to local syslog |
| `syslog.facility` | string | syslog facility, e.g. `LOG_LOCAL0` |
| `syslog.tag` | string | syslog tag for Orin entries |
| `webhooks[]` | array | One entry per webhook destination |
| `webhooks[].format` | string | `slack`, `teams`, or `generic` |
| `webhooks[].min_severity` | string | Per-webhook override of the global filter |
| `webhooks[].headers` | object | Optional extra HTTP headers (e.g. auth tokens) |
| `retry.max_attempts` / `retry.backoff_seconds` | int | Exponential backoff retry policy |
| `audit_log` | string | Path to append-only JSONL delivery log |

Dispatched automatically after every `orin analyze`. All transports use stdlib
`urllib.request` — no third-party dependencies. Core module: `orin.core.notifier`.

---

## Environment Variables

| Variable | Used by | Purpose |
|---|---|---|
| `ORIN_VAULT_PASSPHRASE` | `orin init`, `orin collect`, etc. | Enables AES-256-GCM vault encryption. Without it, the vault is unencrypted. |
| `ORIN_AGENT_SIGNING_KEY` | `orin scan` / `run_remote_scan()` | HMAC-SHA256 key for signing the remote SSH agent script (min. 12 characters). See [AGENT_SIGNING.md](AGENT_SIGNING.md). |
| `ORIN_TEST_FAST` | test suite | `1` skips slow/integration tests (eBPF loads, heavy subprocess, large DB writes); `0`/unset runs the full suite. See [TESTING.md](TESTING.md). |
| *(custom name)* | `--passphrase-env-var <NAME>` | Lets you supply the vault passphrase via a custom-named environment variable instead of `ORIN_VAULT_PASSPHRASE`. |

> **Note:** Some earlier drafts of this documentation referenced `ORIN_DB_POOL_SIZE`
> and `ORIN_DB_TIMEOUT` environment variables for tuning the SQLite connection pool.
> These are **not** environment variables in the documented implementation — pool
> size and timeout are constructor parameters of `OrinStorage` (`pool_size`,
> `pool_timeout`, default `10` and `30.0`). See
> [DATABASE_INTERNALS.md](DATABASE_INTERNALS.md). If your deployment exposes these as
> env vars via a wrapper script, document that separately — don't rely on this page
> for that.

---

## Secure Credential Input (CLI flags)

For `orin diff`, `orin export`, `orin verify`, `orin collect`, and similar
passphrase-consuming commands:

| Flag | Behavior |
|---|---|
| `--passphrase-file <path>` | Reads passphrase from a file; file must be mode `0600` |
| `--passphrase-prompt` | Interactive masked prompt |
| `--passphrase-env-var <NAME>` | Reads passphrase from the named environment variable, then evicts it from `os.environ` |
| `--secret-file` / `--secret-prompt` / `--secret-env-var` | Equivalent options for `diff`/`export`/`verify` operations |
| `--token-file <path>` | Persists the dashboard session token to a `0600` file instead of printing only to terminal |

---

## Related Documentation

- [SSH_GUIDE.md](SSH_GUIDE.md) — SSH host key verification, rate limiting, agent requirements
- [AGENT_SIGNING.md](AGENT_SIGNING.md) — remote agent signing key management
- [DATABASE_INTERNALS.md](DATABASE_INTERNALS.md) — connection pool tuning
- [STATUS.md](STATUS.md) — deployment assumptions and known limitations
- [SECURITY.md](SECURITY.md) — vulnerability reporting