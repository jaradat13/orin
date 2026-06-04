# Security Policy

## Supported Versions

Orin follows a **rolling release** model. Only the latest version on the `main` branch receives security fixes and patches. Older versions are not actively maintained.

| Version | Supported |
|---------|-----------|
| Latest (`main`) | ✅ |
| Older releases  | ❌ |

---

## Scope

This security policy applies to vulnerabilities in the **Orin engine itself** — its collectors, analysis rules, cryptographic signing logic, database schema, and CLI. It does not cover issues in the underlying operating system, Python runtime, or third-party tools installed on the host.

Because Orin is a **fully offline, zero-dependency** forensic tool, there are no cloud endpoints, APIs, or network services to secure. All data stays on the local machine.

---

## Reporting a Vulnerability

If you discover a security vulnerability in Orin, please **do not open a public GitHub issue**.

Instead, report it privately via GitHub's built-in security advisory workflow:

1. Navigate to the [Security tab](../../security) of this repository.
2. Click **"Report a vulnerability"**.
3. Fill in the details: affected component, reproduction steps, and potential impact.

You can also reach the maintainer directly at the email listed on the GitHub profile.

### What to expect

| Step | Timeline |
|------|----------|
| Acknowledgement of your report | Within **48 hours** |
| Initial assessment & severity triage | Within **5 business days** |
| Patch or mitigation available | Within **14 days** for critical issues |
| Public disclosure (coordinated) | After a fix is merged and released |

We follow **responsible disclosure** — we will coordinate the public release of any advisory with you before publishing.

---

## Security Design Notes

Orin is designed with the following security principles:

- **No network access at runtime** — the engine never makes outbound connections during collection or analysis.
- **No remote code execution surface** — all inputs are local filesystem reads; there are no sockets, HTTP handlers, or RPC interfaces.
- **Tamper-evident exports** — all snapshot exports are signed with HMAC-SHA256. Any modification to the export file is immediately detected by `orin verify`.
- **Minimal privilege surface** — only specific collectors (e.g. `/var/log/auth.log`, `/var/spool/cron/crontabs/`) require root. The `orin status`, `orin diff`, and `orin report` subcommands run fine as a non-root user.
- **Zero third-party dependencies** — the entire runtime uses only Python standard library modules, eliminating supply-chain risk from external packages.

---

## Out of Scope

The following are **not** considered vulnerabilities for the purposes of this policy:

- False positives or false negatives in threat detection rules (these are engine quality issues, not security vulnerabilities — file a regular issue).
- Issues that require physical access to the machine being monitored.
- Vulnerabilities in Python itself or the Linux kernel.
