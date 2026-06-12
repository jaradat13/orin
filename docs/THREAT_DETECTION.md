# Threat Detection Rules

Orin evaluates dozens of security conditions across collected data. Below is the complete rule set.

## Process & Execution Anomalies

- **Kernel thread masquerade** – Processes mimicking kernel workers (`kworker`, `ksoftirqd`, …) with non‑system PPID.
- **Reverse shell detection** – Dangerous invocation patterns (`python -c`, `bash -i`, `sh -i`, `nc -e`, etc.).
- **Volatile‑directory execution** – Processes running from `/tmp`, `/dev/shm`, `/var/tmp`.
- **Known‑bad binaries** – `nc`, `ncat`, `netcat`, `socat`, `nmap`, `xmrig`, and other offensive tools.
- **C2 blocklist** – Outbound connections to IPs/domains from offline threat intel feeds.
- **In‑memory deleted binaries** – Processes whose executable has been unlinked from disk.
- **Hidden process detection** – PIDs active in scheduler but absent from `/proc`.

## Kernel & Rootkit Indicators

- **Kernel rootkit symbols** – Suspicious `kallsyms` entries matching known rootkits (diamorphine, reptile).
- **Credential manipulation symbols** – `commit_creds`, `prepare_kernel_cred` in third‑party modules.
- **Unlinked kernel modules** – Modules exporting symbols but missing from `/proc/modules`.
- **eBPF program anomalies** – Non‑GPL‑compatible licenses, suspicious program names.
- **Pinned eBPF objects** – Map/program pins under `/sys/fs/bpf` with rootkit patterns.
- **Dynamic linker preload** – Entries in `/etc/ld.so.preload`.

## Persistence & Account Abuse

- **SSH key persistence** – New authorized_keys appearing between snapshots.
- **Unauthorized user accounts** – UID‑0 accounts not in baseline, new users.
- **Cron job drift** – Newly added scheduled tasks.
- **Cron execution anomalies** – Jobs from volatile directories or containing reverse‑shell commands.
- **SUID/SGID privilege anomalies** – Modified or new SUID/SGID binaries.
- **Systemd service persistence** – New or modified unit files.
- **Persistence configurations** – rc.local, systemd timers, XDG autostart, etc.

## Network & Communications

- **Promiscuous mode** – Network interface with `IFF_PROMISC` flag active.
- **DNS tunneling** – High entropy domains, long subdomains, TXT record abuse.
- **DGA detection** – Domain generation algorithm patterns (Shannon entropy, character distribution).
- **Unexpected outbound connections** – Connections to non‑whitelisted IPs/ports.
- **C2 beaconing** – Periodic outbound connections to blocklisted destinations.

## File Integrity & Tampering

- **FIM violations** – SHA‑256 changes in critical system files.
- **Package integrity failure** – MD5 mismatch between on‑disk binary and dpkg record.
- **Log tampering** – Zeroed records or epoch resets in wtmp/lastlog.
- **YARA signature match** – Malware patterns in files or dumped in‑memory payloads.
- **Deleted file descriptors** – Processes holding open handles to deleted files in system directories.
- **memfd anonymous execution** – Fileless execution via `memfd_create`.

## Identity & Privilege Escalation

- **PAM authentication failures** – Brute force patterns.
- **sudo / su escalation** – Privileged command execution.
- **setuid/setgid/capset syscalls** – Privilege elevation via syscall monitoring (eBPF or audit).
- **ptrace usage** – Potential process injection.
- **Credential access** – Reads of `/etc/shadow`, SSH agent sockets, Kerberos caches.

## Sigma Rules

Orin includes a zero‑dependency Sigma rules evaluator. Built‑in rules cover:

- SSH brute force
- su/sudo privilege escalation
- Useradd/userdel drift
- Session management anomalies

Custom Sigma rules can be placed in `/etc/orin/sigma/`.

## Alert Suppression & Auto‑Resolution

- **Suppression rules** – Silence alerts by event type, file path, or process name (configured via dashboard or `orin_config.json`).
- **Severity override** – Raise or lower alert severity per rule.
- **Auto‑resolution** – Alert is automatically closed when the anomalous condition no longer exists in a later snapshot.