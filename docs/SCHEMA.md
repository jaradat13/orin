## 🗄️ Database Schema

Single SQLite file (default: `/var/lib/orin/orin_vault.db`).

```
system_snapshots               — one row per orin collect run
collected_processes            — process list per snapshot
collected_ports                — listening sockets per snapshot
collected_outbound_connections — outbound TCP sessions per snapshot
collected_kernel_modules       — loaded LKMs per snapshot
collected_kernel_symbols       — kernel symbol table entries for rootkit analysis
collected_ssh_keys             — authorized_keys inventory per snapshot
collected_file_hashes          — SHA-256 FIM records (+ mtime, ctime, size for stat-cache)
collected_users                — /etc/passwd accounts per snapshot
collected_deleted_binaries     — unlinked process image dump records per snapshot
collected_promisc_interfaces   — promiscuous network mode flags per snapshot
collected_wtmp_sessions        — parsed binary logins/logouts per snapshot
collected_lastlog_records      — parsed binary lastlogin timestamps per snapshot
collected_privilege_events     — privilege escalation and credential access events per snapshot
collected_pkg_integrity        — dpkg signature mismatch/missing records per snapshot
collected_crontabs             — cron job records per snapshot
collected_suid_binaries        — SUID/SGID binary records per snapshot
collected_auth_logs            — fetched system authentication logs per snapshot
collected_ebpf_programs        — loaded eBPF programs per snapshot
collected_ebpf_pinned          — eBPF program/map pins in /sys/fs/bpf per snapshot
collected_ld_preload           — library preloads listed in /etc/ld.so.preload per snapshot
collected_special_fds          — process open descriptors (memfd, deleted files) per snapshot
collected_persistence_configs  — persistence mechanism configurations per snapshot
collected_dns_queries          — DNS query telemetry with tunneling/DGA detection per snapshot
kernel_analysis_summary        — kernel integrity analysis summary per snapshot
kernel_rootkit_indicators      — detected kernel rootkit indicators per snapshot
kernel_hidden_modules          — hidden kernel module detections per snapshot
security_events                — persistent, deduplicated alert ledger
baseline_kernel_modules        — trusted LKM allowlist (set at init)
baseline_users                 — trusted account allowlist (set at init)
baseline_suid_binaries         — trusted SUID/SGID binary allowlist (set at init)