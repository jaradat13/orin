# Parallel Collection

`orin collect --parallel` runs independent collectors concurrently using
`concurrent.futures.ThreadPoolExecutor`, reducing collection time on multi-core systems
from roughly 15-20 seconds (sequential) to ~1.3 seconds (4 workers).

## CLI Usage

```bash
orin collect                                  # sequential (default)
orin collect --parallel                       # auto-detected workers
orin collect --parallel --workers 8           # custom worker count
orin collect --parallel --timeout 120         # custom per-collector timeout
orin collect --parallel --workers 4 --timeout 60
```

Default worker count is `CPU count + 4`, capped at 32. Default per-collector timeout is
300 seconds.

## Programmatic API

```python
from orin.collectors.parallel import ParallelCollector, gather_parallel_system_state

# High-level convenience function
successful, failed = gather_parallel_system_state(max_workers=4, timeout=60.0)

# Fine-grained control
collector = ParallelCollector(max_workers=4, default_timeout=300.0)
collector.add_task("processes", gather_active_processes, timeout=60)
collector.add_task("ports", gather_listening_ports, timeout=30)
collector.add_task("users", gather_system_accounts, priority=1)

results = collector.run(progress_callback=lambda name, done, total: print(f"[{done}/{total}] {name}"))

successful_data = collector.get_successful_results()
failed_data = collector.get_failed_results()
summary = collector.get_summary()
```

## Components

- **`ParallelCollector`** — thread pool manager with configurable workers, timeouts,
  priority ordering, and progress callbacks.
- **`CollectorTask`** — dataclass describing an individual collector task.
- **`CollectorResult`** — captures success/failure, timing, and error details.

## Collectors That Run in Parallel

These 18 collectors have no shared state or DB-connection dependencies and run
concurrently: `processes`, `listening_ports`, `outbound_connections`,
`promisc_interfaces`, `kernel_modules`, `system_users`, `crontabs`, `wtmp_sessions`,
`lastlog_records`, `deleted_binaries`, `suid_binaries`, `auth_logs`, `ebpf_programs`,
`ebpf_pinned`, `ld_preload`, `special_fds`, `persistence_configs`, `dns_queries`.

**Run sequentially** (require an active DB connection or depend on another collector's
output): `file_integrity_signatures`, `kernel_symbols`, `privilege_events`, `ssh_keys`,
`pkg_integrity_drift`.

## Error Handling

- Each collector has its own timeout; a hung collector doesn't block the others.
- One collector's exception doesn't affect the rest — partial results are preserved.
- All failures are logged in structured JSON with full error context.
- Race conditions from processes exiting mid-collection are handled gracefully.

## Notes

- No external dependencies — stdlib `concurrent.futures` only.
- Thread-safe result collection; compatible with the existing sequential workflow.
- Does not modify collected data — forensic integrity is preserved.
- Actual speedup depends on CPU core count, I/O latency, process count, and interface
  count.