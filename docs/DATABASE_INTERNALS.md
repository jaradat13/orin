# Database Internals

Technical reference for `src/orin/core/database.py`: the connection pool, performance
tuning, and encrypted-storage exception handling. Intended for contributors working on
the storage layer.

---

## Connection Pool

`ConnectionPool` provides thread-safe, reusable SQLite connections.

- Configurable pool size (default 10) and acquisition timeout (default 30s)
- Automatic health checking — stale connections are replaced
- Connection warmup — pre-creates 3 connections on init
- Statistics via `stats()`

### Atomic counter management

The created-connection counter is incremented *before* attempting connection creation
(inside the lock), with rollback on failure:

```python
with self._lock:
    if self._created < self.max_connections:
        self._created += 1
        should_create = True
    else:
        should_create = False

if should_create:
    try:
        return self._create_connection()
    except Exception:
        with self._lock:
            self._created = max(0, self._created - 1)
        raise
```

This avoids the earlier non-atomic check-then-increment pattern, which allowed the
counter to be incremented by multiple threads past `max_connections`, and avoided
decrementing on creation failure (causing pool exhaustion over time).

### `acquire()`

- Connection variable initialized to `None` at the top of each loop iteration.
- On unexpected error, any partially-acquired connection is closed before the
  exception propagates — no leaked handles.

### `release()`

- Null-safe (`release(None)` is a no-op).
- Atomically checks `_closed` state and connection validity under the lock; invalid or
  post-close connections are closed and the counter decremented rather than returned to
  the pool.

### `close()`

Idempotent — repeated calls are safe. Sets `_closed` under the lock, drains and closes
all pooled connections (logging any close errors as warnings), resets the counter to 0,
and logs completion.

### Stale connection recovery

When a stale connection is detected: close it immediately, clear the reference to
prevent double-close, then atomically decide whether a replacement can be created
(decrementing the counter on failure) or whether to return to the wait loop at
capacity.

### Test coverage

`tests/test_connection_pool_race_conditions.py` (12 tests) covers concurrent
acquire/release under load, leak prevention on failure, atomic counter bounds,
close-vs-acquire races, stale connection handling, pool-full behavior, exception
cleanup, double-close idempotency, null safety, and a 20-thread × 50-iteration stress
test. All pass consistently under high concurrency with no measurable performance
regression — locks are held only briefly for counter bookkeeping, and connection
creation happens outside the lock where possible.

---

## SQLite Performance Tuning

### `OrinStorage` constructor

```python
OrinStorage(
    db_path: Path,
    encryption_passphrase: str = None,
    pool_size: int = 10,
    pool_timeout: float = 30.0,
)
```

### Pool lifecycle

- `initialize_pool()` — initialize and warm up the pool
- `close_pool()` — close pool, re-encrypting the database if needed
- `get_pool_stats()` — returns `{max_connections, current_size, created_connections, closed}`

```python
storage = OrinStorage(Path("forensics.db"), pool_size=10)
storage.initialize_pool()
storage.initialize_db()

with storage.get_connection() as conn:   # pooled by default
    snapshot_id = storage.create_snapshot(conn)
    storage.store_processes(conn, snapshot_id, processes)
    conn.commit()

print(storage.get_pool_stats())
storage.close_pool()
```

Use `get_connection(use_pool=False)` for legacy non-pooled behavior.

### Applied PRAGMAs

| PRAGMA | Value | Effect |
|---|---|---|
| `journal_mode` | `WAL` | Readers don't block writers; better crash recovery |
| `synchronous` | `NORMAL` | Balanced durability/performance |
| `cache_size` | `-64000` | 64MB page cache |
| `temp_store` | `MEMORY` | Temp tables in RAM |
| `mmap_size` | `268435456` | 256MB memory-mapped I/O |
| `busy_timeout` | `30000` | 30s wait on lock contention |
| `foreign_keys` | `ON` | Referential integrity enforced |

### Batch inserts

```python
storage.batch_store_processes(snapshot_id, records, chunk_size=500)
storage.batch_store_kernel_symbols(snapshot_id, records, chunk_size=1000)
storage.batch_store_generic(table_name, columns, records, chunk_size=500)
```

Chunking reduces transaction overhead by roughly 90% on large imports (e.g. 500 records
in 25-record chunks = 20 transactions instead of 500).

### Database optimization

```python
stats = storage.optimize_database()
```

Applies all performance PRAGMAs plus `ANALYZE` on all tables; run after large imports.

### Concurrent access

Each thread acquires its own pooled connection; the pool handles thread-safety:

```python
def collector_thread(data):
    with storage.get_connection() as conn:
        snapshot_id = storage.create_snapshot(conn)
        storage.store_processes(conn, snapshot_id, data)
        conn.commit()
```

### Backward compatibility

All of the above is additive. Existing code continues to work unchanged; pooling is
opt-in via `initialize_pool()`, and new constructor parameters have sensible defaults.

### Test coverage

`tests/test_database_performance.py` (12 tests): pool init/acquire/release, concurrent
access, timeouts, WAL verification, PRAGMA application, batch inserts (generic and
specific), database optimization, and batch-vs-regular performance comparison.

---

## Encrypted Storage Exception Handling

`EncryptedStorage.encrypt_file()` and `decrypt_file()` implement comprehensive
validation, atomic writes, and structured logging.

### `encrypt_file()`

- Validates the plaintext file exists, is non-empty, and is accessible before starting.
- Writes ciphertext to a temporary file, then performs an atomic rename — no partial
  output files on failure.
- Temporary files are removed on any failure.
- Plaintext is deleted **only after** encryption succeeds; a warning is logged if
  cleanup of the plaintext itself fails.
- Raises `FileNotFoundError`, `PermissionError`, `ValueError`, or `IOError` as
  appropriate, with INFO-level success logs and ERROR-level failure logs.

### `decrypt_file()`

- Validates ciphertext and metadata files exist, salt is exactly 16 bytes, nonce is
  exactly 12 bytes, and ciphertext is non-empty.
- Validates that the salt in the metadata matches the salt embedded with the
  ciphertext (tamper check) before attempting decryption.
- GCM authentication failures (tampering, wrong passphrase) are caught and surface as
  `PermissionError` / `ValueError` as appropriate.
- Same atomic temp-file + rename + cleanup-on-failure pattern as encryption.

### Security properties

- No plaintext is ever left on disk after a failed encryption.
- GCM authentication tags provide tamper detection on decrypt.
- All operations are logged for audit trail purposes, including tampering attempts
  (logged at ERROR level).

### Test coverage

`tests/test_encryption_exceptions.py` (16 tests, 1 skipped when running as root) covers:
missing/empty files, successful roundtrip with plaintext cleanup, atomic-write failure
handling, missing ciphertext/metadata, wrong passphrase, tampered ciphertext, invalid
salt/nonce sizes, empty ciphertext, and logging on both success and failure paths.

### Recommendations for future work

- Secure memory zeroization of sensitive data after use
- Rate limiting on encryption/decryption operations
- Centralized audit log integration
- Automatic key rotation
- Pre-encryption backup strategy