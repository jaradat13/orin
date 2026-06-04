# Contributing to Orin

Thanks for your interest in contributing. Orin is a **zero-dependency, fully offline** forensic engine — keeping it that way is the most important constraint when evaluating any contribution.

---

## Ground Rules

- **No third-party runtime dependencies.** The entire engine must run on Python ≥ 3.10 standard library only. If you need JSON, SQLite, HMAC, or regex — it is already available. Do not add `pip install` requirements.
- **No network calls at runtime.** Collectors read from the local filesystem and kernel interfaces only. Nothing may make an outbound connection during `collect`, `analyze`, or `report`.
- **No shell subprocesses.** Read directly from `/proc`, `/sys`, and other kernel interfaces. Do not use `subprocess.run(["ps", ...])` or similar — it is fragile, privilege-dependent, and slower.
- **All contributions must include tests.** A pull request without a corresponding test file will not be merged.

---

## Development Setup

```bash
git clone https://github.com/jaradat13/orin.git
cd orin

# Run without installing (recommended for development)
PYTHONPATH=src python -m orin.main status

# Or install in editable mode
pip install -e .
```

Run the full test suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

All tests must pass before opening a pull request.

---

## Architecture Overview

```
src/orin/
├── main.py              # CLI entry point & subcommand router
├── core/
│   ├── config.py        # JSON config loader with safe defaults
│   ├── crypto.py        # HMAC-SHA256 sign & verify
│   └── database.py      # SQLite schema & OrinStorage ORM
├── collectors/          # One file per data source
│   ├── processes.py
│   ├── connections.py
│   ├── crontabs.py
│   └── ...
└── analysis/
    ├── engine.py        # Threat detection rules (reads from DB, writes security_events)
    ├── diff.py          # Cross-snapshot comparator
    ├── timeline.py      # Intra-vault delta
    ├── unhide.py        # Out-of-band hidden process scanner
    └── reporter.py      # Markdown & HTML report compilers
```

The data pipeline is linear:

```
orin collect  →  collectors/*.py  →  SQLite vault
orin analyze  →  analysis/engine.py  →  security_events table
orin report   →  analysis/reporter.py  →  Markdown / HTML
```

---

## How to Add a New Collector

A collector is a single Python file under `src/orin/collectors/` that reads a system data source and persists a structured snapshot to the SQLite vault.

### Step 1 — Define the schema in `database.py`

Add a `CREATE TABLE IF NOT EXISTS` block inside `OrinStorage.initialize_db()`:

```python
cursor.execute("""
    CREATE TABLE IF NOT EXISTS collected_example (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_id INTEGER NOT NULL,
        field_one   TEXT    NOT NULL,
        field_two   TEXT,
        FOREIGN KEY (snapshot_id) REFERENCES system_snapshots(id)
    )
""")
```

Use `snapshot_id` as the foreign key on every table — this is how all data is tied to a point-in-time snapshot.

### Step 2 — Write the collector module

Create `src/orin/collectors/example.py`:

```python
"""Collector: example data source."""

from __future__ import annotations


def collect_example() -> list[dict]:
    """
    Read from the kernel/filesystem and return a list of records.
    Each dict maps directly to a row in collected_example.
    Never call subprocess or make network requests here.
    """
    results = []
    # ... read from /proc, /sys, /etc, etc.
    return results
```

Return a plain list of dicts. No database access inside the collector — that stays in `main.py`.

### Step 3 — Wire it into `main.py`

In the `collect` subcommand handler, call your collector and persist the results:

```python
from orin.collectors.example import collect_example

example_rows = collect_example()
for row in example_rows:
    storage.insert_example(snapshot_id, row["field_one"], row.get("field_two"))
```

Add the corresponding `insert_example` method to `OrinStorage` in `database.py`.

### Step 4 — Write the test

Create `tests/test_example.py`. Use `unittest.mock.patch` or `unittest.mock.mock_open` to mock filesystem reads — **never read real `/proc` or `/etc` files in tests**.

```python
import unittest
from unittest.mock import patch, mock_open
from orin.collectors.example import collect_example


class TestExampleCollector(unittest.TestCase):

    @patch("builtins.open", mock_open(read_data="..."))
    def test_parses_correctly(self):
        results = collect_example()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["field_one"], "expected_value")


if __name__ == "__main__":
    unittest.main()
```

---

## How to Add a New Threat Detection Rule

All rules live in `src/orin/analysis/engine.py` inside the `run_analysis(snapshot_id, storage, config)` function.

### Pattern

```python
# --- My New Rule ---
rows = storage.get_example(snapshot_id)
for row in rows:
    if some_condition(row):
        storage.insert_security_event(
            snapshot_id  = snapshot_id,
            event_type   = "my_rule_identifier",      # snake_case, unique per rule
            severity     = "high",                    # critical / high / medium / low
            description  = f"Human-readable detail about {row['field_one']}",
            source       = "example_collector",
            raw_data     = str(row),
        )
```

### Severity guide

| Severity | When to use |
|----------|-------------|
| `critical` | Active exploitation / immediate system compromise (e.g. rootkit detected, UID-0 backdoor) |
| `high` | Strong indicator of malicious intent (e.g. reverse shell pattern, volatile exec) |
| `medium` | Suspicious but context-dependent (e.g. unexpected port, new cron job) |
| `low` | Informational drift worth tracking (e.g. new SSH key, config change) |

### Adding auto-resolution

If the anomaly is transient (e.g. a process that can be killed, a cron job that can be removed), add a resolver block in the same function:

```python
storage.resolve_events_where_not_present(
    event_type     = "my_rule_identifier",
    current_values = {row["field_one"] for row in rows},
    match_field    = "field_one_value_in_description",
)
```

Check existing resolvers in `engine.py` for the exact calling convention.

---

## Pull Request Checklist

Before opening a PR, confirm:

- [ ] `PYTHONPATH=src python3 -m unittest discover -s tests -v` passes with zero failures.
- [ ] No new runtime dependencies introduced.
- [ ] No `subprocess` calls added in any collector.
- [ ] New collector has a corresponding `tests/test_<name>.py` file.
- [ ] New DB table uses `CREATE TABLE IF NOT EXISTS` (so `orin init` is safe to re-run).
- [ ] Severity levels follow the guide above.
- [ ] `README.md` telemetry table and `ROADMAP.md` updated if applicable.

---

## What to Work On

Good first issues are labelled [`good first issue`](../../issues?q=is%3Aopen+label%3A%22good+first+issue%22) on GitHub. If you want to pick up a planned feature, check the [`ROADMAP.md`](ROADMAP.md) — every item there is up for grabs. Leave a comment on the relevant issue first so we can coordinate.

If you have an idea not in the roadmap, open an issue before writing code — a quick discussion saves both of us time.

---

## Code Style

- Follow **PEP 8**. Line length: 100 characters.
- Use f-strings over `.format()`.
- All public functions must have a one-line docstring.
- Type hints are encouraged for function signatures.
- No `print()` in library code — use `logging` or return data to the caller.
