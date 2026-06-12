# Orin Testing Guidelines & Contributor Onboarding

This document provides guidelines for setting up the development environment, running tests, and writing new tests for the Orin Forensic Engine.

---

## 🛠️ Local Environment Setup

Orin uses optional dependencies for testing and development. To set up your local development environment:

1. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install Orin in editable mode with development dependencies:**
   ```bash
   pip install -e .[dev]
   ```
   This command installs Orin along with `pytest` and `pytest-cov` as defined in `pyproject.toml`.

---

## 🧪 Running Tests

Orin uses `pytest` as its primary test runner.

### Running the Test Suite
To run the test suite locally:
```bash
ORIN_TEST_FAST=1 pytest
```

> [!TIP]
> The `ORIN_TEST_FAST=1` environment variable skips slow-running integrations (like real eBPF loads, heavy subprocess calls, or extensive database writes) to ensure rapid developer feedback.

### Fast vs. Full Test Modes

Orin supports two testing modes controlled by the `ORIN_TEST_FAST` environment variable:

| Environment Variable | Description | Use Case |
|----------------------|-------------|----------|
| `ORIN_TEST_FAST=1` (Recommended) | Skips long-running or system-level integration tests. | Active local development & rapid feedback loop. |
| `ORIN_TEST_FAST=0` (or unset) | Runs the complete test suite including eBPF setups, heavy operations, and stress tests. | Pre-commit validation and CI checks. |

### Legacy Test Runner (Alternative)
You can still run the legacy `unittest` suite directly, though it does not generate coverage reports:
```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

---

## 📊 Test Coverage Gate

To maintain engine stability and code reliability, Orin enforces a strict coverage threshold:

> [!IMPORTANT]
> **85% Minimum Code Coverage:** The CI pipeline will fail if total test coverage falls below 85%.
> This is configured via `[tool.pytest.ini_options]` in `pyproject.toml`.

### Checking Coverage Locally
When running tests, a detailed terminal report will list missing line coverage:
```bash
# Run tests and show missing lines in terminal
pytest --cov=orin --cov-report=term-missing
```

Certain files that cannot be tested safely in CI (e.g., remote daemon servers or the CLI entry points) are omitted from coverage tracking under `[tool.coverage.run]` in `pyproject.toml`.

---

## ✍️ Writing New Tests

### Test File Location & Naming
- All test files must be located in the [tests/](file:///home/musa/orin/tests) directory.
- Test files must be prefixed with `test_` (e.g., `test_my_feature.py`).
- Test classes should inherit from `unittest.TestCase` or use standard `pytest` assertion patterns.

### Temporary Databases
When testing database operations, **never** read or write to the active `orin_vault.db`. Instead, create a temporary SQLite database during setup and ensure it is cleaned up afterwards.

Example:
```python
import unittest
from pathlib import Path
from orin.core.database import OrinStorage

class TestMyFeature(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_db_temp.db")
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_database_write(self):
        # Your test logic here...
        pass
```

### Mocking System Interaction & eBPF
Since Orin is a forensic engine that interacts deeply with the Linux kernel and system state:
- Use `unittest.mock.patch` to mock system commands, process execution, or file systems.
- Mock kernel modules or eBPF configurations to prevent tests from requiring root privileges.

Example of patching a system utility:
```python
from unittest.mock import patch
import unittest

class TestSystemCheck(unittest.TestCase):
    @patch("subprocess.run")
    def test_system_command(self, mock_run):
        # Configure the mock to return desired stdout
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = b"active"
        
        # Call the function and assert behavior
        # ...
```
