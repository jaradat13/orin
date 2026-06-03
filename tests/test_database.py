import unittest
from pathlib import Path
from orin.core.database import OrinStorage

class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_db_unit.db")
        self.storage = OrinStorage(self.db_path)

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_initialize_db(self):
        self.storage.initialize_db()
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row["name"] for row in cursor.fetchall()}
            
            expected_tables = {
                "system_snapshots",
                "baseline_kernel_modules",
                "collected_processes",
                "collected_ports",
                "collected_outbound_connections",
                "collected_kernel_modules",
                "collected_ssh_keys",
                "collected_file_hashes",
                "security_events",
                "baseline_users",
                "collected_users"
            }
            
            for table in expected_tables:
                self.assertIn(table, tables, f"Table {table} missing from DB schema.")

if __name__ == "__main__":
    unittest.main()
