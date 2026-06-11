# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
"""
Unit tests for orin.analysis.yara_engine
"""
import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from pathlib import Path

from orin.analysis.yara_engine import YaraMatch, YaraScanResult, YaraEngine, YARA_AVAILABLE


class TestYaraMatch(unittest.TestCase):
    def test_to_dict(self):
        match = YaraMatch(
            rule_name="TestRule",
            namespace="test_ns",
            matched_strings=["string1"],
            tags=["malware"],
            meta={"author": "tester"},
            file_path="/tmp/test.exe",
            process_pid=1234,
            match_context="context_str",
        )
        d = match.to_dict()
        self.assertEqual(d["rule_name"], "TestRule")
        self.assertEqual(d["namespace"], "test_ns")
        self.assertEqual(d["file_path"], "/tmp/test.exe")
        self.assertEqual(d["process_pid"], 1234)

    def test_default_values(self):
        match = YaraMatch(rule_name="R", namespace="ns")
        self.assertEqual(match.matched_strings, [])
        self.assertEqual(match.tags, [])
        self.assertIsNone(match.file_path)
        self.assertIsNone(match.process_pid)
        self.assertIsNone(match.match_context)


class TestYaraScanResult(unittest.TestCase):
    def test_default_values(self):
        r = YaraScanResult()
        self.assertEqual(r.total_files_scanned, 0)
        self.assertEqual(r.total_matches, 0)
        self.assertEqual(r.matches, [])
        self.assertEqual(r.scan_errors, [])
        self.assertEqual(r.rules_loaded, 0)

    def test_to_dict(self):
        match = YaraMatch(rule_name="R", namespace="ns")
        r = YaraScanResult(
            total_files_scanned=5,
            total_matches=1,
            matches=[match],
            scan_errors=["error1"],
            rules_loaded=10,
        )
        d = r.to_dict()
        self.assertEqual(d["total_files_scanned"], 5)
        self.assertEqual(d["total_matches"], 1)
        self.assertEqual(len(d["matches"]), 1)
        self.assertEqual(d["scan_errors"], ["error1"])
        self.assertEqual(d["rules_loaded"], 10)


class TestYaraEngineInitialization(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_init_with_custom_dirs(self):
        dirs = [Path("/tmp/rules")]
        engine = YaraEngine(rules_dirs=dirs)
        self.assertEqual(engine.rules_dirs, dirs)
        self.assertIsNone(engine.compiled_rules)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_init_uses_default_dirs(self):
        engine = YaraEngine()
        self.assertIsNotNone(engine.rules_dirs)
        self.assertGreater(len(engine.rules_dirs), 0)

    def test_init_raises_without_yara(self):
        """When YARA is not available, should raise RuntimeError."""
        with patch("orin.analysis.yara_engine.YARA_AVAILABLE", False):
            with self.assertRaises(RuntimeError):
                YaraEngine()


class TestYaraEngineComputeRulesHash(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_hash_is_deterministic(self):
        engine = YaraEngine(rules_dirs=[])
        content = {"rule_a": "rule A {}", "rule_b": "rule B {}"}
        h1 = engine._compute_rules_hash(content)
        h2 = engine._compute_rules_hash(content)
        self.assertEqual(h1, h2)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_different_content_different_hash(self):
        engine = YaraEngine(rules_dirs=[])
        h1 = engine._compute_rules_hash({"a": "rule A {}"})
        h2 = engine._compute_rules_hash({"a": "rule B {}"})
        self.assertNotEqual(h1, h2)


class TestYaraEngineLoadRules(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_load_rules_no_dirs(self):
        """No directories => 0 rules loaded."""
        engine = YaraEngine(rules_dirs=[Path("/nonexistent_empty_dir_xyz")])
        count = engine.load_rules()
        self.assertEqual(count, 0)
        self.assertIsNone(engine.compiled_rules)


    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_load_rules_dir_not_exist(self):
        engine = YaraEngine(rules_dirs=[Path("/nonexistent")])
        count = engine.load_rules()
        self.assertEqual(count, 0)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_load_rules_caches_if_unchanged(self):
        """If rules hash is unchanged, should skip recompilation."""
        import yara
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = MagicMock()
        engine._rules_hash = "abc123"
        engine.loaded_rules_count = 5

        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "glob", return_value=[Path("/fake/rule.yar")]), \
             patch.object(Path, "read_text", return_value="rule test {}"), \
             patch.object(engine, "_compute_rules_hash", return_value="abc123"):
            count = engine.load_rules()
        self.assertEqual(count, 5)  # Returned cached count


class TestYaraEngineScanFile(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_file_no_rules_loaded(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = None
        result = engine.scan_file(Path("/some/file.exe"))
        self.assertEqual(result, [])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_file_not_exists(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = MagicMock()
        with patch.object(Path, "exists", return_value=False):
            result = engine.scan_file(Path("/nonexistent.exe"))
        self.assertEqual(result, [])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_file_returns_matches(self):
        import yara

        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()

        # Mock a yara match object
        mock_match = MagicMock()
        mock_match.rule = "TestRule"
        mock_match.namespace = "test"
        mock_match.strings = []
        mock_match.tags = ["malware"]
        mock_match.meta = {}

        mock_compiled.match.return_value = [mock_match]
        engine.compiled_rules = mock_compiled

        with patch.object(Path, "exists", return_value=True):
            results = engine.scan_file(Path("/some/malware.exe"))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].rule_name, "TestRule")
        self.assertEqual(results[0].tags, ["malware"])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_file_handles_timeout(self):
        import yara

        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()
        mock_compiled.match.side_effect = yara.TimeoutError
        engine.compiled_rules = mock_compiled

        with patch.object(Path, "exists", return_value=True):
            result = engine.scan_file(Path("/slow_file.bin"))
        self.assertEqual(result, [])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_file_handles_exception(self):
        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()
        mock_compiled.match.side_effect = Exception("unexpected error")
        engine.compiled_rules = mock_compiled

        with patch.object(Path, "exists", return_value=True):
            result = engine.scan_file(Path("/some/file.bin"))
        self.assertEqual(result, [])


class TestYaraEngineScanData(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_data_no_rules(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = None
        result = engine.scan_data(b"some data")
        self.assertEqual(result, [])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_data_returns_matches(self):
        import yara

        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()

        mock_match = MagicMock()
        mock_match.rule = "MemRule"
        mock_match.namespace = "mem"
        mock_match.strings = []
        mock_match.tags = []
        mock_match.meta = {}

        mock_compiled.match.return_value = [mock_match]
        engine.compiled_rules = mock_compiled

        results = engine.scan_data(b"\x4d\x5a\x90\x00", "pid_1234")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].rule_name, "MemRule")
        self.assertEqual(results[0].process_pid, 1234)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_data_timeout_handled(self):
        import yara

        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()
        mock_compiled.match.side_effect = yara.TimeoutError
        engine.compiled_rules = mock_compiled

        result = engine.scan_data(b"data", "memory_dump")
        self.assertEqual(result, [])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_data_exception_handled(self):
        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()
        mock_compiled.match.side_effect = RuntimeError("boom")
        engine.compiled_rules = mock_compiled

        result = engine.scan_data(b"data")
        self.assertEqual(result, [])


class TestYaraEngineExtractMatchContext(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_extract_context_empty_strings(self):
        engine = YaraEngine(rules_dirs=[])
        result = engine._extract_match_context(b"some data", [])
        self.assertIsNone(result)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_extract_context_returns_text(self):
        engine = YaraEngine(rules_dirs=[])
        data = b"Hello, MALWARE, World!"

        mock_string = MagicMock()
        mock_string.offset = 7
        mock_string.matched_data = b"MALWARE"

        result = engine._extract_match_context(data, [mock_string], context_bytes=5)
        self.assertIsNotNone(result)
        self.assertIn("MALWARE", result)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_extract_context_handles_exception(self):
        engine = YaraEngine(rules_dirs=[])
        # Pass a broken string object that will raise an exception
        result = engine._extract_match_context(b"data", [object()])
        self.assertIsNone(result)


class TestYaraEngineScanDirectory(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_directory_no_rules_loaded(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = None
        result = engine.scan_directory(Path("/some/dir"))
        self.assertIn("No YARA rules loaded", result.scan_errors)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_directory_not_exists(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = MagicMock()
        with patch.object(Path, "exists", return_value=False):
            result = engine.scan_directory(Path("/nonexistent"))
        self.assertEqual(len(result.scan_errors), 1)
        self.assertIn("does not exist", result.scan_errors[0])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_directory_empty(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = MagicMock()
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "rglob", return_value=iter([])):
            result = engine.scan_directory(Path("/empty_dir"))
        self.assertEqual(result.total_files_scanned, 0)
        self.assertEqual(result.total_matches, 0)


if __name__ == "__main__":
    unittest.main()
