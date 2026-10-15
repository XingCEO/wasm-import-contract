import json
import subprocess
import sys
import unittest


class NativeFileTests(unittest.TestCase):
    def test_committed_native_fixture(self):
        result = subprocess.run(
            [sys.executable, "-m", "wasm_import_contract"]
            + ["--wasm", "examples/plugin.wasm", "--host", "examples/host.json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsInstance(json.loads(result.stdout), dict)

    def test_missing_native_path_is_clean_error(self):
        args = ["--wasm", "examples/plugin.wasm", "--host", "examples/host.json"]
        args[1] = "nonexistent-test-input"
        result = subprocess.run(
            [sys.executable, "-m", "wasm_import_contract"] + args,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)
