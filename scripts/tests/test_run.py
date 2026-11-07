"""Native launcher integration tests; supply a built app via SEKSCAN_TEST_BINARY."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get("SEKSCAN_TEST_BINARY"), "set SEKSCAN_TEST_BINARY to a built sekscan")
class NativeLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sekscan launcher ")
        self.root = Path(self.temp.name)
        shutil.copy2(ROOT / "run.sh", self.root / "run.sh")
        shutil.copy2(ROOT / ".env.example", self.root / ".env.example")
        (self.root / ".run").mkdir()
        shutil.copy2(os.environ["SEKSCAN_TEST_BINARY"], self.root / ".run/sekscan")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.env = os.environ.copy()
        self.env.pop("SEKSCAN_ENV_FILE", None)
        self.settings = (
            f"SEKSCAN_PORT={self.port}\nSEKSCAN_START_TIMEOUT=3\nSEKSCAN_STOP_TIMEOUT=3\n"
            "SEKSCAN_WORKSPACE='./persistent workspace'\n"
            "SEKSCAN_SETTINGS_JSON='{\"project\":{\"namespace\":\"launcher-test\"}}'\n"
        )
        self.write_env()

    def write_env(self, extra=""):
        (self.root / ".env").write_text(self.settings + extra)

    def run_app(self, *args, expected=0):
        result = subprocess.run(
            [str(self.root / "run.sh"), *args], cwd="/tmp", env=self.env,
            text=True, capture_output=True, timeout=20,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result.stdout

    def tearDown(self):
        self.write_env()
        self.run_app("stop")
        self.temp.cleanup()

    def test_default_workspace_is_app_directory(self):
        self.settings = self.settings.replace("SEKSCAN_WORKSPACE='./persistent workspace'\n", "")
        self.env.pop("SEKSCAN_WORKSPACE", None)
        self.write_env()
        self.run_app("cli", "config", "show")
        self.assertTrue((self.root / ".run-settings.json").exists())
        self.assertTrue((self.root / ".sekscan-workspace").exists())
        self.assertFalse((self.root / "workspace").exists())

    def test_lifecycle_and_preserved_data(self):
        self.run_app("status", expected=1)
        self.assertIn("Started:", self.run_app("start"))
        self.assertIn("Already running", self.run_app("start"))
        self.assertIn("Running", self.run_app("status"))
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=3) as response:
            self.assertEqual(response.status, 200)
        self.assertIn(f"http://127.0.0.1:{self.port}", self.run_app("logs"))
        self.run_app("build", expected=1)
        settings = self.root / "persistent workspace/.run-settings.json"
        self.assertEqual(json.loads(settings.read_text())["project"]["namespace"], "launcher-test")
        shown = json.loads(self.run_app("cli", "config", "show"))
        self.assertEqual(shown["project"]["namespace"], "launcher-test")
        self.run_app("restart")
        sentinel = self.root / "persistent workspace/data/keep.txt"
        sentinel.write_text("scan history must survive clean")
        self.run_app("clean")
        self.assertTrue(sentinel.exists())
        self.assertTrue((self.root / ".env").exists())
        self.assertFalse((self.root / ".run/sekscan").exists())
        self.assertFalse((self.root / ".run/app.log").exists())

    def test_invalid_config_does_not_start(self):
        self.write_env("SEKSCAN_SETTINGS_JSON='{broken}'\n")
        self.run_app("start", expected=2)
        self.assertFalse((self.root / ".run/app.pid").exists())

    def test_dotenv_is_literal_and_stale_pid_is_safe(self):
        self.write_env("SEKSCAN_DB_DSN='$(touch SHOULD_NOT_EXIST)'\n")
        self.run_app("cli", "config", "show")
        self.assertFalse((self.root / "SHOULD_NOT_EXIST").exists())
        (self.root / ".run/app.pid").write_text(f"{os.getpid()} 0\n")
        self.run_app("stop")
        self.assertFalse((self.root / ".run/app.pid").exists())

    def test_port_collision_is_reported(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", self.port))
            sock.listen()
            self.run_app("start", expected=1)
        self.run_app("status", expected=1)


if __name__ == "__main__":
    unittest.main()
