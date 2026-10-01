"""Execute the real Windows source host from the browser's working directory."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nomorepwn import config
from nomorepwn_app import browser_bridge


@unittest.skipUnless(sys.platform == "win32", "Windows native host launcher")
class SourceLauncherTests(unittest.TestCase):
    def test_ping_from_data_directory_without_pythonpath(self):
        with tempfile.TemporaryDirectory(prefix="nomorepwn launcher ") as directory:
            data = Path(directory)
            with patch.object(config, "DATA_DIR", data):
                launcher = browser_bridge._ensure_launcher()
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            env["NOMOREPWN_DATA"] = str(data)
            payload = json.dumps({"type": "ping"}).encode()
            result = subprocess.run([str(launcher)], input=struct.pack("<I", len(payload)) + payload,
                                    cwd=data, env=env, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            length = struct.unpack("<I", result.stdout[:4])[0]
            reply = json.loads(result.stdout[4:4 + length])
            self.assertEqual(reply["type"], "pong")
            self.assertFalse(reply["vaultPresent"])
