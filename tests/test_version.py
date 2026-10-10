"""The repo-root VERSION file is the single source of truth for the release version."""
import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VERSION = (REPO / "VERSION").read_text(encoding="utf-8").strip()


class VersionConsistencyTests(unittest.TestCase):
    def test_version_file_is_plain_semver(self):
        self.assertRegex(VERSION, r"^\d+\.\d+\.\d+$")

    def test_core_package_matches(self):
        import nomorepwn

        self.assertEqual(nomorepwn.__version__, VERSION)

    def test_extension_manifest_and_package_match(self):
        for rel in ("extension/manifest.json", "extension/package.json", "extension/dist/chrome/manifest.json",
                    "extension/dist/firefox/manifest.json"):
            data = json.loads((REPO / rel).read_text(encoding="utf-8"))
            self.assertEqual(data["version"], VERSION, rel)

    def test_installer_default_matches(self):
        iss = (REPO / "build/installer.iss").read_text(encoding="utf-8")
        self.assertIn(f'#define MyAppVersion "{VERSION}"', iss)

    def test_sync_script_check_passes(self):
        import subprocess
        import sys

        r = subprocess.run([sys.executable, str(REPO / "scripts/sync_version.py"), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_release_workflow_reads_version_file(self):
        wf = (REPO / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("VERSION", wf)
        self.assertNotIn("1.0.${{ github.run_number }}", wf)


if __name__ == "__main__":
    unittest.main()
