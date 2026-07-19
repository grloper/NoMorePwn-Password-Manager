"""Build browser-specific extension packages.

Chrome and Firefox have incompatible manifest requirements for MV3 background
scripts: Chrome requires ``service_worker`` and rejects ``scripts``; Firefox
requires ``scripts`` and may not support ``service_worker``.

This script copies the extension source into per-browser output directories
with the correct manifest for each.

Usage:
    python extension/build.py          # builds both
    python extension/build.py chrome   # Chrome only
    python extension/build.py firefox  # Firefox only

Output:
    extension/dist/chrome/
    extension/dist/firefox/
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT  # the extension source is the extension/ directory itself
DIST = ROOT / "dist"

# Files and directories that should NOT be copied into dist.
EXCLUDE = {"dist", "build.py", "node_modules", "package.json", "package-lock.json", "tests", ".git"}


def _copy_source(target: Path) -> None:
    """Copy the extension source tree to *target*, excluding build artifacts."""
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)

    for item in SRC.iterdir():
        if item.name in EXCLUDE:
            continue
        dest = target / item.name
        if item.is_dir():
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)


def _read_manifest(target: Path) -> dict:
    return json.loads((target / "manifest.json").read_text(encoding="utf-8"))


def _write_manifest(target: Path, manifest: dict) -> None:
    (target / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_chrome() -> Path:
    """Build the Chrome/Edge/Brave variant."""
    target = DIST / "chrome"
    _copy_source(target)
    manifest = _read_manifest(target)

    # Chrome does not need browser_specific_settings (Gecko-only).
    manifest.pop("browser_specific_settings", None)

    # Ensure background uses service_worker (already the default).
    bg = manifest.setdefault("background", {})
    bg.pop("scripts", None)
    bg["service_worker"] = "src/background/service-worker.js"

    _write_manifest(target, manifest)
    print(f"  [OK] Chrome build -> {target}")
    return target


def build_firefox() -> Path:
    """Build the Firefox variant."""
    target = DIST / "firefox"
    _copy_source(target)
    manifest = _read_manifest(target)

    # Firefox requires scripts, not service_worker.
    bg = manifest.setdefault("background", {})
    bg.pop("service_worker", None)
    bg["scripts"] = ["src/background/service-worker.js"]
    # Keep "type": "module" — Firefox supports ES module event pages.

    # Firefox ignores the Chrome key field.
    manifest.pop("key", None)

    _write_manifest(target, manifest)
    print(f"  [OK] Firefox build -> {target}")
    return target


def main() -> None:
    targets = sys.argv[1:] or ["chrome", "firefox"]
    print("Building extension packages...")
    for t in targets:
        if t.lower() == "chrome":
            build_chrome()
        elif t.lower() == "firefox":
            build_firefox()
        else:
            print(f"  [ERR] Unknown target: {t}")
            sys.exit(1)
    print("Done.")


if __name__ == "__main__":
    main()
