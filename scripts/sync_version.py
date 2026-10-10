#!/usr/bin/env python3
"""Propagate the repo-root VERSION file into every place that must carry a version.

VERSION is the single source of truth. Usage:
    python scripts/sync_version.py            # rewrite derived files
    python scripts/sync_version.py --check    # exit 1 if any derived file is out of sync
After changing VERSION, run this, then `python extension/build.py` (rebuilds extension/dist).
Releases are created from VERSION by .github/workflows/release.yml; this script never tags or publishes.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
if not re.fullmatch(r"\d+\.\d+\.\d+", VERSION):
    sys.exit(f"VERSION must be MAJOR.MINOR.PATCH, got {VERSION!r}")

# (file, regex whose group 1 is the prefix and group 3 the suffix around the version)
TARGETS = [
    ("nomorepwn/__init__.py", r'(__version__ = ")([^"]*)(")'),
    ("extension/manifest.json", r'(^  "version": ")([^"]*)(")'),
    ("extension/package.json", r'(^  "version": ")([^"]*)(")'),
    ("extension/package-lock.json", r'(^  "version": ")([^"]*)(")'),
    ("build/installer.iss", r'(#define MyAppVersion ")([^"]*)(")'),
]


def main() -> int:
    check = "--check" in sys.argv[1:]
    bad = []
    for rel, pattern in TARGETS:
        path = ROOT / rel
        text = path.read_text(encoding="utf-8")
        new, n = re.subn(pattern, lambda m: m.group(1) + VERSION + m.group(3), text, count=1, flags=re.M)
        if n != 1:
            bad.append(f"{rel}: version field not found")
        elif new != text:
            if check:
                bad.append(f"{rel}: out of sync with VERSION ({VERSION})")
            else:
                path.write_text(new, encoding="utf-8", newline="")
                print(f"updated {rel}")
    for msg in bad:
        print(msg, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
