# Changelog

## 1.0.27

- Added `docs/AUDIT.md`, a code audit of the app with findings and open gaps.
- Windows: copied secrets are now excluded from clipboard history and cloud clipboard sync (opt-out formats).
- A copied secret is wiped from the clipboard when the app quits.
- Fixed a test-process crash at exit (CI teardown) and an encoding problem introduced with the clipboard change.
- Relicensed under the MIT License (`LICENSE`).
- Added launch visuals (banner, real app captures, security card, threat-model diagram) and a dev.to article draft.
- Version now has a single source of truth (`VERSION` file plus `scripts/sync_version.py`).

## 1.0.26

- Added `SECURITY.md` and the threat model.
