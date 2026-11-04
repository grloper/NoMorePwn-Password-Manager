# Audit (2026-11-03, branch ai/finish-v1)

Method: read the code, built it from a clean venv, ran the tests, ran the app. Not an independent audit.

## What exists
Python 3.13 / PySide6 desktop vault (`nomorepwn/` core, `nomorepwn_app/` GUI), SQLite storage, Chromium/Firefox login-capture extension (`extension/`, native messaging host), PyInstaller + Inno Setup packaging, CI (lint, tests, manual release). The repo description undersells it: groups, history, generator, search, auto-lock, backup/restore, recovery kit, breach check, updater and audit view all exist in code.

## Build and run
- From source: `python -m venv .venv`, `pip install -r requirements.txt`, `python -m nomorepwn_app`. Works.
- Packaged: `pyinstaller build/NoMorePwn.spec` produced `dist/NoMorePwn.exe` (47.2 MB, single file, Windows). Launched it: window opens, data dir and IPC token created.
- Tests: 306 Python tests pass (11 skipped, Linux/optional), 5 extension tests pass, 88-test GUI subset re-run clean. Browser e2e scripts not re-run here.

## Security review
| Area | Finding |
|---|---|
| KDF | Argon2id t=3, m=64 MiB, p=4, 16-byte random salt; PBKDF2-SHA256 600k fallback; parameters bounds-checked before use. Sound. |
| Encryption | AES-256-GCM via `cryptography`, fresh random 96-bit nonce per seal, AAD binds row and field. Sound. |
| Key storage | Derived key in memory only while unlocked; never written. Python cannot zeroize it. |
| Clipboard | Auto-clear after 20 s only if unchanged. Was missing Windows history/cloud exclusion (fixed here). |
| Browser capture | Local IPC socket, current user only, per-install 256-bit token (constant-time compare). Locked vault rejects capture, no plaintext queue. No network listener. |
| Logs | No logging of secrets found (no logging of credentials; grep clean). |
| Dependencies | pip-audit on requirements.txt and npm audit: 0 known vulnerabilities. Version ranges, no hash lock. |

## Ranked issues
- Critical: none found.
- High: none found in the vault design.
- Medium (fixed): clipboard copies were eligible for Windows Win+V history and cloud clipboard.
- Medium (open): service names, usernames, groups are plaintext in SQLite; KDF params unauthenticated; no unlock rate limit; master password not Unicode-normalized (changing it would break existing vaults, so not changed); installers unsigned, deps not hash-locked; capture success is heuristic.
