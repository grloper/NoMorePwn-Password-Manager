---
name: verify-change
description: Verify a change to NoMorePwn actually works by exercising it, not by reading the diff. Use after changing anything under nomorepwn/ or nomorepwn_app/ — and before claiming a change works. Covers the Python test suite and headless Qt view driving.
---

# Verifying a change in NoMorePwn

This repo publishes a public GitHub Release on **every push to main**, tests run *after* merge, and
the built `.exe` is never executed before release. There is no PR gate. Verification is your job,
not CI's.

## Before you touch anything: are you about to write to the real vault?

`config.DATA_DIR` is `%APPDATA%\NoMorePwn`, not the repo. `config.DB_PATH` is a module-level
constant computed at **import time**, so `NOMOREPWN_DATA` only works if set *before* the process
imports `nomorepwn.config`. In-process, patch `config.DB_PATH` instead:

```python
self._real = config_module.DB_PATH
config_module.DB_PATH = Path(tempfile.mkdtemp()) / "vault.db"
# ... restore in tearDown
```

`python scripts/backup_tool.py restore <f> --force` will overwrite the developer's live vault.
Never run it to "check something".

## Pick the right level

| Changed | Run |
|---|---|
| `nomorepwn/` | `python -m unittest discover tests -v` |
| `nomorepwn_app/` views | `python -m unittest tests.test_views -v`, then `python NoMorePwn.py` if visual |
| Prefer the gate | `scripts/verify.sh` (ruff + unittest; sets `NOMOREPWN_DATA`) |

Shell is PowerShell 5.1: `&&` is a parser error, use `;`.

## Driving Qt views headlessly

`tests/test_views.py` sets `QT_QPA_PLATFORM=offscreen` at import, before `QApplication` — order
matters. One `QApplication` per process, created in `setUpModule`. This makes "I changed the audit
view" observable instead of assumed:

```python
view = AuditView(ctx)
view.set_vault(vlt)
view._render_report({...})
self.assertEqual(view.card_total.value.text(), "1")
```

Assert on widget state (`.text()`, `.isEnabled()`), not appearance. To drive a button, call
`.click()` — it runs the connected slot synchronously.

For work that hops threads via `workers.run_async`, call the underlying logic directly rather than
asserting on timing. Better still: move the logic into `nomorepwn/` as a pure function and test it
there (see `leakcheck.check_many`).

## Make the test fail first

A test that passes against the broken code proves nothing. Reintroduce the bug, watch the test
fail, restore, watch it pass.
