---
name: verify-change
description: Verify a change to NoMorePwn actually works by exercising it, not by reading the diff. Use after changing anything under nomorepwn/, nomorepwn_app/, or extension/ — and before claiming a change works. Covers both test suites, headless Qt view driving, and spawning the native-messaging host.
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
| `extension/src/` | `cd extension; npm test` |
| native host / entry points | `NativeHostTests`, plus spawn the real process (below) |

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

## Spawning the native host for real

The browser launches it as a child process and speaks 4-byte little-endian length + JSON frames.
`NativeHostTests` covers the framing against `io.BytesIO`; to exercise the actual process:

```python
proc = subprocess.Popen([sys.executable, "-m", "nomorepwn_app", "--native-host"],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
payload = json.dumps({"type": "ping"}).encode()
out, _ = proc.communicate(struct.pack("<I", len(payload)) + payload)
```

Any stray stdout write corrupts the stream; the only symptom is a dropped connection. If the host
misbehaves, check for `print()` before suspecting the protocol.

## Make the test fail first

A test that passes against the broken code proves nothing. This repo has already shipped a test
that passed for the wrong reason (`vaultPresent` asserted only in the False direction, against an
empty sandbox, while the check was permanently broken).

So: reintroduce the bug, watch the test fail, restore, watch it pass.

```
# reintroduce the bug, then:
python -m unittest tests.test_core.NativeHostTests    # expect failures
# restore, then re-run                                 # expect OK
```

For any boolean-returning check, assert **both** directions.

## Before you claim it works

- Did you run the suite, or infer from the diff? Say which.
- If a suite failed, report the output — do not describe it as passing.
- Does a test actually cover what you changed? Several invariants in CLAUDE.md have **no test**;
  a green suite is not evidence they hold.
- If you changed `extension/`, remember CI never runs `npm test`.
