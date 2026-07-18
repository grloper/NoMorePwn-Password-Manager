---
name: extension-change
description: Checklist for editing the NoMorePwn browser extension under extension/src/. Use when touching the service worker, content scripts, credential holder, pending store, or native-messaging bridge. Covers the MV3 and credential-lifetime traps that its 52-check suite does not all cover, and that CI never runs.
---

# Changing the NoMorePwn extension

`extension/` is a Manifest V3 extension that captures credentials **only after verifying a login
succeeded**. It holds plaintext credentials in memory for seconds at a time, so the failure modes
here are worse than usual.

**CI never runs `npm test`.** `cd extension; npm test` is the only thing that will catch you.

## The credential lifetime rules

Credentials live in the **background service worker only** — never in a content script. A content
script shares a renderer process with the page it is defending against. `capture.js` reads the
credential, ships it to the worker, and drops it; the SPA observer reports only a *verdict*.

Do not reintroduce "encrypt in the content script": `chrome.runtime.sendMessage` uses internal IPC
that page JS cannot observe, and the key would live in the same renderer as the hostile page.

Every exit path must wipe:

- `pending-store.discard()` = remove + wipe. Use this by default.
- `pending-store.detach()` = remove **without** wiping. The caller then owns `entry.holder` and
  **must** `.finally(() => entry.holder.wipe())`.

`detach()` exists so the success path can be atomic. Reading a credential is async
(`subtle.decrypt`); leaving the entry in the map across that await lets a trailing 401, the 5s
deadline, or a closed tab resolve the same capture twice — or wipe the holder mid-decrypt. Detach
**synchronously**, then await. The `if (!entry) return` after detach is the exactly-once guard.

## Traps that will not announce themselves

- **`Object.create()` does not install `#private` fields.** `SecureCredentialHolder` is built via
  `create()` because construction is async (`generateKey` is awaited). `Object.create()` bypasses
  the constructor, so the `INTERNAL` token check never fires *and* `#key`/`#iv`/`#ciphertext` are
  never installed — you get a `TypeError` on first write. This has already happened here.
- **Register every `chrome.*` listener at module top level** in `service-worker.js`. Registering in
  a callback or after an `await` means the worker misses the very events that would have woken it
  after an idle teardown.
- **`capture.js` cannot import.** Content scripts are classic scripts, so it hardcodes its own copy
  of the message-type strings. Renaming a type in `shared/messages.js` leaves all 52 checks green
  and the capture path silently dead. It has zero test coverage — grep for the literal.
- **`content_scripts.js` is load-ordered.** `spa-observer.js` must stay before `capture.js`.
- **The SPA observer never gets its advertised 10s.** `WINDOW_MS = 10000` in the content script, but
  `VERIFICATION_WINDOW_MS = 5000` in the background store hard-caps it, and late verdicts are
  dropped with no log.
- **`LOGIN_ROUTE` in `verifier.js` is an unanchored substring regex** — `/author/ofek` matches
  "auth". Adding a word silently zeroes verification for unrelated routes.
- **`scoreResponse` never compares origins.** Third-party traffic in the tab contributes points, and
  a 401 from any subframe rejects the capture outright.
- **`extension/.keys/` must never be committed.** The public half in `manifest.json` pins the
  extension ID; the private half lets anyone build an extension carrying the ID that the user's
  registered native host already authorizes.
- If you change the manifest `key`, `EXTENSION_ID` in `nomorepwn_app/browser_bridge.py` must change
  with it. `tests/test_views.py` asserts the coupling — a mismatch otherwise reports
  "✓ Connected" while refusing every connection.

## MutationObserver CPU discipline

`subtree: true` on a busy SPA fires thousands of times a second. The observer subscribes to
`childList` only, queues records, and evaluates on a throttled tick — N mutations cost one
evaluation. Text scanning is limited to nodes added since the last tick. There is one `teardown()`
that every exit path funnels through, plus a hard deadline.

If you touch it, keep the test that pushes 500 mutations and asserts ≤3 evaluations, and the one
that asserts no further evaluation after settling.

## Test-suite mechanics

`extension/tests/observer.test.mjs` sections share mutable globals and are **strictly
order-dependent**: the fake `chrome` must exist before `service-worker.js` is imported, and ESM
caches modules, so there is exactly one import per run. Roughly 22s of the runtime is real sleeps
(the 10s deadline test).

To assert something reached the desktop app, use the fake native host — `globalThis.__native`
records every `sendNativeMessage` call and lets you set `reply` or `fail`.

## Reality check

The save path does not work end to end. `bridge.js` sends `save-credential`; the host answers
`not-implemented` because the browser-spawned host process is **not** the running desktop app and
cannot reach the in-RAM master key. Do not describe the extension as saving passwords.
