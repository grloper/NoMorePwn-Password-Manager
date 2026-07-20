# NoMorePwn — Verified Authentication Observer

A Manifest V3 browser extension that captures credentials **only after the
login is verified to have succeeded**, instead of on every form submit. This
avoids the classic password-manager failure: saving the typo you just fixed.

Status: **core architecture, verified by tests.** The save prompt and the
bridge to the desktop vault are stubbed (`TODO(save-prompt)`); a verified login
currently logs `Login verified for URL: <url>`.

## Flow

```
 content/capture.js          background/service-worker.js
 ──────────────────          ────────────────────────────
 submit event
   └─ read credential ─────► SUBMIT_OBSERVED
        (forgets it)           └─ SecureCredentialHolder (AES-GCM, non-extractable key)
                                  stored in a Map keyed by tabId, 5s deadline
 content/spa-observer.js
   └─ MutationObserver ────► SPA_SUCCESS / SPA_FAILURE   ┐
                                                          ├─► score ≥ 3 → verified
      chrome.webRequest.onHeadersReceived  ───────────────┤   401/403     → wiped
      chrome.webNavigation.onCommitted     ───────────────┘   5s timeout  → wiped
```

Two independent detectors, because they cover different sites:

| | Multi-page (server redirect) | SPA (GitHub, Netflix) |
|---|---|---|
| Signal | HTTP status + `Location` + `Set-Cookie` | DOM transition |
| Owner | `background/verifier.js` | `content/spa-observer.js` |
| Window | 5s | 10s |

## Three places this deviates from the original spec

**1. The content script never holds the password.**
The spec said to keep credentials in content-script scope while the
`MutationObserver` runs. It doesn't — it reads the credential, ships it to the
background worker, and drops it. The observer then reports only a *verdict*
(`SPA_SUCCESS` / `SPA_FAILURE`), never the secret.

Why: a content script shares a renderer process with the page it's injected
into. Holding a plaintext password there for 10 seconds, on every site, is the
single largest piece of exposure in the original design. The background service
worker is a separate process — a real trust boundary. Same feature, one process
better.

**2. There is no content-script → background encryption.**
The spec called for an "encrypted payload". That encryption would be theatre:
`chrome.runtime.sendMessage` travels over Chrome's internal IPC, which page
JavaScript cannot observe, and the key would have to live in the content
script — i.e. in the same renderer as the page you're defending against. It
buys nothing and costs latency plus a key to manage. The message is already
private; the credential is encrypted once it reaches the worker, where the key
can actually be kept non-extractable.

**3. `SecureCredentialHolder` is hygiene, not a memory-dump defence.**
It does real work — AES-GCM with a **non-extractable** key (raw key material
stays in the browser's crypto backend, not our heap), and `wipe()` genuinely
overwrites the ciphertext/IV buffers with random bytes then zeros, because
typed arrays are mutable.

What it cannot do, despite the spec's framing:

- **JS strings are immutable and uncopyable-by-you.** The credential arrives as
  a string (from `input.value`, through structured clone). V8 may have already
  copied it during a GC scavenge. Those copies die when the GC decides, not
  when `wipe()` runs. No JavaScript can fix this.
- **It does not stop XSS.** Page script cannot reach extension memory at all
  (isolated world). XSS steals the password from the form field, before this
  code ever sees it.

The genuine win is architectural: credentials live in one process, for seconds,
and every exit path wipes. Treat the crypto as defence-in-depth on top of that,
not as the thing keeping you safe.

## Heuristic honesty

The scoring in `verifier.js` is additive (threshold 3) rather than a chain of
`if`s, so signals corroborate:

| Signal | Points | Note |
|---|---|---|
| Redirect away from the login path | 3 | strongest MPA signal |
| Destination looks authenticated (`/dashboard`, `/home`, …) | 2 | |
| Committed navigation off the login path | 2 | |
| `Set-Cookie` with a session-shaped name | 1 | **deliberately weak** |
| HTTP 401 / 403 | conclusive rejection | |

`Set-Cookie` scores 1, not enough to verify on its own, because the spec's
"HTTP 200 with a cookie ⇒ success" rule fires on almost everything: failed
logins rotate CSRF tokens, set analytics cookies, and issue anonymous sessions.
On its own it is close to a coin flip.

Two things worth knowing before tuning further:

- **Only the login site's own responses are scored.** `webRequest` fires for
  every request in the tab, including third-party subframes and analytics/ad
  traffic. `scoreResponse`/`scoreNavigation` ignore any response whose origin is
  not same-site as the page the form was submitted from — otherwise a stray 401
  from a subframe would reject the capture, and a stray redirect or
  session-shaped cookie from a third party would inflate it toward a false
  "verified". Same-site is same-scheme + same registrable domain (last two
  labels; an extension has no Public Suffix List).
- **A redirect back to `/login` scores zero, by design** — that's the standard
  failure pattern, and treating any 302 as success inverts the whole feature.
- **Fail-closed means silently dropping saves.** Every heuristic that misses
  costs the user a password they wanted stored, and they get no signal that
  anything happened. Chrome's and Bitwarden's built-in managers mostly *don't*
  verify — they prompt and let you dismiss. If this turns out to lose saves in
  practice, the fix is to prompt on ambiguity rather than to keep adding
  signals.

## MV3 service-worker lifetime

The worker is torn down after ~30s idle. Two consequences, both handled:

- **Listeners are registered synchronously at module top level.** Registering
  after an `await` means the worker misses the events that would have woken it.
- **Nothing is persisted.** `chrome.storage` is never touched. If the worker
  dies mid-verification the credential dies with it and the save prompt is
  lost — the correct direction to fail.

`setTimeout` for the 5s deadline is fine here (in-flight webRequest events keep
the worker alive) but is not a guarantee. `chrome.alarms` is not an
alternative: its minimum period is far coarser than this window.

## Permissions

`webRequest` + `<all_urls>` is a broad, heavily-scrutinised combination in
Chrome Web Store review, and `extraHeaders` is required for `Set-Cookie` to be
visible at all. Note that `webRequest` here is **observational only** —
`webRequestBlocking` is not requested and is not available to non-enterprise
MV3 extensions. If review friction becomes a problem, dropping the
`Set-Cookie` signal (worth 1 point) allows dropping `extraHeaders`.

## Running it

Chrome and Firefox need different manifests, so the extension is built into two
per-browser folders. Build them (both are also committed under `dist/`):

```bash
python extension/build.py          # -> extension/dist/chrome and extension/dist/firefox
```

1. In NoMorePwn: **Settings → Browser extension → Auto-install on browser**.
   Pick a browser; NoMorePwn writes the native-messaging host manifest, registers
   it under HKCU (Chrome, Edge, Brave, or Firefox — no admin rights), opens that
   browser's extensions page, and opens the folder to load.
2. Finish in the browser — this one click is yours, since browsers don't let an
   app install an unpacked extension silently:
   - **Chrome / Edge / Brave:** `chrome://extensions` → Developer mode →
     **Load unpacked** → select `extension/dist/chrome`.
   - **Firefox:** `about:debugging#/runtime/this-firefox` → **Load Temporary
     Add-on…** → pick any file in `extension/dist/firefox`.

Never load the top-level `extension/` source folder — its combined manifest is
not what either browser expects; load the per-browser `dist/` build instead.

Watch the worker's console via *Inspect views: service worker*; it logs whether
the desktop app is reachable at startup.

The extension ID is pinned to `cjgphedkabfdfbhkfleagmanmmhlolkl` by the `key`
field in `manifest.json`. That matters: an unpacked extension's ID is otherwise
derived from its install path, so it would differ per machine — and the host
manifest's `allowed_origins` has to name the exact ID. Pinning is what lets the
app register the bridge without you copying an ID by hand. Change that key and
`EXTENSION_ID` in `nomorepwn_app/browser_bridge.py` must change with it.

```bash
cd extension
npm install
npm test     # 62 assertions
```

The tests run the real background modules against a fake `chrome.*` event bus
and a fake native host, and the real MutationObserver against jsdom —
including that it coalesces 500 mutations into ≤3 evaluations, disconnects on
settle, and honours the 10s deadline.

## Not done yet

**The save path stops at the host.** `bridge.js` sends `save-credential` and
the host answers `not-implemented`. That is a real architectural gap, not a
missing function body:

> The browser *spawns* the native host. That process is **not** the running
> desktop app, and the master key lives only in the running app's RAM. A
> freshly spawned host can see that a vault file exists; it cannot open it.

Closing it needs either host → app IPC over a local named pipe (better — the
key stays in one process, and the app can show the save prompt), or the host
prompting for the master password itself (a second place handling master
passwords). Also unresolved: what should happen when a verified login arrives
while the vault is **locked** — queue it (holds the secret far longer than 5
seconds, against the whole design), prompt to unlock, or drop it.

Other gaps:

- Password-change and 2FA-step detection (both look like a login submit today).
- CI does not run `npm test`, so the extension can break without anyone noticing.
- Firefox: `browser.*` polyfill and MV3 differences are untested.
