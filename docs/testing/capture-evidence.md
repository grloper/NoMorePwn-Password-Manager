# Login capture evidence

## Reproduced and repaired

* Last-two-label domain matching trusted unrelated `co.uk` and `github.io` tenants. Verification now requires the exact origin, including scheme and port.
* An early redirect could mark a login verified before a final HTTP 401. Network evidence now waits for the committed final successful response; HTTP errors discard pending capture.
* A multi-hop redirect could carry that provisional score to another origin or back to a login form. The final successful destination must independently be same-origin and outside login routes; both chains have observer and real Chromium regressions.
* Locked captures retained plaintext passwords until unlock. They now return `vault-locked` and require retry after unlock.
* Source native-host launchers failed to import the app when launched from another working directory. Windows launchers now enter the module root first; a real generated-launcher test covers this.
* Invalid captures falsely acknowledged success. They now return `capture-not-saved`.
* Capture notifications ignored the preference. They now respect it.
* Firefox instructions described Chromium loading. They now explain temporary add-ons and restart limitations.

## Local execution

Windows: 261 Python tests passed; 73 extension observer assertions and five origin-boundary tests passed. Actual Chromium extension fixtures cover a valid login, direct 401, cross-origin `co.uk` navigation, a redirect ending in 401, and multi-hop redirects ending at a foreign origin or back on the login form. Native messaging is intercepted in that browser probe.

The separate desktop probe runs a real native-host child, framed stdin/stdout protocol, Qt local socket, desktop controller and encrypted temporary vault. It clicks the actual unlock UI, saves fictional credentials, locks and unlocks, checks rejection and failure acknowledgements, and renders the actual vault, generator and security screens. It does not register an OS browser host.

The added Ubuntu/Windows CI workflow runs unit, extension and both component probes. Remote CI success must be checked on the PR's exact head; local success does not establish remote success.

## Limits

Login verification remains heuristic, not proof that a remote service authenticated a user. Metadata remains plaintext. Secret strings may have memory copies. Autofill is absent. Firefox runtime, installed registration, packaged distribution and external providers were not exercised. There is no independent security audit.
