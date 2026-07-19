/**
 * Cross-browser namespace shim.
 *
 * Firefox exposes the WebExtension APIs on `browser.*` (Promise-based) and
 * provides a limited `chrome.*` compatibility object — but content scripts
 * often get only `browser`, not `chrome`. Chrome has no `browser` global at
 * all.
 *
 * This module exports a single `api` reference that points to whichever
 * namespace is available, preferring `chrome` (since most of our code already
 * uses callback-style) and falling back to `browser`.
 *
 * Usage:
 *   import { api } from '../shared/browser-api.js';   // ES module
 *   — or for content scripts (classic, no import) —
 *   const api = globalThis.chrome ?? globalThis.browser;
 */

// eslint-disable-next-line no-undef
export const api = globalThis.chrome ?? globalThis.browser;
