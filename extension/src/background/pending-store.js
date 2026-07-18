/**
 * Volatile, tab-scoped store of in-flight login captures.
 *
 * Nothing here is persisted. `chrome.storage` is deliberately never touched:
 * an unverified credential must not survive a service-worker restart, and the
 * worker being torn down mid-verification is a *safe* failure (the credential
 * dies with it, we simply lose the save prompt).
 */

import { SecureCredentialHolder } from '../shared/secure-credential.js';
import { OUTCOME } from '../shared/messages.js';

/** How long a submission may stay pending before we give up and wipe. */
export const VERIFICATION_WINDOW_MS = 5000;

/** @type {Map<number, PendingLogin>} tabId -> pending capture */
const pending = new Map();

/**
 * @typedef {object} PendingLogin
 * @property {number} tabId
 * @property {SecureCredentialHolder} holder
 * @property {string} targetUrl   where the credential will be saved against
 * @property {string} loginUrl    the page the form was submitted from
 * @property {number} submittedAt
 * @property {number} timer       setTimeout handle for the deadline
 * @property {number} score       accumulated success evidence
 * @property {string[]} evidence  human-readable reasons, for logging
 */

/**
 * Record a submission and start its verification deadline.
 *
 * @param {number} tabId
 * @param {{username: string, password: string, targetUrl: string, timestamp: number}} credential
 * @param {string} loginUrl
 * @param {(entry: PendingLogin, outcome: string) => void} onDeadline
 * @returns {Promise<PendingLogin>}
 */
export async function open(tabId, credential, loginUrl, onDeadline) {
  // A second submission on the same tab supersedes the first (e.g. the user
  // fixed a typo and resubmitted). Wipe the stale one rather than leaking it.
  discard(tabId, OUTCOME.SUPERSEDED);

  const holder = await SecureCredentialHolder.create(credential);

  const entry = {
    tabId,
    holder,
    targetUrl: credential.targetUrl,
    loginUrl,
    submittedAt: credential.timestamp,
    score: 0,
    evidence: [],
    timer: setTimeout(() => {
      // `pending` may have been resolved between the timer firing and here.
      const live = pending.get(tabId);
      if (live === entry) onDeadline(entry, OUTCOME.TIMED_OUT);
    }, VERIFICATION_WINDOW_MS),
  };

  pending.set(tabId, entry);
  return entry;
}

/** @returns {PendingLogin|undefined} */
export function get(tabId) {
  return pending.get(tabId);
}

export function has(tabId) {
  return pending.has(tabId);
}

/**
 * Claim a pending capture: remove it from the map and cancel its deadline,
 * **without** wiping. The caller owns the holder and MUST wipe it.
 *
 * This exists so the success path can be atomic. Reading a credential is async
 * (`subtle.decrypt`), and leaving the entry in the map across that await lets a
 * second event — a trailing 401, the deadline, a closed tab — resolve the same
 * capture twice or wipe the holder mid-decrypt. Detaching synchronously makes
 * resolution exactly-once.
 *
 * @returns {PendingLogin|null} null if another path already claimed it
 */
export function detach(tabId, outcome) {
  const entry = pending.get(tabId);
  if (!entry) return null;

  pending.delete(tabId);
  clearTimeout(entry.timer);
  entry.resolvedAs = outcome;

  return entry;
}

/**
 * Remove a pending capture and wipe its credential. Idempotent.
 *
 * Every terminal path — rejected, timed out, tab closed — funnels through
 * here; the verified path uses `detach()` and wipes in its own `finally`.
 *
 * @returns {PendingLogin|null} the entry, already wiped, for logging
 */
export function discard(tabId, outcome) {
  const entry = detach(tabId, outcome);
  if (entry) entry.holder.wipe();
  return entry;
}

/** Wipe everything — used on service-worker suspend. */
export function discardAll(outcome) {
  for (const tabId of [...pending.keys()]) discard(tabId, outcome);
}

export function size() {
  return pending.size;
}
