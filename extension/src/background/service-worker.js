/**
 * Verified Authentication Observer — background entry point.
 *
 * Flow:
 *   1. content script sees a submit -> SUBMIT_OBSERVED (credential crosses once)
 *   2. credential is sealed into a SecureCredentialHolder, keyed by tab id
 *   3. webRequest + webNavigation score the tab's next few network events
 *   4. threshold reached  -> verified   (today: log; later: save prompt)
 *      401/403 / timeout  -> wiped
 *
 * MV3 note: every listener below is registered synchronously at module top
 * level. Registering inside a callback or after an `await` means the worker
 * misses the very events that would have woken it after an idle teardown.
 */

import { MSG, OUTCOME } from '../shared/messages.js';
import * as store from './pending-store.js';
import { SUCCESS_THRESHOLD, scoreResponse, scoreNavigation } from './verifier.js';

/* ------------------------------------------------------------------ */
/* Resolution                                                          */
/* ------------------------------------------------------------------ */

/** Credential verified: hand it to the vault. */
function verify(tabId, outcome) {
  // Detach synchronously so no other listener can resolve this capture while
  // we are awaiting the decrypt. We now own the holder — hence the finally.
  const entry = store.detach(tabId, outcome);
  if (!entry) return;

  const { targetUrl } = entry;

  entry.holder
    .reveal(async (credential) => {
      // TODO(save-prompt): open the save UI and hand `credential` to the vault.
      // Deliberately not logging the credential itself.
      console.log('Login verified for URL: ' + targetUrl);
      console.debug('[nmp] outcome=%s user=%s evidence=%o', outcome, credential.username, entry.evidence);
    })
    .catch((err) => console.warn('[nmp] reveal failed', err))
    .finally(() => entry.holder.wipe());
}

/** Credential rejected or abandoned: wipe it. */
function reject(tabId, outcome) {
  const entry = store.discard(tabId, outcome);
  if (entry) console.debug('[nmp] wiped %s (%s)', entry.targetUrl, outcome);
}

/** Apply a score delta and resolve if we have crossed the threshold. */
function applyScore(tabId, { rejected, points, evidence }) {
  const entry = store.get(tabId);
  if (!entry) return;

  if (rejected) {
    reject(tabId, OUTCOME.REJECTED_STATUS);
    return;
  }
  if (!points) return;

  entry.score += points;
  entry.evidence.push(...evidence);

  if (entry.score >= SUCCESS_THRESHOLD) {
    verify(tabId, evidence.some((e) => e.includes('cookie')) ? OUTCOME.VERIFIED_SESSION : OUTCOME.VERIFIED_REDIRECT);
  }
}

/* ------------------------------------------------------------------ */
/* Listeners                                                           */
/* ------------------------------------------------------------------ */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;
  if (typeof tabId !== 'number') return false;

  switch (message?.type) {
    case MSG.SUBMIT_OBSERVED:
      store
        .open(tabId, message.credential, sender.url ?? message.credential.targetUrl, (_entry, outcome) =>
          reject(tabId, outcome),
        )
        .then(() => sendResponse({ tracking: true }))
        .catch((err) => {
          console.warn('[nmp] could not seal credential', err);
          sendResponse({ tracking: false });
        });
      return true; // keep the message channel open for the async response

    case MSG.SPA_SUCCESS:
      // The DOM verdict is independent evidence, so it resolves on its own
      // rather than adding to the network score.
      if (store.has(tabId)) verify(tabId, OUTCOME.VERIFIED_SPA);
      return false;

    case MSG.SPA_FAILURE:
      reject(tabId, message.reason === 'timeout' ? OUTCOME.TIMED_OUT : OUTCOME.REJECTED_SPA);
      return false;

    default:
      return false;
  }
});

// Response headers: status codes, Location, Set-Cookie.
// `extraHeaders` is required for Set-Cookie to be visible at all.
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0 || !store.has(details.tabId)) return;
    applyScore(details.tabId, scoreResponse(store.get(details.tabId), details));
  },
  { urls: ['<all_urls>'], types: ['main_frame', 'sub_frame', 'xmlhttprequest'] },
  ['responseHeaders', 'extraHeaders'],
);

// A committed navigation confirms the tab actually landed somewhere.
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || !store.has(details.tabId)) return;
  applyScore(details.tabId, scoreNavigation(store.get(details.tabId), details));
});

// A network-level failure is not proof of bad credentials, but we are not
// going to get our answer, so do not sit on the secret.
chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    if (details.tabId < 0 || details.type !== 'main_frame') return;
    reject(details.tabId, OUTCOME.TIMED_OUT);
  },
  { urls: ['<all_urls>'] },
);

chrome.tabs.onRemoved.addListener((tabId) => reject(tabId, OUTCOME.TAB_GONE));

// Best-effort: the worker is about to be torn down. Memory dies with it either
// way, but wiping explicitly keeps the invariant honest.
chrome.runtime.onSuspend?.addListener(() => store.discardAll(OUTCOME.TIMED_OUT));

console.debug('[nmp] verified authentication observer registered');
