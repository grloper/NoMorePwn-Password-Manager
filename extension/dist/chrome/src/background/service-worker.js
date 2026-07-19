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
import { api } from '../shared/browser-api.js';
import * as store from './pending-store.js';
import * as bridge from './bridge.js';
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
      console.log('Login verified for URL: ' + targetUrl);
      console.debug('[nmp] outcome=%s user=%s evidence=%o', outcome, credential.username, entry.evidence);
      fetch('http://localhost:9999/log', { method: 'POST', body: 'Login verified for URL: ' + targetUrl }).catch(() => { });

      const saved = await bridge.send({
        type: 'save-credential',
        targetUrl,
        username: credential.username,
        password: credential.password,
      });
      fetch('http://localhost:9999/log', { method: 'POST', body: 'Saved result: ' + JSON.stringify(saved) }).catch(() => { });

      if (!saved.ok || saved.data?.type === 'error') {
        console.debug('[nmp] not saved: %s', saved.ok ? saved.data.code : saved.error);
      }
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

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
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
// `extraHeaders` is required for Chrome to see Set-Cookie; Firefox throws on it.
const extraInfoSpec = ['responseHeaders'];
if (!navigator.userAgent.includes('Firefox')) extraInfoSpec.push('extraHeaders');

api.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0 || !store.has(details.tabId)) return;
    applyScore(details.tabId, scoreResponse(store.get(details.tabId), details));
  },
  { urls: ['<all_urls>'], types: ['main_frame', 'sub_frame', 'xmlhttprequest'] },
  extraInfoSpec,
);

// A committed navigation confirms the tab actually landed somewhere.
api.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || !store.has(details.tabId)) return;
  applyScore(details.tabId, scoreNavigation(store.get(details.tabId), details));
});

// A network-level failure is not proof of bad credentials, but we are not
// going to get our answer, so do not sit on the secret.
api.webRequest.onErrorOccurred.addListener(
  (details) => {
    if (details.tabId < 0 || details.type !== 'main_frame') return;
    reject(details.tabId, OUTCOME.TIMED_OUT);
  },
  { urls: ['<all_urls>'] },
);

api.tabs.onRemoved.addListener((tabId) => reject(tabId, OUTCOME.TAB_GONE));

// Best-effort: the worker is about to be torn down. Memory dies with it either
// way, but wiping explicitly keeps the invariant honest.
api.runtime.onSuspend?.addListener(() => store.discardAll(OUTCOME.TIMED_OUT));

console.debug('[nmp] verified authentication observer registered');

// Report bridge reachability once at startup. A missing host is the expected
// state until the user runs Settings -> Browser extension -> Set up.
bridge.ping().then((r) => {
  if (r.connected) console.log(`[nmp] connected to NoMorePwn ${r.version} (vault present: ${r.vaultPresent})`);
  else console.log('[nmp] desktop app not reachable — run Settings → Browser extension → Set up. ' + (r.error ?? ''));
});
