/**
 * SPA fallback detector.
 *
 * Single-page apps log in over `fetch`/XHR and re-render — there is no
 * navigation and often no informative status code on the main frame. This
 * watches the DOM instead and reports a verdict to the background worker.
 *
 * It never touches the password. The background worker already holds the
 * sealed credential; this module only decides *whether* to release it.
 *
 * ## CPU discipline
 *
 * A `subtree: true` observer on a busy SPA can fire thousands of times a
 * second. Three things keep that cheap:
 *   1. We subscribe to `childList` only — not `attributes` or
 *      `characterData`, which are the high-frequency ones.
 *   2. Mutation records are queued and evaluated on a throttled tick
 *      (`EVAL_INTERVAL_MS`), so N mutations cost one evaluation, not N.
 *   3. Text scanning is limited to nodes added since the last tick, never
 *      the whole document.
 * Plus a hard deadline: the observer cannot outlive `WINDOW_MS`, and
 * `teardown()` is the single exit through which every path disconnects.
 *
 * Content scripts are classic scripts, so this exposes itself on `globalThis`
 * (the extension's isolated world) rather than using ES module exports.
 */

(() => {
  'use strict';

  /** Hard ceiling on how long we watch the DOM. */
  const WINDOW_MS = 10000;

  /** Minimum gap between heuristic evaluations. */
  const EVAL_INTERVAL_MS = 250;

  /** Cap on characters read per added subtree, to bound text scanning. */
  const MAX_TEXT_PER_NODE = 2000;

  /** Elements that generally only render for an authenticated user. */
  const AUTH_MARKERS = [
    '#user-menu',
    '[data-testid*="user-menu" i]',
    '[aria-label*="account" i]',
    'a[href*="logout" i]',
    'a[href*="signout" i]',
    'a[href*="sign-out" i]',
    'button[data-action*="logout" i]',
  ].join(',');

  const LOGOUT_TEXT = /\b(log ?out|sign ?out|my account)\b/i;

  const ERROR_TEXT =
    /\b(invalid|incorrect|wrong|failed|unrecogni[sz]ed|does ?n[o']?t match)\b[^.]{0,40}\b(password|credential|username|email|login|combination)\b|\b(password|username|email)\b[^.]{0,40}\b(invalid|incorrect|wrong)\b|\btry again\b/i;

  /**
   * Watch the DOM for evidence that a login succeeded or failed.
   *
   * @param {object} options
   * @param {HTMLFormElement} options.form   the submitted form
   * @param {string} options.username        used as a success marker if echoed into the UI
   * @param {(reason: string) => void} options.onSuccess
   * @param {(reason: string) => void} options.onFailure
   * @returns {() => void} teardown, safe to call repeatedly
   */
  function watch({ form, username, onSuccess, onFailure }) {
    let observer = null;
    let deadline = null;
    let tick = null;
    let settled = false;

    /** Nodes added since the last evaluation. */
    let queued = [];

    // The form may be removed from the DOM, so remember what it looked like.
    const formWasConnected = form?.isConnected ?? false;
    const usernameNeedle = username && username.length >= 3 ? username.toLowerCase() : null;

    /** The single exit. Every path — success, failure, timeout — lands here. */
    function teardown() {
      if (observer) observer.disconnect();
      observer = null;
      clearTimeout(deadline);
      clearTimeout(tick);
      deadline = tick = null;
      queued = [];
      window.removeEventListener('pagehide', onPageHide);
    }

    function settle(outcome, reason) {
      if (settled) return;
      settled = true;
      try {
        outcome(reason);
      } finally {
        teardown();
      }
    }

    function onPageHide() {
      // A full navigation means the background worker's network heuristics
      // own this decision now. Stand down without a verdict.
      settled = true;
      teardown();
    }

    /** Read a bounded amount of text out of an added node. */
    function textOf(node) {
      if (node.nodeType === Node.TEXT_NODE) return node.nodeValue ?? '';
      if (node.nodeType !== Node.ELEMENT_NODE) return '';
      const text = node.textContent ?? '';
      return text.length > MAX_TEXT_PER_NODE ? text.slice(0, MAX_TEXT_PER_NODE) : text;
    }

    function evaluate() {
      tick = null;
      if (settled) return;

      const batch = queued;
      queued = [];

      // --- failure first: an error message outranks any success signal ---
      for (const node of batch) {
        if (ERROR_TEXT.test(textOf(node))) {
          settle(onFailure, 'error-text');
          return;
        }
      }

      // --- success: authenticated chrome appeared ---
      if (document.querySelector(AUTH_MARKERS)) {
        settle(onSuccess, 'auth-marker');
        return;
      }

      for (const node of batch) {
        const text = textOf(node);
        if (LOGOUT_TEXT.test(text)) {
          settle(onSuccess, 'logout-control');
          return;
        }
        if (usernameNeedle && text.toLowerCase().includes(usernameNeedle)) {
          settle(onSuccess, 'username-echoed');
          return;
        }
      }

      // --- success: the login form itself went away ---
      // Only meaningful if it *was* attached and no password field remains,
      // otherwise a re-rendered login form reads as success.
      if (formWasConnected && !form.isConnected && !document.querySelector('input[type="password"]')) {
        settle(onSuccess, 'login-form-removed');
      }
    }

    function schedule() {
      if (tick === null && !settled) tick = setTimeout(evaluate, EVAL_INTERVAL_MS);
    }

    observer = new MutationObserver((records) => {
      if (settled) {
        // Defensive: a queued callback can still arrive after disconnect().
        teardown();
        return;
      }
      for (const record of records) {
        for (const node of record.addedNodes) queued.push(node);
      }
      schedule();
    });

    observer.observe(document.body, { childList: true, subtree: true });
    window.addEventListener('pagehide', onPageHide, { once: true });

    deadline = setTimeout(() => settle(onFailure, 'timeout'), WINDOW_MS);

    return teardown;
  }

  globalThis.__nmpSpaObserver = { watch, WINDOW_MS };
})();
