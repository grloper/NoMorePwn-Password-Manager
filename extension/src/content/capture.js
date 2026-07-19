/**
 * Form-submit capture.
 *
 * Reads the credential out of the form and hands it to the background worker
 * immediately, then forgets it. The only thing this script keeps is the
 * username (already visible in the DOM) so the SPA observer can spot it being
 * echoed back into the UI.
 *
 * Deliberately *not* done here: holding the password in a closure for ten
 * seconds while the SPA observer runs. See extension/README.md.
 */

(() => {
  'use strict';

  // Cross-browser compat: Firefox content scripts expose `browser`, not `chrome`.
  const api = globalThis.chrome ?? globalThis.browser;

  const MSG = {
    SUBMIT_OBSERVED: 'nmp:submit-observed',
    SPA_SUCCESS: 'nmp:spa-success',
    SPA_FAILURE: 'nmp:spa-failure',
  };

  /** Teardown for the SPA observer currently running, if any. */
  let stopObserving = null;

  function readCredential(form) {
    const password = form.querySelector('input[type="password"]');
    if (!password?.value) return null;

    // Best-effort username: the labelled field, else the last text-ish input
    // before the password field.
    const candidates = [...form.querySelectorAll('input')];
    const passwordIndex = candidates.indexOf(password);
    const username =
      form.querySelector('input[type="email"], input[autocomplete="username"], input[name*="user" i], input[name*="email" i]') ??
      candidates.slice(0, passwordIndex).reverse().find((i) => ['text', 'email', 'tel', ''].includes(i.type));

    return {
      username: username?.value ?? '',
      password: password.value,
      targetUrl: location.origin,
      timestamp: Date.now(),
    };
  }

  function onSubmit(event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;

    const credential = readCredential(form);
    if (!credential) return;

    const { username } = credential;

    api.runtime.sendMessage({ type: MSG.SUBMIT_OBSERVED, credential }, (response) => {
      // Drop our reference the moment it is across the boundary. The string
      // itself is not wipeable from here — the background holder is where the
      // credential actually gets protected.
      if (api.runtime.lastError || !response?.tracking) return;

      stopObserving?.();
      stopObserving = globalThis.__nmpSpaObserver.watch({
        form,
        username,
        onSuccess: (reason) => {
          api.runtime.sendMessage({ type: MSG.SPA_SUCCESS, reason });
          stopObserving = null;
        },
        onFailure: (reason) => {
          api.runtime.sendMessage({ type: MSG.SPA_FAILURE, reason });
          stopObserving = null;
        },
      });
    });
  }

  // Capture phase: fires even if the page calls stopPropagation() on submit.
  document.addEventListener('submit', onSubmit, true);

  // SPAs frequently bind to click and never fire a real submit event.
  document.addEventListener(
    'click',
    (event) => {
      const trigger = event.target?.closest?.('button[type="submit"], input[type="submit"], button:not([type])');
      const form = trigger?.form ?? trigger?.closest('form');
      if (form) onSubmit({ target: form });
    },
    true,
  );
})();

