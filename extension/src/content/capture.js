/**
 * Login capture.
 *
 * Reads the credential out of the page and hands it to the background worker
 * immediately, then forgets it. The only thing this script keeps is the
 * username (already visible in the DOM) so the SPA observer can spot it being
 * echoed back into the UI.
 *
 * A classic `<form>` submit is the easy case. Big sites don't do that: Google,
 * and most SPA logins, submit with a `<button type="button">` (or a
 * `role="button"` element) and background XHR, and intercept Enter — so a
 * submit event never fires. This script therefore also captures on a click of a
 * sign-in-looking control and on Enter in a login field, gated on there
 * actually being a filled password on the page. Whatever it can't *verify*
 * afterwards is not dropped silently — the background asks the user (see
 * service-worker.js `promptUnverified`).
 *
 * Deliberately *not* done here: holding the password in a closure while the SPA
 * observer runs. See extension/README.md.
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

  // Text on a control that plausibly submits a login, so a click on it counts
  // even when it is not a native submit button.
  const SUBMIT_TEXT =
    /(log[\s-]?in|log[\s-]?on|sign[\s-]?in|sign[\s-]?on|continue|next|submit|access|proceed|anmelden|einloggen|entrar|acceder|connexion|se connecter|iniciar|войти)/i;

  /** Teardown for the SPA observer currently running, if any. */
  let stopObserving = null;

  // Debounce: a single login often triggers submit + click + Enter together, and
  // buttons can fire repeatedly. Skip an identical credential seen moments ago.
  let lastSignature = '';
  let lastAt = 0;

  /** The password field that currently holds a value, searched page-wide. */
  function filledPassword(scope) {
    const fields = [...(scope || document).querySelectorAll('input[type="password"]')];
    return fields.find((f) => f.value) || null;
  }

  function readCredential(scope) {
    // Page-wide, not just within one form: multi-step flows (Google) put the
    // email and password on separate views, and the password may sit outside a
    // <form> entirely.
    const password = filledPassword(scope) || filledPassword(document);
    if (!password?.value) return null;

    const root = password.form || document;
    const inputs = [...root.querySelectorAll('input')];
    const passwordIndex = inputs.indexOf(password);
    const username =
      root.querySelector(
        'input[type="email"], input[autocomplete="username"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]',
      ) ??
      (passwordIndex >= 0
        ? inputs.slice(0, passwordIndex).reverse().find((i) => ['text', 'email', 'tel', ''].includes(i.type))
        : null) ??
      document.querySelector('input[type="email"], input[autocomplete="username"]');

    return {
      username: username?.value ?? '',
      password: password.value,
      targetUrl: location.origin,
      timestamp: Date.now(),
    };
  }

  function capture(scope) {
    const credential = readCredential(scope);
    if (!credential) return;

    const signature = `${credential.username}\u0000${credential.password}`;
    const now = Date.now();
    if (signature === lastSignature && now - lastAt < 1500) return;
    lastSignature = signature;
    lastAt = now;

    const { username } = credential;
    const form = (filledPassword(scope) || filledPassword(document))?.form ?? null;

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

  // 1. Native form submit (classic multi-page login). Capture phase so it fires
  //    even if the page calls stopPropagation().
  document.addEventListener(
    'submit',
    (event) => {
      if (event.target instanceof HTMLFormElement) capture(event.target);
    },
    true,
  );

  // 2. Click on a submit-looking control — the SPA case. Gated on a filled
  //    password so a stray button click on a normal page doesn't fire.
  document.addEventListener(
    'click',
    (event) => {
      const el = event.target?.closest?.(
        'button, input[type="submit"], input[type="button"], [role="button"], a[role="button"]',
      );
      if (!el) return;
      const nativeSubmit = el.matches('button[type="submit"], input[type="submit"], button:not([type])');
      const label = (el.innerText || el.value || el.getAttribute?.('aria-label') || '').trim();
      if (!nativeSubmit && !SUBMIT_TEXT.test(label)) return;
      if (!(filledPassword(el.form || document) || filledPassword(document))) return;
      capture(el.form || document);
    },
    true,
  );

  // 3. Enter inside a login field — SPAs that submit on Enter via JS, never
  //    firing a real submit event.
  document.addEventListener(
    'keydown',
    (event) => {
      if (event.key !== 'Enter') return;
      const t = event.target;
      if (!(t instanceof HTMLInputElement)) return;
      if (!['password', 'text', 'email', 'tel'].includes(t.type)) return;
      if (!(filledPassword(t.form || document) || filledPassword(document))) return;
      capture(t.form || document);
    },
    true,
  );
})();
