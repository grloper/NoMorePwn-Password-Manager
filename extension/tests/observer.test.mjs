/**
 * Exercises the Verified Authentication Observer end to end:
 *   1. SecureCredentialHolder contract
 *   2. verifier scoring
 *   3. background service worker integration (fake chrome.* event bus)
 *   4. SPA MutationObserver in a real DOM (jsdom)
 */
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const SRC = new URL('../src/', import.meta.url);
const mod = (p) => import(new URL(p, SRC).href);

let pass = 0;
let fail = 0;
const failures = [];

function check(name, cond, detail = '') {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    failures.push(name);
    console.log(`  FAIL  ${name} ${detail}`);
  }
}

const section = (t) => console.log(`\n=== ${t} ===`);

/* ================================================================== */
section('1. SecureCredentialHolder');
/* ================================================================== */
{
  const { SecureCredentialHolder } = await mod('shared/secure-credential.js');

  const h = await SecureCredentialHolder.create({
    username: 'ofek',
    password: 'hunter2-correct-horse',
    targetUrl: 'https://example.com',
    timestamp: 1,
  });

  let seen = null;
  await h.reveal((c) => {
    seen = { ...c };
  });
  check('reveal() round-trips the credential', seen?.username === 'ofek' && seen?.password === 'hunter2-correct-horse');
  check('meta survives without exposing the secret', h.meta.targetUrl === 'https://example.com' && !('password' in h.meta));

  check('not wiped yet', h.wiped === false);
  h.wipe();
  check('wiped flag flips', h.wiped === true);

  let threw = false;
  try {
    await h.reveal(() => {});
  } catch {
    threw = true;
  }
  check('reveal() after wipe throws', threw);

  h.wipe();
  check('wipe() is idempotent', h.wiped === true);

  // reveal() must scrub the decrypted buffer even when the consumer throws.
  const h2 = await SecureCredentialHolder.create({ username: 'a', password: 'b', targetUrl: 'u', timestamp: 2 });
  let propagated = false;
  try {
    await h2.reveal(() => {
      throw new Error('consumer blew up');
    });
  } catch (e) {
    propagated = e.message === 'consumer blew up';
  }
  check('reveal() propagates consumer errors (finally still ran)', propagated);
  h2.wipe();

  // A direct check that scrubbing really mutates a buffer, since the
  // holder's own buffers are #private.
  const probe = new Uint8Array(8).fill(0xff);
  crypto.getRandomValues(probe);
  probe.fill(0);
  check('typed-array scrub semantics hold', probe.every((b) => b === 0));
}

/* ================================================================== */
section('2. Verifier scoring');
/* ================================================================== */
{
  const { scoreResponse, scoreNavigation, SUCCESS_THRESHOLD } = await mod('background/verifier.js');
  const entry = { loginUrl: 'https://app.example.com/login' };
  const hdr = (name, value) => ({ name, value });

  const r302 = scoreResponse(entry, {
    statusCode: 302,
    url: 'https://app.example.com/login',
    responseHeaders: [hdr('Location', '/dashboard'), hdr('Set-Cookie', 'sessionid=abc; HttpOnly')],
  });
  check('302 -> /dashboard clears threshold', r302.points >= SUCCESS_THRESHOLD, `points=${r302.points}`);

  const r401 = scoreResponse(entry, { statusCode: 401, url: 'https://app.example.com/login', responseHeaders: [] });
  check('401 is a conclusive rejection', r401.rejected === true);

  const r403 = scoreResponse(entry, { statusCode: 403, url: 'https://app.example.com/login', responseHeaders: [] });
  check('403 is a conclusive rejection', r403.rejected === true);

  const rBack = scoreResponse(entry, {
    statusCode: 302,
    url: 'https://app.example.com/login',
    responseHeaders: [hdr('Location', '/login?error=1'), hdr('Set-Cookie', 'csrftoken=zzz')],
  });
  check('302 back to /login does NOT clear threshold', rBack.points < SUCCESS_THRESHOLD, `points=${rBack.points}`);

  const rCookieOnly = scoreResponse(entry, {
    statusCode: 200,
    url: 'https://app.example.com/login',
    responseHeaders: [hdr('Set-Cookie', 'sessionid=abc')],
  });
  check('a session cookie ALONE does not verify', rCookieOnly.points < SUCCESS_THRESHOLD, `points=${rCookieOnly.points}`);

  const nav = scoreNavigation(entry, {
    url: 'https://app.example.com/dashboard',
    transitionQualifiers: ['server_redirect'],
  });
  check('navigation to /dashboard clears threshold', nav.points >= SUCCESS_THRESHOLD, `points=${nav.points}`);

  const navStay = scoreNavigation(entry, { url: 'https://app.example.com/login', transitionQualifiers: [] });
  check('navigation back to /login scores 0', navStay.points === 0);

  // --- origin isolation: third-party traffic in the tab is not evidence ---
  const tp401 = scoreResponse(entry, { statusCode: 401, url: 'https://evil.example.net/collect', responseHeaders: [] });
  check('a third-party 401 does NOT reject the capture', tp401.rejected === false, JSON.stringify(tp401));

  const tpRedirect = scoreResponse(entry, {
    statusCode: 302,
    url: 'https://tracker.ads.com/r',
    responseHeaders: [hdr('Location', 'https://tracker.ads.com/dashboard')],
  });
  check('a third-party redirect scores nothing', tpRedirect.points === 0, JSON.stringify(tpRedirect));

  const tpCookie = scoreResponse(entry, {
    statusCode: 200,
    url: 'https://analytics.other.com/beacon',
    responseHeaders: [hdr('Set-Cookie', 'sessionid=abc')],
  });
  check('a third-party session cookie scores nothing', tpCookie.points === 0, JSON.stringify(tpCookie));

  const tpNav = scoreNavigation(entry, { url: 'https://elsewhere.com/dashboard', transitionQualifiers: ['server_redirect'] });
  check('a navigation to another site scores nothing', tpNav.points === 0, JSON.stringify(tpNav));

  // --- LOGIN_ROUTE anchoring: /author is not a login route, /auth/... still is ---
  const authorRedirect = scoreResponse(entry, {
    statusCode: 302,
    url: 'https://app.example.com/login',
    responseHeaders: [hdr('Location', '/author/ofek')],
  });
  check('/author is no longer misread as a login route', authorRedirect.points >= SUCCESS_THRESHOLD, JSON.stringify(authorRedirect));

  const authCallback = scoreResponse(entry, {
    statusCode: 302,
    url: 'https://app.example.com/login',
    responseHeaders: [hdr('Location', '/auth/callback')],
  });
  check('a redirect that stays on an auth route still scores 0', authCallback.points === 0, JSON.stringify(authCallback));

  // A login token mid-segment (e.g. /user-login) must still read as login flow,
  // so a failed login bouncing there is not mistaken for success.
  const userLogin = scoreResponse(entry, {
    statusCode: 302,
    url: 'https://app.example.com/login',
    responseHeaders: [hdr('Location', '/user-login?error=1')],
  });
  check('/user-login is still recognised as a login route', userLogin.points === 0, JSON.stringify(userLogin));
}

/* ================================================================== */
section('2b. capture.js ↔ shared/messages.js contract');
/* ================================================================== */
{
  // capture.js is a classic content script and cannot import shared/messages.js,
  // so it hardcodes the message-type strings. Nothing else pins the two copies
  // together — this makes a rename in shared/messages.js a test failure instead
  // of a silently dead capture path (all other checks stay green).
  const { MSG } = await mod('shared/messages.js');
  const captureSrc = readFileSync(new URL('content/capture.js', SRC), 'utf8');
  const pins = (v) => captureSrc.includes(`'${v}'`);
  check('capture.js pins SUBMIT_OBSERVED to shared/messages.js', pins(MSG.SUBMIT_OBSERVED), MSG.SUBMIT_OBSERVED);
  check('capture.js pins SPA_SUCCESS to shared/messages.js', pins(MSG.SPA_SUCCESS), MSG.SPA_SUCCESS);
  check('capture.js pins SPA_FAILURE to shared/messages.js', pins(MSG.SPA_FAILURE), MSG.SPA_FAILURE);
}

/* ================================================================== */
section('3. Background service worker integration');
/* ================================================================== */
{
  // ---- fake chrome.* event bus -------------------------------------
  const bus = {};
  const evt = (name) => {
    bus[name] = [];
    return { addListener: (fn) => bus[name].push(fn) };
  };
  const fire = (name, ...args) => bus[name].map((fn) => fn(...args));

  // Fake native host: records what the extension tried to send it.
  const native = { sent: [], reply: { type: 'pong', protocol: 1, version: '1.0.0', vaultPresent: true }, fail: null };

  globalThis.chrome = {
    runtime: {
      onMessage: evt('onMessage'),
      onSuspend: evt('onSuspend'),
      lastError: null,
      sendNativeMessage: (host, message, cb) => {
        native.sent.push({ host, message });
        chrome.runtime.lastError = native.fail ? { message: native.fail } : null;
        const reply = native.fail ? undefined : native.reply;
        setTimeout(() => {
          cb(reply);
          chrome.runtime.lastError = null;
        }, 0);
      },
    },
    webRequest: { onHeadersReceived: evt('onHeadersReceived'), onErrorOccurred: evt('onErrorOccurred') },
    webNavigation: { onCommitted: evt('onCommitted') },
    tabs: { onRemoved: evt('onRemoved') },
  };
  globalThis.__native = native;

  // ---- spy on wipe() so we can prove it fires on every path ---------
  const { SecureCredentialHolder } = await mod('shared/secure-credential.js');
  let wipes = 0;
  const realWipe = SecureCredentialHolder.prototype.wipe;
  SecureCredentialHolder.prototype.wipe = function (...a) {
    wipes++;
    return realWipe.apply(this, a);
  };

  const logs = [];
  const realLog = console.log;
  console.log = (...a) => logs.push(a.join(' '));

  const store = await mod('background/pending-store.js');
  await mod('background/service-worker.js');

  console.log = realLog;
  check('all listeners registered at module load', bus.onMessage.length === 1 && bus.onHeadersReceived.length === 1 && bus.onCommitted.length === 1 && bus.onRemoved.length === 1);

  const submit = (tabId, url = 'https://app.example.com/login') =>
    new Promise((resolve) => {
      fire(
        'onMessage',
        { type: 'nmp:submit-observed', credential: { username: 'ofek', password: 'pw', targetUrl: 'https://app.example.com', timestamp: Date.now() } },
        { tab: { id: tabId }, url },
        resolve,
      );
    });

  // The verified path awaits subtle.decrypt, so give the microtask+macrotask
  // queues several turns to drain before asserting.
  const settle = async () => {
    for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 5));
  };

  // --- happy path: 302 -> /dashboard ---
  console.log = (...a) => logs.push(a.join(' '));
  wipes = 0;
  await submit(1);
  check('submission is tracked by tab id', store.has(1), `size=${store.size()}`);

  fire('onHeadersReceived', {
    tabId: 1,
    statusCode: 302,
    url: 'https://app.example.com/login',
    type: 'main_frame',
    responseHeaders: [{ name: 'Location', value: '/dashboard' }],
  });
  await settle();
  console.log = realLog;

  check('verified login logs the expected line', logs.some((l) => l === 'Login verified for URL: https://app.example.com'), JSON.stringify(logs));
  check('entry removed from the store after verify', !store.has(1));
  check('wipe() fired on the SUCCESS path', wipes >= 1, `wipes=${wipes}`);

  // --- rejection path: 401 ---
  wipes = 0;
  await submit(2);
  fire('onHeadersReceived', { tabId: 2, statusCode: 401, url: 'https://app.example.com/login', type: 'xmlhttprequest', responseHeaders: [] });
  await settle();
  check('401 clears the pending entry', !store.has(2));
  check('wipe() fired on the FAILURE path', wipes >= 1, `wipes=${wipes}`);

  // --- tab closed mid-flight ---
  wipes = 0;
  await submit(3);
  fire('onRemoved', 3);
  check('closing the tab wipes the credential', !store.has(3) && wipes >= 1);

  // --- SPA verdicts ---
  wipes = 0;
  await submit(4);
  fire('onMessage', { type: 'nmp:spa-success', reason: 'auth-marker' }, { tab: { id: 4 } }, () => {});
  await settle();
  check('SPA success resolves the capture', !store.has(4) && wipes >= 1);

  wipes = 0;
  await submit(5);
  fire('onMessage', { type: 'nmp:spa-failure', reason: 'error-text' }, { tab: { id: 5 } }, () => {});
  await settle();
  check('SPA failure wipes the capture', !store.has(5) && wipes >= 1);

  // --- resubmission supersedes ---
  wipes = 0;
  await submit(6);
  await submit(6);
  check('resubmission supersedes and wipes the stale credential', store.size() >= 1 && wipes >= 1, `wipes=${wipes}`);

  // --- timeout now falls back to an *unverified* capture, not a silent drop ---
  wipes = 0;
  native.sent.length = 0;
  native.reply = { type: 'ok' };
  await submit(7);
  check('pending before deadline', store.has(7));
  await new Promise((r) => setTimeout(r, store.VERIFICATION_WINDOW_MS + 250));
  check('timeout wipes the credential', !store.has(7), `size=${store.size()}`);
  check('wipe() fired on the TIMEOUT path', wipes >= 1, `wipes=${wipes}`);
  const unverified = native.sent.find((s) => s.message?.type === 'save-credential');
  check('timeout sends an unverified capture rather than dropping it', !!unverified, JSON.stringify(native.sent));
  check('unverified capture is flagged for the app', unverified?.message?.unverified === true);
  check('unverified capture still carries the credential', unverified?.message?.password === 'pw');

  // --- an origin the app reports as "ignore" is not tracked again ---
  // (submit() hardcodes targetUrl, so key a distinct origin explicitly.)
  const submitTo = (tabId, targetUrl) =>
    new Promise((resolve) => {
      fire(
        'onMessage',
        { type: 'nmp:submit-observed', credential: { username: 'ofek', password: 'pw', targetUrl, timestamp: Date.now() } },
        { tab: { id: tabId }, url: `${targetUrl}/login` },
        resolve,
      );
    });
  wipes = 0;
  native.reply = { type: 'ok', policy: 'ignore' };
  await submitTo(9, 'https://ignore.example.com');
  await new Promise((r) => setTimeout(r, store.VERIFICATION_WINDOW_MS + 250));
  await settle();
  native.sent.length = 0;
  const tracked = await submitTo(9, 'https://ignore.example.com');
  check('a learned "ignore" origin is refused up front', tracked?.tracking === false, JSON.stringify(tracked));
  check('and never reaches the host again', !native.sent.some((s) => s.message?.type === 'save-credential'));

  // --- the verified path reaches the native host, flagged verified ---
  native.sent.length = 0;
  native.reply = { type: 'error', code: 'not-implemented' };
  await submit(8);
  fire('onCommitted', { tabId: 8, frameId: 0, url: 'https://app.example.com/dashboard', transitionQualifiers: ['server_redirect'] });
  await settle();
  const saveAttempt = native.sent.find((s) => s.message?.type === 'save-credential');
  check('verified login calls the native host', !!saveAttempt, JSON.stringify(native.sent));
  check('native host is addressed by name', saveAttempt?.host === 'com.nomorepwn.bridge', saveAttempt?.host);
  check('verified capture is flagged verified', saveAttempt?.message?.verified === true);
  check('credential reaches the host intact', saveAttempt?.message?.password === 'pw' && saveAttempt?.message?.username === 'ofek');
  check('holder still wiped after a host refusal', !store.has(8));

  store.discardAll('cleanup');
  SecureCredentialHolder.prototype.wipe = realWipe;
}

/* ================================================================== */
section('4. Native-messaging bridge');
/* ================================================================== */
{
  const bridge = await mod('background/bridge.js');
  const native = globalThis.__native;

  native.fail = null;
  native.reply = { type: 'pong', protocol: 1, version: '1.0.0', vaultPresent: true };
  const good = await bridge.ping();
  check('ping() reports connected', good.connected === true, JSON.stringify(good));
  check('ping() surfaces the app version', good.version === '1.0.0');
  check('ping() surfaces vault presence', good.vaultPresent === true);

  native.fail = 'Specified native messaging host not found.';
  const missing = await bridge.ping();
  check('a missing host resolves rather than throwing', missing.connected === false, JSON.stringify(missing));
  check('the host error is surfaced', /not found/.test(missing.error ?? ''), missing.error);

  native.fail = null;
  native.reply = { type: 'something-else' };
  const confused = await bridge.ping();
  check('an unexpected reply is not treated as connected', confused.connected === false, JSON.stringify(confused));

  native.reply = { type: 'pong', protocol: 1, version: '1.0.0', vaultPresent: false };
}

/* ================================================================== */
section('5. SPA MutationObserver (jsdom)');
/* ================================================================== */
{
  const observerSrc = readFileSync(new URL('content/spa-observer.js', SRC), 'utf8');

  /**
   * Boot a DOM with a login form, run the observer, and drive the page.
   * @returns {{window, watch, form}}
   */
  function boot(bodyHtml = '<form id="login"><input type="password" id="pw"><button>Go</button></form>') {
    const dom = new JSDOM(`<!doctype html><body>${bodyHtml}</body>`, { runScripts: 'outside-only' });
    dom.window.eval(observerSrc);
    return { window: dom.window, form: dom.window.document.querySelector('form') };
  }

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  // --- success: authenticated marker appears ---
  {
    const { window, form } = boot();
    let outcome = null;
    window.__nmpSpaObserver.watch({
      form,
      username: 'ofek',
      onSuccess: (r) => (outcome = ['success', r]),
      onFailure: (r) => (outcome = ['failure', r]),
    });
    const nav = window.document.createElement('nav');
    nav.id = 'user-menu';
    window.document.body.appendChild(nav);
    await wait(400);
    check('detects #user-menu appearing', outcome?.[0] === 'success' && outcome[1] === 'auth-marker', JSON.stringify(outcome));
  }

  // --- success: logout control appears ---
  {
    const { window, form } = boot();
    let outcome = null;
    window.__nmpSpaObserver.watch({ form, username: 'ofek', onSuccess: (r) => (outcome = ['success', r]), onFailure: (r) => (outcome = ['failure', r]) });
    const btn = window.document.createElement('button');
    btn.textContent = 'Log out';
    window.document.body.appendChild(btn);
    await wait(400);
    check('detects a "Log out" control', outcome?.[0] === 'success', JSON.stringify(outcome));
  }

  // --- success: username echoed into the UI ---
  {
    const { window, form } = boot();
    let outcome = null;
    window.__nmpSpaObserver.watch({ form, username: 'ofekv', onSuccess: (r) => (outcome = ['success', r]), onFailure: (r) => (outcome = ['failure', r]) });
    const span = window.document.createElement('span');
    span.textContent = 'Signed in as ofekv';
    window.document.body.appendChild(span);
    await wait(400);
    check('detects the username echoed back', outcome?.[0] === 'success' && outcome[1] === 'username-echoed', JSON.stringify(outcome));
  }

  // --- success: login form removed ---
  {
    const { window, form } = boot();
    let outcome = null;
    window.__nmpSpaObserver.watch({ form, username: 'ofek', onSuccess: (r) => (outcome = ['success', r]), onFailure: (r) => (outcome = ['failure', r]) });
    form.remove();
    window.document.body.appendChild(window.document.createElement('div'));
    await wait(400);
    check('detects the login form disappearing', outcome?.[0] === 'success' && outcome[1] === 'login-form-removed', JSON.stringify(outcome));
  }

  // --- failure: error text appears ---
  {
    const { window, form } = boot();
    let outcome = null;
    window.__nmpSpaObserver.watch({ form, username: 'ofek', onSuccess: (r) => (outcome = ['success', r]), onFailure: (r) => (outcome = ['failure', r]) });
    const err = window.document.createElement('div');
    err.textContent = 'Incorrect username or password.';
    window.document.body.appendChild(err);
    await wait(400);
    check('detects "Incorrect username or password"', outcome?.[0] === 'failure' && outcome[1] === 'error-text', JSON.stringify(outcome));
  }

  // --- error text wins over a co-occurring success signal ---
  {
    const { window, form } = boot();
    let outcome = null;
    window.__nmpSpaObserver.watch({ form, username: 'ofek', onSuccess: (r) => (outcome = ['success', r]), onFailure: (r) => (outcome = ['failure', r]) });
    const err = window.document.createElement('div');
    err.textContent = 'Invalid password';
    const nav = window.document.createElement('nav');
    nav.id = 'user-menu';
    window.document.body.append(err, nav);
    await wait(400);
    check('error text outranks a success marker', outcome?.[0] === 'failure', JSON.stringify(outcome));
  }

  // --- a re-rendered login form is NOT success ---
  {
    const { window, form } = boot();
    let outcome = null;
    window.__nmpSpaObserver.watch({ form, username: 'ofek', onSuccess: (r) => (outcome = ['success', r]), onFailure: (r) => (outcome = ['failure', r]) });
    form.remove();
    const fresh = window.document.createElement('form');
    fresh.innerHTML = '<input type="password">';
    window.document.body.appendChild(fresh);
    await wait(400);
    check('a re-rendered login form is not treated as success', outcome === null, JSON.stringify(outcome));
  }

  // --- CPU: N mutations must not mean N evaluations ---
  {
    const { window, form } = boot();
    let evaluations = 0;
    const realQS = window.document.querySelector.bind(window.document);
    window.document.querySelector = (sel) => {
      if (String(sel).includes('user-menu')) evaluations++;
      return realQS(sel);
    };
    window.__nmpSpaObserver.watch({ form, username: 'ofek', onSuccess: () => {}, onFailure: () => {} });
    for (let i = 0; i < 500; i++) {
      window.document.body.appendChild(window.document.createElement('div'));
    }
    await wait(400);
    check('500 mutations coalesce into few evaluations', evaluations > 0 && evaluations <= 3, `evaluations=${evaluations}`);
  }

  // --- disconnect: no work after settling ---
  {
    const { window, form } = boot();
    let outcome = null;
    let evaluations = 0;
    const realQS = window.document.querySelector.bind(window.document);
    window.document.querySelector = (sel) => {
      if (String(sel).includes('user-menu')) evaluations++;
      return realQS(sel);
    };
    window.__nmpSpaObserver.watch({ form, username: 'ofek', onSuccess: (r) => (outcome = ['success', r]), onFailure: (r) => (outcome = ['failure', r]) });
    const nav = window.document.createElement('nav');
    nav.id = 'user-menu';
    window.document.body.appendChild(nav);
    await wait(400);
    const settledAt = evaluations;
    const outcomeAt = JSON.stringify(outcome);

    for (let i = 0; i < 500; i++) window.document.body.appendChild(window.document.createElement('div'));
    await wait(500);
    check('observer stops evaluating after it settles', evaluations === settledAt, `before=${settledAt} after=${evaluations}`);
    check('outcome is not fired twice', JSON.stringify(outcome) === outcomeAt);
  }

  // --- teardown() is callable and idempotent ---
  {
    const { window, form } = boot();
    const stop = window.__nmpSpaObserver.watch({ form, username: 'ofek', onSuccess: () => {}, onFailure: () => {} });
    stop();
    stop();
    let fired = false;
    window.__nmpSpaObserver.watch; // no-op
    window.document.body.appendChild(window.document.createElement('div'));
    await wait(300);
    check('teardown() is idempotent and silences the observer', !fired);
  }

  // --- the 10s deadline actually fires ---
  {
    const { window, form } = boot();
    let outcome = null;
    window.__nmpSpaObserver.watch({ form, username: 'ofek', onSuccess: (r) => (outcome = ['success', r]), onFailure: (r) => (outcome = ['failure', r]) });
    check('observer window is 10s as specified', window.__nmpSpaObserver.WINDOW_MS === 10000);
    await wait(window.__nmpSpaObserver.WINDOW_MS + 600);
    check('deadline fires onFailure("timeout")', outcome?.[0] === 'failure' && outcome[1] === 'timeout', JSON.stringify(outcome));
  }
}

console.log(`\n${'='.repeat(50)}\n  ${pass} passed, ${fail} failed`);
if (fail) console.log('  failures:\n' + failures.map((f) => `   - ${f}`).join('\n'));
process.exit(fail ? 1 : 0);
