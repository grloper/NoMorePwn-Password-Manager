/**
 * Success/failure heuristics for a submitted login.
 *
 * These are *heuristics*, and the false-positive rate matters: see
 * extension/README.md ("Heuristic honesty") for why `Set-Cookie` alone is
 * nearly worthless as a success signal and is scored accordingly.
 *
 * The scorer is additive so signals can corroborate each other. Rejection is
 * not scored — a 401/403 is conclusive and resolves immediately.
 */

/** Score at or above which we call the login verified. */
export const SUCCESS_THRESHOLD = 3;

const SCORE = {
  /** Redirected away from the login page entirely. Strongest MPA signal. */
  REDIRECT_OFF_LOGIN: 3,
  /** Landed on something that looks like an authenticated route. */
  AUTHENTICATED_ROUTE: 2,
  /** A session-shaped cookie was issued. Weak: failures set cookies too. */
  SESSION_COOKIE: 1,
  /** Committed a navigation to a different path than the login page. */
  NAVIGATED_OFF_LOGIN: 2,
};

/** Statuses that conclusively mean "those credentials were wrong". */
const REJECTION_STATUSES = new Set([401, 403]);

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Paths that generally only exist behind a login. */
const AUTHENTICATED_ROUTE = /^\/(dashboard|home|account|profile|app|admin|settings|feed|inbox|my)\b/i;

/**
 * Paths that mean we are still sitting on the login flow.
 *
 * A login token matches only when it is NOT the *prefix* of a longer word, so
 * `/author/ofek` no longer matches "auth" (the old unanchored regex did, which
 * silently zeroed verification for those routes) while `/auth/callback`,
 * `/oauth/authorize`, `/login-error`, `/user-login`, and `/sign-in` still do.
 * Matching here fails safe: a false match only costs a missed save; a false
 * *miss* would let a failed login redirecting to a login page score as success,
 * so we keep the token list broad and only trim the prefix-of-a-word case.
 */
const LOGIN_ROUTE = /(?:login|sign-?in|auth|authenticate|session|sso|challenge|verify|mfa|otp)(?![a-z])/i;

/** Cookie names that plausibly carry a session, rather than CSRF/analytics. */
const SESSION_COOKIE = /^(sid|sess|session|auth|token|jwt|remember|login|connect\.sid|_?[a-z]*session[a-z_]*)/i;

function pathOf(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return '';
  }
}

/** Resolve a possibly-relative URL (e.g. a `Location` header) against a base. */
function absoluteUrl(url, base) {
  try {
    return new URL(url, base).href;
  } catch {
    return '';
  }
}

function isIpLiteral(host) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

/** Registrable-ish domain: the last two dot-labels (no Public Suffix List here). */
function baseDomain(host) {
  const labels = host.split('.').filter(Boolean);
  return labels.length <= 2 ? host : labels.slice(-2).join('.');
}

/**
 * Is `url` on the same site as the login page `base`?
 *
 * `webRequest` fires for *every* request in the tab — third-party subframes, ad
 * beacons, analytics XHR — so without this gate a stray 401 from any of them
 * rejects the capture outright, and a stray redirect or session-shaped cookie
 * inflates the score toward a false "verified". Only the login site's own
 * responses are evidence.
 *
 * "Same site" is same scheme + same registrable domain, approximated by the
 * last two labels because an extension has no Public Suffix List. The residual
 * gap (two sibling `*.co.uk` sites in one tab) is far narrower than the bug it
 * closes, and IP literals fall back to exact-host equality so `1.2.3.4` and
 * `9.8.3.4` are never grouped.
 */
function isSameSite(url, base) {
  let a;
  let b;
  try {
    a = new URL(url);
  } catch {
    return false;
  }
  try {
    b = new URL(base);
  } catch {
    return false;
  }
  if (a.protocol !== b.protocol) return false;
  const ha = a.hostname.toLowerCase();
  const hb = b.hostname.toLowerCase();
  if (ha === hb) return true;
  if (isIpLiteral(ha) || isIpLiteral(hb)) return false;
  return baseDomain(ha) === baseDomain(hb);
}

function headerValues(headers, name) {
  const wanted = name.toLowerCase();
  return (headers ?? []).filter((h) => h.name.toLowerCase() === wanted).map((h) => h.value ?? '');
}

/**
 * Evaluate a response observed on a tab with a pending capture.
 *
 * @param {import('./pending-store.js').PendingLogin} entry
 * @param {{statusCode: number, url: string, responseHeaders?: chrome.webRequest.HttpHeader[]}} response
 * @returns {{rejected: boolean, points: number, evidence: string[]}}
 */
export function scoreResponse(entry, response) {
  const evidence = [];
  let points = 0;

  // Only the login site's own responses are evidence. A third-party 401 must
  // not reject the capture, and a third-party redirect/cookie must not score.
  if (!isSameSite(response.url, entry.loginUrl)) {
    return { rejected: false, points: 0, evidence };
  }

  if (REJECTION_STATUSES.has(response.statusCode)) {
    return { rejected: true, points: 0, evidence: [`HTTP ${response.statusCode}`] };
  }

  const loginPath = pathOf(entry.loginUrl);

  if (REDIRECT_STATUSES.has(response.statusCode)) {
    const [location] = headerValues(response.responseHeaders, 'location');
    const destUrl = location ? absoluteUrl(location, response.url) : '';
    const destination = destUrl ? pathOf(destUrl) : '';

    // A redirect *back to* the login page is the classic failure pattern, and a
    // redirect *off to another site* is not evidence this login succeeded —
    // both earn nothing.
    if (
      destination &&
      isSameSite(destUrl, entry.loginUrl) &&
      destination !== loginPath &&
      !LOGIN_ROUTE.test(destination)
    ) {
      points += SCORE.REDIRECT_OFF_LOGIN;
      evidence.push(`${response.statusCode} -> ${destination}`);

      if (AUTHENTICATED_ROUTE.test(destination)) {
        points += SCORE.AUTHENTICATED_ROUTE;
        evidence.push(`authenticated route ${destination}`);
      }
    }
  }

  const cookies = headerValues(response.responseHeaders, 'set-cookie');
  if (cookies.some((c) => SESSION_COOKIE.test(c.split('=')[0]?.trim() ?? ''))) {
    points += SCORE.SESSION_COOKIE;
    evidence.push('session cookie issued');
  }

  return { rejected: false, points, evidence };
}

/**
 * Evaluate a committed navigation on a tab with a pending capture.
 *
 * `chrome.webNavigation` gives us no status code, but it does tell us the tab
 * actually landed somewhere — which `onHeadersReceived` alone cannot confirm.
 *
 * @param {import('./pending-store.js').PendingLogin} entry
 * @param {{url: string, transitionQualifiers?: string[]}} nav
 */
export function scoreNavigation(entry, nav) {
  const evidence = [];
  let points = 0;

  // A top-frame navigation to a different site is the user leaving the login
  // site, not a successful login on it.
  if (!isSameSite(nav.url, entry.loginUrl)) {
    return { rejected: false, points: 0, evidence };
  }

  const loginPath = pathOf(entry.loginUrl);
  const landedPath = pathOf(nav.url);

  if (!landedPath || landedPath === loginPath || LOGIN_ROUTE.test(landedPath)) {
    return { rejected: false, points: 0, evidence };
  }

  points += SCORE.NAVIGATED_OFF_LOGIN;
  evidence.push(`navigated to ${landedPath}`);

  if (AUTHENTICATED_ROUTE.test(landedPath)) {
    points += SCORE.AUTHENTICATED_ROUTE;
    evidence.push(`authenticated route ${landedPath}`);
  }

  if (nav.transitionQualifiers?.includes('server_redirect')) {
    points += SCORE.REDIRECT_OFF_LOGIN;
    evidence.push('server redirect');
  }

  return { rejected: false, points, evidence };
}
