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

/** Paths that mean we are still sitting on the login flow. */
const LOGIN_ROUTE = /(login|signin|sign-in|auth|session|sso|challenge|verify|mfa|otp)/i;

/** Cookie names that plausibly carry a session, rather than CSRF/analytics. */
const SESSION_COOKIE = /^(sid|sess|session|auth|token|jwt|remember|login|connect\.sid|_?[a-z]*session[a-z_]*)/i;

function pathOf(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return '';
  }
}

function sameOriginPath(url, base) {
  try {
    return new URL(url, base).pathname;
  } catch {
    return '';
  }
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

  if (REJECTION_STATUSES.has(response.statusCode)) {
    return { rejected: true, points: 0, evidence: [`HTTP ${response.statusCode}`] };
  }

  const loginPath = pathOf(entry.loginUrl);

  if (REDIRECT_STATUSES.has(response.statusCode)) {
    const [location] = headerValues(response.responseHeaders, 'location');
    const destination = location ? sameOriginPath(location, response.url) : '';

    // A redirect *back to* the login page is the classic failure pattern —
    // it earns nothing rather than being treated as evidence of success.
    if (destination && destination !== loginPath && !LOGIN_ROUTE.test(destination)) {
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
