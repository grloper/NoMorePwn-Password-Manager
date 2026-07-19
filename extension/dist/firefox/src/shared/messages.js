/**
 * Message contract between the content scripts and the background worker.
 *
 * Credentials travel exactly once, in SUBMIT_OBSERVED. Every later message is
 * a verdict about a tab, never a secret — see extension/README.md ("Why the
 * content script never holds the password").
 */

export const MSG = {
  /** content -> background: a login form was submitted. Carries credentials. */
  SUBMIT_OBSERVED: 'nmp:submit-observed',
  /** content -> background: the SPA heuristics decided the login succeeded. */
  SPA_SUCCESS: 'nmp:spa-success',
  /** content -> background: SPA heuristics saw an error, or timed out. */
  SPA_FAILURE: 'nmp:spa-failure',
};

/** Reasons a pending capture was resolved — used for logging and metrics. */
export const OUTCOME = {
  VERIFIED_REDIRECT: 'redirect-to-authenticated-route',
  VERIFIED_SESSION: 'session-credential-issued',
  VERIFIED_SPA: 'spa-dom-transition',
  REJECTED_STATUS: 'auth-rejected-status',
  REJECTED_SPA: 'spa-error-detected',
  TIMED_OUT: 'verification-timeout',
  TAB_GONE: 'tab-closed',
  SUPERSEDED: 'newer-submission',
};
