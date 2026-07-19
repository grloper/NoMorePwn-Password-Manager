/**
 * Native-messaging bridge to the NoMorePwn desktop app.
 *
 * The browser launches a short-lived host process (registered by the app's
 * Settings → Browser extension → "Set up"). We use one-shot
 * `sendNativeMessage` calls rather than a long-lived `connectNative` port,
 * because an MV3 worker is torn down on idle anyway — a port would die with
 * it and the reconnect bookkeeping would buy nothing.
 *
 * Every call resolves to a result object rather than throwing: a missing host
 * is the normal state before setup, not an exceptional one.
 */

import { api } from '../shared/browser-api.js';

export const HOST_NAME = 'com.nomorepwn.bridge';

/** @typedef {{ok: true, data: object} | {ok: false, error: string}} BridgeResult */

/**
 * Send one message to the host.
 * @returns {Promise<BridgeResult>}
 */
export function send(message) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };

    try {
      api.runtime.sendNativeMessage(HOST_NAME, message, (response) => {
        if (api.runtime.lastError) {
          finish({ ok: false, error: api.runtime.lastError.message });
          return;
        }
        finish({ ok: true, data: response });
      });
    } catch (err) {
      finish({ ok: false, error: String(err?.message ?? err) });
    }
  });
}

/**
 * Check whether the desktop app is reachable.
 * @returns {Promise<{connected: boolean, version?: string, vaultPresent?: boolean, error?: string}>}
 */
export async function ping() {
  const result = await send({ type: 'ping' });
  if (!result.ok) return { connected: false, error: result.error };
  if (result.data?.type !== 'pong') {
    return { connected: false, error: `unexpected reply: ${result.data?.type}` };
  }
  return {
    connected: true,
    version: result.data.version,
    vaultPresent: result.data.vaultPresent,
  };
}
