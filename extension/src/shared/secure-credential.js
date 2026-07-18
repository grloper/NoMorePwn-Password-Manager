/**
 * SecureCredentialHolder — minimises how long a captured credential is
 * readable in the service worker's heap.
 *
 * ## What this actually buys you (read before trusting it)
 *
 * This class is hygiene and blast-radius reduction, NOT a defence against an
 * attacker who can dump the process's memory. Be clear-eyed about the limits:
 *
 *  - **JS strings cannot be wiped.** They are immutable, and V8's GC copies
 *    them during scavenges. The credential arrives as a string (it came from
 *    `input.value` and crossed `sendMessage` via structured clone), so by the
 *    time we see it, uncontrolled copies may already exist on the heap. We
 *    convert to a `Uint8Array` immediately and never re-hold the string, but
 *    the originals die whenever the GC decides, not when we say so.
 *  - **Zeroing `Uint8Array`s does work.** Typed-array backing stores are real
 *    mutable buffers; `fill(0)` genuinely overwrites them. That is the part of
 *    `wipe()` with teeth.
 *  - **The AES key is non-extractable.** `generateKey(..., false, ...)` keeps
 *    the raw key material inside the browser's crypto backend, not in our
 *    heap. This is the only reason encrypting-at-rest-in-RAM is worth anything
 *    here: a heap dump yields ciphertext without the key. If the key were an
 *    ordinary `Uint8Array` sitting beside the ciphertext, this class would be
 *    pure theatre.
 *  - **It does not stop XSS.** Page JavaScript cannot reach extension memory
 *    at all (isolated world / separate process). XSS steals the password from
 *    the form field long before this class exists.
 *
 * The real security win is architectural, not cryptographic: credentials live
 * only in the background service worker, for seconds, and are wiped on every
 * exit path.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Gate on the constructor: only `create()` holds this token. */
const INTERNAL = Symbol('SecureCredentialHolder.internal');

/** `crypto.getRandomValues` rejects views longer than 65536 bytes. */
const RANDOM_CHUNK = 65536;

/** Overwrite a typed array with random bytes, then zeros. */
function scrub(view) {
  if (!view) return;
  for (let offset = 0; offset < view.length; offset += RANDOM_CHUNK) {
    crypto.getRandomValues(view.subarray(offset, offset + RANDOM_CHUNK));
  }
  view.fill(0);
}

export class SecureCredentialHolder {
  #key = null;
  #iv = null;
  #ciphertext = null;
  #wiped = false;

  /** Non-secret context, safe to read after wiping. */
  #meta = null;

  /** Construction is async (key generation), so go through `create()`. */
  constructor(token) {
    if (token !== INTERNAL) throw new Error('Use SecureCredentialHolder.create()');
  }

  /**
   * @param {{username: string, password: string, targetUrl: string, timestamp: number}} credential
   * @returns {Promise<SecureCredentialHolder>}
   */
  static async create({ username, password, targetUrl, timestamp }) {
    const holder = new SecureCredentialHolder(INTERNAL);

    holder.#meta = { targetUrl, timestamp, usernameLength: username?.length ?? 0 };

    // extractable=false keeps the raw key out of our address space.
    holder.#key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    holder.#iv = crypto.getRandomValues(new Uint8Array(12));

    const plaintext = encoder.encode(JSON.stringify({ username, password }));
    try {
      const sealed = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: holder.#iv },
        holder.#key,
        plaintext,
      );
      holder.#ciphertext = new Uint8Array(sealed);
    } finally {
      // The one buffer we fully control. Kill it whether or not encrypt threw.
      scrub(plaintext);
    }

    return holder;
  }

  get wiped() {
    return this.#wiped;
  }

  get meta() {
    return this.#meta;
  }

  /**
   * Decrypt, hand the credential to `consumer`, and scrub the decrypted buffer
   * before returning — even if `consumer` throws.
   *
   * The object passed to `consumer` contains real JS strings, which we cannot
   * wipe. Keep the callback short: hand them to the vault and return. Do not
   * stash them, log them, or close over them.
   *
   * @template T
   * @param {(credential: {username: string, password: string}) => Promise<T>|T} consumer
   * @returns {Promise<T>}
   */
  async reveal(consumer) {
    if (this.#wiped) throw new Error('SecureCredentialHolder already wiped');

    const opened = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: this.#iv }, this.#key, this.#ciphertext),
    );

    try {
      return await consumer(JSON.parse(decoder.decode(opened)));
    } finally {
      scrub(opened);
    }
  }

  /**
   * Overwrite every buffer we own and drop the key reference. Idempotent, so
   * it is safe to call from overlapping `finally` blocks.
   */
  wipe() {
    if (this.#wiped) return;
    this.#wiped = true;

    scrub(this.#ciphertext);
    scrub(this.#iv);

    this.#ciphertext = null;
    this.#iv = null;
    // Dropping the last reference to a non-extractable CryptoKey lets the
    // browser release the underlying key material. We cannot force it.
    this.#key = null;
  }
}
