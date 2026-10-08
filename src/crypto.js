/**
 * Password encryption for on-disk persistence (AES-256-GCM via WebCrypto).
 *
 * Uses only `globalThis.crypto.subtle`, which exists in Node >= 22 and in
 * modern browsers, so the library keeps zero npm dependencies.
 *
 * Format of a serialized secret:
 * ```json
 * {
 *   "v": 1, "alg": "AES-GCM",
 *   "kdf": { "name": "PBKDF2", "hash": "SHA-256", "iterations": 250000, "salt": "<b64>" },
 *   "iv": "<b64>", "ct": "<b64>"   // ct includes the GCM tag
 * }
 * ```
 */

import { ConfigurationError } from './errors.js';

const KDF_ITERATIONS = 250_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

/** True when WebCrypto subtle is usable in this runtime. */
export function isCryptoAvailable() {
  return typeof globalThis.crypto?.subtle?.importKey === 'function';
}

function requireSubtle() {
  if (!isCryptoAvailable()) {
    throw new ConfigurationError('WebCrypto (crypto.subtle) is unavailable; cannot encrypt secrets', {
      code: 'CRYPTO_UNAVAILABLE',
    });
  }
}

/** @param {string|Uint8Array} bytes @returns {string} base64 */
export function toBase64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < arr.length; i += CHUNK) {
    bin += String.fromCharCode(...arr.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

/** @param {string} b64 @returns {Uint8Array} */
export function fromBase64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(keyMaterial, salt, iterations) {
  const material =
    typeof keyMaterial === 'string' ? new TextEncoder().encode(keyMaterial) : new Uint8Array(keyMaterial);
  if (material.length === 0) throw new ConfigurationError('encryptionKey must not be empty');
  const baseKey = await globalThis.crypto.subtle.importKey('raw', material, 'PBKDF2', false, ['deriveKey']);
  return globalThis.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Encrypt a secret (account password) with the caller-provided key.
 *
 * @param {string} secret
 * @param {string|Uint8Array} keyMaterial passphrase (option or AUT_CAS_SESSION_KEY)
 * @returns {Promise<object>} serializable blob
 */
export async function encryptSecret(secret, keyMaterial) {
  requireSubtle();
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(keyMaterial, salt, KDF_ITERATIONS);
  const ct = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(secret));
  return {
    v: 1,
    alg: 'AES-GCM',
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: KDF_ITERATIONS, salt: toBase64(salt) },
    iv: toBase64(iv),
    ct: toBase64(new Uint8Array(ct)),
  };
}

/**
 * Decrypt a blob produced by {@link encryptSecret}.
 *
 * @param {object} blob
 * @param {string|Uint8Array} keyMaterial
 * @returns {Promise<string>}
 */
export async function decryptSecret(blob, keyMaterial) {
  requireSubtle();
  if (!blob || blob.v !== 1 || blob.alg !== 'AES-GCM') {
    throw new ConfigurationError('Unsupported secret blob format');
  }
  const key = await deriveKey(keyMaterial, fromBase64(blob.kdf.salt), blob.kdf.iterations);
  try {
    const pt = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(blob.iv) },
      key,
      fromBase64(blob.ct),
    );
    return new TextDecoder().decode(pt);
  } catch {
    throw new ConfigurationError('Failed to decrypt stored secret (wrong encryptionKey?)', {
      code: 'DECRYPTION_FAILED',
    });
  }
}
