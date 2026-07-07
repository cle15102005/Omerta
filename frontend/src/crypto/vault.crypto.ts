/**
 * vault.crypto.ts
 *
 * All cryptographic operations for Omerta vault.
 * Uses browser Web Crypto API ONLY — no npm dependencies.
 *
 * Key operations:
 *   - PBKDF2 key derivation (master password → Auth Key + PEK)
 *   - AES-256-GCM encrypt / decrypt
 *   - Secure random password generation
 */

const PBKDF2_ITERATIONS = 310_000;
const PBKDF2_HASH       = 'SHA-256';
const KEY_LENGTH        = 256; // bits

// ── Helpers ───────────────────────────────────────────────────────────────────

function bufferToBase64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuffer(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function bufferToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBuffer(hex: string): Uint8Array {
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return result;
}

// ── Key Derivation ────────────────────────────────────────────────────────────

/**
 * Derive Auth Key + Personal Encryption Key (PEK) from master password + salt.
 *
 * PBKDF2 produces 64 bytes:
 *   [0..31]  = Auth Key  → sent to server as hex for login/register verification
 *   [32..63] = PEK       → held in Zustand memory ONLY, never transmitted
 */
export async function deriveMasterKeys(
  masterPassword: string,
  saltBase64: string
): Promise<{ authKeyHex: string; pek: CryptoKey }> {
  const enc      = new TextEncoder();
  const salt     = base64ToBuffer(saltBase64);
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(masterPassword), 'PBKDF2', false, ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
    keyMaterial,
    512 // 64 bytes
  );

  const authKeyRaw = derivedBits.slice(0, 32);
  const pekRaw     = derivedBits.slice(32, 64);

  const pek = await crypto.subtle.importKey(
    'raw', pekRaw, { name: 'AES-GCM', length: KEY_LENGTH }, false, ['encrypt', 'decrypt']
  );

  return { authKeyHex: bufferToHex(authKeyRaw), pek };
}

// ── AES-256-GCM Encrypt / Decrypt ─────────────────────────────────────────────

/**
 * Encrypt a JSON-serializable object with AES-256-GCM.
 * Returns: "base64(iv):base64(ciphertext)"  (authTag is appended by GCM automatically)
 */
export async function encryptPayload(key: CryptoKey, plaintext: object): Promise<string> {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(JSON.stringify(plaintext))
  );

  return `${bufferToBase64(iv)}:${bufferToBase64(ciphertext)}`;
}

/**
 * Decrypt an AES-256-GCM encrypted string back to the original object.
 */
export async function decryptPayload<T = unknown>(key: CryptoKey, encrypted: string): Promise<T> {
  const [ivB64, ciphertextB64] = encrypted.split(':');
  const iv         = base64ToBuffer(ivB64);
  const ciphertext = base64ToBuffer(ciphertextB64);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  return JSON.parse(new TextDecoder().decode(plaintext)) as T;
}

// ── Password Generator ────────────────────────────────────────────────────────

const CHARSET = {
  lower:   'abcdefghijklmnopqrstuvwxyz',
  upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
};

export interface PasswordOptions {
  length:    number;
  uppercase: boolean;
  numbers:   boolean;
  symbols:   boolean;
}

export function generatePassword(opts: PasswordOptions): string {
  let pool = CHARSET.lower;
  if (opts.uppercase) pool += CHARSET.upper;
  if (opts.numbers)   pool += CHARSET.numbers;
  if (opts.symbols)   pool += CHARSET.symbols;

  const randomValues = crypto.getRandomValues(new Uint32Array(opts.length));
  return Array.from(randomValues, (v) => pool[v % pool.length]).join('');
}

// ── SHA-256 (for Merkle leaf hashes) ─────────────────────────────────────────

export async function sha256hex(input: string): Promise<string> {
  const enc    = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(input));
  return bufferToHex(digest);
}

// ── Re-export helpers for other crypto modules ────────────────────────────────
export { bufferToBase64, base64ToBuffer, bufferToHex, hexToBuffer };
