/**
 * rsa.crypto.ts — v2
 *
 * RSA-OAEP key pair operations for Shared Vault key exchange.
 * Now includes ECDSA P-256 key signing for public key authentication.
 *
 * ── Key pairs generated at registration ──────────────────────────────────────
 *   RSA-OAEP key pair   → VEK encryption/decryption (shared vault invite flow)
 *   ECDSA P-256 key pair → Key self-certification (prevents key substitution MITM)
 *
 * ── ECDSA binding model ───────────────────────────────────────────────────────
 *   At registration:
 *     keySignature = ECDSA_Sign(ecdsaPrivateKey, SHA-256(rsaPublicKey))
 *     Stored in DB: { rsaPublicKey, ecdsaPublicKey, keySignature }
 *
 *   At invite (Alice invites Bob):
 *     Alice fetches: { rsaPublicKey, ecdsaPublicKey, keySignature }
 *     Alice verifies: ECDSA_Verify(ecdsaPublicKey, keySignature, rsaPublicKey)
 *     ✅ pass → RSA key is authentic, Alice encrypts VEK with it
 *     ❌ fail → key substitution detected, abort
 *
 * ── Three layers of key authentication ───────────────────────────────────────
 *   Layer 1 — ECDSA binding    : cryptographic proof both keys belong to same registration
 *   Layer 2 — TOFU             : browser caches own key fingerprint, warns on change
 *   Layer 3 — Fingerprint UI   : user compares fingerprints out-of-band (Signal-style)
 *
 * ── MITM coverage ────────────────────────────────────────────────────────────
 *   Network MITM (packet sniffing, DNS poisoning) → handled by HTTPS/TLS (not here)
 *   Application-layer key substitution            → handled by ECDSA + TOFU + fingerprint
 */

import { encryptPayload, decryptPayload, bufferToBase64, base64ToBuffer } from './vault.crypto';

// ── RSA-OAEP Key Generation ───────────────────────────────────────────────────

export async function generateRSAKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name:           'RSA-OAEP',
      modulusLength:  2048,
      publicExponent: new Uint8Array([1, 0, 1]) as any,
      hash:           'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );
}

// ── ECDSA P-256 Key Generation ────────────────────────────────────────────────

/**
 * Generate an ECDSA P-256 signing key pair for key self-certification.
 * The private key is encrypted with the user's PEK and stored in the DB.
 * The public key is stored in plaintext — it IS meant to be public.
 */
export async function generateECDSAKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

// ── RSA Export / Import ───────────────────────────────────────────────────────

export async function exportPublicKeyPEM(publicKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('spki', publicKey);
  const b64      = bufferToBase64(exported);
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
}

export async function importPublicKeyPEM(pem: string): Promise<CryptoKey> {
  const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, '');
  const der = base64ToBuffer(b64);
  return crypto.subtle.importKey('spki', der as any, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}

// ── ECDSA Export / Import ─────────────────────────────────────────────────────

/** Export ECDSA public key as base64 JWK string (stored in DB, returned to invite party) */
export async function exportECDSAPublicKey(ecdsaPublicKey: CryptoKey): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', ecdsaPublicKey);
  return btoa(JSON.stringify(jwk));
}

/** Import ECDSA public key from base64 JWK string (for signature verification during invite) */
export async function importECDSAPublicKey(b64Jwk: string): Promise<CryptoKey> {
  const jwk = JSON.parse(atob(b64Jwk));
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

// ── Private Key Storage (encrypted with PEK) ──────────────────────────────────

export async function encryptPrivateKey(privateKey: CryptoKey, pek: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('pkcs8', privateKey);
  const b64      = bufferToBase64(exported);
  return encryptPayload(pek, { privateKey: b64 });
}

export async function decryptPrivateKey(encryptedPrivateKey: string, pek: CryptoKey): Promise<CryptoKey> {
  const { privateKey: b64 } = await decryptPayload<{ privateKey: string }>(pek, encryptedPrivateKey);
  const der = base64ToBuffer(b64);
  return crypto.subtle.importKey('pkcs8', der as any, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
}

/** Encrypt ECDSA private key with PEK — same pattern as RSA private key */
export async function encryptECDSAPrivateKey(ecdsaPrivateKey: CryptoKey, pek: CryptoKey): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', ecdsaPrivateKey);
  return encryptPayload(pek, { ecdsaPrivateKey: JSON.stringify(jwk) });
}

/** Decrypt ECDSA private key with PEK — used when signing an updated key binding */
export async function decryptECDSAPrivateKey(encrypted: string, pek: CryptoKey): Promise<CryptoKey> {
  const { ecdsaPrivateKey: jwkStr } = await decryptPayload<{ ecdsaPrivateKey: string }>(pek, encrypted);
  const jwk = JSON.parse(jwkStr);
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

// ── ECDSA Key Binding (self-certification) ────────────────────────────────────

/**
 * Sign the RSA public key with the ECDSA private key.
 * Creates a cryptographic binding: proof that both keys belong to the same registration event.
 *
 * What is signed: SHA-256(rsaPublicKeyPEM encoded as UTF-8 bytes)
 * The PEM string is the canonical form — consistent across export/import cycles.
 */
export async function signRSAPublicKey(
  ecdsaPrivateKey: CryptoKey,
  rsaPublicKeyPEM: string
): Promise<string> {
  const data      = new TextEncoder().encode(rsaPublicKeyPEM);
  const sigBuffer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    ecdsaPrivateKey,
    data as any
  );
  return bufferToBase64(sigBuffer);
}

/**
 * Verify that the RSA public key was signed by the ECDSA private key corresponding
 * to the given ECDSA public key.
 *
 * Called by Alice when processing Bob's public key during a vault invite.
 * Returns false (not throw) on failure — caller decides how to handle.
 */
export async function verifyRSAPublicKey(
  ecdsaPublicKey: CryptoKey,
  signatureB64:   string,
  rsaPublicKeyPEM: string
): Promise<boolean> {
  try {
    const data      = new TextEncoder().encode(rsaPublicKeyPEM);
    const sigBuffer = base64ToBuffer(signatureB64);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      ecdsaPublicKey,
      sigBuffer as any,
      data as any
    );
  } catch {
    return false; // malformed input = treat as failed verification
  }
}

// ── Key Fingerprint ───────────────────────────────────────────────────────────

/**
 * Compute a human-readable fingerprint from the ECDSA public key.
 * Displayed in Settings → "My Key" and during vault invites for out-of-band verification.
 *
 * Format: "A3F2-9KL1-MN84-PQ72" (first 16 chars of SHA-256, grouped in 4s)
 * Same model as SSH fingerprints and Signal safety numbers.
 */
export async function computeKeyFingerprint(ecdsaPublicKeyB64: string): Promise<string> {
  const data    = new TextEncoder().encode(ecdsaPublicKeyB64);
  const hashBuf = await crypto.subtle.digest('SHA-256', data as any);
  const hex     = Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase()
    .slice(0, 16);

  // Group into 4-char blocks: "A3F29KL1MN84PQ72" → "A3F2-9KL1-MN84-PQ72"
  return hex.match(/.{4}/g)!.join('-');
}

// ── TOFU (Trust On First Use) key pinning ────────────────────────────────────

const TOFU_KEY_PREFIX = 'omerta_key_fp_';

/**
 * On login success, call this to establish or verify the TOFU baseline.
 * - First login:  stores the fingerprint in localStorage
 * - Later logins: compares stored fingerprint to current — returns false if changed
 *
 * A false result should show a security warning to the user:
 *   "Your signing key changed since last login.
 *    If you didn't reset your account, your server may be compromised."
 */
export async function checkTOFU(email: string, ecdsaPublicKeyB64: string): Promise<boolean> {
  const fingerprint = await computeKeyFingerprint(ecdsaPublicKeyB64);
  const storageKey  = `${TOFU_KEY_PREFIX}${email}`;
  const cached      = localStorage.getItem(storageKey);

  if (!cached) {
    // First login — establish baseline
    localStorage.setItem(storageKey, fingerprint);
    return true;
  }

  // Subsequent logins — verify key hasn't changed
  return cached === fingerprint;
}

/** Clear TOFU baseline for an account (call during full account reset / key rotation) */
export function clearTOFU(email: string): void {
  localStorage.removeItem(`${TOFU_KEY_PREFIX}${email}`);
}

// ── Full registration bundle ──────────────────────────────────────────────────

/**
 * Convenience function: generate both key pairs, sign RSA with ECDSA, export everything.
 * Called once at registration — all outputs are sent to the server.
 */
export async function generateAndBindKeyPairs(pek: CryptoKey): Promise<{
  // RSA-OAEP
  publicKey:                string;   // RSA public key PEM
  encryptedPrivateKey:      string;   // AES-256-GCM(RSA private key, PEK)
  // ECDSA
  ecdsaPublicKey:           string;   // ECDSA P-256 public key (base64 JWK)
  encryptedECDSAPrivateKey: string;   // AES-256-GCM(ECDSA private key, PEK)
  keySignature:             string;   // ECDSA_Sign(ecdsaPriv, SHA-256(rsaPublicKeyPEM))
}> {
  // Generate both key pairs in parallel
  const [rsaKeyPair, ecdsaKeyPair] = await Promise.all([
    generateRSAKeyPair(),
    generateECDSAKeyPair(),
  ]);

  // Export RSA public key to PEM (the signed artifact)
  const publicKey = await exportPublicKeyPEM(rsaKeyPair.publicKey);

  // Sign RSA public key with ECDSA private key (key binding)
  const keySignature = await signRSAPublicKey(ecdsaKeyPair.privateKey, publicKey);

  // Encrypt both private keys with PEK (in parallel)
  const [encryptedPrivateKey, encryptedECDSAPrivateKey, ecdsaPublicKey] = await Promise.all([
    encryptPrivateKey(rsaKeyPair.privateKey, pek),
    encryptECDSAPrivateKey(ecdsaKeyPair.privateKey, pek),
    exportECDSAPublicKey(ecdsaKeyPair.publicKey),
  ]);

  return { publicKey, encryptedPrivateKey, ecdsaPublicKey, encryptedECDSAPrivateKey, keySignature };
}

// ── VEK Exchange ──────────────────────────────────────────────────────────────

/** Generate a new random Vault Encryption Key (VEK) for a shared vault */
export async function generateVEK(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

/**
 * Alice encrypts VEK with Bob's RSA public key → encryptedVEK for Bob's membership record.
 * MUST call verifyRSAPublicKey() before calling this — never encrypt with an unverified key.
 */
export async function encryptVEKForMember(vek: CryptoKey, memberPublicKey: CryptoKey): Promise<string> {
  const rawVEK = await crypto.subtle.exportKey('raw', vek);
  const enc    = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, memberPublicKey, rawVEK as any);
  return bufferToBase64(enc);
}

/** Bob decrypts his encryptedVEK with his RSA private key → recovers VEK */
export async function decryptVEKFromMembership(encryptedVEKB64: string, privateKey: CryptoKey): Promise<CryptoKey> {
  const enc    = base64ToBuffer(encryptedVEKB64);
  const rawVEK = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, enc as any);
  return crypto.subtle.importKey('raw', rawVEK as any, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
