/**
 * recovery.crypto.ts
 *
 * Recovery Code mechanism — zero-knowledge account recovery.
 *
 * Flow:
 *   Registration: generate Recovery Code → derive RecoveryKey via PBKDF2 →
 *                 AES-256-GCM(PEK, RecoveryKey) → encryptedPEKBackup → stored in DB
 *
 *   Recovery:     user enters Recovery Code → derive RecoveryKey →
 *                 decrypt encryptedPEKBackup → recover PEK →
 *                 set new master password
 */

import { deriveMasterKeys, encryptPayload, decryptPayload, bufferToBase64, base64ToBuffer } from './vault.crypto';

/** Generate a human-readable Recovery Code: OMERTA-XXXX-XXXX-XXXX-XXXX */
export function generateRecoveryCode(): string {
  const segment = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(2));
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  };
  return `OMERTA-${segment()}-${segment()}-${segment()}-${segment()}`;
}

/** Generate salt2 (base64, 16 bytes) for RecoveryKey PBKDF2 */
export function generateSalt2(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return bufferToBase64(bytes.buffer);
}

/**
 * Derive a RecoveryKey from the Recovery Code + salt2.
 * Uses same PBKDF2 parameters as master password derivation.
 * Only the left 32 bytes (AES-256 key) are used — no auth key needed here.
 */
export async function deriveRecoveryKey(recoveryCode: string, salt2Base64: string): Promise<CryptoKey> {
  const { pek } = await deriveMasterKeys(recoveryCode, salt2Base64);
  return pek; // pek here is just "right 32B used as AES key" — we reuse the same derivation
}

/**
 * At registration: encrypt the user's PEK with the RecoveryKey.
 * The result is stored in DB as encryptedPEKBackup.
 *
 * NOTE: We export the raw PEK bytes, encrypt them, then re-import on recovery.
 */
export async function encryptPEKWithRecovery(
  pek: CryptoKey,
  recoveryKey: CryptoKey
): Promise<string> {
  // Export PEK to raw bytes
  const rawPEK = await crypto.subtle.exportKey('raw', pek);
  const pekB64 = bufferToBase64(rawPEK);

  // Encrypt raw PEK bytes with recoveryKey
  return encryptPayload(recoveryKey, { pek: pekB64 });
}

/**
 * At recovery: decrypt encryptedPEKBackup using RecoveryKey → get PEK back.
 */
export async function decryptPEKFromBackup(
  encryptedPEKBackup: string,
  recoveryKey: CryptoKey
): Promise<CryptoKey> {
  const { pek: pekB64 } = await decryptPayload<{ pek: string }>(recoveryKey, encryptedPEKBackup);
  const rawPEK = base64ToBuffer(pekB64);

  return crypto.subtle.importKey(
    'raw', rawPEK, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
