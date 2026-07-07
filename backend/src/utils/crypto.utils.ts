import { randomBytes, createHash } from 'node:crypto';

/** Generate a cryptographically random salt (16 bytes) as base64 */
export function generateSalt(): string {
  return randomBytes(16).toString('base64');
}

/** Generate a recovery code in format: OMERTA-XXXX-XXXX-XXXX-XXXX */
export function generateRecoveryCode(): string {
  const segment = () => randomBytes(2).toString('hex').toUpperCase();
  return `OMERTA-${segment()}-${segment()}-${segment()}-${segment()}`;
}

/** SHA-256 hash of a string → hex string (for Merkle leaf hashes) */
export function sha256hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}
