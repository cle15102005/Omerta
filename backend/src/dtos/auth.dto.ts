import { z } from 'zod';

// POST /api/auth/register
export const RegisterDto = z.object({
  email:                    z.string().email(),
  authKeyHex:               z.string().min(64),  // hex-encoded Auth Key (left 32B of PBKDF2 output)
  salt:                     z.string().min(1),   // base64, 16 bytes — for master password PBKDF2
  salt2:                    z.string().min(1),   // base64, 16 bytes — for recovery code PBKDF2
  recoveryAuthHash:         z.string().min(1),   // SHA256 of recovery code
  encryptedPEKBackup:       z.string().min(1),   // AES-256-GCM(PEK, RecoveryKey)
  // RSA-OAEP keys
  publicKey:                z.string().min(1),   // RSA-OAEP public key PEM
  encryptedPrivateKey:      z.string().min(1),   // AES-256-GCM(RSA private key, PEK)
  // ECDSA P-256 keys (key self-certification)
  ecdsaPublicKey:           z.string().min(1),   // ECDSA P-256 public key (base64 JWK)
  encryptedECDSAPrivateKey: z.string().min(1),   // AES-256-GCM(ECDSA private key, PEK)
  keySignature:             z.string().min(1),   // ECDSA_Sign(ecdsaPriv, SHA-256(rsaPublicKeyPEM))
});

// POST /api/auth/login
export const LoginDto = z.object({
  email:      z.string().email(),
  authKeyHex: z.string().min(64), // client derives this from master password + salt
});

// POST /api/auth/recovery-data
export const RecoveryDataRequestDto = z.object({
  email: z.string().email(),
  recoveryAuthHash: z.string().min(1),
});

// POST /api/auth/recover
export const RecoverDto = z.object({
  email:              z.string().email(),
  recoveryAuthHash:   z.string().min(1),
  newAuthKeyHex:      z.string().min(64),
  newEncryptedPEKBackup: z.string().min(1),
  newEncryptedPrivateKey: z.string().min(1),
  newEncryptedECDSAPrivateKey: z.string().min(1),
  vaultItems: z.array(z.object({
    _id: z.string(),
    encryptedData: z.string(),
    history: z.array(z.object({
      encryptedData: z.string(),
      savedAt: z.string(),
    })).default([]),
  })),
});

export type RegisterInput = z.infer<typeof RegisterDto>;
export type LoginInput    = z.infer<typeof LoginDto>;
export type RecoveryDataRequestInput = z.infer<typeof RecoveryDataRequestDto>;
export type RecoverInput  = z.infer<typeof RecoverDto>;
