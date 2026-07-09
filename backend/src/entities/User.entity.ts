import mongoose, { Schema, Document } from 'mongoose';

export interface IUser extends Document {
  email: string;
  authKeyHash: string;             // bcrypt(Auth Key) — NOT the master password
  salt: string;                    // base64, 16 bytes — for PBKDF2 (master password)
  salt2: string;                   // base64, 16 bytes — for PBKDF2 (recovery code)
  recoveryAuthHash: string;        // bcrypt(SHA256(recoveryCode)) — to verify recovery
  encryptedPEKBackup: string;      // AES-256-GCM(PEK, RecoveryKey) — for account recovery
  // ── RSA-OAEP keys (VEK exchange for shared vaults) ──────────────────────
  publicKey: string;               // RSA-OAEP public key PEM — shared freely
  encryptedPrivateKey: string;     // AES-256-GCM(RSA private key, PEK)
  // ── ECDSA P-256 keys (key self-certification — prevents key substitution MITM) ─
  ecdsaPublicKey: string;          // ECDSA P-256 public key (base64 JWK) — public
  encryptedECDSAPrivateKey: string;// AES-256-GCM(ECDSA private key, PEK)
  keySignature: string;            // ECDSA_Sign(ecdsaPriv, SHA-256(rsaPublicKeyPEM))
  vaultIndex: {
    merkleRoot: string;       // SHA-256 Merkle root of all item name hashes
    leafHashes: string[];     // SHA-256(name+nameSalt) for each item
  };
  // ── Account lockout ────────────────────────────────────────────────────────
  failedLoginAttempts: number; // incremented on each failed login, reset on success
  lockedUntil: Date | null;    // null = not locked; future date = locked until then
  createdAt: Date;
  updatedAt: Date;
}

const UserSchema = new Schema<IUser>(
  {
    email:               { type: String, required: true, unique: true, lowercase: true },
    authKeyHash:         { type: String, required: true },
    salt:                { type: String, required: true },
    salt2:               { type: String, required: true },
    recoveryAuthHash:    { type: String, required: true },
    encryptedPEKBackup:  { type: String, required: true },
    publicKey:                { type: String, required: true },
    encryptedPrivateKey:      { type: String, required: true },
    ecdsaPublicKey:           { type: String, required: true },
    encryptedECDSAPrivateKey: { type: String, required: true },
    keySignature:             { type: String, required: true },
    vaultIndex: {
      merkleRoot: { type: String, default: '' },
      leafHashes: { type: [String], default: [] },
    },
    failedLoginAttempts: { type: Number, default: 0 },
    lockedUntil:         { type: Date,   default: null },
  },
  { timestamps: true }
);

export const User = mongoose.model<IUser>('User', UserSchema);
