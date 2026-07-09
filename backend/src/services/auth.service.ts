import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { User } from '../entities/User.entity';
import { VaultItem } from '../entities/VaultItem.entity';
import {
  JWT_SECRET, JWT_EXPIRY, BCRYPT_ROUNDS,
  LOCKOUT_MAX_ATTEMPTS, LOCKOUT_DURATION_MS,
} from '../env';
import type { RegisterInput, LoginInput, RecoverInput } from '../dtos/auth.dto';

export interface TokenPayload {
  userId: string;
  email:  string;
}

// ── Token helpers ─────────────────────────────────────────────────────────────

export function generateToken(payload: TokenPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY as any });
}

export function verifyToken(token: string): TokenPayload | null {
  try {
    return jwt.verify(token, JWT_SECRET) as TokenPayload;
  } catch {
    return null;
  }
}

// ── Auth operations ───────────────────────────────────────────────────────────

export async function registerUser(data: RegisterInput) {
  const exists = await User.findOne({ email: data.email });
  if (exists) throw new Error('EMAIL_TAKEN');

  // Convert hex Auth Key to Buffer then bcrypt it
  const authKeyBuffer  = Buffer.from(data.authKeyHex, 'hex');
  const authKeyHash    = await bcrypt.hash(authKeyBuffer.toString('base64'), BCRYPT_ROUNDS);

  // Hash the recoveryAuthHash
  const recoveryAuthHash = await bcrypt.hash(data.recoveryAuthHash, BCRYPT_ROUNDS);

  const user = await User.create({
    email:                    data.email,
    authKeyHash,
    salt:                     data.salt,
    salt2:                    data.salt2,
    recoveryAuthHash,
    encryptedPEKBackup:       data.encryptedPEKBackup,
    // RSA-OAEP keys
    publicKey:                data.publicKey,
    encryptedPrivateKey:      data.encryptedPrivateKey,
    // ECDSA P-256 keys (key self-certification)
    ecdsaPublicKey:           data.ecdsaPublicKey,
    encryptedECDSAPrivateKey: data.encryptedECDSAPrivateKey,
    keySignature:             data.keySignature,
    vaultIndex: { merkleRoot: '', leafHashes: [] },
  });

  return user;
}

export async function loginUser(
  data: LoginInput
): Promise<{ payload: TokenPayload } | { locked: true; retryAfter: Date } | null> {
  const user = await User.findOne({ email: data.email });
  if (!user) return null;

  // Check if account is currently locked
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    return { locked: true, retryAfter: user.lockedUntil };
  }

  const authKeyBuffer = Buffer.from(data.authKeyHex, 'hex');
  const isValid = await bcrypt.compare(authKeyBuffer.toString('base64'), user.authKeyHash);

  if (!isValid) {
    // Increment failed attempts
    user.failedLoginAttempts += 1;

    if (user.failedLoginAttempts >= LOCKOUT_MAX_ATTEMPTS) {
      // Lock account for 15 minutes
      user.lockedUntil = new Date(Date.now() + LOCKOUT_DURATION_MS);
      user.failedLoginAttempts = 0; // reset counter for next window
    }

    await user.save();
    return null;
  }

  // Successful login — reset lockout state
  user.failedLoginAttempts = 0;
  user.lockedUntil         = null;
  await user.save();

  return { payload: { userId: user._id.toString(), email: user.email } };
}

export async function getSalt(email: string): Promise<string | null> {
  const user = await User.findOne({ email }, 'salt');
  return user?.salt ?? null;
}

export async function getRecoverySalt(email: string): Promise<string | null> {
  const user = await User.findOne({ email }, 'salt2');
  return user?.salt2 ?? null;
}

export async function getEncryptedPEKBackup(email: string): Promise<string | null> {
  const user = await User.findOne({ email }, 'encryptedPEKBackup');
  return user?.encryptedPEKBackup ?? null;
}

export async function getRecoveryData(email: string, recoveryAuthHash: string) {
  const user = await User.findOne({ email }, 'encryptedPEKBackup encryptedPrivateKey encryptedECDSAPrivateKey recoveryAuthHash');
  if (!user) return null;

  const isValid = await bcrypt.compare(recoveryAuthHash, user.recoveryAuthHash);
  if (!isValid) throw new Error('INVALID_RECOVERY_HASH');
  const items = await VaultItem.find({ userId: user._id }, 'encryptedData history');
  return {
    encryptedPEKBackup: user.encryptedPEKBackup,
    encryptedPrivateKey: user.encryptedPrivateKey,
    encryptedECDSAPrivateKey: user.encryptedECDSAPrivateKey,
    vaultItems: items,
  };
}

export async function resetPassword(data: RecoverInput): Promise<boolean> {
  try {
    const user = await User.findOne({ email: data.email });
    if (!user) {
      return false;
    }

    const isValid = await bcrypt.compare(data.recoveryAuthHash, user.recoveryAuthHash);
    if (!isValid) throw new Error('INVALID_RECOVERY_HASH');

    const authKeyBuffer = Buffer.from(data.newAuthKeyHex, 'hex');
    const newAuthKeyHash = await bcrypt.hash(authKeyBuffer.toString('base64'), BCRYPT_ROUNDS);

    user.authKeyHash = newAuthKeyHash;
    user.encryptedPEKBackup = data.newEncryptedPEKBackup;
    user.encryptedPrivateKey = data.newEncryptedPrivateKey;
    user.encryptedECDSAPrivateKey = data.newEncryptedECDSAPrivateKey;
    await user.save();

    for (const item of data.vaultItems) {
      await VaultItem.updateOne(
        { _id: item._id, userId: user._id },
        { 
          $set: { 
            encryptedData: item.encryptedData,
            history: item.history.map(h => ({ encryptedData: h.encryptedData, savedAt: new Date(h.savedAt) }))
          } 
        }
      );
    }

    return true;
  } catch (err) {
    throw err;
  }
}

export async function deleteAccount(userId: string): Promise<boolean> {
  try {
    await VaultItem.deleteMany({ userId });
    const result = await User.deleteOne({ _id: userId });
    return result.deletedCount > 0;
  } catch (err) {
    throw err;
  }
}
