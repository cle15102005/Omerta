import mongoose, { Schema, Document } from 'mongoose';

export type MembershipRole = 'owner' | 'editor' | 'viewer';

export interface IVaultMembership extends Document {
  vaultId: mongoose.Types.ObjectId;
  userId: mongoose.Types.ObjectId;
  role: MembershipRole;
  encryptedVEK: string; // RSA_Encrypt(VEK, member.publicKey)
  addedAt: Date;
}

const VaultMembershipSchema = new Schema<IVaultMembership>({
  vaultId: { type: Schema.Types.ObjectId, ref: 'SharedVault', required: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  role: { type: String, enum: ['owner', 'editor', 'viewer'], required: true },
  encryptedVEK: { type: String, required: true },
  addedAt: { type: Date, default: Date.now }
});

// Ensure a user can only have one membership per vault
VaultMembershipSchema.index({ vaultId: 1, userId: 1 }, { unique: true });

export const VaultMembership = mongoose.model<IVaultMembership>('VaultMembership', VaultMembershipSchema);
