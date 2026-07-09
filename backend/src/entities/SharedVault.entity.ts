import mongoose, { Schema, Document } from 'mongoose';

export interface ISharedVault extends Document {
  name?: string; // Legacy plaintext name
  encryptedMetadata: string; // AES-256-GCM(VEK) of { name, description }
  ownerId: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

const SharedVaultSchema = new Schema<ISharedVault>(
  {
    name: { type: String, required: false }, // Optional for backwards compatibility
    encryptedMetadata: { type: String, required: true },
    ownerId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  },
  { timestamps: true }
);

export const SharedVault = mongoose.model<ISharedVault>('SharedVault', SharedVaultSchema);
