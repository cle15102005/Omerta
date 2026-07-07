import mongoose, { Schema, Document } from 'mongoose';

export interface ISharedVaultItemHistory {
  encryptedData: string;
  updatedAt: Date;
}

export interface ISharedVaultItem extends Document {
  vaultId: mongoose.Types.ObjectId;
  name: string; // Stored in plaintext (only members can see it)
  category: string;
  encryptedData: string; // AES-256-GCM encrypted with VEK
  addedBy: mongoose.Types.ObjectId;
  history: ISharedVaultItemHistory[];
  createdAt: Date;
  updatedAt: Date;
}

const SharedVaultItemSchema = new Schema<ISharedVaultItem>(
  {
    vaultId: { type: Schema.Types.ObjectId, ref: 'SharedVault', required: true },
    name: { type: String, required: true },
    category: { type: String, required: true },
    encryptedData: { type: String, required: true },
    addedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    history: {
      type: [
        {
          encryptedData: { type: String, required: true },
          updatedAt: { type: Date, required: true },
        },
      ],
      default: [],
    },
  },
  { timestamps: true }
);

export const SharedVaultItem = mongoose.model<ISharedVaultItem>('SharedVaultItem', SharedVaultItemSchema);
