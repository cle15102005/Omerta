import mongoose, { Schema, Document } from 'mongoose';

// ── History entry (previous version of a vault item) ─────────────────────────
export interface IHistoryEntry {
  encryptedData: string; // AES-256-GCM(PEK) — still zero-knowledge
  savedAt: Date;
}

// ── Vault Item ────────────────────────────────────────────────────────────────
export interface IVaultItem extends Document {
  userId: mongoose.Types.ObjectId;
  nameLeafHash: string;    // SHA-256(name+nameSalt) — for Merkle index only
  category: 'password' | 'api_key' | 'note' | 'card';
  encryptedData: string;   // AES-256-GCM(PEK) of { name, nameSalt, ...secrets }
  history: IHistoryEntry[];// previous versions, max 10 entries (git-like)
  isFavorite: boolean;
  lastAccessedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

const HistoryEntrySchema = new Schema<IHistoryEntry>(
  {
    encryptedData: { type: String, required: true },
    savedAt:       { type: Date,   required: true },
  },
  { _id: false }
);

const VaultItemSchema = new Schema<IVaultItem>(
  {
    userId:       { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    nameLeafHash: { type: String, required: true },
    category:     { type: String, enum: ['password', 'api_key', 'note', 'card'], required: true },
    encryptedData:{ type: String, required: true },
    history:      { type: [HistoryEntrySchema], default: [] },
    isFavorite:   { type: Boolean, default: false },
    lastAccessedAt:{ type: Date, default: Date.now },
  },
  { timestamps: true }
);

export const VaultItem = mongoose.model<IVaultItem>('VaultItem', VaultItemSchema);
