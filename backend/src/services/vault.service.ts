import mongoose from 'mongoose';
import { VaultItem } from '../entities/VaultItem.entity';
import { User } from '../entities/User.entity';
import type { CreateVaultItemInput, UpdateVaultItemInput } from '../dtos/vault.dto';
import { VAULT_HISTORY_LIMIT } from '../env';

// ── List ──────────────────────────────────────────────────────────────────────
export async function listItems(userId: string) {
  return VaultItem.find({ userId }, {
    nameLeafHash: 1, category: 1, isFavorite: 1, updatedAt: 1, lastAccessedAt: 1,
  }).sort({ updatedAt: -1 });
}

// ── Get one (returns encryptedData for client to decrypt) ─────────────────────
export async function getItem(userId: string, itemId: string) {
  const item = await VaultItem.findOne({ _id: itemId, userId });
  if (!item) return null;

  item.lastAccessedAt = new Date();
  await item.save();
  return item;
}

// ── Create ────────────────────────────────────────────────────────────────────
export async function createItem(userId: string, data: CreateVaultItemInput) {
  const [item] = await VaultItem.create([{
    userId,
    nameLeafHash:  data.nameLeafHash,
    category:      data.category,
    encryptedData: data.encryptedData,
  }]);

  // Update user's Merkle vault index
  await User.findByIdAndUpdate(userId, {
    'vaultIndex.merkleRoot': data.vaultIndex.merkleRoot,
    'vaultIndex.leafHashes': data.vaultIndex.leafHashes,
  });

  return item;
}

// ── Update (push current to history before replacing) ────────────────────────
export async function updateItem(userId: string, itemId: string, data: UpdateVaultItemInput) {
  const item = await VaultItem.findOne({ _id: itemId, userId });
  if (!item) return null;

  // Push current encryptedData to history (git-like versioning)
  item.history.push({ encryptedData: item.encryptedData, savedAt: new Date() });

  // Cap history at HISTORY_LIMIT
  if (item.history.length > VAULT_HISTORY_LIMIT) {
    item.history = item.history.slice(item.history.length - VAULT_HISTORY_LIMIT);
  }

  // Apply updates
  item.encryptedData = data.encryptedData;
  if (data.nameLeafHash) item.nameLeafHash = data.nameLeafHash;
  if (data.category)     item.category     = data.category;

  await item.save();

  // Rebuild Merkle index if name changed
  if (data.vaultIndex) {
    await User.findByIdAndUpdate(userId, {
      'vaultIndex.merkleRoot': data.vaultIndex.merkleRoot,
      'vaultIndex.leafHashes': data.vaultIndex.leafHashes,
    });
  }

  return item;
}

// ── Delete ────────────────────────────────────────────────────────────────────
export async function deleteItem(userId: string, itemId: string, newVaultIndex: {
  merkleRoot: string;
  leafHashes: string[];
}) {
  const result = await VaultItem.deleteOne({ _id: itemId, userId });
  if (result.deletedCount === 0) return false;

  await User.findByIdAndUpdate(userId, {
    'vaultIndex.merkleRoot': newVaultIndex.merkleRoot,
    'vaultIndex.leafHashes': newVaultIndex.leafHashes,
  });

  return true;
}

// ── History ───────────────────────────────────────────────────────────────────
export async function getItemHistory(userId: string, itemId: string) {
  const item = await VaultItem.findOne({ _id: itemId, userId }, 'history');
  return item?.history ?? null;
}

// ── Export (full vault for backup) ───────────────────────────────────────────
export async function exportVault(userId: string) {
  const user  = await User.findById(userId, 'email salt vaultIndex');
  // Explicitly select encryptedData so the client can decrypt items for backup
  const items = await VaultItem.find({ userId }, {
    encryptedData: 1, category: 1, nameLeafHash: 1, isFavorite: 1, history: 1,
  });
  return { user, items };
}

// ── Import (restore full vault from backup) ──────────────────────────────────
export async function importVault(userId: string, data: {
  items: any[];
  vaultIndex: { merkleRoot: string; leafHashes: string[] };
}) {
  await VaultItem.deleteMany({ userId });
  
  const mappedItems = data.items.map(item => ({
    userId,
    nameLeafHash: item.nameLeafHash,
    category: item.category,
    encryptedData: item.encryptedData,
    history: item.history || [],
    isFavorite: item.isFavorite || false,
    createdAt: item.createdAt || new Date(),
    updatedAt: item.updatedAt || new Date(),
  }));
  
  if (mappedItems.length > 0) {
    await VaultItem.insertMany(mappedItems);
  }

  await User.findByIdAndUpdate(userId, {
    'vaultIndex.merkleRoot': data.vaultIndex.merkleRoot,
    'vaultIndex.leafHashes': data.vaultIndex.leafHashes,
  });
  return true;
}
