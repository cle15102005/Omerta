import mongoose from 'mongoose';
import { SharedVault } from '../entities/SharedVault.entity';
import { VaultMembership, MembershipRole } from '../entities/VaultMembership.entity';
import { SharedVaultItem } from '../entities/SharedVaultItem.entity';
import { User } from '../entities/User.entity';
import { CreateSharedVaultInput, InviteMemberInput, SharedVaultItemInput } from '../dtos/shared-vault.dto';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Check if user is a member, and optionally enforce a minimum role */
async function checkMembership(vaultId: string, userId: string, requiredRole?: MembershipRole) {
  const membership = await VaultMembership.findOne({ vaultId, userId });
  if (!membership) {
    throw new Error('Access denied: not a member of this vault');
  }
  if (requiredRole) {
    const roleHierarchy = { viewer: 1, editor: 2, owner: 3 };
    if (roleHierarchy[membership.role] < roleHierarchy[requiredRole]) {
      throw new Error(`Access denied: requires ${requiredRole} role`);
    }
  }
  return membership;
}

// ── Vault Management ──────────────────────────────────────────────────────────

export async function createSharedVault(userId: string, data: CreateSharedVaultInput) {
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const vault = new SharedVault({
      name: data.name,
      ownerId: userId,
    });
    await vault.save({ session });

    const membership = new VaultMembership({
      vaultId: vault._id,
      userId: userId,
      role: 'owner',
      encryptedVEK: data.encryptedVEK,
    });
    await membership.save({ session });

    await session.commitTransaction();
    return { vault, membership };
  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
}

export async function getMySharedVaults(userId: string) {
  const memberships = await VaultMembership.find({ userId }).populate('vaultId');
  return memberships.map((m) => ({
    vault: m.vaultId,
    role: m.role,
    encryptedVEK: m.encryptedVEK,
    addedAt: m.addedAt,
  }));
}

// ── Member Management ─────────────────────────────────────────────────────────

export async function inviteMember(ownerId: string, vaultId: string, data: InviteMemberInput) {
  await checkMembership(vaultId, ownerId, 'owner');

  const invitee = await User.findOne({ email: data.email.toLowerCase() });
  if (!invitee) {
    throw new Error('User not found');
  }

  const existing = await VaultMembership.findOne({ vaultId, userId: invitee._id });
  if (existing) {
    throw new Error('User is already a member of this vault');
  }

  const membership = await VaultMembership.create({
    vaultId,
    userId: invitee._id,
    role: data.role,
    encryptedVEK: data.encryptedVEK,
  });

  return membership;
}

export async function removeMember(ownerId: string, vaultId: string, targetUserId: string) {
  await checkMembership(vaultId, ownerId, 'owner');
  if (ownerId === targetUserId) {
    throw new Error('Owner cannot remove themselves. Delete the vault instead.');
  }

  const result = await VaultMembership.deleteOne({ vaultId, userId: targetUserId });
  return result.deletedCount > 0;
}

// ── Item CRUD ─────────────────────────────────────────────────────────────────

export async function getVaultItems(userId: string, vaultId: string) {
  await checkMembership(vaultId, userId, 'viewer');
  return SharedVaultItem.find({ vaultId });
}

export async function addVaultItem(userId: string, vaultId: string, data: SharedVaultItemInput) {
  await checkMembership(vaultId, userId, 'editor');

  return SharedVaultItem.create({
    vaultId,
    name: data.name,
    category: data.category,
    encryptedData: data.encryptedData,
    addedBy: userId,
    history: [],
  });
}

export async function updateVaultItem(userId: string, vaultId: string, itemId: string, data: SharedVaultItemInput) {
  await checkMembership(vaultId, userId, 'editor');

  const item = await SharedVaultItem.findOne({ _id: itemId, vaultId });
  if (!item) {
    throw new Error('Item not found');
  }

  // Push current encryptedData to history (max 10)
  item.history.unshift({
    encryptedData: item.encryptedData,
    updatedAt: item.updatedAt,
  });
  if (item.history.length > 10) {
    item.history.pop();
  }

  item.name = data.name;
  item.category = data.category;
  item.encryptedData = data.encryptedData;
  return item.save();
}

export async function deleteVaultItem(userId: string, vaultId: string, itemId: string) {
  await checkMembership(vaultId, userId, 'editor');

  const result = await SharedVaultItem.deleteOne({ _id: itemId, vaultId });
  return result.deletedCount > 0;
}
