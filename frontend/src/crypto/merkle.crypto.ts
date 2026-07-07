/**
 * merkle.crypto.ts
 *
 * Merkle tree for the blind vault index.
 * Adapted from DACS blockchain project (shared/merkle.ts).
 *
 * Key difference from DACS:
 *   - Uses SHA-256 (Web Crypto API) instead of keccak256
 *   - Operates on vault item names instead of course grades
 *   - One tree per user's entire vault (rebuilt on add/edit-name/delete)
 */

import { sha256hex } from './vault.crypto';
import type { VaultLeaf, VaultIndex } from '../types';

// ── Build tree from a list of leaves ─────────────────────────────────────────

/**
 * Build a Merkle tree from vault leaves.
 * Each leaf = SHA-256(name + nameSalt)
 */
export async function buildVaultIndex(
  leaves: Array<{ name: string; nameSalt: string }>
): Promise<VaultIndex> {
  if (leaves.length === 0) {
    return { merkleRoot: '', leaves: [] };
  }

  const vaultLeaves: VaultLeaf[] = await Promise.all(
    leaves.map(async (l) => ({
      name:     l.name,
      nameSalt: l.nameSalt,
      hash:     await sha256hex(l.name + l.nameSalt),
    }))
  );

  const merkleRoot = await computeMerkleRoot(vaultLeaves.map((l) => l.hash));
  return { merkleRoot, leaves: vaultLeaves };
}

/**
 * Compute Merkle root from an array of hex leaf hashes.
 * Uses SHA-256(left + right) for internal nodes.
 */
async function computeMerkleRoot(hashes: string[]): Promise<string> {
  if (hashes.length === 0) return '';
  if (hashes.length === 1) return hashes[0];

  let level = [...hashes];

  // If odd number of nodes, duplicate last
  if (level.length % 2 !== 0) level.push(level[level.length - 1]);

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const combined = level[i] + level[i + 1];
      next.push(await sha256hex(combined));
    }
    if (next.length % 2 !== 0 && next.length > 1) next.push(next[next.length - 1]);
    level = next;
  }

  return level[0];
}

// ── Client-side search (the "selective disclosure" step) ──────────────────────

/**
 * Search the vault index for leaves whose name matches the query.
 * This is fully client-side — server never sees the query or the names.
 */
export function searchIndex(index: VaultIndex, query: string): VaultLeaf[] {
  const q = query.toLowerCase().trim();
  if (!q) return index.leaves;
  return index.leaves.filter((l) => l.name.toLowerCase().includes(q));
}

/**
 * Generate a new random nameSalt for a vault item (32 hex bytes).
 * Analogous to the randomSalt() function in DACS merkle.ts.
 */
export function generateNameSalt(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
