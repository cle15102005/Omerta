/**
 * vault.store.ts — Zustand store
 *
 * Holds all cryptographic keys in browser memory ONLY.
 * Keys are NEVER written to localStorage, sessionStorage, or cookies.
 * Cleared immediately on logout or session lock.
 */

import { create } from 'zustand';
import type { User, VaultIndex } from '../types';
import type { SecurityStatus } from '../crypto/security.check';

interface VaultState {
  // ── Auth ────────────────────────────────────────────────────────────────────
  user:           User | null;
  isAuthenticated: boolean;

  // ── Crypto keys (in memory only) ────────────────────────────────────────────
  pek:            CryptoKey | null;  // Personal Encryption Key
  rsaPrivateKey:  CryptoKey | null;  // RSA-OAEP private key (for shared vaults)
  vaultKeys:      Map<string, CryptoKey>; // vaultId → VEK (shared vault keys)

  // ── Vault index (decrypted Merkle tree, client-side only) ──────────────────
  vaultIndex:     VaultIndex | null;

  // ── Security audit results (client-side only) ────────────────────────────────
  // Map of itemId → SecurityStatus, populated after auditVault() runs
  securityStatuses: Map<string, SecurityStatus>;

  // ── Session lock ─────────────────────────────────────────────────────────────
  isLocked:       boolean;

  // ── Actions ──────────────────────────────────────────────────────────────────
  setSession: (user: User, pek: CryptoKey, rsaPrivateKey: CryptoKey) => void;
  setVaultKey: (vaultId: string, vek: CryptoKey) => void;
  setVaultIndex: (index: VaultIndex) => void;
  setSecurityStatuses: (statuses: SecurityStatus[]) => void;
  lock: () => void;       // lock screen — clears keys but keeps user info for re-auth
  unlock: (pek: CryptoKey, rsaPrivateKey: CryptoKey) => void;
  clearAll: () => void;   // full logout — clears everything
}

export const useVaultStore = create<VaultState>((set) => ({
  user:            null,
  isAuthenticated: false,
  pek:             null,
  rsaPrivateKey:   null,
  vaultKeys:       new Map(),
  vaultIndex:      null,
  securityStatuses: new Map(),
  isLocked:        false,

  setSession: (user, pek, rsaPrivateKey) =>
    set({ user, pek, rsaPrivateKey, isAuthenticated: true, isLocked: false }),

  setVaultKey: (vaultId, vek) =>
    set((state) => {
      const vaultKeys = new Map(state.vaultKeys);
      vaultKeys.set(vaultId, vek);
      return { vaultKeys };
    }),

  setVaultIndex: (vaultIndex) => set({ vaultIndex }),

  setSecurityStatuses: (statuses) =>
    set({
      securityStatuses: new Map(statuses.map((s) => [s.itemId, s])),
    }),

  // Lock: wipes keys from memory but keeps user info so lock screen can show email
  lock: () =>
    set({ pek: null, rsaPrivateKey: null, vaultKeys: new Map(), isLocked: true }),

  // Unlock: re-derive keys after user re-enters master password on lock screen
  unlock: (pek, rsaPrivateKey) =>
    set({ pek, rsaPrivateKey, isLocked: false }),

  // Full logout
  clearAll: () =>
    set({
      user: null, isAuthenticated: false,
      pek: null, rsaPrivateKey: null,
      vaultKeys: new Map(), vaultIndex: null,
      securityStatuses: new Map(),
      isLocked: false,
    }),
}));
