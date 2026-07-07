// ── Types shared across frontend ──────────────────────────────────────────────

export type Category = 'password' | 'api_key' | 'note' | 'card';

/** Decrypted payload stored inside encryptedData — varies by category */
export interface VaultItemPayload {
  name:     string;   // item name e.g. "GitHub"
  nameSalt: string;   // hex, 32 bytes — used for SHA-256(name+nameSalt) = nameLeafHash
  // Password
  url?:      string;
  username?: string;
  password?: string;
  // API Key
  service?:  string;
  apiKey?:   string;
  // Note
  note?:     string;
  // Card
  cardNumber?:    string;
  cardHolder?:    string;
  cardExpiry?:    string;
  cardCvv?:       string;
}

/** Vault item as returned by GET /api/vault/ (metadata only, no encryptedData) */
export interface VaultItemMeta {
  _id:            string;
  nameLeafHash:   string;
  category:       Category;
  isFavorite:     boolean;
  updatedAt:      string;
  lastAccessedAt: string;
}

/** Vault item as returned by GET /api/vault/:id (includes encryptedData) */
export interface VaultItemFull extends VaultItemMeta {
  encryptedData: string;
  history: Array<{ encryptedData: string; savedAt: string }>;
}

/** Vault item after client-side decryption — ready to display */
export interface VaultItemDecrypted extends VaultItemMeta {
  payload: VaultItemPayload;
}

/** Merkle tree leaf (name + salt + hash) */
export interface VaultLeaf {
  name:     string;
  nameSalt: string;
  hash:     string; // SHA-256(name+nameSalt) hex
}

/** Merkle vault index stored client-side after decryption */
export interface VaultIndex {
  merkleRoot: string;
  leaves:     VaultLeaf[];
}

export interface User {
  email:  string;
  userId: string;
}
