/* TODO: Implement Vault Dashboard UI
 *
 * This is the main page after login.
 *
 * On mount:
 *   1. GET /api/vault/ → list of VaultItemMeta (no encryptedData)
 *   2. For each item, fetch encryptedData via GET /api/vault/:id
 *   3. Client: decryptPayload(pek, encryptedData) → VaultItemPayload
 *   4. Build VaultIndex from decrypted payloads:
 *      buildVaultIndex(items.map(i => ({ name: i.payload.name, nameSalt: i.payload.nameSalt })))
 *   5. Store in useVaultStore.setVaultIndex(index)
 *
 * Search:
 *   - User types in search bar
 *   - searchIndex(vaultIndex, query) → filtered VaultLeaf[]
 *   - Display matched items only
 *
 * Add item:
 *   1. User fills form (name, category, secrets)
 *   2. generateNameSalt() → nameSalt
 *   3. sha256hex(name + nameSalt) → nameLeafHash
 *   4. encryptPayload(pek, { name, nameSalt, ...secrets }) → encryptedData
 *   5. buildVaultIndex([...existing, { name, nameSalt }]) → new VaultIndex
 *   6. POST /api/vault/ { nameLeafHash, category, encryptedData, vaultIndex }
 *
 * Session auto-lock:
 *   - Set inactivity timer (default 5 min)
 *   - On timeout: useVaultStore.lock()
 *   - Show lock overlay requiring master password re-entry
 *   - On unlock: re-derive pek + rsaPrivateKey → useVaultStore.unlock()
 */

export default function VaultPage() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
      <h1>🔇 Omerta — VaultPage (TODO)</h1>
    </div>
  );
}
