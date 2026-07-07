/* TODO: Implement Recovery Page UI
 *
 * Flow:
 *   1. User enters email + Recovery Code
 *   2. GET /api/auth/recovery-salt/:email → salt2
 *   3. Client: deriveRecoveryKey(recoveryCode, salt2) → recoveryKey
 *   4. GET /api/auth/pek-backup/:email → encryptedPEKBackup
 *   5. Client: decryptPEKFromBackup(encryptedPEKBackup, recoveryKey) → pek
 *      (if this fails, the recovery code is wrong — show error)
 *   6. User sets new master password
 *   7. Client: generateSalt() → new salt
 *   8. Client: deriveMasterKeys(newPassword, newSalt) → { newAuthKeyHex, newPEK }
 *      NOTE: newPEK and old pek are IDENTICAL content-wise (we kept the old PEK raw bytes)
 *      So vault items don't need re-encryption — just update auth credentials
 *   9. Client: generateSalt2() → new salt2
 *   10. Client: generateRecoveryCode() → new recovery code (show once again)
 *   11. Client: deriveRecoveryKey(newRecoveryCode, newSalt2) → newRecoveryKey
 *   12. Client: encryptPEKWithRecovery(pek, newRecoveryKey) → newEncryptedPEKBackup
 *   13. POST /api/auth/recover { email, newAuthKeyHex: newAuthKeyHex, newEncryptedPEKBackup }
 *   14. Show new Recovery Code modal → navigate to /login
 */

export default function RecoverPage() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
      <h1>🔇 Omerta — RecoverPage (TODO)</h1>
    </div>
  );
}
