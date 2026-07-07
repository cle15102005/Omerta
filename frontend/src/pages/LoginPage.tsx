/* TODO: Implement Login and Register UI
 *
 * This page handles TWO flows toggled by a tab/link:
 *
 * REGISTER flow:
 *   1. User enters email + master password
 *   2. Client: generateSalt() → base64 salt
 *   3. Client: deriveMasterKeys(password, salt) → { authKeyHex, pek }
 *   4. Client: generateSalt2() → salt2 for recovery code PBKDF2
 *   5. Client: generateRecoveryCode() → show to user ONCE in modal
 *   6. Client: deriveRecoveryKey(recoveryCode, salt2) → recoveryKey
 *   7. Client: encryptPEKWithRecovery(pek, recoveryKey) → encryptedPEKBackup
 *   8. Client: generateRSAKeyPair() → { publicKey, privateKey }
 *   9. Client: exportPublicKeyPEM(publicKey) → publicKeyPEM
 *   10. Client: encryptPrivateKey(privateKey, pek) → encryptedPrivateKey
 *   11. POST /api/auth/register { email, authKeyHex, salt, salt2,
 *             encryptedPEKBackup, publicKey: publicKeyPEM, encryptedPrivateKey }
 *   12. Show Recovery Code modal (user must acknowledge + download)
 *
 * LOGIN flow:
 *   1. User enters email + master password
 *   2. GET /api/auth/salt/:email → salt
 *   3. Client: deriveMasterKeys(password, salt) → { authKeyHex, pek }
 *   4. POST /api/auth/login { email, authKeyHex }
 *   5. Fetch user's encryptedPrivateKey from /api/auth/me (extended)
 *   6. Client: decryptPrivateKey(encryptedPrivateKey, pek) → rsaPrivateKey
 *   7. useVaultStore.setSession(user, pek, rsaPrivateKey)
 *   8. Navigate to /vault
 */

export default function LoginPage() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
      <h1>🔇 Omerta — LoginPage (TODO)</h1>
    </div>
  );
}
