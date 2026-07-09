async function test() {
  try {
    const payload = {
      email: 'admin2@gmail.com',
      authKeyHex: '0'.repeat(64),
      salt: 'salt1',
      salt2: 'salt2',
      encryptedPEKBackup: 'pek',
      publicKey: 'pubkey',
      encryptedPrivateKey: 'privkey',
      ecdsaPublicKey: 'ecdsaPub',
      encryptedECDSAPrivateKey: 'ecdsaPriv',
      keySignature: 'sig'
    };
    const res = await fetch('http://localhost:3000/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const text = await res.text();
    console.log(res.status, text);
  } catch (err: any) {
    console.log(err.message);
  }
}
test();
