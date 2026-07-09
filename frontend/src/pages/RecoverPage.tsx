import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useNavigate as useNav } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Shield } from 'lucide-react';
import { Button } from '../components/Button';
import { Input, PasswordInput } from '../components/Input';
import { authApi } from '../api/auth.api';
import { deriveRecoveryKey, decryptPEKFromBackup, encryptPEKWithRecovery } from '../crypto/recovery.crypto';
import { deriveMasterKeys, decryptPayload, encryptPayload, bufferToHex } from '../crypto/vault.crypto';

export default function RecoverPage() {
  const navigate = useNavigate();
  
  const [step, setStep] = useState<1 | 2>(1);
  const [isLoading, setIsLoading] = useState(false);
  
  // Step 1 State
  const [email, setEmail] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  
  // Step 2 State
  const [newPassword, setNewPassword] = useState('');
  
  // Intermediary Crypto State
  const [recoveryKey, setRecoveryKey] = useState<CryptoKey | null>(null);
  const [oldPEK, setOldPEK] = useState<CryptoKey | null>(null);
  const [recoveryData, setRecoveryData] = useState<any>(null);
  const [salt, setSalt] = useState<string>('');

  const handleVerifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !recoveryCode) return;
    
    setIsLoading(true);
    try {
      // Hash recovery code
      const codeBuf = new TextEncoder().encode(recoveryCode);
      const hashBuf = await crypto.subtle.digest('SHA-256', codeBuf);
      const recoveryAuthHash = bufferToHex(hashBuf);

      // 1. Fetch user's salts and recovery data
      const [{ data: { salt2 } }, { data: { salt } }, { data: recData }] = await Promise.all([
        authApi.getRecoverySalt(email),
        authApi.getSalt(email),
        authApi.getRecoveryData({ email, recoveryAuthHash })
      ]);
      
      // 2. Derive RecoveryKey
      const recKey = await deriveRecoveryKey(recoveryCode, salt2);
      
      // 3. Decrypt old PEK
      const pek = await decryptPEKFromBackup(recData.encryptedPEKBackup, recKey);
      
      setRecoveryKey(recKey);
      setOldPEK(pek);
      setRecoveryData(recData);
      setSalt(salt);
      
      setStep(2);
      toast.success('Recovery code verified! Proceed to set a new password.');
    } catch (err: any) {
      console.error(err);
      toast.error('Invalid recovery code or email.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPassword || !oldPEK || !recoveryKey || !recoveryData) return;

    setIsLoading(true);
    toast('Re-encrypting vault... Please do not close the browser.', { icon: '🔄', duration: 4000 });
    
    try {
      // 1. Derive new AuthKey and new PEK
      const { authKeyHex: newAuthKeyHex, pek: newPEK } = await deriveMasterKeys(newPassword, salt);
      
      // 2. Encrypt new PEK with existing Recovery Key
      const newEncryptedPEKBackup = await encryptPEKWithRecovery(newPEK, recoveryKey);
      
      // 3. Re-encrypt RSA Private Key
      const rawRSAPriv = await decryptPayload<{ privateKey: string }>(oldPEK, recoveryData.encryptedPrivateKey);
      const newEncryptedPrivateKey = await encryptPayload(newPEK, rawRSAPriv);
      
      // 4. Re-encrypt ECDSA Private Key
      const rawECDSAPriv = await decryptPayload<{ ecdsaPrivateKey: string }>(oldPEK, recoveryData.encryptedECDSAPrivateKey);
      const newEncryptedECDSAPrivateKey = await encryptPayload(newPEK, rawECDSAPriv);
      
      // 5. Re-encrypt all Vault Items
      const reencryptedItems = await Promise.all(recoveryData.vaultItems.map(async (item: any) => {
        // Decrypt current data
        let rawPayload;
        try {
          rawPayload = await decryptPayload<any>(oldPEK, item.encryptedData);
        } catch (err) {
          console.warn(`Failed to decrypt vault item ${item._id}. Skipping re-encryption.`);
          return null;
        }
        
        // Encrypt with new PEK
        const newEncryptedData = await encryptPayload(newPEK, rawPayload);
        
        // Re-encrypt history if present
        const newHistory = [];
        if (item.history && item.history.length > 0) {
          for (const hist of item.history) {
            try {
              const rawHistPayload = await decryptPayload<any>(oldPEK, hist.encryptedData);
              const newHistEncrypted = await encryptPayload(newPEK, rawHistPayload);
              newHistory.push({ encryptedData: newHistEncrypted, savedAt: hist.savedAt });
            } catch (e) {
              // Ignore corrupted history items
            }
          }
        }
        
        return {
          _id: item._id,
          encryptedData: newEncryptedData,
          history: newHistory
        };
      }));

      // 6. Send bulk update to backend
      const codeBuf = new TextEncoder().encode(recoveryCode);
      const hashBuf = await crypto.subtle.digest('SHA-256', codeBuf);
      const recoveryAuthHash = bufferToHex(hashBuf);

      const validItems = reencryptedItems.filter((i): i is NonNullable<typeof i> => i !== null);

      await authApi.recover({
        email,
        recoveryAuthHash,
        newAuthKeyHex,
        newEncryptedPEKBackup,
        newEncryptedPrivateKey,
        newEncryptedECDSAPrivateKey,
        vaultItems: validItems
      });

      toast.success('Password successfully reset! You can now log in.');
      navigate('/');
      
    } catch (err: any) {
      console.error(err);
      let errMsg = 'Failed to reset password. An error occurred during re-encryption.';
      if (err.response?.data?.message) {
        errMsg = err.response.data.message;
        if (err.response.data.error) {
           errMsg += ': ' + JSON.stringify(err.response.data.error);
        }
      }
      toast.error(errMsg);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="landing-wrapper">
      <header className="landing-header">
        <div className="landing-logo" style={{ cursor: 'pointer' }} onClick={() => navigate('/')}>
          <Shield size={32} />
          <span>OMERTA</span>
        </div>
      </header>

      <div className="landing-hero" style={{ justifyContent: 'center', alignItems: 'center' }}>
        <div className="auth-glass-card" style={{ width: '100%', maxWidth: '450px' }}>
          
          <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
              <h2 className="text-2xl font-bold" style={{ color: '#fff', fontSize: '1.8rem', marginBottom: '0.5rem' }}>Account Recovery</h2>
              {step === 1 && (
                <p style={{ color: 'var(--dim)', fontSize: '0.9rem', lineHeight: '1.5' }}>
                  Enter your email and the Recovery Code you saved during registration to unlock your vault keys.
                </p>
              )}
            </div>

            {step === 1 && (
              <form onSubmit={handleVerifyCode} className="auth-form">
                <Input
                  label="Email Address"
                  type="email"
                  placeholder="neo@matrix.com"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  required
                />
                <Input
                  label="Recovery Code"
                  placeholder="OMERTA-XXXX-XXXX-XXXX-XXXX"
                  value={recoveryCode}
                  onChange={e => setRecoveryCode(e.target.value)}
                  required
                />
                <button type="submit" className="auth-submit-btn" disabled={isLoading} style={{ marginTop: '1rem' }}>
                  {isLoading ? 'Verifying...' : 'Verify Recovery Code'}
                </button>
              </form>
            )}

            {step === 2 && (
              <>
                <div style={{ background: 'rgba(0, 240, 255, 0.1)', border: '1px solid rgba(0, 240, 255, 0.2)', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem', textAlign: 'center' }}>
                  <p style={{ color: '#00f0ff', fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                    Recovery code verified!
                  </p>
                  <p style={{ color: 'var(--dim)', fontSize: '0.85rem', lineHeight: '1.5' }}>
                    Please set a new Master Password. This will securely re-encrypt your entire vault. Do not close the browser.
                  </p>
                </div>
                <form onSubmit={handleResetPassword} className="auth-form">
                  <PasswordInput
                    label="New Master Password"
                    placeholder="••••••••••••"
                    value={newPassword}
                    onChange={e => setNewPassword(e.target.value)}
                    showStrength
                  />
                  <button type="submit" className="auth-submit-btn" disabled={isLoading} style={{ marginTop: '1rem' }}>
                    {isLoading ? 'Re-encrypting...' : 'Re-encrypt Vault & Save'}
                  </button>
                </form>
              </>
            )}

            <div style={{ textAlign: 'center', marginTop: '1.5rem' }}>
              <button 
                type="button" 
                onClick={() => navigate('/')} 
                style={{ background: 'none', border: 'none', color: 'var(--dim)', cursor: 'pointer', fontSize: '0.9rem', textDecoration: 'underline' }}
              >
                Return to Login
              </button>
            </div>

          </div>
      </div>
    </div>
  );
}
