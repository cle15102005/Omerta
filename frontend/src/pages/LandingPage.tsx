import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Lock, Shield, Key, EyeOff, Copy } from 'lucide-react';
import { Input, PasswordInput } from '../components/Input';
import { Modal } from '../components/Modal';
import { Button } from '../components/Button';
import { authApi } from '../api/auth.api';
import { useVaultStore } from '../store/vault.store';
import { generateSalt, deriveMasterKeys, bufferToHex } from '../crypto/vault.crypto';
import { generateSalt2, generateRecoveryCode, deriveRecoveryKey, encryptPEKWithRecovery } from '../crypto/recovery.crypto';
import { generateAndBindKeyPairs, decryptPrivateKey } from '../crypto/rsa.crypto';
import './LandingPage.css';

export default function LandingPage() {
  const [isRegistering, setIsRegistering] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  // Recovery Modal State
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);
  const navigate = useNavigate();
  const setSession = useVaultStore(s => s.setSession);
  const isAuthenticated = useVaultStore(s => s.isAuthenticated);

  // Auto-redirect if already logged in
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/vault');
    }
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;
    setIsLoading(true);

    try {
      if (isRegistering) {
        await handleRegister();
      } else {
        await handleLogin();
      }
    } catch (err: any) {
      console.error(err);
      toast.error(err.response?.data?.message || err.message || 'An error occurred', {
        style: { background: 'var(--surface)', color: 'var(--danger)', border: '1px solid var(--danger)' }
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegister = async () => {
    toast('Generating cryptographic keys... (This may take a moment)', { icon: '🔐' });
    
    const salt = generateSalt();
    const { authKeyHex, pek } = await deriveMasterKeys(password, salt);
    
    const salt2 = generateSalt2();
    const code = generateRecoveryCode();
    const recoveryKey = await deriveRecoveryKey(code, salt2);
    const encryptedPEKBackup = await encryptPEKWithRecovery(pek, recoveryKey);
    
    // Hash recovery code for server-side verification during recovery flow
    const codeBuf = new TextEncoder().encode(code);
    const hashBuf = await crypto.subtle.digest('SHA-256', codeBuf);
    const recoveryAuthHash = bufferToHex(hashBuf);
    
    const { 
      publicKey, encryptedPrivateKey, 
      ecdsaPublicKey, encryptedECDSAPrivateKey, keySignature 
    } = await generateAndBindKeyPairs(pek);

    await authApi.register({
      email, authKeyHex, salt, salt2, recoveryAuthHash, encryptedPEKBackup,
      publicKey, encryptedPrivateKey, ecdsaPublicKey, encryptedECDSAPrivateKey, keySignature
    });

    toast.success('Registration successful!');
    setRecoveryCode(code); // Show recovery modal
  };

  const handleLogin = async () => {
    const { data: { salt } } = await authApi.getSalt(email);
    const { authKeyHex, pek } = await deriveMasterKeys(password, salt);
    
    await authApi.login({ email, authKeyHex });
    
    const { data: me } = await authApi.me();
    if (!me.encryptedPrivateKey) throw new Error('Missing private key on server');
    
    const rsaPrivateKey = await decryptPrivateKey(me.encryptedPrivateKey, pek);
    
    setSession({ email: me.email, userId: me.userId }, pek, rsaPrivateKey);
    navigate('/vault');
  };

  const closeRecoveryModal = () => {
    setRecoveryCode(null);
    setIsRegistering(false);
    setPassword('');
  };

  return (
    <div className="landing-wrapper">
      <header className="landing-header">
        <div className="landing-logo">
          <Lock size={32} />
          <span>OMERTA</span>
        </div>
      </header>
      <div className="landing-hero">
        {/* Left side: System Content */}
        <div className="landing-content">

        <h1 className="landing-hero-title">
          Secure Password Manager
        </h1>
        <p className="landing-hero-subtitle">
          Omerta is a zero-knowledge vault. Your passwords are encrypted on your device before they ever reach our servers. We can't see your data, we can't share it, and we can't lose it. Absolute privacy, guaranteed.
        </p>

        <div className="features-grid">
          <div className="feature-item">
            <div className="feature-icon"><Shield size={24} /></div>
            <div className="feature-text">
              <h4>Bulletproof Security</h4>
              <p>Your data is locked with military-grade encryption. Only you hold the key to unlock it.</p>
            </div>
          </div>
          
          <div className="feature-item">
            <div className="feature-icon pink"><Key size={24} /></div>
            <div className="feature-text">
              <h4>Secure Sharing</h4>
              <p>Safely share access to accounts with friends or family without ever exposing your actual password.</p>
            </div>
          </div>

          <div className="feature-item">
            <div className="feature-icon"><EyeOff size={24} /></div>
            <div className="feature-text">
              <h4>Total Privacy</h4>
              <p>We don't track you. We don't know your master password. Your secrets remain entirely yours.</p>
            </div>
          </div>
        </div>
      </div>

      {/* Right side: Auth Form */}
      <div className="landing-auth-sidebar">
        <div className="auth-glass-card">
          <div className="auth-tabs">
            <button 
              type="button" 
              className={`auth-tab-btn ${!isRegistering ? 'active' : ''}`}
              onClick={() => setIsRegistering(false)}
            >
              Access Vault
            </button>
            <button 
              type="button" 
              className={`auth-tab-btn ${isRegistering ? 'active' : ''}`}
              onClick={() => setIsRegistering(true)}
            >
              Create Vault
            </button>
          </div>

          <form onSubmit={handleSubmit} className="auth-form">
            <Input 
              label="Email Address"
              type="email" 
              placeholder="neo@matrix.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              autoComplete="off"
              name="omerta-email-off"
            />
            <PasswordInput 
              label="Password"
              placeholder="••••••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              showStrength={isRegistering}
              autoComplete="new-password"
              name="omerta-password-off"
            />

            <button type="submit" className="auth-submit-btn">
              {isLoading ? 'Processing...' : (isRegistering ? 'Register' : 'Enter Vault')}
            </button>

            {!isRegistering && (
              <div style={{ textAlign: 'center', marginTop: '1rem' }}>
                <a 
                  href="/recover" 
                  style={{ color: 'var(--dim)', fontSize: '0.9rem', textDecoration: 'underline' }}
                >
                  Forgot Password? Recover Account
                </a>
              </div>
            )}
          </form>
        </div>
      </div>
      </div>

      {/* Scrollable Quote Section */}
      <div className="landing-quote-section">
        <h2 className="landing-quote-text">
          What happens in the vault, stays in the vault.
        </h2>
      </div>

      {/* Recovery Code Modal */}
      <Modal 
        isOpen={!!recoveryCode} 
        onClose={closeRecoveryModal} 
        title={
          <div className="flex items-center gap-2">
            <Key size={24} className="text-accent" />
            <span>Save Recovery Code</span>
          </div>
        }
        hideClose
      >
        <div className="flex flex-col gap-5">
          <div className="text-gray-300">
            <p className="text-sm leading-relaxed text-dim">
              We cannot reset your password if you lose it. Please save this recovery code in a safe place, as it will be the only way to restore your account.
            </p>
          </div>
          
          <div className="flex items-center justify-between p-4" style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '8px' }}>
            <div className="text-accent" style={{ fontSize: '1.2rem', letterSpacing: '1px', fontFamily: 'var(--font)', fontWeight: 'bold' }}>
              {recoveryCode}
            </div>
            <button 
              type="button"
              className="btn-ghost"
              style={{ padding: '8px', color: 'var(--accent)' }}
              onClick={() => {
                if (recoveryCode) {
                  navigator.clipboard.writeText(recoveryCode);
                  toast.success('Recovery code copied!', { style: { background: 'var(--surface)', color: 'var(--text)', border: '1px solid var(--accent)' } });
                }
              }}
              title="Copy to clipboard"
            >
              <Copy size={20} />
            </button>
          </div>

          <div className="flex justify-center mt-2">
            <Button variant="primary" onClick={closeRecoveryModal}>
              I Have Saved It Securely
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
