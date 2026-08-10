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
          One password to remember.<br />Everything else, protected.
        </h1>
        <p className="landing-hero-subtitle">
          Omerta locks all your passwords behind a single master password — one only you know.
          We never see it. We never store it. Even if someone broke into our servers,
          your passwords would be completely unreadable.
        </p>

        <div className="features-grid">
          <div className="feature-item">
            <div className="feature-icon"><Shield size={24} /></div>
            <div className="feature-text">
              <h4>Only you can unlock it</h4>
              <p>Your passwords are scrambled on your device before anything leaves it. Not even we can read them.</p>
            </div>
          </div>
          
          <div className="feature-item">
            <div className="feature-icon pink"><Key size={24} /></div>
            <div className="feature-text">
              <h4>Share safely with family</h4>
              <p>Give someone access to a shared account without telling them the actual password — and revoke it anytime.</p>
            </div>
          </div>

          <div className="feature-item">
            <div className="feature-icon"><EyeOff size={24} /></div>
            <div className="feature-text">
              <h4>We know nothing about you</h4>
              <p>No ads, no tracking, no data harvesting. We don't know your passwords, and we want to keep it that way.</p>
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
              Sign In
            </button>
            <button 
              type="button" 
              className={`auth-tab-btn ${isRegistering ? 'active' : ''}`}
              onClick={() => setIsRegistering(true)}
            >
              Create Account
            </button>
          </div>

          <form onSubmit={handleSubmit} className="auth-form">
            <Input 
              label="Email Address"
              type="email" 
              placeholder="you@example.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              autoComplete="off"
              name="omerta-email-off"
            />
            <PasswordInput 
              label={isRegistering ? 'Master Password' : 'Master Password'}
              placeholder={isRegistering ? 'Choose a strong password you will remember' : 'Enter your master password'}
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              showStrength={isRegistering}
              autoComplete="new-password"
              name="omerta-password-off"
            />

            {isRegistering && (
              <p style={{ fontSize: '0.78rem', color: 'var(--dim)', lineHeight: '1.5', margin: '-0.5rem 0 0' }}>
                ⚠️ This password unlocks your vault. If you forget it, only your Recovery Code can restore access — so make it memorable.
              </p>
            )}

            <button type="submit" className="auth-submit-btn">
              {isLoading
                ? (isRegistering ? 'Setting up your vault…' : 'Unlocking vault…')
                : (isRegistering ? 'Create My Vault' : 'Open My Vault')}
            </button>

            {!isRegistering && (
              <div style={{ textAlign: 'center', marginTop: '1rem' }}>
                <a 
                  href="/recover" 
                  style={{ color: 'var(--dim)', fontSize: '0.85rem', textDecoration: 'underline' }}
                >
                  Forgot your master password? Recover account →
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
          Your passwords are yours alone — not ours to see, not ours to sell.
        </h2>
      </div>

      {/* Recovery Code Modal */}
      <Modal 
        isOpen={!!recoveryCode} 
        onClose={closeRecoveryModal} 
        title={
          <div className="flex items-center gap-2">
            <Key size={24} className="text-accent" />
            <span>Save Your Recovery Code</span>
          </div>
        }
        hideClose
      >
        <div className="flex flex-col gap-5">
          <div>
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text)' }}>
              This is your <strong>lifeline</strong>. Write it down and keep it somewhere safe — a notebook, a safe, anywhere you won't lose it.
            </p>
            <p className="text-sm leading-relaxed mt-3" style={{ color: 'var(--danger)', fontWeight: 600 }}>
              ⚠️ If you forget your master password and lose this code, your vault cannot be recovered by anyone — not even us. This is not a warning to skip.
            </p>
          </div>
          
          <div className="flex items-center justify-between p-4" style={{ background: 'rgba(0,0,0,0.3)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
            <div className="text-accent" style={{ fontSize: '1.15rem', letterSpacing: '2px', fontFamily: 'var(--font)', fontWeight: 'bold', wordBreak: 'break-all' }}>
              {recoveryCode}
            </div>
            <button 
              type="button"
              className="btn-ghost"
              style={{ padding: '8px', color: 'var(--accent)', flexShrink: 0, marginLeft: '1rem' }}
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

          <p className="text-xs" style={{ color: 'var(--dim)', textAlign: 'center' }}>
            Treat this like a spare key to your house. Store it offline if possible.
          </p>

          <div className="flex justify-center mt-2">
            <Button variant="primary" onClick={closeRecoveryModal}>
              ✓ I've Written It Down Somewhere Safe
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
