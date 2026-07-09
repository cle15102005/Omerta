import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Lock, LogOut } from 'lucide-react';
import { PasswordInput } from '../components/Input';
import { Button } from '../components/Button';
import { authApi } from '../api/auth.api';
import { useVaultStore } from '../store/vault.store';
import { deriveMasterKeys } from '../crypto/vault.crypto';
import { decryptPrivateKey } from '../crypto/rsa.crypto';
import './LandingPage.css'; // Reusing LandingPage styles

export default function LockScreen() {
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  const user = useVaultStore(s => s.user);
  const unlock = useVaultStore(s => s.unlock);
  const clearAll = useVaultStore(s => s.clearAll);
  
  const navigate = useNavigate();

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user?.email || !password) return;
    setIsLoading(true);

    try {
      const email = user.email;
      
      const { data: { salt } } = await authApi.getSalt(email);
      const { authKeyHex, pek } = await deriveMasterKeys(password, salt);
      
      await authApi.login({ email, authKeyHex });
      
      const { data: me } = await authApi.me();
      if (!me.encryptedPrivateKey) throw new Error('Missing private key on server');
      
      const rsaPrivateKey = await decryptPrivateKey(me.encryptedPrivateKey, pek);
      
      unlock(pek, rsaPrivateKey);
      toast.success('Vault Unlocked');
      
      // ProtectedRoute will automatically unmount LockScreen and mount VaultPage
    } catch (err: any) {
      console.error(err);
      toast.error(err.response?.data?.message || err.message || 'Invalid Master Password', {
        style: { background: 'var(--surface)', color: 'var(--danger)', border: '1px solid var(--danger)' }
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    clearAll();
    navigate('/login');
  };

  return (
    <div className="landing-wrapper">
      <header className="landing-header">
        <div className="landing-logo">
          <Lock size={32} />
          <span>OMERTA</span>
        </div>
      </header>
      
      <div className="landing-hero" style={{ minHeight: 'calc(100vh - 100px)', padding: '2rem' }}>
        <div className="auth-box animate-slide-up" style={{ margin: '0 auto' }}>
          <div className="auth-header text-center">
            <div className="mx-auto bg-surface p-4 rounded-full w-max mb-4 shadow-neon">
              <Lock size={32} className="text-accent" />
            </div>
            <h2 className="text-2xl font-bold font-ui text-white mb-2">Vault Locked</h2>
            <p className="text-sm text-dim">
              Session restored for <strong className="text-white">{user?.email}</strong>
            </p>
          </div>
          
          <form onSubmit={handleUnlock} className="auth-form mt-6">
            <PasswordInput 
              label="Master Password" 
              placeholder="••••••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
            />
            
            <Button variant="primary" type="submit" className="w-full mt-4" isLoading={isLoading}>
              Unlock Vault
            </Button>
            
            <div className="text-center mt-6">
              <button 
                type="button" 
                onClick={handleLogout}
                className="text-sm text-dim hover:text-white transition-colors flex items-center justify-center gap-2 w-full"
              >
                <LogOut size={16} /> Log in as a different user
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
