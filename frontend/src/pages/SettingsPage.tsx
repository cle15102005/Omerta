import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Settings, Shield, Download, Upload, Key, Trash2, Copy, AlertTriangle } from 'lucide-react';
import { useVaultStore } from '../store/vault.store';
import { authApi } from '../api/auth.api';
import { vaultApi } from '../api/vault.api';
import { Button } from '../components/Button';
import { PasswordInput, Input } from '../components/Input';
import { sha256hex, deriveMasterKeys, decryptPayload, encryptPayload } from '../crypto/vault.crypto';
import { encryptPEKWithRecovery } from '../crypto/recovery.crypto';
import { Modal } from '../components/Modal';
export default function SettingsPage() {
  const navigate = useNavigate();
  const { clearAll, authKeyHex, pek, triggerVaultRefresh } = useVaultStore();
  
  const [email, setEmail] = useState('');
  const [userId, setUserId] = useState('');
  const [fingerprint, setFingerprint] = useState('');
  
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  
  const [isConfirmingDelete, setIsConfirmingDelete] = useState(false);
  const [deleteConfirmationText, setDeleteConfirmationText] = useState('');
  
  const [pendingImportFile, setPendingImportFile] = useState<File | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadProfile();
  }, []);

  const loadProfile = async () => {
    try {
      const { data } = await authApi.me();
      setEmail(data.email);
      setUserId(data.userId);
      
      if (data.ecdsaPublicKey) {
        const hash = await sha256hex(data.ecdsaPublicKey);
        const fp = hash.substring(0, 16).toUpperCase().match(/.{1,4}/g)?.join(' · ') || '';
        setFingerprint(fp);
      }
    } catch (err) {
      toast.error('Failed to load profile');
    }
  };

  const copyFingerprint = () => {
    navigator.clipboard.writeText(fingerprint);
    toast.success('Fingerprint copied to clipboard');
  };

  const handleExport = async () => {
    setIsExporting(true);
    try {
      const { data } = await vaultApi.export();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `omerta-backup-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success('Vault exported successfully!');
    } catch (err) {
      toast.error('Export failed');
    } finally {
      setIsExporting(false);
    }
  };

  const handleSelectImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) setPendingImportFile(file);
    e.target.value = '';
  };

  const confirmImport = async () => {
    if (!pendingImportFile) return;
    const file = pendingImportFile;

    setIsImporting(true);
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      
      if (!parsed.items || !parsed.user?.vaultIndex) {
        throw new Error('Invalid backup format');
      }

      await vaultApi.import({
        items: parsed.items,
        vaultIndex: parsed.user.vaultIndex
      });
      
      toast.success('Vault restored successfully!');
      setTimeout(() => triggerVaultRefresh(), 500);
    } catch (err) {
      console.error(err);
      toast.error('Failed to import vault. Invalid file format.');
    } finally {
      setIsImporting(false);
      setPendingImportFile(null);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentPassword || !newPassword || !pek) return;

    setIsChangingPassword(true);
    const loadingToast = toast.loading('Re-encrypting entire vault... Do not close window.');
    
    try {
      // 1. Verify current password matches our salt
      const { data: { salt } } = await authApi.getSalt(email);
      const { authKeyHex: testAuthKey } = await deriveMasterKeys(currentPassword, salt);
      if (testAuthKey !== authKeyHex) {
        throw new Error('Incorrect current password');
      }

      // 2. Fetch all required data for re-encryption
      const { data: recData } = await authApi.getRecoveryData(email);
      const { data: { salt2 } } = await authApi.getRecoverySalt(email);
      
      // 3. Derive NEW keys
      const { authKeyHex: newAuthKeyHex, pek: newPEK } = await deriveMasterKeys(newPassword, salt);
      
      // 4. We need the RecoveryKey to re-encrypt the PEK backup. 
      // But wait, the user doesn't have the recovery code right now!
      // Actually, if we don't have the recovery code, we cannot update the encryptedPEKBackup.
      // So changing password without Recovery Code breaks the Recovery Code.
      // To fix this without breaking the UI, we can fetch the old PEK, but we can't derive the RecoveryKey.
      toast.error('Change password currently requires going through the Account Recovery flow.', { id: loadingToast });
      setIsChangingPassword(false);
      return;
      
    } catch (err: any) {
      toast.error(err.message || 'Failed to change password', { id: loadingToast });
      setIsChangingPassword(false);
    }
  };

  const handleDeleteAccount = async () => {
    if (deleteConfirmationText !== 'DELETE') {
      toast.error('Please type DELETE to confirm');
      return;
    }
    
    try {
      await authApi.deleteAccount();
      clearAll();
      toast.success('Account successfully deleted');
      navigate('/login');
    } catch (err) {
      toast.error('Failed to delete account');
    }
  };

  return (
    <div className="flex-col w-full animate-fade-in pb-20">
      <div className="flex items-center gap-3 mb-8 animate-slide-down">
        <Settings size={32} className="text-accent" />
        <h2 className="dashboard-header-title" style={{ fontSize: '2rem', margin: 0 }}>Settings</h2>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Left Column */}
        <div className="flex flex-col gap-8">
          
          {/* Account Identity */}
          <div className="vault-item-card" style={{ padding: '2rem' }}>
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2"><Shield size={20} className="text-accent" /> Cryptographic Identity</h3>
            <div className="mb-4">
              <div className="text-sm text-dim mb-1">Email Address</div>
              <div className="font-mono bg-bg p-3 rounded border border-white/5">{email || 'Loading...'}</div>
            </div>
            
            <div>
              <div className="text-sm text-dim mb-1 flex justify-between items-end">
                <span>ECDSA Key Fingerprint</span>
                <button onClick={copyFingerprint} className="text-accent hover:text-white transition-colors"><Copy size={14} /></button>
              </div>
              <div className="font-mono bg-bg p-3 rounded border border-white/5 text-accent tracking-wider text-center font-bold">
                {fingerprint || 'Computing...'}
              </div>
              <p className="text-xs text-dim mt-2 leading-relaxed">
                This fingerprint uniquely identifies your public key. When someone invites you to a Shared Vault, they will see this fingerprint. Verify it with them over a secure channel (e.g. Signal or phone call) to prevent impersonation attacks.
              </p>
            </div>
          </div>

          {/* Backup & Restore */}
          <div className="vault-item-card" style={{ padding: '2rem' }}>
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2"><Download size={20} className="text-success" style={{ color: '#50fa7b' }}/> Vault Backup & Restore</h3>
            <p className="text-sm text-dim leading-relaxed" style={{ marginBottom: '2.5rem' }}>
              Export your entire vault as an encrypted JSON file. Your data remains fully AES-256-GCM encrypted and cannot be opened without your Master Password.
            </p>
            
            <div className="flex flex-wrap gap-4">
              <Button variant="primary" onClick={handleExport} isLoading={isExporting} className="w-max flex items-center gap-2">
                <Download size={18} /> Export Vault
              </Button>
              
              <div>
                <input 
                  type="file" 
                  accept=".json" 
                  onChange={handleSelectImportFile} 
                  disabled={isImporting}
                  style={{ display: 'none' }}
                  ref={fileInputRef}
                />
                <Button variant="secondary" onClick={() => fileInputRef.current?.click()} isLoading={isImporting} className="w-max flex items-center gap-2" style={{ border: '1px dashed rgba(255,255,255,0.2)' }}>
                  <Upload size={18} /> Import Backup
                </Button>
              </div>
            </div>
          </div>

        </div>

        {/* Right Column */}
        <div className="flex flex-col gap-8">

          {/* Change Password */}
          <div className="vault-item-card" style={{ padding: '2rem' }}>
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2"><Key size={20} className="text-accent-alt" /> Change Master Password</h3>
            <p className="text-sm text-dim leading-relaxed" style={{ marginBottom: '2.5rem' }}>
              Due to Omerta's zero-knowledge architecture, changing your password requires your original Recovery Code to prevent cryptographic lockouts. 
            </p>
            
            <Button variant="ghost" onClick={() => { clearAll(); navigate('/recover'); }} className="w-max flex justify-center items-center gap-2 border-accent-alt text-accent-alt">
              Go to Account Recovery Flow
            </Button>
          </div>

          {/* Danger Zone */}
          <div className="vault-item-card" style={{ padding: '2rem', borderColor: 'rgba(255, 42, 42, 0.3)', background: 'linear-gradient(180deg, rgba(255,42,42,0.05) 0%, transparent 100%)' }}>
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2 text-danger"><AlertTriangle size={20} /> Danger Zone</h3>
            <p className="text-sm text-dim leading-relaxed" style={{ marginBottom: '2.5rem' }}>
              Permanently delete your account, keys, and all vault items. This action cannot be undone and no backups are kept on the server.
            </p>
            
            {!isConfirmingDelete ? (
              <Button variant="danger" onClick={() => setIsConfirmingDelete(true)} className="w-max flex justify-center items-center gap-2">
                <Trash2 size={18} /> Delete Account
              </Button>
            ) : (
              <div className="flex flex-col gap-5">
                <p className="text-danger text-sm font-bold">Type "DELETE" below to confirm:</p>
                <div className="flex gap-4">
                  <div className="flex-1">
                    <Input 
                      value={deleteConfirmationText}
                      onChange={e => setDeleteConfirmationText(e.target.value)}
                      placeholder="DELETE" 
                    />
                  </div>
                  <Button variant="ghost" onClick={() => { setIsConfirmingDelete(false); setDeleteConfirmationText(''); }}>
                    Cancel
                  </Button>
                  <Button variant="danger" onClick={handleDeleteAccount} disabled={deleteConfirmationText !== 'DELETE'} className="w-max flex items-center gap-2">
                    <Trash2 size={18} /> Confirm Delete
                  </Button>
                </div>
              </div>
            )}
          </div>

        </div>
      </div>

      {/* Import Warning Modal */}
      <Modal 
        isOpen={!!pendingImportFile} 
        onClose={() => setPendingImportFile(null)} 
        title={
          <div className="flex items-center gap-2 text-danger">
            <AlertTriangle size={24} />
            <span>Overwrite Vault?</span>
          </div>
        }
      >
        <div className="flex flex-col gap-5">
          <p className="text-sm leading-relaxed text-dim">
            <strong className="text-white">WARNING:</strong> Importing a backup will completely overwrite your current vault.
            Ensure this backup was encrypted with your <strong className="text-white">current master password</strong>.
          </p>
          <div className="flex justify-end gap-3 mt-2">
            <Button variant="ghost" onClick={() => setPendingImportFile(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={confirmImport} isLoading={isImporting}>
              Proceed with Import
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
