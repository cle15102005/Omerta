import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Settings, Shield, Download, Upload, Key, Trash2, Copy, AlertTriangle, Lock } from 'lucide-react';
import { useVaultStore } from '../store/vault.store';
import { authApi } from '../api/auth.api';
import { vaultApi } from '../api/vault.api';
import { Button } from '../components/Button';
import { Input, PasswordInput } from '../components/Input';
import { sha256hex, decryptPayload, encryptPayload, generateSalt, deriveBackupKey } from '../crypto/vault.crypto';
import { buildVaultIndex } from '../crypto/merkle.crypto';
import { Modal } from '../components/Modal';

export default function SettingsPage() {
  const navigate = useNavigate();
  const { clearAll, pek, triggerVaultRefresh } = useVaultStore();

  const [email, setEmail] = useState('');
  const [fingerprint, setFingerprint] = useState('');

  const [isExporting, setIsExporting] = useState(false);
  const [isImporting, setIsImporting] = useState(false);

  const [isConfirmingDelete, setIsConfirmingDelete] = useState(false);
  const [deleteConfirmationText, setDeleteConfirmationText] = useState('');

  // ── Export password modal ────────────────────────────────────────────────────
  const [exportPwdOpen, setExportPwdOpen] = useState(false);
  const [exportPwd, setExportPwd] = useState('');

  // ── Import flow ──────────────────────────────────────────────────────────────
  const [pendingImportFile, setPendingImportFile] = useState<File | null>(null);
  const [pendingV3Backup, setPendingV3Backup] = useState<any>(null); // parsed v3 JSON
  const [importPwdOpen, setImportPwdOpen] = useState(false);
  const [importPwd, setImportPwd] = useState('');

  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { loadProfile(); }, []);

  // ── Profile ──────────────────────────────────────────────────────────────────

  const loadProfile = async () => {
    try {
      const { data } = await authApi.me();
      setEmail(data.email);
      if (data.ecdsaPublicKey) {
        const hash = await sha256hex(data.ecdsaPublicKey);
        const fp = hash.substring(0, 16).toUpperCase().match(/.{1,4}/g)?.join(' · ') || '';
        setFingerprint(fp);
      }
    } catch {
      toast.error('Failed to load profile');
    }
  };

  const copyFingerprint = () => {
    navigator.clipboard.writeText(fingerprint);
    toast.success('Fingerprint copied to clipboard');
  };

  // ── Export ───────────────────────────────────────────────────────────────────

  const handleExport = () => {
    if (!pek) { toast.error('Vault is locked — please log in again'); return; }
    setExportPwd('');
    setExportPwdOpen(true);
  };

  const performExport = async () => {
    if (!pek || !exportPwd.trim()) return;
    setExportPwdOpen(false);
    setIsExporting(true);
    try {
      // 1. Fetch encrypted items from server
      const { data: exportData } = await vaultApi.export();
      const items: any[] = exportData.items ?? [];

      // 2. Decrypt every item client-side
      const decryptedItems = await Promise.all(
        items.map(async (item: any) => {
          try {
            const payload = await decryptPayload(pek, item.encryptedData);
            return { category: item.category, payload };
          } catch {
            return null; // skip corrupted items
          }
        })
      );
      const validItems = decryptedItems.filter(Boolean);

      // 3. Derive a backup key from the user's password + a fresh random salt
      const backupSalt = generateSalt();
      const backupKey = await deriveBackupKey(exportPwd, backupSalt);

      // 4. Encrypt the entire bundle with the backup key (AES-256-GCM)
      const encrypted = await encryptPayload(backupKey, { items: validItems });

      // 5. Build the backup file — the encrypted blob is safe to store anywhere
      const backup = {
        version: 3,
        exportedAt: new Date().toISOString(),
        salt: backupSalt,   // random salt used to derive the backup key
        encrypted,          // AES-256-GCM ciphertext of { items }
      };

      const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `omerta-backup-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast.success(`✅ Exported ${validItems.length} items. File is AES-256-GCM encrypted — safe to store anywhere.`);
    } catch (err) {
      console.error(err);
      toast.error('Export failed');
    } finally {
      setIsExporting(false);
      setExportPwd('');
    }
  };

  // ── Import ───────────────────────────────────────────────────────────────────

  const handleSelectImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) setPendingImportFile(file);
    e.target.value = '';
  };

  // Step 1: user clicks "Proceed" on the overwrite warning
  const confirmImport = async () => {
    if (!pendingImportFile) return;
    if (!pek) { toast.error('Vault is locked — please log in again'); return; }
    const file = pendingImportFile;
    setPendingImportFile(null);

    try {
      const text = await file.text();
      const parsed = JSON.parse(text);

      if (parsed.version === 3 && parsed.encrypted && parsed.salt) {
        // v3: encrypted with backup password — show password modal
        setPendingV3Backup(parsed);
        setImportPwd('');
        setImportPwdOpen(true);

      } else if (parsed.version === 2 && Array.isArray(parsed.items)) {
        // v2: plaintext payload (old format) — re-encrypt directly
        await importV2(parsed.items);

      } else if (parsed.items && parsed.user?.vaultIndex) {
        // v1: legacy encrypted blobs — same account only
        toast('⚠️ Legacy backup — only works for the same account.', { icon: '⚠️' });
        setIsImporting(true);
        await vaultApi.import({ items: parsed.items, vaultIndex: parsed.user.vaultIndex });
        toast.success('Vault restored (legacy format).');
        setTimeout(() => triggerVaultRefresh(), 500);
        setIsImporting(false);

      } else {
        throw new Error('Unrecognised backup format');
      }
    } catch (err: any) {
      console.error(err);
      toast.error(err.message || 'Failed to read backup file.');
    }
  };

  // v2 import: plaintext → re-encrypt with current PEK
  const importV2 = async (rawItems: any[]) => {
    if (!pek) return;
    setIsImporting(true);
    try {
      const items = rawItems.filter((i: any) => i.payload && !i.decryptError);
      if (items.length === 0) throw new Error('No valid items found in backup');
      await uploadReEncrypted(items);
      toast.success(`Restored ${items.length} items!`);
      setTimeout(() => triggerVaultRefresh(), 500);
    } catch (err: any) {
      toast.error(err.message || 'Import failed');
    } finally {
      setIsImporting(false);
    }
  };

  // Step 2 (v3): user enters the backup password → decrypt → re-encrypt with current PEK
  const performV3Import = async () => {
    if (!pek || !pendingV3Backup || !importPwd.trim()) return;
    setImportPwdOpen(false);
    setIsImporting(true);
    try {
      // Derive the same backup key using the password + stored salt from the file
      const backupKey = await deriveBackupKey(importPwd, pendingV3Backup.salt);

      // Decrypt the bundle — throws OperationError if the password is wrong
      const bundle = await decryptPayload<{ items: any[] }>(backupKey, pendingV3Backup.encrypted);

      const items = bundle.items.filter((i: any) => i.payload);
      if (items.length === 0) throw new Error('No items found in backup');

      await uploadReEncrypted(items);
      toast.success(`Restored ${items.length} items!`);
      setTimeout(() => triggerVaultRefresh(), 500);
    } catch (err: any) {
      if (err.name === 'OperationError') {
        toast.error('Wrong password — could not decrypt this backup.');
      } else {
        toast.error(err.message || 'Import failed');
      }
    } finally {
      setIsImporting(false);
      setImportPwd('');
      setPendingV3Backup(null);
    }
  };

  // Shared helper: re-encrypt plaintext items with current PEK and upload
  const uploadReEncrypted = async (items: any[]) => {
    if (!pek) throw new Error('Vault is locked');
    const reEncrypted = await Promise.all(
      items.map(async (item: any) => {
        const encryptedData = await encryptPayload(pek, item.payload);
        return { encryptedData, category: item.category };
      })
    );
    const index = await buildVaultIndex(
      items.map((i: any) => ({ name: i.payload?.name ?? '', nameSalt: i.payload?.nameSalt ?? '00' }))
    );
    await vaultApi.import({
      items: reEncrypted,
      vaultIndex: {
        merkleRoot: index.merkleRoot,
        leafHashes: index.leaves.map((l: any) => l.hash),
      },
    });
  };

  // ── Account deletion ─────────────────────────────────────────────────────────

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
    } catch {
      toast.error('Failed to delete account');
    }
  };

  // ── Render ───────────────────────────────────────────────────────────────────

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
                This fingerprint uniquely identifies your public key. When someone invites you to a Shared Vault, verify it over a secure channel (e.g. Signal or phone call) to prevent impersonation attacks.
              </p>
            </div>
          </div>

          {/* Backup & Restore */}
          <div className="vault-item-card" style={{ padding: '2rem' }}>
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
              <Lock size={20} style={{ color: '#50fa7b' }} /> Vault Backup &amp; Restore
            </h3>
            <p className="text-sm text-dim leading-relaxed" style={{ marginBottom: '1rem' }}>
              Export your vault as an <strong className="text-white">AES-256-GCM encrypted</strong> file protected by a password you choose.
              Safe to store on USB, cloud, or email — useless without the password.
            </p>
            <p className="text-xs text-dim leading-relaxed" style={{ marginBottom: '2rem', color: '#8be9fd' }}>
              💡 Backups are portable — you can restore into a completely new account, even with a different master password.
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
                    <Input value={deleteConfirmationText} onChange={e => setDeleteConfirmationText(e.target.value)} placeholder="DELETE" />
                  </div>
                  <Button variant="ghost" onClick={() => { setIsConfirmingDelete(false); setDeleteConfirmationText(''); }}>Cancel</Button>
                  <Button variant="danger" onClick={handleDeleteAccount} disabled={deleteConfirmationText !== 'DELETE'} className="w-max flex items-center gap-2">
                    <Trash2 size={18} /> Confirm Delete
                  </Button>
                </div>
              </div>
            )}
          </div>

        </div>
      </div>

      {/* ── Export Password Modal ─────────────────────────────────────────────── */}
      <Modal
        isOpen={exportPwdOpen}
        onClose={() => { setExportPwdOpen(false); setExportPwd(''); }}
        title={
          <div className="flex items-center gap-2" style={{ color: '#50fa7b' }}>
            <Lock size={22} /> Encrypt Your Backup
          </div>
        }
      >
        <div className="flex flex-col gap-5">
          <p className="text-sm text-dim leading-relaxed">
            Choose a password to encrypt this backup file.<br />
            <strong className="text-white">Remember it</strong> — you will need it to restore from this backup, even into a new account.
          </p>
          <PasswordInput
            label="Backup Password"
            value={exportPwd}
            onChange={e => setExportPwd(e.target.value)}
            placeholder="Enter a strong password for this backup"
            onKeyDown={(e: React.KeyboardEvent) => { if (e.key === 'Enter') performExport(); }}
            autoFocus
          />
          <div className="flex justify-end gap-3 mt-2">
            <Button variant="ghost" onClick={() => { setExportPwdOpen(false); setExportPwd(''); }}>Cancel</Button>
            <Button variant="primary" onClick={performExport} isLoading={isExporting} disabled={!exportPwd.trim()} className="flex items-center gap-2">
              <Download size={18} /> Export &amp; Encrypt
            </Button>
          </div>
        </div>
      </Modal>

      {/* ── Import Overwrite Warning Modal ────────────────────────────────────── */}
      <Modal
        isOpen={!!pendingImportFile}
        onClose={() => setPendingImportFile(null)}
        title={
          <div className="flex items-center gap-2 text-danger">
            <AlertTriangle size={24} /> <span>Overwrite Vault?</span>
          </div>
        }
      >
        <div className="flex flex-col gap-5">
          <p className="text-sm leading-relaxed text-dim">
            <strong className="text-white">WARNING:</strong> Importing will completely overwrite your current vault. Make sure you have a backup of what's currently in your vault before proceeding.
          </p>
          <div className="flex justify-end gap-3 mt-2">
            <Button variant="ghost" onClick={() => setPendingImportFile(null)}>Cancel</Button>
            <Button variant="danger" onClick={confirmImport} isLoading={isImporting}>Proceed</Button>
          </div>
        </div>
      </Modal>

      {/* ── Import Password Modal (v3 encrypted backup) ───────────────────────── */}
      <Modal
        isOpen={importPwdOpen}
        onClose={() => { setImportPwdOpen(false); setImportPwd(''); setPendingV3Backup(null); }}
        title={
          <div className="flex items-center gap-2 text-accent">
            <Lock size={22} /> Decrypt Backup
          </div>
        }
      >
        <div className="flex flex-col gap-5">
          <p className="text-sm text-dim leading-relaxed">
            This backup is encrypted. Enter the password that was used <strong className="text-white">when this backup was created</strong>.
          </p>
          <PasswordInput
            label="Backup Password"
            value={importPwd}
            onChange={e => setImportPwd(e.target.value)}
            placeholder="Password used when exporting"
            onKeyDown={(e: React.KeyboardEvent) => { if (e.key === 'Enter') performV3Import(); }}
            autoFocus
          />
          <div className="flex justify-end gap-3 mt-2">
            <Button variant="ghost" onClick={() => { setImportPwdOpen(false); setImportPwd(''); setPendingV3Backup(null); }}>Cancel</Button>
            <Button variant="primary" onClick={performV3Import} isLoading={isImporting} disabled={!importPwd.trim()} className="flex items-center gap-2">
              <Upload size={18} /> Decrypt &amp; Restore
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
