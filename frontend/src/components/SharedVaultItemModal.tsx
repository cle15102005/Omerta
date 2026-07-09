import React, { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { Eye, EyeOff, Clock, RotateCcw } from 'lucide-react';
import { Modal } from './Modal';
import { Button } from './Button';
import { Input, PasswordInput } from './Input';
import { sharedVaultApi } from '../api/shared-vault.api';
import { encryptPayload, decryptPayload } from '../crypto/vault.crypto';

import type { VaultItemPayload, Category } from '../types';

interface SharedVaultItemDecrypted {
  _id: string;
  vaultId: string;
  name: string;
  category: string;
  payload: any;
  history?: Array<{ encryptedData: string; updatedAt: string }>;
  updatedAt: string;
}

interface SharedVaultItemModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  existingItem?: SharedVaultItemDecrypted;
  vaultId: string;
  vek: CryptoKey;
  canEdit: boolean;
}

interface HistoryEntry {
  password: string;
  savedAt: string;
}

export function SharedVaultItemModal({ isOpen, onClose, onSuccess, existingItem, vaultId, vek, canEdit }: SharedVaultItemModalProps) {
  const [loading, setLoading] = useState(false);
  const [category, setCategory] = useState<Category>('password');
  
  const [name, setName] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [url, setUrl] = useState('');

  const [apiKey, setApiKey] = useState('');
  const [note, setNote] = useState('');
  const [cardNumber, setCardNumber] = useState('');
  const [cardHolder, setCardHolder] = useState('');
  const [cardExpiry, setCardExpiry] = useState('');
  const [cardCvv, setCardCvv] = useState('');

  const [isEditing, setIsEditing] = useState(!existingItem);
  const [mainPasswordRevealed, setMainPasswordRevealed] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  const [decryptedHistory, setDecryptedHistory] = useState<HistoryEntry[]>([]);
  const [revealedHistory, setRevealedHistory] = useState<number[]>([]);
  const [isDecryptingHistory, setIsDecryptingHistory] = useState(false);

  useEffect(() => {
    if (existingItem) {
      setCategory(existingItem.category as Category);
      setName(existingItem.payload.name || existingItem.name);
      setUsername(existingItem.payload.username || '');
      setPassword(existingItem.payload.password || '');
      setUrl(existingItem.payload.url || '');
      setApiKey(existingItem.payload.apiKey || '');
      setNote(existingItem.payload.note || '');
      setCardNumber(existingItem.payload.cardNumber || '');
      setCardHolder(existingItem.payload.cardHolder || '');
      setCardExpiry(existingItem.payload.cardExpiry || '');
      setCardCvv(existingItem.payload.cardCvv || '');

      if (existingItem.history && existingItem.history.length > 0 && existingItem.category === 'password') {
        setIsDecryptingHistory(true);
        Promise.all(
          existingItem.history.map(async (h) => {
            try {
              const p = await decryptPayload(vek, h.encryptedData) as VaultItemPayload;
              return { password: p.password || '', savedAt: h.updatedAt };
            } catch {
              return null;
            }
          })
        ).then(hist => {
          setDecryptedHistory(hist.filter(Boolean) as HistoryEntry[]);
        }).finally(() => setIsDecryptingHistory(false));
      }
    } else {
      setCategory('password');
      setName('');
      setUsername('');
      setPassword('');
      setUrl('');
      setApiKey('');
      setNote('');
      setCardNumber('');
      setCardHolder('');
      setCardExpiry('');
      setCardCvv('');
      setIsEditing(true);
      setDecryptedHistory([]);
    }
    setMainPasswordRevealed(false);
    setRevealedHistory([]);
    setIsEditing(!existingItem);
  }, [existingItem, isOpen, vek]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) { toast.error('Item name is required'); return; }
    if (category === 'password' && !password) { toast.error('Password is required'); return; }
    if (category === 'api_key' && !apiKey) { toast.error('API Key is required'); return; }
    if (category === 'note' && !note.trim()) { toast.error('Secure Note content is required'); return; }
    if (category === 'card' && !cardNumber) { toast.error('Card Number is required'); return; }
    
    setLoading(true);
    try {
      const payload: any = { name };
      if (category === 'password') {
        payload.username = username;
        payload.password = password;
        payload.url = url;
      } else if (category === 'api_key') {
        payload.apiKey = apiKey;
      } else if (category === 'note') {
        payload.note = note;
      } else if (category === 'card') {
        payload.cardNumber = cardNumber;
        payload.cardHolder = cardHolder;
        payload.cardExpiry = cardExpiry;
        payload.cardCvv = cardCvv;
      }
      
      const encryptedData = await encryptPayload(vek, payload);
      
      const requestData = {
        name,
        category,
        encryptedData
      };

      if (existingItem) {
        await sharedVaultApi.updateItem(vaultId, existingItem._id, requestData);
        toast.success('Item updated');
      } else {
        await sharedVaultApi.addItem(vaultId, requestData);
        toast.success('Item added to Shared Vault');
      }
      
      onSuccess();
    } catch (err: any) {
      console.error(err);
      toast.error('Failed to save item');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = () => setShowDeleteConfirm(true);

  const confirmDelete = async () => {
    if (!existingItem) return;
    setShowDeleteConfirm(false);
    
    setLoading(true);
    try {
      await sharedVaultApi.deleteItem(vaultId, existingItem._id);
      toast.success('Item deleted');
      onSuccess();
    } catch (err) {
      console.error(err);
      toast.error('Failed to delete item');
    } finally {
      setLoading(false);
    }
  };

  const toggleReveal = (index: number) => {
    if (revealedHistory.includes(index)) {
      setRevealedHistory(revealedHistory.filter(i => i !== index));
    } else {
      setRevealedHistory([...revealedHistory, index]);
    }
  };

  const renderHistory = () => {
    if (category !== 'password' || !existingItem || decryptedHistory.length === 0) return null;
    
    return (
      <div className="mt-2 pt-4 border-t border-dim animate-slide-down">
        <h4 className="text-sm font-semibold text-accent mb-3 flex items-center gap-2">
          <Clock size={16}/> Password History
        </h4>
        {isDecryptingHistory ? (
          <div className="text-sm text-dim animate-pulse">Decrypting timeline...</div>
        ) : (
          <div className="flex flex-col gap-2 max-h-48 overflow-y-auto pr-2 custom-scrollbar">
            {[...decryptedHistory].reverse().map((h, idx) => (
              <div key={idx} className="flex items-center justify-between bg-black/20 p-2 rounded border border-white/5 hover:border-white/20 transition-colors">
                <div className="flex-col">
                  <div className="text-xs text-dim mb-1">{new Date(h.savedAt).toLocaleString()}</div>
                  <div className="font-mono text-sm tracking-[0.2em] text-white flex items-center gap-3">
                    {revealedHistory.includes(idx) ? h.password : '••••••••'}
                    <button type="button" onClick={() => toggleReveal(idx)} className="text-dim hover:text-white transition-colors outline-none focus:outline-none" title="Toggle visibility" style={{ letterSpacing: 'normal', border: 'none', background: 'transparent', padding: 0, boxShadow: 'none' }}>
                      {revealedHistory.includes(idx) ? <EyeOff size={14}/> : <Eye size={14}/>}
                    </button>
                  </div>
                </div>
                {isEditing && (
                  <Button type="button" variant="ghost" onClick={() => setPassword(h.password)} className="text-xs flex items-center gap-1 text-accent hover:bg-accent/10">
                    <RotateCcw size={14}/> Restore
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={existingItem ? (isEditing ? 'Edit Shared Item' : name) : 'New Shared Item'}>
      {!isEditing ? (
        <div className="flex-col flex gap-5">
          {category === 'password' && (
            <>
              <div className="flex-col flex gap-1">
                <label className="text-xs text-dim uppercase font-semibold">Username</label>
                <div className="text-base text-white">{username || 'N/A'}</div>
              </div>
              <div className="flex-col flex gap-1">
                <label className="text-xs text-dim uppercase font-semibold">Password</label>
                <div className="flex items-center gap-3 bg-surface p-3 rounded border border-dim">
                  <div className="font-mono text-base text-white tracking-wider flex-grow">
                    {mainPasswordRevealed ? password : '••••••••••••'}
                  </div>
                  <button type="button" onClick={() => setMainPasswordRevealed(!mainPasswordRevealed)} className="text-dim hover:text-white outline-none focus:outline-none" style={{ border: 'none', background: 'transparent', padding: 0, boxShadow: 'none' }}>
                    {mainPasswordRevealed ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>
              {url && (
                <div className="flex-col flex gap-1">
                  <label className="text-xs text-dim uppercase font-semibold">Website / URL</label>
                  <a href={url.startsWith('http') ? url : `https://${url}`} target="_blank" rel="noreferrer" className="text-base text-accent hover:underline">
                    {url}
                  </a>
                </div>
              )}
            </>
          )}

          {category === 'api_key' && (
            <div className="flex-col flex gap-1">
              <label className="text-xs text-dim uppercase font-semibold">API Key</label>
              <div className="flex items-center gap-3 bg-surface p-3 rounded border border-dim">
                <div className="font-mono text-base text-white tracking-wider flex-grow break-all">
                  {mainPasswordRevealed ? apiKey : '••••••••••••••••••••••••'}
                </div>
                <button type="button" onClick={() => setMainPasswordRevealed(!mainPasswordRevealed)} className="text-dim hover:text-white outline-none focus:outline-none" style={{ border: 'none', background: 'transparent', padding: 0, boxShadow: 'none' }}>
                  {mainPasswordRevealed ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>
          )}

          {category === 'note' && (
            <div className="flex-col flex gap-1">
              <label className="text-xs text-dim uppercase font-semibold">Secure Note</label>
              <div className="bg-surface p-4 rounded border border-dim text-white whitespace-pre-wrap leading-relaxed text-sm">
                {note}
              </div>
            </div>
          )}

          {category === 'card' && (
            <>
              <div className="flex-col flex gap-1">
                <label className="text-xs text-dim uppercase font-semibold">Cardholder Name</label>
                <div className="text-base text-white">{cardHolder || 'N/A'}</div>
              </div>
              <div className="flex-col flex gap-1">
                <label className="text-xs text-dim uppercase font-semibold">Card Number</label>
                <div className="flex items-center gap-3 bg-surface p-3 rounded border border-dim">
                  <div className="font-mono text-base text-white tracking-wider flex-grow">
                    {mainPasswordRevealed ? cardNumber : `•••• •••• •••• ${cardNumber.slice(-4) || '••••'}`}
                  </div>
                  <button type="button" onClick={() => setMainPasswordRevealed(!mainPasswordRevealed)} className="text-dim hover:text-white outline-none focus:outline-none" style={{ border: 'none', background: 'transparent', padding: 0, boxShadow: 'none' }}>
                    {mainPasswordRevealed ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>
              <div className="flex gap-4">
                <div className="flex-col flex gap-1 flex-1">
                  <label className="text-xs text-dim uppercase font-semibold">Expiry Date</label>
                  <div className="text-base text-white">{cardExpiry || 'MM/YY'}</div>
                </div>
                <div className="flex-col flex gap-1 flex-1">
                  <label className="text-xs text-dim uppercase font-semibold">CVV</label>
                  <div className="text-base text-white tracking-widest">{mainPasswordRevealed ? cardCvv : '•••'}</div>
                </div>
              </div>
            </>
          )}

          {renderHistory()}

          <div className="flex gap-4 mt-4">
            <Button type="button" variant="ghost" className="w-full" onClick={onClose}>
              Close
            </Button>
            {canEdit && (
              <Button type="button" variant="primary" className="btn-gradient w-full" onClick={() => setIsEditing(true)}>
                Edit Item
              </Button>
            )}
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="flex-col flex gap-4">
          <div className="flex-col flex gap-2">
            <label className="text-sm text-accent">Category</label>
            <select value={category} onChange={(e) => setCategory(e.target.value as Category)} className="p-2 rounded bg-surface border border-dim text-white outline-none focus:border-accent">
              <option value="password">Login / Password</option>
              <option value="api_key">API Key</option>
              <option value="note">Secure Note</option>
              <option value="card">Credit Card</option>
            </select>
          </div>

          <Input 
            label="Name"
            placeholder="e.g. Netflix, AWS"
            value={name} 
            onChange={e => setName(e.target.value)} 
            autoFocus
          />

          {category === 'password' && (
            <>
              <Input 
                label="Username / Email"
                placeholder="neo@matrix.com"
                value={username} 
                onChange={e => setUsername(e.target.value)} 
              />
              <PasswordInput 
                label="Password"
                placeholder="••••••••••••"
                value={password} 
                onChange={e => setPassword(e.target.value)} 
              />
              <Input 
                label="Website URL"
                placeholder="https://... (optional)"
                type="url"
                value={url} 
                onChange={e => setUrl(e.target.value)} 
              />
            </>
          )}

          {category === 'api_key' && (
            <PasswordInput 
              label="API Key"
              placeholder="Paste your secret key..."
              value={apiKey} 
              onChange={e => setApiKey(e.target.value)} 
            />
          )}

          {category === 'note' && (
            <div className="flex-col flex gap-2">
              <label className="text-sm text-accent">Secure Note Content</label>
              <textarea 
                value={note}
                onChange={e => setNote(e.target.value)}
                className="w-full p-3 rounded bg-surface border border-dim text-white outline-none focus:border-accent resize-y"
                style={{ minHeight: '150px' }}
                placeholder="Write your secure note here..."
              />
            </div>
          )}

          {category === 'card' && (
            <div className="flex flex-col gap-4">
              <Input 
                label="Cardholder Name"
                placeholder="John Doe"
                value={cardHolder} 
                onChange={e => setCardHolder(e.target.value)} 
              />
              <PasswordInput 
                label="Card Number"
                placeholder="1234 5678 9101 1121"
                value={cardNumber} 
                onChange={e => setCardNumber(e.target.value)} 
              />
              <div className="flex gap-4">
                <div className="flex-1">
                  <Input 
                    label="Expiry (MM/YY)"
                    placeholder="12/25"
                    value={cardExpiry} 
                    onChange={e => setCardExpiry(e.target.value)} 
                  />
                </div>
                <div className="flex-1">
                  <PasswordInput 
                    label="CVV"
                    placeholder="123"
                    value={cardCvv} 
                    onChange={e => setCardCvv(e.target.value)} 
                  />
                </div>
              </div>
            </div>
          )}

          {renderHistory()}

          <div className="flex gap-4 mt-4">
            <Button type="button" variant="ghost" className="w-full" onClick={() => existingItem ? setIsEditing(false) : onClose()} disabled={loading}>
              Cancel
            </Button>
            {existingItem && (
              <Button type="button" variant="danger" className="w-full" onClick={handleDelete} disabled={loading}>
                Delete
              </Button>
            )}
            <Button type="submit" variant="primary" className="btn-gradient w-full" isLoading={loading}>
              Save
            </Button>
          </div>
        </form>
      )}

      <Modal isOpen={showDeleteConfirm} onClose={() => setShowDeleteConfirm(false)} title="Delete Shared Item">
        <div className="flex flex-col gap-5">
          <p className="text-sm text-dim">Are you sure you want to permanently delete this shared item? This action cannot be undone.</p>
          <div className="flex justify-end gap-3 mt-2">
            <Button type="button" variant="ghost" onClick={() => setShowDeleteConfirm(false)}>Cancel</Button>
            <Button type="button" variant="danger" onClick={confirmDelete} disabled={loading}>Delete Item</Button>
          </div>
        </div>
      </Modal>
    </Modal>
  );
}
