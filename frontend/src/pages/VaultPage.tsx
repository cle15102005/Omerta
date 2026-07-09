import { useEffect, useState } from 'react';
import { Plus, Search, KeyRound, Lock, Eye, EyeOff } from 'lucide-react';
import toast from 'react-hot-toast';
import { Sidebar } from '../components/Sidebar';
import { Button } from '../components/Button';
import { vaultApi } from '../api/vault.api';
import { useVaultStore } from '../store/vault.store';
import { decryptPayload } from '../crypto/vault.crypto';
import { buildVaultIndex, searchIndex } from '../crypto/merkle.crypto';
import type { VaultItemDecrypted, VaultLeaf } from '../types';
import { VaultItemModal } from '../components/VaultItemModal';
import { getIconForVaultItem } from '../utils/iconMap';
import SharedVaultView from './SharedVaultView';
import SecurityAudit from './SecurityAudit';
import SettingsPage from './SettingsPage';

export default function VaultPage({ activeTab = 'personal' }: { activeTab?: 'personal' | 'shared' | 'security' | 'settings' }) {
  const pek = useVaultStore(s => s.pek);
  const setVaultIndex = useVaultStore(s => s.setVaultIndex);
  const vaultIndex = useVaultStore(s => s.vaultIndex);
  const vaultRefreshTrigger = useVaultStore(s => s.vaultRefreshTrigger);
  
  const [items, setItems] = useState<VaultItemDecrypted[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  
  const [revealedItems, setRevealedItems] = useState<Set<string>>(new Set());
  
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<VaultItemDecrypted | undefined>(undefined);

  const fetchVault = async () => {
    if (!pek) return;
    try {
      setLoading(true);
      const { data: metaList } = await vaultApi.list();
      
      // Fetch full items in parallel
      const fullItems = await Promise.all(
        metaList.map(m => vaultApi.get(m._id).then(res => res.data))
      );

      // Decrypt payloads
      const decrypted: VaultItemDecrypted[] = await Promise.all(
        fullItems.map(async (fi) => {
          try {
            const payload = await decryptPayload(pek, fi.encryptedData) as any;
            return { ...fi, payload };
          } catch (err) {
            console.error(`Failed to decrypt item ${fi._id}`, err);
            return { ...fi, payload: { name: 'Error Decrypting', nameSalt: '00', username: 'Unknown' } };
          }
        })
      );

      setItems(decrypted);

      // Build Merkle Index for search
      const index = await buildVaultIndex(decrypted.map(d => ({ name: d.payload.name, nameSalt: d.payload.nameSalt })));
      setVaultIndex(index);
      
    } catch (err: any) {
      toast.error('Failed to load vault');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchVault();
  }, [pek, vaultRefreshTrigger]);

  // Client-side search via blind index logic
  const filteredItems = items.filter(item => {
    if (!searchQuery) return true;
    if (!vaultIndex) return false;
    const matches = searchIndex(vaultIndex, searchQuery);
    return matches.some(m => m.nameSalt === item.payload.nameSalt);
  }).sort((a, b) => {
    const nameA = (a.payload.name || '').toLowerCase();
    const nameB = (b.payload.name || '').toLowerCase();
    return nameA.localeCompare(nameB);
  });

  const groupedItems = filteredItems.reduce((acc, item) => {
    const category = item.category || 'Uncategorized';
    if (!acc[category]) acc[category] = [];
    acc[category].push(item);
    return acc;
  }, {} as Record<string, VaultItemDecrypted[]>);

  const handleEdit = (item: VaultItemDecrypted) => {
    setEditingItem(item);
    setIsModalOpen(true);
  };

  const handleAddNew = () => {
    setEditingItem(undefined);
    setIsModalOpen(true);
  };

  return (
    <div className="flex w-full" style={{ height: '100vh', overflow: 'hidden' }}>
      <Sidebar />
      
      <div className="dashboard-main-panel flex-col">
        {activeTab === 'personal' && (
          <>
            <div className="flex justify-between items-center mb-10 animate-slide-down">
              <h2 className="dashboard-header-title" style={{ margin: 0 }}>Personal Vault</h2>
              
              <div className="flex items-center gap-4">
                <div className="search-pill flex items-center gap-3 w-full" style={{ width: '350px' }}>
                  <Search size={20} className="text-accent" />
                  <input 
                    type="text" 
                    placeholder="Search vault..." 
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    style={{ background: 'transparent', border: 'none', padding: 0, boxShadow: 'none', width: '100%' }}
                  />
                </div>

                <Button variant="primary" onClick={handleAddNew} className="btn-gradient flex items-center gap-2">
                  <Plus size={18} /> ADD ITEM
                </Button>
              </div>
            </div>

            {loading ? (
              <div className="text-center text-dim mt-10">Decrypting vault contents...</div>
            ) : filteredItems.length === 0 ? (
              <div className="text-center text-dim mt-10 card">No items found.</div>
            ) : (
              <div className="flex flex-col w-full pb-20 gap-16 mt-4">
                {Object.entries(groupedItems).map(([category, catItems]) => {
                  const categoryLabels: Record<string, string> = {
                    'password': 'Logins & Passwords',
                    'api_key': 'API Keys',
                    'note': 'Secure Notes',
                    'card': 'Credit Cards'
                  };
                  return (
                  <div key={category} className="w-full animate-slide-up">
                    <h3 className="text-2xl mb-6 font-bold" style={{ color: '#fff', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '1rem', letterSpacing: '0.5px' }}>
                      {categoryLabels[category] || category}
                    </h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '1.5rem' }}>
                      {catItems.map((item, idx) => (
                        <div 
                          key={item._id} 
                          className="vault-item-card flex-col flex animate-slide-right"
                          style={{ animationDelay: `${0.1 + (idx * 0.05)}s`, opacity: 0, padding: '1.5rem', cursor: 'pointer', height: '100%' }}
                          onClick={() => handleEdit(item)}
                        >
                          <div style={{ background: 'linear-gradient(135deg, rgba(255,0,127,0.2) 0%, rgba(0,240,255,0.2) 100%)', padding: '12px', borderRadius: '50%', color: 'var(--accent)', width: 'max-content', marginBottom: '1rem' }}>
                            {getIconForVaultItem(item.payload.name, item.payload.url)}
                          </div>
                          <div className="flex-grow">
                            <div style={{ fontWeight: 700, fontSize: '1.25rem', fontFamily: 'var(--font-ui)', color: '#fff', marginBottom: '4px' }}>{item.payload.name}</div>
                            <div className="text-sm flex items-center gap-2" style={{ color: 'var(--text-dim)', marginBottom: '1.5rem' }}>
                              <span>{revealedItems.has(item._id) ? (item.payload.username || item.category) : '••••••••••••'}</span>
                              {item.payload.username && (
                                <button 
                                  type="button" 
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const next = new Set(revealedItems);
                                    next.has(item._id) ? next.delete(item._id) : next.add(item._id);
                                    setRevealedItems(next);
                                  }} 
                                  className="text-dim hover:text-white outline-none focus:outline-none" 
                                  style={{ border: 'none', background: 'transparent', padding: 0, boxShadow: 'none' }}
                                >
                                  {revealedItems.has(item._id) ? <EyeOff size={14} /> : <Eye size={14} />}
                                </button>
                              )}
                            </div>
                          </div>
                          <div className="flex justify-between items-center text-sm" style={{ color: 'var(--text-dim)', borderTop: '1px solid rgba(0, 240, 255, 0.1)', paddingTop: '1rem' }}>
                            <div className="flex items-center gap-2">
                              <Lock size={14} /> <span>••••••••</span>
                            </div>
                            <span style={{ fontSize: '0.75rem' }}>{new Date(item.updatedAt).toLocaleDateString()}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                  );
                })}
              </div>
            )}
          </>
        )}

        {activeTab === 'shared' && <SharedVaultView />}
        {activeTab === 'security' && <SecurityAudit items={items} />}
        {activeTab === 'settings' && <SettingsPage />}
      </div>

      <VaultItemModal 
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSuccess={() => { setIsModalOpen(false); fetchVault(); }}
        existingItem={editingItem}
      />
    </div>
  );
}
