import { useEffect, useState } from 'react';
import { Plus, Users, ShieldAlert, ArrowLeft, Trash2, Lock, Eye, EyeOff } from 'lucide-react';
import toast from 'react-hot-toast';
import { Button } from '../components/Button';
import { Input } from '../components/Input';
import { Modal } from '../components/Modal';
import { useVaultStore } from '../store/vault.store';
import { sharedVaultApi } from '../api/shared-vault.api';
import { authApi } from '../api/auth.api';
import { 
  generateVEK, encryptVEKForMember, importPublicKeyPEM, 
  importECDSAPublicKey, verifyRSAPublicKey, computeKeyFingerprint,
  decryptVEKFromMembership
} from '../crypto/rsa.crypto';
import { encryptPayload, decryptPayload } from '../crypto/vault.crypto';
import { SharedVaultItemModal } from '../components/SharedVaultItemModal';
import { getIconForVaultItem } from '../utils/iconMap';

export default function SharedVaultView() {
  const user = useVaultStore(s => s.user);
  const setVaultKey = useVaultStore(s => s.setVaultKey);
  const vaultKeys = useVaultStore(s => s.vaultKeys);
  
  const [vaults, setVaults] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Drill-down State
  const [selectedVault, setSelectedVault] = useState<any>(null);
  const [items, setItems] = useState<any[]>([]);
  const [loadingItems, setLoadingItems] = useState(false);
  const [isItemModalOpen, setIsItemModalOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<any>(undefined);
  
  const [revealedItems, setRevealedItems] = useState<Set<string>>(new Set());

  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [newVaultName, setNewVaultName] = useState('');
  const [newVaultDescription, setNewVaultDescription] = useState('');
  const [isCreating, setIsCreating] = useState(false);

  const [inviteVaultId, setInviteVaultId] = useState<string | null>(null);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'owner' | 'editor' | 'viewer'>('editor');
  const [isInviting, setIsInviting] = useState(false);

  const rsaPrivateKey = useVaultStore(s => s.rsaPrivateKey);

  useEffect(() => {
    fetchVaults();
  }, []);

  const [pendingDeleteVault, setPendingDeleteVault] = useState<string | null>(null);
  const [pendingRemoveMember, setPendingRemoveMember] = useState<{ vaultId: string, uid: string, email: string } | null>(null);
  const [pendingInviteConfirmation, setPendingInviteConfirmation] = useState<{ fingerprint: string, resolve: (val: boolean) => void } | null>(null);

  const fetchVaults = async () => {
    try {
      setLoading(true);
      const data = await sharedVaultApi.getAll();
      let decryptedVaults = [...data];
      if (user && rsaPrivateKey) {
        decryptedVaults = await Promise.all(data.map(async (vault: any) => {
          let decryptedVault = { ...vault, decryptedMetadata: { name: vault.name || 'Unknown Vault', description: '' } };
          const myMem = vault.members.find((m: any) => m.userId?._id === user.userId || m.userId === user.userId);
          if (myMem && myMem.encryptedVEK) {
            try {
              const vek = await decryptVEKFromMembership(myMem.encryptedVEK, rsaPrivateKey);
              setVaultKey(vault._id, vek);
              
              if (vault.encryptedMetadata) {
                const metadata = await decryptPayload(vek, vault.encryptedMetadata);
                decryptedVault.decryptedMetadata = metadata;
              }
            } catch (e) {
              console.error('Failed to decrypt VEK or metadata for vault', vault._id, e);
            }
          }
          return decryptedVault;
        }));
      }
      setVaults(decryptedVaults);
    } catch (err) {
      toast.error('Failed to load shared vaults');
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveMember = (vaultId: string, uid: string, email: string) => {
    setPendingRemoveMember({ vaultId, uid, email });
  };

  const confirmRemoveMember = async () => {
    if (!pendingRemoveMember) return;
    const { vaultId, uid } = pendingRemoveMember;
    try {
      await sharedVaultApi.removeMember(vaultId, uid);
      toast.success('Member removed');
      fetchVaults();
    } catch (err: any) {
      toast.error(err.response?.data?.message || 'Failed to remove member');
    } finally {
      setPendingRemoveMember(null);
    }
  };

  const fetchItems = async (vaultId: string) => {
    try {
      setLoadingItems(true);
      const data = await sharedVaultApi.getItems(vaultId);
      
      const vek = vaultKeys.get(vaultId);
      if (!vek) throw new Error('Vault Encryption Key not loaded');

      const decrypted = await Promise.all(
        data.map(async (item: any) => {
          try {
            const payload = await decryptPayload(vek, item.encryptedData);
            return { ...item, payload };
          } catch {
            return { ...item, payload: { name: 'Error Decrypting', username: 'Unknown' } };
          }
        })
      );
      setItems(decrypted);
    } catch (err) {
      toast.error('Failed to load items');
    } finally {
      setLoadingItems(false);
    }
  };

  const openVault = (vault: any) => {
    setSelectedVault(vault);
    fetchItems(vault._id);
  };

  const closeVault = () => {
    setSelectedVault(null);
    setItems([]);
  };

  const handleDeleteVault = (vaultId: string) => {
    setPendingDeleteVault(vaultId);
  };

  const confirmDeleteVault = async () => {
    if (!pendingDeleteVault) return;
    try {
      await sharedVaultApi.deleteVault(pendingDeleteVault);
      toast.success("Vault deleted successfully");
      fetchVaults();
      if (selectedVault?._id === pendingDeleteVault) closeVault();
    } catch (err: any) {
      toast.error(err.response?.data?.message || "Failed to delete vault");
    } finally {
      setPendingDeleteVault(null);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newVaultName.trim() || !user?.email) return;

    try {
      setIsCreating(true);
      const vek = await generateVEK();
      await authApi.me(); 
      const pkRes = await fetch(`/api/auth/public-keys/${user.email}`).then(res => res.json());
      
      if (!pkRes.publicKey) throw new Error('Could not fetch my public key');
      
      const myPub = await importPublicKeyPEM(pkRes.publicKey);
      const encryptedVEK = await encryptVEKForMember(vek, myPub);
      
      const metadataPayload = { name: newVaultName, description: newVaultDescription };
      const encryptedMetadata = await encryptPayload(vek, metadataPayload);
      
      const newVault = await sharedVaultApi.create({ encryptedMetadata, encryptedVEK });
      
      setVaultKey(newVault._id, vek);
      
      toast.success('Shared vault created');
      setIsCreateOpen(false);
      setNewVaultName('');
      setNewVaultDescription('');
      fetchVaults();
    } catch (err: any) {
      toast.error(err.response?.data?.message || err.message || 'Error creating vault');
    } finally {
      setIsCreating(false);
    }
  };

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteVaultId || !inviteEmail.trim()) return;

    try {
      setIsInviting(true);
      const pkRes = await fetch(`/api/auth/public-keys/${inviteEmail}`).then(res => res.json());
      if (pkRes.message === 'User not found' || !pkRes.publicKey) {
        throw new Error('User not found or has no public keys');
      }

      const ecdsaPub = await importECDSAPublicKey(pkRes.ecdsaPublicKey);
      const isValid = await verifyRSAPublicKey(ecdsaPub, pkRes.keySignature, pkRes.publicKey);
      
      if (!isValid) {
        toast.error('SECURITY ALERT: User key signature verification failed! MITM attack possible.', { icon: <ShieldAlert color="red" />, duration: 10000 });
        throw new Error('Key substitution detected');
      }

      const fingerprint = await computeKeyFingerprint(pkRes.ecdsaPublicKey);
      // fingerprint confirmed via UI modal
      const isConfirmed = await new Promise<boolean>((resolve) => {
        setPendingInviteConfirmation({ fingerprint, resolve });
      });
      setPendingInviteConfirmation(null);
      if (!isConfirmed) throw new Error('User cancelled invite');

      const vek = vaultKeys.get(inviteVaultId);
      if (!vek) throw new Error('Vault Encryption Key not found in memory. Please reload the vault.');

      const inviteePub = await importPublicKeyPEM(pkRes.publicKey);
      const encryptedVEK = await encryptVEKForMember(vek, inviteePub);

      await sharedVaultApi.inviteMember(inviteVaultId, {
        email: inviteEmail,
        role: inviteRole,
        encryptedVEK
      });

      toast.success('Member invited successfully');
      setInviteVaultId(null);
      setInviteEmail('');
      fetchVaults();
    } catch (err: any) {
      toast.error(err.response?.data?.message || err.message || 'Failed to invite member');
    } finally {
      setIsInviting(false);
    }
  };

  if (selectedVault) {
    const myMem = selectedVault.members.find((m: any) => m.userId?._id === user?.userId || m.userId === user?.userId);
    const myRole = myMem?.role || 'viewer';
    const canEdit = myRole === 'owner' || myRole === 'editor';
    const vek = vaultKeys.get(selectedVault._id);

    const sortedItems = [...items].sort((a, b) => {
      const nameA = (a.payload?.name || '').toLowerCase();
      const nameB = (b.payload?.name || '').toLowerCase();
      return nameA.localeCompare(nameB);
    });

    const groupedItems = sortedItems.reduce((acc, item) => {
      const category = item.category || 'Uncategorized';
      if (!acc[category]) acc[category] = [];
      acc[category].push(item);
      return acc;
    }, {} as Record<string, any[]>);

    return (
      <div className="flex-col w-full h-full">
        <div className="flex items-center gap-4 animate-slide-down">
          <Button variant="ghost" onClick={closeVault} style={{ padding: '0.5rem' }}>
            <ArrowLeft size={20} />
          </Button>
          <div style={{ flexGrow: 1 }}>
            <h2 className="dashboard-header-title" style={{ margin: 0 }}>{selectedVault.decryptedMetadata?.name || selectedVault.name}</h2>
            {selectedVault.decryptedMetadata?.description && (
              <p className="text-dim text-sm mt-1">{selectedVault.decryptedMetadata.description}</p>
            )}
          </div>
          {canEdit && (
            <Button variant="primary" onClick={() => { setEditingItem(undefined); setIsItemModalOpen(true); }} className="btn-gradient">
              <Plus size={16} className="mr-2" /> Add Item
            </Button>
          )}
        </div>
        <div className="mb-10"></div>

        {loadingItems ? (
          <div className="text-dim text-center mt-10">Decrypting vault contents...</div>
        ) : items.length === 0 ? (
          <div className="card text-center text-dim mt-10">
            This vault is empty.
          </div>
        ) : (
          <div className="flex flex-col w-full pb-20 gap-16 mt-4">
            {Object.entries(groupedItems).map(([category, catItems]: [string, any]) => {
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
                  {catItems.map((item: any, idx: number) => (
                    <div 
                      key={item._id} 
                      className="vault-item-card flex-col flex animate-slide-right"
                      style={{ animationDelay: `${0.1 + (idx * 0.05)}s`, opacity: 0, padding: '1.5rem', cursor: 'pointer', height: '100%' }}
                      onClick={() => { setEditingItem(item); setIsItemModalOpen(true); }}
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

        {vek && (
          <SharedVaultItemModal
            isOpen={isItemModalOpen}
            onClose={() => setIsItemModalOpen(false)}
            onSuccess={() => { setIsItemModalOpen(false); fetchItems(selectedVault._id); }}
            existingItem={editingItem}
            vaultId={selectedVault._id}
            vek={vek}
            canEdit={canEdit}
          />
        )}
      </div>
    );
  }

  return (
    <div className="flex-col w-full h-full">
      <div className="flex justify-between items-center mb-10 animate-slide-down">
        <h2 className="dashboard-header-title" style={{ margin: 0 }}>Shared Vaults</h2>
        <Button variant="primary" onClick={() => setIsCreateOpen(true)} className="btn-gradient">
          <Plus size={16} className="mr-2" /> New Vault
        </Button>
      </div>

      {loading ? (
        <div className="text-dim text-center mt-10">Loading shared vaults...</div>
      ) : vaults.length === 0 ? (
        <div className="card text-center text-dim mt-10">
          You don't have any shared vaults yet.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {vaults.map((vault, idx) => {
            const myMem = vault.members.find((m: any) => m.userId?._id === user?.userId || m.userId === user?.userId);
            const myRole = myMem?.role || 'viewer';
            const isOwner = myRole === 'owner';

            return (
              <div key={vault._id} className="vault-item-card flex-col flex animate-slide-right" style={{ animationDelay: `${0.1 + (idx * 0.05)}s`, opacity: 0, padding: '1.5rem', cursor: 'pointer' }} onClick={() => openVault(vault)}>
                <div className="flex justify-between items-start border-b border-dim pb-4 mb-4" onClick={e => e.stopPropagation()}>
                  <div>
                    <h3 className="m-0 text-xl text-accent">{vault.decryptedMetadata?.name || vault.name || 'Encrypted Vault'}</h3>
                    {vault.decryptedMetadata?.description && (
                      <p className="text-sm text-dim mt-1">{vault.decryptedMetadata.description}</p>
                    )}
                  </div>
                  <div className="flex gap-2">
                    {isOwner && (
                      <Button variant="danger" onClick={(e) => { e.stopPropagation(); handleDeleteVault(vault._id); }} style={{ padding: '0.4rem 0.8rem' }}>
                        <Trash2 size={16} />
                      </Button>
                    )}
                    <Button variant="ghost" onClick={(e) => { e.stopPropagation(); setInviteVaultId(vault._id); }}>
                      <Users size={16} className="mr-2" /> Invite
                    </Button>
                  </div>
                </div>
                
                <div className="text-sm text-dim mb-2">Members:</div>
                <div className="flex flex-col gap-2">
                  {vault.members.map((m: any) => {
                    const uid = m.userId?._id || m.userId;
                    const email = m.userId?.email || 'Unknown User';
                    return (
                      <div key={uid || Math.random()} className="flex justify-between items-center p-2 rounded" style={{ background: 'var(--surface-light)' }}>
                        <span>{email}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-xs uppercase px-2 py-1 rounded" style={{ background: 'rgba(0, 240, 255, 0.1)', color: 'var(--accent)' }}>
                            {m.role}
                          </span>
                          {isOwner && m.role !== 'owner' && (
                            <Button 
                              variant="ghost" 
                              onClick={(e) => { e.stopPropagation(); handleRemoveMember(vault._id, uid, email); }}
                              style={{ padding: '0.2rem 0.4rem' }}
                              title="Remove Member"
                            >
                              <Trash2 size={14} className="text-dim hover:text-danger transition-colors" />
                            </Button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Create Vault Modal */}
      <Modal isOpen={isCreateOpen} onClose={() => setIsCreateOpen(false)} title="Create Shared Vault">
        <form onSubmit={handleCreate} className="flex flex-col gap-4">
          <Input 
            label="Vault Name"
            placeholder="E.g., Family Passwords"
            value={newVaultName}
            onChange={(e) => setNewVaultName(e.target.value)}
            required
          />
          <Input 
            label="Description (Optional)"
            placeholder="E.g., Shared passwords for the house"
            value={newVaultDescription}
            onChange={(e) => setNewVaultDescription(e.target.value)}
          />
          <div className="flex justify-end gap-2 mt-4">
            <Button variant="ghost" type="button" onClick={() => setIsCreateOpen(false)}>Cancel</Button>
            <Button variant="primary" type="submit" isLoading={isCreating}>Create</Button>
          </div>
        </form>
      </Modal>

      {/* Invite Member Modal */}
      <Modal isOpen={!!inviteVaultId} onClose={() => setInviteVaultId(null)} title="Secure Invite">
        <form onSubmit={handleInvite} className="flex flex-col gap-4">
          <p className="text-sm text-dim mb-2">
            The user's ECDSA public key signature will be cryptographically verified before their invite is encrypted.
          </p>
          <Input 
            label="Email Address"
            type="email"
            placeholder="member@gmail.com"
            value={inviteEmail}
            onChange={(e) => setInviteEmail(e.target.value)}
            required
          />
          <div className="flex flex-col gap-1">
            <label className="text-sm font-semibold text-dim">Role</label>
            <select 
              className="p-2 rounded bg-surface border border-dim text-white outline-none focus:border-accent"
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value as any)}
            >
              <option value="viewer">Viewer</option>
              <option value="editor">Editor</option>
            </select>
          </div>
          <div className="flex justify-end gap-2 mt-4">
            <Button variant="ghost" type="button" onClick={() => setInviteVaultId(null)}>Cancel</Button>
            <Button variant="primary" type="submit" isLoading={isInviting}>Verify & Invite</Button>
          </div>
        </form>
      </Modal>

      {/* Delete Vault Confirmation */}
      <Modal isOpen={!!pendingDeleteVault} onClose={() => setPendingDeleteVault(null)} title="Delete Shared Vault">
        <div className="flex flex-col gap-5">
          <p className="text-sm text-dim">Are you sure you want to permanently delete this shared vault? This action cannot be undone.</p>
          <div className="flex justify-end gap-3 mt-2">
            <Button variant="ghost" onClick={() => setPendingDeleteVault(null)}>Cancel</Button>
            <Button variant="danger" onClick={confirmDeleteVault}>Delete Vault</Button>
          </div>
        </div>
      </Modal>

      {/* Remove Member Confirmation */}
      <Modal isOpen={!!pendingRemoveMember} onClose={() => setPendingRemoveMember(null)} title="Remove Member">
        <div className="flex flex-col gap-5">
          <p className="text-sm text-dim">Are you sure you want to remove <strong className="text-white">{pendingRemoveMember?.email}</strong> from this vault?</p>
          <div className="flex justify-end gap-3 mt-2">
            <Button variant="ghost" onClick={() => setPendingRemoveMember(null)}>Cancel</Button>
            <Button variant="danger" onClick={confirmRemoveMember}>Remove Member</Button>
          </div>
        </div>
      </Modal>

      {/* Security Verification Confirmation */}
      <Modal isOpen={!!pendingInviteConfirmation} onClose={() => pendingInviteConfirmation?.resolve(false)} title="Security Verification Passed">
        <div className="flex flex-col gap-5">
          <p className="text-sm text-success flex items-center gap-2">
            <ShieldAlert size={16} /> Verified ECDSA key signature.
          </p>
          <div className="flex flex-col gap-1">
            <span className="text-xs text-dim">Invitee Fingerprint:</span>
            <div className="font-mono bg-bg p-3 rounded border border-white/5 text-accent tracking-wider text-center font-bold break-all text-sm">
              {pendingInviteConfirmation?.fingerprint}
            </div>
          </div>
          <p className="text-xs text-dim">Please verify this fingerprint with the recipient over a secure channel before proceeding.</p>
          <div className="flex justify-end gap-3 mt-2">
            <Button variant="ghost" onClick={() => pendingInviteConfirmation?.resolve(false)}>Cancel Invite</Button>
            <Button variant="primary" onClick={() => pendingInviteConfirmation?.resolve(true)}>Trust & Proceed</Button>
          </div>
        </div>
      </Modal>

    </div>
  );
}
