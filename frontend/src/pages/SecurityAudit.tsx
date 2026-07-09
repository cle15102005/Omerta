import { useEffect, useState } from 'react';
import { ShieldAlert, CheckCircle, AlertTriangle, RefreshCw, KeyRound, Lock, Search } from 'lucide-react';
import { useVaultStore } from '../store/vault.store';
import { decryptPayload } from '../crypto/vault.crypto';
import { auditOffline, enrichWithHIBP, DecryptedItem, clearHIBPCache } from '../crypto/security.check';
import { Button } from '../components/Button';
import toast from 'react-hot-toast';

export default function SecurityAudit({ items }: { items: any[] }) {
  const pek = useVaultStore(s => s.pek);
  const securityStatuses = useVaultStore(s => s.securityStatuses);
  const setSecurityStatuses = useVaultStore(s => s.setSecurityStatuses);
  
  const [isScanning, setIsScanning] = useState(false);
  const [isHibpScanning, setIsHibpScanning] = useState(false);
  const [decryptedItems, setDecryptedItems] = useState<DecryptedItem[]>([]);

  // 1. Decrypt history and map to DecryptedItem for the engine
  useEffect(() => {
    let isMounted = true;
    const prepareItems = async () => {
      if (!pek || !items) {
        setIsScanning(false);
        return;
      }
      if (items.length === 0) {
        setDecryptedItems([]);
        setSecurityStatuses([]);
        setIsScanning(false);
        return;
      }
      setIsScanning(true);
      try {
        const mapped: DecryptedItem[] = await Promise.all(items.map(async (item) => {
          // Decrypt history payloads if they exist
          let history: { password: string }[] = [];
          if (item.history && item.history.length > 0) {
            const histPayloads = await Promise.all(
              item.history.map(async (h: any) => {
                try {
                  return await decryptPayload(pek, h.encryptedData) as any;
                } catch { return {}; }
              })
            );
            history = histPayloads.map(hp => ({ password: hp.password || hp.apiKey || '' }));
          }

          return {
            id: item._id,
            name: item.payload.name,
            password: item.payload.password || item.payload.apiKey || '',
            history
          };
        }));
        
        if (isMounted) {
          setDecryptedItems(mapped);
          // Run offline scan automatically
          const newOfflineStatuses = await auditOffline(mapped);
          const currentStore = useVaultStore.getState().securityStatuses;
          
          const merged = newOfflineStatuses.map(status => {
            const existing = currentStore.get(status.itemId);
            if (existing && existing.pwned !== undefined) {
              return { ...status, pwned: existing.pwned, pwnedCount: existing.pwnedCount };
            }
            return status;
          });
          
          setSecurityStatuses(merged);
        }
      } catch (err) {
        console.error("Failed to prepare items for audit", err);
      } finally {
        if (isMounted) setIsScanning(false);
      }
    };
    prepareItems();
    return () => { isMounted = false; };
  }, [items, pek, setSecurityStatuses]);

  const handleHibpCheck = async () => {
    if (decryptedItems.length === 0) return;
    setIsHibpScanning(true);
    const toastId = toast.loading('Checking for breaches (k-Anonymity)...');
    try {
      const currentStatuses = Array.from(securityStatuses.values());
      const enriched = await enrichWithHIBP(currentStatuses, decryptedItems, () => {
        // Optional progress update
      });
      setSecurityStatuses(enriched);
      toast.success('Breach check complete!', { id: toastId });
    } catch (err) {
      toast.error('Failed to contact HIBP server', { id: toastId });
    } finally {
      setIsHibpScanning(false);
    }
  };

  const forceRefreshCache = () => {
    clearHIBPCache();
    toast.success('Local breach cache cleared.');
  };

  const statusesArray = Array.from(securityStatuses.values());
  const weakCount = statusesArray.filter(s => s.strength < 3).length;
  const reusedCount = statusesArray.filter(s => s.reused).length;
  const pwnedCount = statusesArray.filter(s => s.pwned).length;
  const strongCount = statusesArray.length - weakCount - reusedCount - pwnedCount;

  const vulnerableItems = statusesArray.filter(s => s.strength < 3 || s.reused || s.pwned).sort((a, b) => {
    if (a.pwned !== b.pwned) return a.pwned ? -1 : 1;
    if (a.reused !== b.reused) return a.reused ? -1 : 1;
    return a.strength - b.strength;
  });

  return (
    <div className="flex-col w-full">
      <div className="flex justify-between items-center mb-10 animate-slide-down">
        <h2 className="dashboard-header-title" style={{ margin: 0 }}>Security Audit</h2>
        
        <div className="flex items-center gap-4">
          <Button variant="ghost" onClick={forceRefreshCache} className="text-dim hover:text-white" title="Clear Cache">
            <RefreshCw size={18} />
          </Button>
          <Button variant="primary" onClick={handleHibpCheck} isLoading={isHibpScanning} className="btn-gradient flex items-center gap-2">
            <Search size={18} /> CHECK FOR BREACHES
          </Button>
        </div>
      </div>

      {isScanning ? (
        <div className="text-center text-dim mt-10 animate-pulse">Running local zero-knowledge audit...</div>
      ) : (
        <>
          {/* Summary Dashboard */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-10 animate-slide-right">
            <div className="vault-item-card text-center" style={{ padding: '2rem 1rem' }}>
              <div className="text-4xl font-bold mb-2" style={{ color: 'var(--accent)', fontFamily: 'var(--font-ui)' }}>{items ? items.length : 0}</div>
              <div className="text-sm text-dim uppercase tracking-wider font-semibold">Total Items</div>
            </div>
            
            <div className="vault-item-card text-center" style={{ padding: '2rem 1rem' }}>
              <div className="text-4xl font-bold mb-2 text-white flex justify-center items-center gap-2" style={{ fontFamily: 'var(--font-ui)' }}>
                <span>{strongCount}</span> <CheckCircle size={28} style={{ color: '#50fa7b' }} />
              </div>
              <div className="text-sm text-dim uppercase tracking-wider font-semibold">Secure Passwords</div>
            </div>

            <div className="vault-item-card text-center" style={{ padding: '2rem 1rem' }}>
              <div className="text-4xl font-bold mb-2" style={{ color: reusedCount > 0 ? '#ffb86c' : 'var(--text-dim)', fontFamily: 'var(--font-ui)' }}>{reusedCount}</div>
              <div className="text-sm text-dim uppercase tracking-wider font-semibold">Reused Passwords</div>
            </div>

            <div className="vault-item-card text-center" style={{ padding: '2rem 1rem' }}>
              <div className="text-4xl font-bold mb-2" style={{ color: pwnedCount > 0 ? 'var(--danger)' : 'var(--text-dim)', fontFamily: 'var(--font-ui)' }}>{pwnedCount}</div>
              <div className="text-sm text-dim uppercase tracking-wider font-semibold">Breached (HIBP)</div>
            </div>
          </div>

          <h3 className="text-xl text-accent mb-6 font-semibold tracking-wide animate-slide-right" style={{ animationDelay: '0.1s', opacity: 0 }}>Vulnerable Items</h3>

          {vulnerableItems.length === 0 ? (
            <div className="vault-item-card text-center text-success py-10 animate-slide-right" style={{ animationDelay: '0.2s', opacity: 0 }}>
              <CheckCircle size={48} className="mx-auto mb-4 opacity-50" />
              <div className="text-lg">Your vault is in excellent shape. No vulnerabilities found!</div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pb-10">
              {vulnerableItems.map((status, idx) => {
                const itemMeta = (items || []).find(i => i._id === status.itemId);
                if (!itemMeta) return null;

                return (
                  <div key={status.itemId} className="vault-item-card flex-col flex animate-slide-right" style={{ animationDelay: `${0.2 + (idx * 0.05)}s`, opacity: 0, padding: '1.5rem' }}>
                    <div className="flex justify-between items-start mb-4">
                      <div className="flex items-center gap-3">
                        <div style={{ background: 'rgba(255,255,255,0.05)', padding: '12px', borderRadius: '12px', color: 'var(--text-dim)' }}>
                          <ShieldAlert size={20} />
                        </div>
                        <div>
                          <div className="text-lg font-bold text-white mb-1">{itemMeta.payload.name}</div>
                          <div className="text-sm text-dim">{itemMeta.payload.username || itemMeta.category}</div>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-col gap-3 mt-2 border-t border-dim pt-4">
                      {status.pwned && (
                        <div className="flex justify-between items-center px-4 py-3 rounded" style={{ background: 'rgba(255, 75, 75, 0.05)', border: '1px solid rgba(255, 75, 75, 0.2)' }}>
                          <span className="text-sm font-semibold flex items-center gap-2" style={{ color: '#ff4b4b' }}>
                            <AlertTriangle size={16}/> Pwned Password
                          </span>
                          <span className="text-xs font-bold px-3 py-1 rounded-full" style={{ background: 'rgba(255, 75, 75, 0.15)', color: '#ff4b4b' }}>
                            {status.pwnedCount.toLocaleString()} times
                          </span>
                        </div>
                      )}
                      
                      {status.reused && (
                        <div className="flex justify-between items-center px-4 py-3 rounded" style={{ background: 'rgba(255, 153, 0, 0.05)', border: '1px solid rgba(255, 153, 0, 0.2)' }}>
                          <span className="text-sm font-semibold flex items-center gap-2" style={{ color: '#ff9900' }}>
                            <KeyRound size={16}/> Reused Password
                          </span>
                          <span className="text-xs font-bold px-3 py-1 rounded-full" style={{ background: 'rgba(255, 153, 0, 0.15)', color: '#ff9900' }}>
                            {status.reusedIn.length} other items
                          </span>
                        </div>
                      )}

                      {status.strength < 3 && (
                        <div className="flex flex-col gap-2 p-4 rounded" style={{ background: 'rgba(226, 209, 52, 0.05)', border: '1px solid rgba(226, 209, 52, 0.2)' }}>
                          <div className="flex justify-between items-center">
                            <span className="text-sm font-semibold flex items-center gap-2" style={{ color: '#e2d134' }}>
                              <Lock size={16}/> Password Strength
                            </span>
                            <span className="text-xs font-bold px-3 py-1 rounded-full" style={{ background: 'rgba(226, 209, 52, 0.15)', color: '#e2d134' }}>
                              {status.strengthLabel}
                            </span>
                          </div>
                          <div className="w-full h-1.5 mt-1 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.1)' }}>
                            <div className="h-full rounded-full transition-all duration-1000" style={{ width: `${Math.max(10, (status.strength + 1) * 25)}%`, background: status.strength === 0 ? '#ff4b4b' : status.strength === 1 ? '#ff9900' : '#e2d134' }} />
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}
    </div>
  );
}
