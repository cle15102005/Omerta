import { useEffect, useState, useRef } from 'react';
import { ShieldAlert, CheckCircle, AlertTriangle, RefreshCw, KeyRound, Lock, Search } from 'lucide-react';
import { useVaultStore } from '../store/vault.store';
import { decryptPayload } from '../crypto/vault.crypto';
import { auditOffline, enrichWithHIBP, DecryptedItem, clearHIBPCache } from '../crypto/security.check';
import { Button } from '../components/Button';
import toast from 'react-hot-toast';

// ── Security score helpers ─────────────────────────────────────────────────────

function computeScore(statuses: ReturnType<typeof Array.from<any>>): number {
  if (statuses.length === 0) return 100;
  let penalty = 0;
  for (const s of statuses) {
    if (s.pwned)        penalty += 40;
    else if (s.reused)  penalty += 15;
    else if (s.strength < 2) penalty += 20;
    else if (s.strength < 3) penalty += 8;
  }
  const maxPenalty = statuses.length * 40;
  return Math.max(0, Math.round(100 - (penalty / maxPenalty) * 100));
}

function scoreGrade(score: number): { label: string; color: string; bg: string } {
  if (score >= 90) return { label: 'A',  color: '#50fa7b', bg: 'rgba(80,250,123,0.12)' };
  if (score >= 75) return { label: 'B',  color: '#8be9fd', bg: 'rgba(139,233,253,0.10)' };
  if (score >= 55) return { label: 'C',  color: '#ffb86c', bg: 'rgba(255,184,108,0.10)' };
  if (score >= 35) return { label: 'D',  color: '#ff9900', bg: 'rgba(255,153,0,0.10)'   };
  return               { label: 'F',  color: '#ff4b4b', bg: 'rgba(255,75,75,0.10)'   };
}

function ScoreRing({ score }: { score: number }) {
  const grade = scoreGrade(score);
  const r = 44;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;

  return (
    <div className="vault-item-card flex flex-col items-center justify-center" style={{ padding: '2rem', background: grade.bg, minWidth: 200 }}>
      <svg width="120" height="120" viewBox="0 0 120 120" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="10" />
        <circle
          cx="60" cy="60" r={r} fill="none"
          stroke={grade.color} strokeWidth="10"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 1.2s ease' }}
        />
      </svg>
      <div style={{ marginTop: '-2.5rem', textAlign: 'center' }}>
        <div style={{ fontSize: '2.8rem', fontWeight: 900, color: grade.color, lineHeight: 1 }}>{grade.label}</div>
        <div style={{ fontSize: '1rem', color: 'rgba(255,255,255,0.5)', marginTop: 4 }}>{score}/100</div>
      </div>
      <div className="text-sm font-semibold mt-4" style={{ color: grade.color }}>Vault Health Score</div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function SecurityAudit({ items }: { items: any[] }) {
  const pek = useVaultStore(s => s.pek);
  const securityStatuses = useVaultStore(s => s.securityStatuses);
  const setSecurityStatuses = useVaultStore(s => s.setSecurityStatuses);

  const [isScanning, setIsScanning]         = useState(false);
  const [isHibpScanning, setIsHibpScanning] = useState(false);
  const [decryptedItems, setDecryptedItems] = useState<DecryptedItem[]>([]);
  const hibpRanOnce = useRef(false);

  // Decrypt items + run offline audit, then auto-run HIBP
  useEffect(() => {
    let isMounted = true;
    hibpRanOnce.current = false;

    const run = async () => {
      if (!pek || !items) { setIsScanning(false); return; }
      if (items.length === 0) {
        setDecryptedItems([]);
        setSecurityStatuses([]);
        setIsScanning(false);
        return;
      }

      setIsScanning(true);
      try {
        // Decrypt
        const mapped: DecryptedItem[] = await Promise.all(items.map(async (item) => {
          let history: { password: string }[] = [];
          if (item.history?.length > 0) {
            const histPayloads = await Promise.all(
              item.history.map(async (h: any) => {
                try { return await decryptPayload(pek, h.encryptedData) as any; }
                catch { return {}; }
              })
            );
            history = histPayloads.map(hp => ({ password: hp.password || hp.apiKey || '' }));
          }
          return { id: item._id, name: item.payload.name, password: item.payload.password || item.payload.apiKey || '', history };
        }));

        if (!isMounted) return;
        setDecryptedItems(mapped);

        // Offline scan
        const offlineStatuses = await auditOffline(mapped);
        const currentStore = useVaultStore.getState().securityStatuses;
        const merged = offlineStatuses.map(s => {
          const ex = currentStore.get(s.itemId);
          return (ex?.pwned !== undefined) ? { ...s, pwned: ex.pwned, pwnedCount: ex.pwnedCount } : s;
        });
        if (isMounted) setSecurityStatuses(merged);

        // Auto-run HIBP (once per mount)
        if (isMounted && !hibpRanOnce.current) {
          hibpRanOnce.current = true;
          setIsHibpScanning(true);
          try {
            const enriched = await enrichWithHIBP(merged, mapped);
            if (isMounted) setSecurityStatuses(enriched);
          } catch {
            // silently ignore — HIBP is optional
          } finally {
            if (isMounted) setIsHibpScanning(false);
          }
        }
      } catch (err) {
        console.error('Audit failed', err);
      } finally {
        if (isMounted) setIsScanning(false);
      }
    };

    run();
    return () => { isMounted = false; };
  }, [items, pek, setSecurityStatuses]);

  const handleHibpCheck = async () => {
    if (decryptedItems.length === 0) return;
    setIsHibpScanning(true);
    const toastId = toast.loading('Checking for data breaches...');
    try {
      const enriched = await enrichWithHIBP(Array.from(securityStatuses.values()), decryptedItems);
      setSecurityStatuses(enriched);
      toast.success('Breach check complete', { id: toastId });
    } catch {
      toast.error('Could not reach the breach database. Try again later.', { id: toastId });
    } finally {
      setIsHibpScanning(false);
    }
  };

  const forceRefreshCache = () => {
    clearHIBPCache();
    hibpRanOnce.current = false;
    toast.success('Breach cache cleared. Re-scanning...');
    handleHibpCheck();
  };

  const statusesArray  = Array.from(securityStatuses.values());
  const reusedCount    = statusesArray.filter(s => s.reused).length;
  const pwnedCount     = statusesArray.filter(s => s.pwned).length;
  const secureCount    = statusesArray.filter(s => !s.pwned && !s.reused && s.strength >= 3).length;
  const score          = computeScore(statusesArray);

  const vulnerableItems = statusesArray
    .filter(s => s.strength < 3 || s.reused || s.pwned)
    .sort((a, b) => {
      if (a.pwned  !== b.pwned)  return a.pwned  ? -1 : 1;
      if (a.reused !== b.reused) return a.reused ? -1 : 1;
      return a.strength - b.strength;
    });

  return (
    <div className="flex-col w-full">
      <div className="flex justify-between items-center mb-10 animate-slide-down">
        <div>
          <h2 className="dashboard-header-title" style={{ margin: 0 }}>Security Check</h2>
          <p className="text-sm text-dim mt-1">
            {isScanning ? 'Scanning your vault...' : isHibpScanning ? 'Checking for data breaches...' : `${items?.length ?? 0} passwords analysed`}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button variant="ghost" onClick={forceRefreshCache} className="text-dim hover:text-white" title="Refresh breach data">
            <RefreshCw size={18} />
          </Button>
          <Button variant="primary" onClick={handleHibpCheck} isLoading={isHibpScanning} className="btn-gradient flex items-center gap-2">
            <Search size={18} /> Check for Breaches
          </Button>
        </div>
      </div>

      {isScanning ? (
        <div className="text-center text-dim mt-20 animate-pulse text-lg">Scanning your vault...</div>
      ) : (
        <>
          {/* Score + Stats row */}
          <div className="grid gap-6 mb-10 animate-slide-right" style={{ gridTemplateColumns: 'auto 1fr' }}>
            <ScoreRing score={score} />

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="vault-item-card text-center" style={{ padding: '1.5rem 1rem' }}>
                <div className="text-4xl font-bold mb-2" style={{ color: 'var(--accent)', fontFamily: 'var(--font-ui)' }}>{items?.length ?? 0}</div>
                <div className="text-xs text-dim uppercase tracking-wider font-semibold">Total Passwords</div>
              </div>

              <div className="vault-item-card text-center" style={{ padding: '1.5rem 1rem' }}>
                <div className="text-4xl font-bold mb-2 flex justify-center items-center gap-2" style={{ fontFamily: 'var(--font-ui)' }}>
                  <span style={{ color: '#50fa7b' }}>{secureCount}</span>
                </div>
                <div className="text-xs text-dim uppercase tracking-wider font-semibold">Safe</div>
              </div>

              <div className="vault-item-card text-center" style={{ padding: '1.5rem 1rem' }}>
                <div className="text-4xl font-bold mb-2" style={{ color: reusedCount > 0 ? '#ffb86c' : 'var(--text-dim)', fontFamily: 'var(--font-ui)' }}>{reusedCount}</div>
                <div className="text-xs text-dim uppercase tracking-wider font-semibold">Reused</div>
              </div>

              <div className="vault-item-card text-center" style={{ padding: '1.5rem 1rem' }}>
                <div className="text-4xl font-bold mb-2" style={{ color: pwnedCount > 0 ? 'var(--danger)' : 'var(--text-dim)', fontFamily: 'var(--font-ui)' }}>{pwnedCount}</div>
                <div className="text-xs text-dim uppercase tracking-wider font-semibold">Leaked Online</div>
                {isHibpScanning && <div className="text-xs text-dim mt-1 animate-pulse">checking...</div>}
              </div>
            </div>
          </div>

          {/* Vulnerable items */}
          <h3 className="text-xl text-accent mb-6 font-semibold tracking-wide animate-slide-right" style={{ animationDelay: '0.1s', opacity: 0 }}>
            {vulnerableItems.length > 0 ? 'Passwords that need attention' : 'All passwords'}
          </h3>

          {vulnerableItems.length === 0 ? (
            <div className="vault-item-card text-center py-16 animate-slide-right" style={{ animationDelay: '0.2s', opacity: 0 }}>
              <CheckCircle size={52} className="mx-auto mb-5" style={{ color: '#50fa7b', opacity: 0.7 }} />
              <div className="text-xl font-bold text-white mb-2">Everything looks good</div>
              <div className="text-dim text-sm">No weak, reused or leaked passwords found</div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pb-10">
              {vulnerableItems.map((status, idx) => {
                const itemMeta = (items || []).find(i => i._id === status.itemId);
                if (!itemMeta) return null;

                return (
                  <div key={status.itemId} className="vault-item-card flex-col flex animate-slide-right" style={{ animationDelay: `${0.2 + idx * 0.05}s`, opacity: 0, padding: '1.5rem' }}>
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
                        <div className="flex justify-between items-center px-4 py-3 rounded" style={{ background: 'rgba(255,75,75,0.05)', border: '1px solid rgba(255,75,75,0.2)' }}>
                          <span className="text-sm font-semibold flex items-center gap-2" style={{ color: '#ff4b4b' }}>
                            <AlertTriangle size={16} /> Found in a data breach
                          </span>
                          <span className="text-xs font-bold px-3 py-1 rounded-full" style={{ background: 'rgba(255,75,75,0.15)', color: '#ff4b4b' }}>
                            {status.pwnedCount.toLocaleString()} times
                          </span>
                        </div>
                      )}

                      {status.reused && (
                        <div className="flex justify-between items-center px-4 py-3 rounded" style={{ background: 'rgba(255,153,0,0.05)', border: '1px solid rgba(255,153,0,0.2)' }}>
                          <span className="text-sm font-semibold flex items-center gap-2" style={{ color: '#ff9900' }}>
                            <KeyRound size={16} /> Used in multiple accounts
                          </span>
                          <span className="text-xs font-bold px-3 py-1 rounded-full" style={{ background: 'rgba(255,153,0,0.15)', color: '#ff9900' }}>
                            {status.reusedIn.length} other {status.reusedIn.length === 1 ? 'account' : 'accounts'}
                          </span>
                        </div>
                      )}

                      {status.strength < 3 && (
                        <div className="flex flex-col gap-2 p-4 rounded" style={{ background: 'rgba(226,209,52,0.05)', border: '1px solid rgba(226,209,52,0.2)' }}>
                          <div className="flex justify-between items-center">
                            <span className="text-sm font-semibold flex items-center gap-2" style={{ color: '#e2d134' }}>
                              <Lock size={16} /> Password is too weak
                            </span>
                            <span className="text-xs font-bold px-3 py-1 rounded-full" style={{ background: 'rgba(226,209,52,0.15)', color: '#e2d134' }}>
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
