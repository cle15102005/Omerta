import { useNavigate, useLocation } from 'react-router-dom';
import { Lock, Users, ShieldAlert, Settings, LogOut } from 'lucide-react';
import { useVaultStore } from '../store/vault.store';
import { authApi } from '../api/auth.api';

export function Sidebar() {
  const navigate = useNavigate();
  const location = useLocation();
  const clearAll = useVaultStore(s => s.clearAll);

  const navItems = [
    { label: 'Personal Vault', icon: <Lock size={18} />, path: '/vault' },
    { label: 'Shared Vaults', icon: <Users size={18} />, path: '/vault/shared' },
    { label: 'Security Audit', icon: <ShieldAlert size={18} />, path: '/vault/security' },
    { label: 'Settings', icon: <Settings size={18} />, path: '/settings' },
  ];

  const handleLogout = async () => {
    await authApi.logout();
    clearAll();
    navigate('/login');
  };

  return (
    <div className="dashboard-sidebar">
      <div>
        <div className="sidebar-logo-frame animate-slide-down">
          <div className="flex items-center gap-3 text-accent" style={{ fontWeight: 800, fontSize: '1.5rem', letterSpacing: '2px', textShadow: '0 0 10px rgba(0, 240, 255, 0.5)' }}>
            <Lock size={28} style={{ flexShrink: 0 }} /> <span className="sidebar-text">OMERTA</span>
          </div>
        </div>

        <div className="flex-col flex gap-1">
          {navItems.map(item => {
            const isActive = location.pathname === item.path;
            return (
              <button
                key={item.path}
                onClick={() => navigate(item.path)}
                className={`dashboard-nav-item ${isActive ? 'active' : ''}`}
              >
                <div style={{ flexShrink: 0, display: 'flex', alignItems: 'center' }}>{item.icon}</div>
                <span className="sidebar-text">{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      <button onClick={handleLogout} className="dashboard-nav-item text-danger" style={{ color: 'var(--danger)' }}>
        <div style={{ flexShrink: 0, display: 'flex', alignItems: 'center' }}><LogOut size={18} /></div>
        <span className="sidebar-text">Logout</span>
      </button>
    </div>
  );
}
