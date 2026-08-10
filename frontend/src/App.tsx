import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useVaultStore } from './store/vault.store';
import { Toaster } from 'react-hot-toast';
import LandingPage  from './pages/LandingPage';
import VaultPage  from './pages/VaultPage';
import RecoverPage from './pages/RecoverPage';
import LockScreen from './pages/LockScreen';
import { ErrorBoundary } from './components/ErrorBoundary';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useVaultStore((s) => s.isAuthenticated);
  const isLocked = useVaultStore((s) => s.isLocked);
  
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (isLocked) return <LockScreen />;
  return <>{children}</>;
}

export default function App() {
  const [isRestoring, setIsRestoring] = useState(true);
  useVaultStore((s) => s.setSession); // keep subscription for side-effects

  useEffect(() => {
    try {
      const saved = sessionStorage.getItem('omerta_session');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed.user) {
          useVaultStore.setState({ user: parsed.user, isAuthenticated: true, isLocked: true });
        }
      }
    } catch (e) {
      console.error('Failed to restore session', e);
    }
    setIsRestoring(false);
  }, []);

  if (isRestoring) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen" style={{ background: '#090214' }}>
        <div className="text-accent mb-4 animate-pulse" style={{ fontFamily: 'var(--font-ui)', fontSize: '1.2rem', fontWeight: 600 }}>
          Restoring Secure Session...
        </div>
      </div>
    );
  }

  return (
    <BrowserRouter>
      <ErrorBoundary>
        <Toaster position="top-right" />
        <Routes>
          <Route path="/"        element={<LandingPage />} />
          <Route path="/login"   element={<LandingPage />} />
          <Route path="/recover" element={<RecoverPage />} />
          
          {/* Protected Routes */}
          <Route path="/vault" element={<ProtectedRoute><VaultPage /></ProtectedRoute>} />
          <Route path="/vault/shared" element={<ProtectedRoute><VaultPage activeTab="shared" /></ProtectedRoute>} />
          <Route path="/vault/security" element={<ProtectedRoute><VaultPage activeTab="security" /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute><VaultPage activeTab="settings" /></ProtectedRoute>} />
          
          <Route path="*"        element={<Navigate to="/vault" replace />} />
        </Routes>
      </ErrorBoundary>
    </BrowserRouter>
  );
}
