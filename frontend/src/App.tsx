import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useVaultStore } from './store/vault.store';
import LoginPage  from './pages/LoginPage';
import VaultPage  from './pages/VaultPage';
import RecoverPage from './pages/RecoverPage';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useVaultStore((s) => s.isAuthenticated);
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login"   element={<LoginPage />} />
        <Route path="/recover" element={<RecoverPage />} />
        <Route path="/vault"   element={<ProtectedRoute><VaultPage /></ProtectedRoute>} />
        <Route path="*"        element={<Navigate to="/vault" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
