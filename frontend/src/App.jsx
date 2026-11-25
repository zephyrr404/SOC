import { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { useAuthStore } from './stores/authStore';
import { queryClient } from './lib/queryClient';
import { ProtectedRoute } from './components/ProtectedRoute';
import { PublicRoute } from './components/PublicRoute';
import { AppShell } from './layouts/AppShell';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { ExplorePage } from './pages/ExplorePage';
import { WorkspacePage } from './pages/WorkspacePage';
import { OverviewPage } from './pages/OverviewPage';
import { LiveEventsPage } from './pages/LiveEventsPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { IncidentDetailPage } from './pages/IncidentDetailPage';
import { APIKeysPage } from './pages/APIKeysPage';
import { IntegrationsPage } from './pages/IntegrationsPage';
import { WebsiteSetupPage } from './pages/WebsiteSetupPage';
import { DataCleanupPage } from './pages/DataCleanupPage';
import { HelpPage } from './pages/HelpPage';
import { SettingsPage } from './pages/SettingsPage';
import { ProjectLayout } from './layouts/ProjectLayout';

function AppRoutes() {
  const checkAuth = useAuthStore((s) => s.checkAuth);
  const initialized = useAuthStore((s) => s.initialized);
  const loading = useAuthStore((s) => s.loading);
  const user = useAuthStore((s) => s.user);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  if (!initialized || loading) {
    return (
      <div className="min-h-screen bg-soc-bg flex items-center justify-center">
        <div className="text-soc-muted text-sm animate-pulse">Loading...</div>
      </div>
    );
  }

  const project = (page) => <ProjectLayout>{page}</ProjectLayout>;
  const shell = (page) => <AppShell>{page}</AppShell>;

  return (
    <Routes>
      <Route path="/login" element={<PublicRoute><LoginPage /></PublicRoute>} />
      <Route path="/register" element={<PublicRoute><RegisterPage /></PublicRoute>} />
      <Route path="/explore" element={<ExplorePage />} />
      <Route path="/workspace" element={<ProtectedRoute>{shell(<WorkspacePage />)}</ProtectedRoute>} />
      <Route path="/help" element={<ProtectedRoute>{shell(<HelpPage />)}</ProtectedRoute>} />
      <Route path="/settings" element={<ProtectedRoute>{shell(<SettingsPage />)}</ProtectedRoute>} />
      <Route path="/overview" element={<ProtectedRoute>{shell(project(<OverviewPage />))}</ProtectedRoute>} />
      <Route path="/live-events" element={<ProtectedRoute>{shell(project(<LiveEventsPage />))}</ProtectedRoute>} />
      <Route path="/threat-intel" element={<ProtectedRoute>{shell(project(<ThreatIntelPage />))}</ProtectedRoute>} />
      <Route path="/incidents" element={<ProtectedRoute>{shell(project(<IncidentsPage />))}</ProtectedRoute>} />
      <Route path="/incidents/:incidentId" element={<ProtectedRoute>{shell(project(<IncidentDetailPage />))}</ProtectedRoute>} />
      <Route path="/api-keys" element={<ProtectedRoute>{shell(project(<APIKeysPage />))}</ProtectedRoute>} />
      <Route path="/integrations" element={<ProtectedRoute>{shell(project(<IntegrationsPage />))}</ProtectedRoute>} />
      <Route path="/website-setup" element={<ProtectedRoute>{shell(project(<WebsiteSetupPage />))}</ProtectedRoute>} />
      <Route path="/data-cleanup" element={<ProtectedRoute>{shell(project(<DataCleanupPage />))}</ProtectedRoute>} />
      <Route path="/" element={user ? <Navigate to="/workspace" replace /> : <Navigate to="/login" replace />} />
      <Route path="*" element={user ? <Navigate to="/workspace" replace /> : <Navigate to="/login" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </QueryClientProvider>
  );
}
