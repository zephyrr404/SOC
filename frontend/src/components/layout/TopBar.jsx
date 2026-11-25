import { useNavigate, useLocation } from 'react-router-dom';
import { LogOut } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';

const PAGE_TITLES = [
  { re: /^\/workspace$/, title: 'Workspace' },
  { re: /^\/help$/, title: 'Help' },
  { re: /^\/settings$/, title: 'Settings' },
  { re: /^\/overview$/, title: 'Overview' },
  { re: /^\/live-events$/, title: 'Live Events' },
  { re: /^\/threat-intel$/, title: 'Threat Intelligence' },
  { re: /^\/incidents\/\d+$/, title: 'Incident Detail' },
  { re: /^\/incidents$/, title: 'Incidents' },
  { re: /^\/api-keys$/, title: 'API Keys' },
  { re: /^\/integrations$/, title: 'Integrations' },
  { re: /^\/website-setup$/, title: 'Website Setup' },
  { re: /^\/data-cleanup$/, title: 'Data Cleanup' },
];

function pageTitleFor(pathname) {
  for (const { re, title } of PAGE_TITLES) {
    if (re.test(pathname)) return title;
  }
  return 'SOC';
}

export function TopBar() {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <header className="fixed top-0 left-0 right-0 lg:left-60 h-14 bg-white border-b border-soc-border flex items-center justify-between px-6 max-lg:pl-14 z-30">
      <h1 className="text-base font-semibold text-soc-text">{pageTitleFor(location.pathname)}</h1>

      {user && (
        <div className="flex items-center gap-2.5">
          <span className="flex items-center gap-2">
            <span className="w-7 h-7 rounded-full bg-soc-accent text-white text-xs font-semibold flex items-center justify-center">
              {(user.name || user.email || '?').charAt(0).toUpperCase()}
            </span>
            <span className="text-sm font-medium text-soc-text hidden md:block">
              {user.name || user.email}
            </span>
          </span>
          <button
            onClick={handleLogout}
            className="flex items-center gap-1.5 text-xs text-soc-muted hover:text-soc-critical transition-colors"
            title="Logout"
          >
            <LogOut size={14} />
            <span className="hidden md:inline">Logout</span>
          </button>
        </div>
      )}
    </header>
  );
}
