import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  User, Lock, Briefcase, LogOut, Pencil, Check, X, ShieldCheck, FolderKanban,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuthStore } from '../stores/authStore';
import { useProjectStore } from '../stores/projectStore';
import { useToastStore } from '../stores/toastStore';
import { PageHeader } from '../components/ui/PageHeader';

function initials(name, email) {
  const src = (name || email || '?').trim();
  const parts = src.split(/\s+/);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return src.slice(0, 2).toUpperCase();
}

function Card({ icon: Icon, title, subtitle, children }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="glass-card rounded-xl p-5"
    >
      <div className="flex items-center gap-2.5 mb-4">
        <span className="w-8 h-8 rounded-lg bg-soc-tint-steel border border-soc-accent/20 flex items-center justify-center shrink-0">
          <Icon size={16} className="text-soc-accent" strokeWidth={2} />
        </span>
        <div>
          <h2 className="font-semibold text-soc-text text-sm">{title}</h2>
          {subtitle && <p className="text-[11px] text-soc-muted">{subtitle}</p>}
        </div>
      </div>
      {children}
    </motion.section>
  );
}

function Row({ label, children, last }) {
  return (
    <div className={`flex items-center justify-between gap-3 py-2.5 ${last ? '' : 'border-b border-soc-border/60'}`}>
      <span className="text-xs text-soc-muted shrink-0">{label}</span>
      <span className="text-sm text-soc-text font-medium text-right min-w-0">{children}</span>
    </div>
  );
}

export function SettingsPage() {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const activeProject = useProjectStore((s) => s.activeProject);
  const addToast = useToastStore((s) => s.addToast);
  const navigate = useNavigate();

  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState('');
  const [savingName, setSavingName] = useState(false);

  const [curPw, setCurPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [pwMsg, setPwMsg] = useState({ type: '', text: '' });
  const [savingPw, setSavingPw] = useState(false);

  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: () => api.projects.list(),
  });
  const projectCount = Array.isArray(projects) ? projects.length : 0;

  const saveName = async () => {
    const name = nameDraft.trim();
    if (!name) return;
    setSavingName(true);
    try {
      await api.auth.updateMe({ name });
      await useAuthStore.getState().checkAuth();
      setEditingName(false);
      addToast('Display name updated', 'success');
    } catch (err) {
      addToast(err.message || 'Failed to update name', 'error');
    } finally {
      setSavingName(false);
    }
  };

  const changePassword = async () => {
    setPwMsg({ type: '', text: '' });
    if (newPw.length < 6) {
      setPwMsg({ type: 'error', text: 'New password must be at least 6 characters.' });
      return;
    }
    if (newPw !== confirmPw) {
      setPwMsg({ type: 'error', text: 'New passwords do not match.' });
      return;
    }
    setSavingPw(true);
    try {
      await api.auth.changePassword({ current_password: curPw, new_password: newPw });
      setCurPw(''); setNewPw(''); setConfirmPw('');
      setPwMsg({ type: 'success', text: 'Password changed successfully.' });
    } catch (err) {
      setPwMsg({ type: 'error', text: err.message || 'Failed to change password.' });
    } finally {
      setSavingPw(false);
    }
  };

  const signOut = async () => {
    await logout();
    navigate('/login');
  };

  const inputCls =
    'w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm text-soc-text focus:outline-none focus:border-soc-accent';

  return (
    <div className="max-w-4xl mx-auto">
      <PageHeader title="Settings" />

      {/* Identity hero */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
        className="relative overflow-hidden rounded-xl border border-soc-border mb-5"
      >
        <div className="absolute inset-0 bg-gradient-to-r from-soc-accent/15 via-soc-accent/5 to-transparent" />
        <div className="relative flex items-center gap-4 p-5">
          <span className="w-14 h-14 rounded-xl bg-soc-accent text-white flex items-center justify-center text-lg font-bold shadow-lift shrink-0">
            {initials(user?.name, user?.email)}
          </span>
          <div className="min-w-0">
            <h2 className="text-lg font-bold text-soc-text truncate">{user?.name || user?.email}</h2>
            <p className="text-xs text-soc-muted truncate">{user?.email}</p>
            <p className="text-[10px] text-soc-muted/70 mt-0.5">
              Member since {user?.created_at ? new Date(user.created_at).toLocaleDateString(undefined, { month: 'long', day: 'numeric', year: 'numeric' }) : '—'}
            </p>
          </div>
          <span className="ml-auto hidden sm:flex items-center gap-1.5 text-[10px] px-2 py-1 rounded-full bg-green-600/[0.12] text-green-700 border border-green-600/20 shrink-0">
            <ShieldCheck size={12} /> signed in
          </span>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="space-y-5">
          <Card icon={User} title="Profile" subtitle="How your name appears in activity logs and notes">
            {editingName ? (
              <div className="flex items-center gap-2">
                <input
                  value={nameDraft}
                  onChange={(e) => setNameDraft(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') saveName(); if (e.key === 'Escape') setEditingName(false); }}
                  placeholder="Display name"
                  autoFocus
                  className={inputCls}
                />
                <button
                  onClick={saveName}
                  disabled={!nameDraft.trim() || savingName}
                  className="p-2 rounded-lg bg-soc-accent text-white hover:bg-soc-accent-glow disabled:opacity-50 shrink-0"
                  title="Save"
                >
                  <Check size={15} />
                </button>
                <button
                  onClick={() => setEditingName(false)}
                  className="p-2 rounded-lg border border-soc-border text-soc-muted hover:text-soc-text shrink-0"
                  title="Cancel"
                >
                  <X size={15} />
                </button>
              </div>
            ) : (
              <div>
                <Row label="Display name">
                  <span className="flex items-center gap-2">
                    {user?.name || '—'}
                    <button
                      onClick={() => { setNameDraft(user?.name || ''); setEditingName(true); }}
                      className="text-soc-muted hover:text-soc-accent"
                      title="Edit display name"
                    >
                      <Pencil size={13} />
                    </button>
                  </span>
                </Row>
                <Row label="Email">
                  <span title="Email addresses cannot be changed">{user?.email}</span>
                </Row>
                <Row label="User ID" last>
                  <span className="font-mono text-xs">#{user?.id}</span>
                </Row>
              </div>
            )}
          </Card>

          <Card icon={Lock} title="Security" subtitle="Change the password you sign in with">
            <div className="space-y-2.5">
              <input
                type="password"
                value={curPw}
                onChange={(e) => setCurPw(e.target.value)}
                placeholder="Current password"
                autoComplete="current-password"
                className={inputCls}
              />
              <div className="grid grid-cols-2 gap-2.5">
                <input
                  type="password"
                  value={newPw}
                  onChange={(e) => setNewPw(e.target.value)}
                  placeholder="New password (6+ chars)"
                  autoComplete="new-password"
                  className={inputCls}
                />
                <input
                  type="password"
                  value={confirmPw}
                  onChange={(e) => setConfirmPw(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') changePassword(); }}
                  placeholder="Confirm new password"
                  autoComplete="new-password"
                  className={inputCls}
                />
              </div>
              {pwMsg.text && (
                <p className={`text-xs ${pwMsg.type === 'error' ? 'text-red-600' : 'text-green-700'}`}>
                  {pwMsg.text}
                </p>
              )}
              <button
                onClick={changePassword}
                disabled={!curPw || newPw.length < 6 || !confirmPw || savingPw}
                title={newPw && newPw.length < 6 ? 'New password must be at least 6 characters' : undefined}
                className="text-xs bg-soc-panel hover:bg-soc-card border border-soc-border text-soc-text px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
              >
                {savingPw ? 'Changing…' : 'Change password'}
              </button>
            </div>
          </Card>
        </div>

        <div className="space-y-5">
          <Card icon={Briefcase} title="Workspace" subtitle="Your footprint in this SOC">
            <Row label="Projects owned">
              <span className="flex items-center gap-1.5">
                <FolderKanban size={13} className="text-soc-muted" />
                {projectCount}
              </span>
            </Row>
            <Row label="Active project">
              {activeProject ? activeProject.name : <span className="text-soc-muted">none selected</span>}
            </Row>
            <Row label="Session auth" last>
              <span className="text-xs font-mono text-soc-muted">cookie + token</span>
            </Row>
          </Card>

          <Card icon={LogOut} title="Session" subtitle="This browser's sign-in">
            <p className="text-xs text-soc-muted mb-3">
              Signing out clears this browser's session. API keys and agents keep working — revoke them separately under API Keys.
            </p>
            <button
              onClick={signOut}
              className="flex items-center gap-2 text-xs bg-red-500/10 hover:bg-red-500/15 text-red-600 border border-red-500/25 px-4 py-2 rounded-lg transition-colors"
            >
              <LogOut size={14} /> Sign out
            </button>
          </Card>
        </div>
      </div>
    </div>
  );
}
