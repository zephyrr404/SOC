import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Plus, Key, ShieldAlert } from 'lucide-react';
import { api } from '../lib/api';
import { useProjectStore } from '../stores/projectStore';
import { useToastStore } from '../stores/toastStore';
import { GenerateKeyModal } from '../components/keys/GenerateKeyModal';
import { PageHeader } from '../components/ui/PageHeader';

export function APIKeysPage() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const pid = activeProject?.id;
  const [showModal, setShowModal] = useState(false);

  const { data: keys, isLoading: keysLoading, isError: keysError, refetch } = useQuery({
    queryKey: ['api-keys', pid],
    queryFn: () => api.projects.listApiKeys(pid),
    enabled: !!pid,
  });

  const { data: agentKeys, isLoading: agentKeysLoading, isError: agentKeysError, refetch: refetchAgentKeys } = useQuery({
    queryKey: ['agent-keys', pid],
    queryFn: () => api.agents.listKeys(pid),
    enabled: !!pid,
  });

  const addToast = useToastStore((s) => s.addToast);

  const handleRevoke = async (keyId) => {
    if (!confirm('Revoke this API key? This cannot be undone.')) return;
    try {
      await api.projects.revokeApiKey(keyId);
      addToast('API key revoked', 'success');
      refetch();
    } catch (err) {
      addToast(err.message || 'Failed to revoke key', 'error');
    }
  };

  const handleRevokeAgent = async (keyId) => {
    if (!confirm('Revoke this agent key? This cannot be undone.')) return;
    try {
      await api.agents.revokeKey(keyId);
      addToast('Agent key revoked', 'success');
      refetchAgentKeys();
    } catch (err) {
      addToast(err.message || 'Failed to revoke key', 'error');
    }
  };

  const formattedKeys = [
    ...(keys || []).map((k) => ({
      id: k.id,
      label: k.label,
      prefix: 'soc_...',
      status: k.revoked ? 'revoked' : 'active',
      platform: 'Website',
      created_at: k.created_at,
      last_used_at: k.last_used_at,
      revocable: !k.revoked,
      revoke: () => handleRevoke(k.id),
      type: 'api',
    })),
    ...(agentKeys || []).map((k) => {
      const osLower = (k.os_type || '').toLowerCase();
      const platformLabel = osLower.includes('windows') ? 'Windows'
        : osLower.includes('linux') || osLower.includes('ubuntu') || osLower.includes('debian') || osLower.includes('centos') || osLower.includes('rhel') ? 'Linux'
        : osLower.includes('darwin') || osLower.includes('mac') ? 'macOS'
        : k.os_type || 'System';
      return {
        id: k.id,
        label: k.label,
        prefix: k.key_prefix,
        status: k.status === 'active' ? 'active' : (k.status === 'revoked' ? 'revoked' : 'pending'),
        platform: platformLabel,
        os_detail: k.os_type || '',
        hostname: k.hostname || '',
        ip_address: k.ip_address || '',
        created_at: k.created_at,
        last_used_at: k.last_seen_at,
        revocable: k.status !== 'revoked',
        revoke: () => handleRevokeAgent(k.id),
        type: 'agent',
      };
    }),
  ].sort((a, b) => (new Date(b.created_at).getTime() || 0) - (new Date(a.created_at).getTime() || 0));

  return (
    <div>
      <PageHeader
        title="API Keys"
        right={
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-1.5 bg-soc-accent hover:bg-soc-accent-glow text-soc-on-accent px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200"
          >
            <Plus size={15} />
            Generate API Key
          </button>
        }
      />

      {keysLoading || agentKeysLoading ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <div key={i} className="glass-card rounded-xl p-4 animate-pulse">
              <div className="h-4 bg-soc-panel rounded w-1/3 mb-2" />
              <div className="h-3 bg-soc-card rounded w-1/2" />
            </div>
          ))}
        </div>
      ) : keysError || agentKeysError ? (
        <div className="flex flex-col items-center justify-center py-16 text-soc-muted">
          <ShieldAlert size={28} strokeWidth={1.5} className="text-slate-400 mb-2" />
          <p className="text-sm text-red-600">Failed to load API keys</p>
          <button onClick={() => { refetch(); refetchAgentKeys(); }} className="mt-3 text-xs bg-white border border-soc-border hover:bg-soc-panel px-3 py-1.5 rounded transition-colors">
            Retry
          </button>
        </div>
      ) : formattedKeys.length > 0 ? (
        <div className="space-y-3">
          {formattedKeys.map((key) => (
            <motion.div
              key={`${key.type}-${key.id}`}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className={`glass-card rounded-xl p-4 flex items-center justify-between ${key.status === 'revoked' ? 'opacity-50' : ''}`}
            >
              <div className="flex items-center gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-soc-text">{key.label}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full border ${
                      key.status === 'active'
                        ? 'bg-green-50 text-green-700 border-green-200'
                        : key.status === 'pending'
                          ? 'bg-amber-50 text-amber-600 border-amber-200'
                          : 'bg-red-50 text-red-600 border-red-200'
                    }`}>
                      {key.status}
                    </span>
                  </div>
                  <div className="flex gap-3 text-xs text-soc-muted mt-0.5 flex-wrap">
                    <span className="font-mono">{key.prefix}</span>
                    <span>Platform: {key.platform}</span>
                    {key.os_detail && <span title={key.os_detail} className="truncate max-w-[180px]">{key.os_detail}</span>}
                    {key.hostname && <span>Host: <span className="font-mono text-soc-muted-cool">{key.hostname}</span></span>}
                    {key.ip_address && <span>IP: <span className="font-mono text-soc-muted-cool">{key.ip_address}</span></span>}
                    <span>Created: {key.created_at ? new Date(key.created_at).toLocaleDateString() : '—'}</span>
                    {key.last_used_at && <span>Last seen: {new Date(key.last_used_at).toLocaleDateString()}</span>}
                  </div>
                </div>
              </div>
              {key.revocable && (
                <button
                  onClick={key.revoke}
                  className="text-xs bg-red-50 text-red-600 hover:bg-red-100 border border-red-200 px-3 py-1.5 rounded-lg transition-colors"
                >
                  Revoke
                </button>
              )}
            </motion.div>
          ))}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-16 text-soc-muted">
          <Key size={28} strokeWidth={1.5} className="text-slate-400 mb-2" />
          <p className="text-sm">No API keys generated</p>
          <p className="text-xs mt-1">Generate a key to start sending events</p>
        </div>
      )}

      {showModal && (
        <GenerateKeyModal
          projectId={pid}
          onClose={() => setShowModal(false)}
        />
      )}
    </div>
  );
}
