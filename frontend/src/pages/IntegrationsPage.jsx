import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { KeyRound } from 'lucide-react';
import { api } from '../lib/api';
import { useProjectStore } from '../stores/projectStore';
import { useCopyToClipboard } from '../hooks/useCopyToClipboard';
import { useToastStore } from '../stores/toastStore';
import { PageHeader } from '../components/ui/PageHeader';
import { GenerateKeyModal } from '../components/keys/GenerateKeyModal';

const WIN_CMD = (serverUrl) =>
  `powershell -NoProfile -ExecutionPolicy Bypass -Command "& { irm ${serverUrl}/install.ps1 -OutFile $env:TEMP\\soc-install.ps1; & $env:TEMP\\soc-install.ps1 -ApiKey YOUR_AGENT_KEY -ApiBase ${serverUrl}; Remove-Item $env:TEMP\\soc-install.ps1 }"`;

const LINUX_CMD = (serverUrl) =>
  `curl -sfL ${serverUrl}/install.sh | bash -s -- --api-key "YOUR_AGENT_KEY" --api-base "${serverUrl}"`;


export function IntegrationsPage() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const pid = activeProject?.id;
  const [platform, setPlatform] = useState('website');
  const [systemTab, setSystemTab] = useState('windows');
  const [copied, copy] = useCopyToClipboard();
  const addToast = useToastStore((s) => s.addToast);
  // Dev (vite :5173) talks to the backend on :8000 of the same host; any
  // other origin IS the backend (same-origin prod), so use it verbatim.
  // The field stays editable for LAN/exotic setups.
  const [serverUrl, setServerUrl] = useState(() => {
    if (!window.location.protocol.startsWith('http')) return 'http://localhost:8000';
    if (window.location.port === '5173') return `${window.location.protocol}//${window.location.hostname}:8000`;
    return window.location.origin;
  });
  const [showKeyModal, setShowKeyModal] = useState(false);

  const { data: snippetData, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['integration-snippet', pid],
    queryFn: () => api.projects.integrationSnippet(pid),
    enabled: !!pid && platform === 'website',
    retry: 0,
  });

  const handleCopy = async () => {
    const text = snippetData?.ai_agent_prompt;
    if (!text) return;
    if (!(await copy(text))) addToast('Copy failed — select the text manually', 'error');
  };

  const systemSnippet = systemTab === 'windows' ? WIN_CMD(serverUrl) : LINUX_CMD(serverUrl);


  return (
    <div>
      <PageHeader title="Integrations" />
      <div className="glass-card rounded-xl p-6">
        <div className="mb-4">
          <label className="text-xs text-soc-muted block mb-1">SOC Server URL</label>
          <input
            value={serverUrl}
            onChange={(e) => setServerUrl(e.target.value)}
            placeholder={window.location.origin}
            className="w-full max-w-sm bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm placeholder:text-soc-muted/40 focus:outline-none focus:border-soc-accent/50"
          />
          <p className="text-xs text-soc-muted/60 mt-1">
            {platform === 'website'
              ? 'The website snippet host is served from the backend\'s PUBLIC_BACKEND_URL setting; this URL only drives the system agent commands.'
              : 'Use localhost for same-machine, or your LAN IP for remote agents.'}
          </p>
        </div>
        <div className="flex gap-2 mb-4">
          {['website', 'system'].map((p) => (
            <button
              key={p}
              onClick={() => setPlatform(p)}
              className={`px-4 py-2 rounded-lg text-sm border transition-colors ${
                platform === p
                  ? 'bg-soc-accent border-soc-accent text-soc-on-accent'
                  : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
              }`}
            >
              {p === 'website' ? 'Website' : 'System'}
            </button>
          ))}
        </div>
        {platform === 'system' && (
          <div className="flex gap-2 mb-4 ml-1">
            {['windows', 'linux'].map((t) => (
              <button
                key={t}
                onClick={() => setSystemTab(t)}
                className={`px-3 py-1 rounded text-xs border transition-colors ${
                  systemTab === t
                    ? 'bg-soc-accent/30 border-soc-accent text-soc-accent-glow'
                    : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
                }`}
              >
                {t === 'windows' ? 'Windows' : 'Linux'}
              </button>
            ))}
          </div>
        )}

        {platform === 'website' ? (
          isLoading ? (
            <p className="text-sm text-soc-muted py-4">Loading integration snippet...</p>
          ) : isError || !snippetData ? (
            <div className="mb-4 p-3 bg-amber-500/10 border border-amber-500/25 rounded-lg">
              <p className="text-xs text-amber-600">
                {error?.message || 'No usable Website Integration API key yet.'}
              </p>
              <p className="text-xs text-soc-muted mt-1">
                Website keys are hashed and only revealed once, so a filled-in
                snippet needs a key you generate here.
              </p>
              <button
                onClick={() => setShowKeyModal(true)}
                className="mt-3 inline-flex items-center gap-1.5 text-xs bg-soc-accent hover:bg-soc-accent-glow text-soc-on-accent px-3 py-1.5 rounded-lg transition-all duration-200"
              >
                <KeyRound size={12} />
                Generate Website API Key
              </button>
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between mb-3">
                <p className="text-sm text-soc-slate">Connect your website</p>
                <div className="flex items-center gap-2">
                  <Link to="/website-setup" className="text-xs text-soc-accent hover:underline">
                    Full setup spec →
                  </Link>
                  <span className="px-3 py-1 text-xs rounded-md bg-soc-accent text-soc-on-accent">
                    AI agent prompt
                  </span>
                </div>
              </div>

              <p className="text-xs text-soc-muted/70 mb-2">
                Paste this into Cursor, Claude Code, or any IDE AI agent — it will wire up real
                telemetry code in your website's codebase.
              </p>
              <pre className="bg-soc-code border border-soc-border rounded-lg p-4 text-xs font-mono break-all select-all whitespace-pre-wrap max-h-96 overflow-auto">
                {snippetData.ai_agent_prompt}
              </pre>
              <button
                onClick={handleCopy}
                className={`mt-3 text-xs px-3 py-1.5 rounded transition-all duration-200 ${
                  copied
                    ? 'bg-green-600/[0.12] text-green-700 border border-green-600/25'
                    : 'bg-soc-panel hover:bg-soc-panel'
                }`}
              >
                {copied ? '✔ Copied!' : 'Copy prompt'}
              </button>
            </>
          )
        ) : (
          <>
            <div className="mb-4 p-3 bg-amber-500/10 border border-amber-500/25 rounded-lg">
              <p className="text-xs text-amber-600">
                Replace <code className="bg-soc-code px-1 rounded">YOUR_AGENT_KEY</code> with a key from the{' '}
                <Link to={`/api-keys`} className="text-soc-accent underline">API Keys</Link> page.
              </p>
            </div>
            <div>
              <p className="text-sm text-soc-muted mb-2">
                {systemTab === 'windows'
                  ? 'Run this command in PowerShell as Administrator on the target Windows machine:'
                  : 'Run this command on the target Linux machine:'}
              </p>
              <pre className="bg-soc-code border border-soc-border rounded-lg p-4 text-xs font-mono break-all select-all whitespace-pre-wrap max-h-48 overflow-auto">
                {systemSnippet}
              </pre>
              <button
                onClick={async () => {
                  if (!(await copy(systemSnippet))) addToast('Copy failed — select the text manually', 'error');
                }}
                className={`mt-3 text-xs px-3 py-1.5 rounded transition-all duration-200 ${
                  copied
                    ? 'bg-green-600/[0.12] text-green-700 border border-green-600/25'
                    : 'bg-soc-panel hover:bg-soc-panel'
                }`}
              >
                {copied ? '✔ Copied!' : 'Copy'}
              </button>
            </div>
          </>
        )}
      </div>

      {showKeyModal && (
        <GenerateKeyModal
          projectId={pid}
          initialPlatform="website"
          onClose={() => {
            setShowKeyModal(false);
            refetch();
          }}
        />
      )}
    </div>
  );
}
