import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Check, Copy, Download, KeyRound, Loader2, Key, ShieldAlert } from 'lucide-react';
import { api, getWebsiteKey } from '../lib/api';
import { useProjectStore } from '../stores/projectStore';
import { useCopyToClipboard } from '../hooks/useCopyToClipboard';
import { useToastStore } from '../stores/toastStore';
import { GenerateKeyModal } from '../components/keys/GenerateKeyModal';
import { PageHeader } from '../components/ui/PageHeader';

export function WebsiteSetupPage() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const pid = activeProject?.id;
  const [copied, copy] = useCopyToClipboard();
  const addToast = useToastStore((s) => s.addToast);
  const [showKeyModal, setShowKeyModal] = useState(false);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['website-setup-prompt', pid],
    queryFn: () => api.projects.websiteSetupPrompt(pid, getWebsiteKey(pid)),
    enabled: !!pid,
    retry: 0,
  });

  const prompt = data?.prompt;
  const keyRequired = isError && error?.status === 409;

  const handleCopy = async () => {
    if (!prompt) return;
    if (!(await copy(prompt))) addToast('Copy failed — select the text manually', 'error');
  };

  const handleDownload = () => {
    if (!prompt) return;
    const blob = new Blob([prompt], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc-website-setup-prompt-${pid}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <PageHeader title="Website Setup" />

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-soc-muted py-10">
          <Loader2 size={16} className="animate-spin" />
          Building your prompt...
        </div>
      )}

      {isError && (
        <div className="glass-card rounded-xl p-8 flex flex-col items-center text-center">
          {keyRequired
            ? <Key size={28} strokeWidth={1.5} className="text-slate-400 mb-3" />
            : <ShieldAlert size={28} strokeWidth={1.5} className="text-slate-400 mb-3" />}
          <p className={`text-sm ${keyRequired ? 'text-amber-600' : 'text-red-600'}`}>
            {keyRequired
              ? 'No usable Website Integration API key yet.'
              : (error?.message || 'Failed to load the setup prompt.')}
          </p>
          {keyRequired && (
            <>
              <p className="text-xs text-soc-muted mt-2 max-w-md">
                The prompt is filled in with your real API key, but keys are only
                revealed once when generated. Generate a Website Integration key
                and this page will build the full prompt with it automatically.
              </p>
              <button
                onClick={() => setShowKeyModal(true)}
                className="mt-4 bg-soc-accent hover:bg-soc-accent-glow text-soc-on-accent px-4 py-2 rounded-lg text-sm transition-all duration-200 flex items-center gap-2"
              >
                <KeyRound size={16} />
                Generate API Key
              </button>
            </>
          )}
          {!keyRequired && (
            <button
              onClick={refetch}
              className="mt-4 text-xs bg-soc-panel hover:bg-soc-panel px-3 py-1.5 rounded transition-colors"
            >
              Retry
            </button>
          )}
        </div>
      )}

      {prompt && (
        <>
          <div className="grid gap-3 mb-6 max-w-3xl">
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4">
              <p className="text-sm text-amber-500">
                <span className="font-semibold">HTTPS required:</span> your SOC backend must be
                reachable over HTTPS if your website is HTTPS — browsers silently block HTTP
                requests from an HTTPS page.
              </p>
            </div>
            <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-4">
              <p className="text-sm text-sky-600">
                <span className="font-semibold">CORS:</span> your backend's /ingest/event
                endpoint allows requests from website origins automatically, separate from
                the dashboard's own CORS_ORIGINS setting.
              </p>
            </div>
          </div>

          <div className="rounded-xl border border-soc-border overflow-hidden">
            <div className="relative max-h-[70vh] overflow-auto bg-soc-code">
              <div className="sticky top-0 z-10 flex items-center justify-between gap-3 px-4 py-2.5 bg-soc-tooltip text-white backdrop-blur border-b border-white/20">
                <p className="text-xs text-white/80 font-medium truncate">
                  Full integration prompt ({prompt.split('\n').length} lines)
                </p>
                <button
                  onClick={handleCopy}
                  className={`shrink-0 text-xs px-3 py-1.5 rounded transition-all duration-200 flex items-center gap-1.5 ${
                    copied
                      ? 'bg-green-500/20 text-green-300 border border-green-500/40'
                      : 'bg-soc-panel hover:bg-soc-card text-soc-text'
                  }`}
                >
                  {copied ? <Check size={12} /> : <Copy size={12} />}
                  {copied ? 'Copied!' : 'Copy full prompt'}
                </button>
              </div>
              <pre className="p-5 text-[13px] leading-relaxed font-mono text-soc-text whitespace-pre select-text">
                {prompt}
              </pre>
            </div>
          </div>

          <button
            onClick={handleDownload}
            className="mt-3 text-xs bg-soc-panel hover:bg-soc-panel px-3 py-1.5 rounded transition-colors flex items-center gap-1.5"
          >
            <Download size={12} />
            Download as .md
          </button>
        </>
      )}

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
