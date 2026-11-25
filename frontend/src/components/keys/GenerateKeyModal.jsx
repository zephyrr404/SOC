import { useState } from 'react';
import { motion } from 'framer-motion';
import { Monitor, Terminal, Globe, Check, Copy, Download, Loader2, X } from 'lucide-react';
import { api, saveWebsiteKey } from '../../lib/api';
import { useToastStore } from '../../stores/toastStore';
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard';

const PLATFORMS = [
  { id: 'windows', label: 'Windows Agent', icon: Monitor, desc: 'Connect the Windows monitoring agent.' },
  { id: 'linux', label: 'Linux Agent', icon: Terminal, desc: 'Connect the Linux monitoring agent.' },
  { id: 'website', label: 'Website Integration', icon: Globe, desc: 'Use with the JavaScript browser snippet for website monitoring.' },
];

export function GenerateKeyModal({ projectId, onClose, initialPlatform = null }) {
  const [selectedPlatform, setSelectedPlatform] = useState(initialPlatform);
  const [label, setLabel] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedKey, setGeneratedKey] = useState(null);
  const [scriptTag, setScriptTag] = useState('');
  const [aiAgentPrompt, setAiAgentPrompt] = useState('');
  const [snippetTab, setSnippetTab] = useState('script');
  const [copied, copy] = useCopyToClipboard();
  const [snippetCopied, copySnippet] = useCopyToClipboard();
  const addToast = useToastStore((s) => s.addToast);

  const resetModal = () => {
    onClose();
  };

  const handleGenerate = async () => {
    if (!selectedPlatform || !label.trim()) return;
    setIsGenerating(true);

      try {
        if (selectedPlatform === 'website') {
          const result = await api.projects.createApiKey(projectId, label.trim());
          setGeneratedKey(result.key);
          setScriptTag(result.script_tag || '');
          setAiAgentPrompt(result.ai_agent_prompt || '');
          saveWebsiteKey(projectId, result.key);
          addToast('API key generated successfully', 'success');
        } else {
        const result = await api.agents.createKey(label.trim(), projectId);
        setGeneratedKey(result.api_key);
        addToast('Agent key generated successfully', 'success');
      }
    } catch (err) {
      addToast(err.message || 'Failed to generate key', 'error');
      setIsGenerating(false);
      return;
    }
    setIsGenerating(false);
  };

  const handleDownload = () => {
    if (!generatedKey) return;
    const blob = new Blob([generatedKey], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'soc-api-key.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-soc-overlay/60 backdrop-blur-sm p-4"
      onClick={(e) => { if (e.target === e.currentTarget) resetModal(); }}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 20 }}
        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
        className="w-full max-w-lg"
      >
        <div className="glass-elevated rounded-2xl p-6 relative border border-soc-border shadow-storm">
          <button
            onClick={resetModal}
            className="absolute top-4 right-4 text-soc-muted hover:text-soc-accent transition-colors"
            aria-label="Close"
          >
            <X size={20} />
          </button>

          {!generatedKey ? (
            <>
              <div className="mb-6">
                <h2 className="text-xl font-bold text-soc-slate">Generate API Key</h2>
                <p className="text-sm text-soc-muted mt-1">Select the platform this API key will be used for.</p>
              </div>

              <div className="grid gap-3 mb-5">
                {PLATFORMS.map((p) => {
                  const isSelected = selectedPlatform === p.id;
                  const Icon = p.icon;
                  return (
                    <button
                      key={p.id}
                      onClick={() => { setSelectedPlatform(p.id); setLabel(''); }}
                      className={`relative flex items-start gap-4 p-4 rounded-xl border text-left transition-all duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-soc-accent ${
                        isSelected
                          ? 'border-soc-accent/50 bg-soc-accent/10 shadow-[0_6px_24px_-6px_rgba(62,92,118,0.35)] scale-[1.02]'
                          : 'border-soc-border bg-soc-card hover:-translate-y-0.5 hover:border-soc-accent/40 hover:shadow-lift hover:bg-soc-panel'
                      }`}
                    >
                      {isSelected && (
                        <div className="absolute top-2 right-2 w-5 h-5 rounded-full bg-soc-accent flex items-center justify-center">
                          <Check size={12} className="text-white" />
                        </div>
                      )}
                      <div className={`p-2 rounded-lg ${isSelected ? 'bg-soc-accent/15 text-soc-accent' : 'bg-soc-panel text-soc-muted'}`}>
                        <Icon size={22} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className={`text-sm font-medium ${isSelected ? 'text-soc-slate' : 'text-soc-muted'}`}>{p.label}</p>
                        <p className="text-xs text-soc-muted/70 mt-0.5">{p.desc}</p>
                      </div>
                    </button>
                  );
                })}
              </div>

              {selectedPlatform && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="mb-5"
                >
                  <label className="text-xs text-soc-muted mb-1.5 block">API Key Label</label>
                  <input
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    placeholder="e.g. my-key"
                    className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2.5 text-sm placeholder:text-soc-muted/40 focus:outline-none focus:border-soc-accent/60 focus:ring-1 focus:ring-soc-accent/25 transition-all"
                    autoFocus
                  />
                </motion.div>
              )}

              <div className="flex justify-end gap-3">
                <button
                  onClick={resetModal}
                  className="px-4 py-2 text-sm text-soc-muted hover:text-soc-accent transition-colors rounded-lg"
                >
                  Cancel
                </button>
                <button
                  onClick={handleGenerate}
                  disabled={!selectedPlatform || !label.trim() || isGenerating}
                  className="bg-soc-accent hover:bg-soc-accent-glow disabled:opacity-40 disabled:cursor-not-allowed text-white px-5 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2"
                >
                  {isGenerating && <Loader2 size={16} className="animate-spin" />}
                  {isGenerating ? 'Generating...' : 'Generate API Key'}
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="mb-5">
                <h2 className="text-xl font-bold text-soc-slate">API Key Generated</h2>
                <p className="text-sm text-amber-600/90 mt-1 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                  This API key will only be shown once. Store it securely.
                </p>
              </div>

              <div className="bg-soc-code rounded-xl p-4 border border-soc-border mb-4">
                <div className="flex items-start justify-between gap-3">
                  <p className="text-xs font-mono break-all select-all text-soc-text flex-1">{generatedKey}</p>
                  <button
                    onClick={() => copy(generatedKey)}
                    className={`shrink-0 px-2 py-1 text-xs rounded transition-all duration-200 flex items-center gap-1.5 ${
                      copied
                        ? 'bg-green-600/[0.12] text-green-700 border border-green-600/25'
                        : 'bg-soc-panel hover:bg-soc-card text-soc-text'
                    }`}
                  >
                    {copied ? <Check size={12} /> : <Copy size={12} />}
                    {copied ? 'Copied!' : 'Copy key'}
                  </button>
                </div>
              </div>

              {selectedPlatform === 'website' && (
                <div className="mb-5">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-sm text-soc-muted font-medium">Connect your website</p>
                    <div className="flex rounded-lg border border-soc-border bg-soc-card p-0.5">
                      {[
                        { id: 'script', label: 'Script tag' },
                        { id: 'prompt', label: 'AI agent prompt' },
                      ].map((t) => (
                        <button
                          key={t.id}
                          onClick={() => setSnippetTab(t.id)}
                          className={`px-3 py-1 text-xs rounded-md transition-colors ${
                            snippetTab === t.id
                              ? 'bg-soc-accent text-white'
                              : 'text-soc-muted hover:text-soc-accent'
                          }`}
                        >
                          {t.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {snippetTab === 'script' ? (
                    <>
                      <p className="text-xs text-soc-muted/70 mb-2">
                        Add this script tag before the closing head tag on your site:
                      </p>
                      <pre className="bg-soc-code rounded-xl p-3 text-xs font-mono break-all select-all whitespace-pre-wrap max-h-40 overflow-auto border border-soc-border">
                        {scriptTag}
                      </pre>
                      <button
                        onClick={() => copySnippet(snippetTab === 'script' ? scriptTag : aiAgentPrompt)}
                        className={`mt-2 text-xs px-3 py-1.5 rounded transition-all duration-200 ${
                          snippetCopied
                            ? 'bg-green-600/[0.12] text-green-700 border border-green-600/25'
                            : 'bg-soc-panel hover:bg-soc-card'
                        }`}
                      >
                        {snippetCopied ? '✓ Copied!' : 'Copy script tag'}
                      </button>
                    </>
                  ) : (
                    <>
                      <p className="text-xs text-soc-muted/70 mb-2">
                        Paste this into Cursor, Claude Code, or any IDE AI agent — it will wire up real
                        logging code in your website's codebase instead of a single script tag.
                      </p>
                      <pre className="bg-soc-code rounded-xl p-3 text-xs font-mono break-all whitespace-pre-wrap max-h-64 overflow-auto border border-soc-border">
                        {aiAgentPrompt}
                      </pre>
                      <button
                        onClick={() => copySnippet(snippetTab === 'script' ? scriptTag : aiAgentPrompt)}
                        className={`mt-2 text-xs px-3 py-1.5 rounded transition-all duration-200 ${
                          snippetCopied
                            ? 'bg-green-600/[0.12] text-green-700 border border-green-600/25'
                            : 'bg-soc-panel hover:bg-soc-card'
                        }`}
                      >
                        {snippetCopied ? '✓ Copied!' : 'Copy prompt'}
                      </button>
                    </>
                  )}
                </div>
              )}

              <div className="flex justify-end gap-3">
                <button
                  onClick={handleDownload}
                  className="px-4 py-2 text-sm bg-soc-panel hover:bg-soc-card text-soc-text rounded-lg transition-colors flex items-center gap-2"
                >
                  <Download size={16} />
                  Download
                </button>
                <button
                  onClick={resetModal}
                  className="bg-soc-accent hover:bg-soc-accent-glow text-white px-5 py-2 rounded-lg text-sm font-medium transition-all"
                >
                  Done
                </button>
              </div>
            </>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}
