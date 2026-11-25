import { useState } from 'react';
import { motion } from 'framer-motion';
import { Globe, Monitor, Check } from 'lucide-react';
import { api, saveWebsiteKey } from '../../lib/api';
import { useToastStore } from '../../stores/toastStore';
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard';

export function NewProjectModal({ onClose, onCreated }) {
  const [step, setStep] = useState(1);
  const [name, setName] = useState('');
  const [type, setType] = useState('website');
  const [systemTab, setSystemTab] = useState('windows');
  const [serverUrl, setServerUrl] = useState(() => {
    if (!window.location.protocol.startsWith('http')) return 'http://localhost:8000';
    if (window.location.port === '5173') return `${window.location.protocol}//${window.location.hostname}:8000`;
    return window.location.origin;
  });
  const [description, setDescription] = useState('');
  const [project, setProject] = useState(null);
  const [apiKey, setApiKey] = useState('');
  const [scriptTag, setScriptTag] = useState('');
  const [aiAgentPrompt, setAiAgentPrompt] = useState('');
  const [snippetTab, setSnippetTab] = useState('script');
  const [loading, setLoading] = useState(false);
  const addToast = useToastStore((s) => s.addToast);
  const [, copy] = useCopyToClipboard();

  const copyText = async (text) => {
    if (!(await copy(text))) addToast('Copy failed — select the text manually', 'error');
  };

  const createKey = async (p) => {
    if (type === 'system') {
      const k = await api.agents.createKey('default', p.id);
      return { apiKey: k.api_key };
    }
    const k = await api.projects.createApiKey(p.id, 'default');
    saveWebsiteKey(p.id, k.key);
    return { apiKey: k.key, scriptTag: k.script_tag, aiAgentPrompt: k.ai_agent_prompt };
  };

  const applyKeyResult = (r) => {
    setApiKey(r.apiKey);
    if (r.scriptTag) setScriptTag(r.scriptTag);
    if (r.aiAgentPrompt) setAiAgentPrompt(r.aiAgentPrompt);
  };

  const handleCreate = async () => {
    if (!name.trim()) {
      addToast('Project name must not be empty', 'error');
      return;
    }
    setLoading(true);
    try {
      const p = project || await api.projects.create({ name: name.trim(), type, description });
      if (!project) {
        applyKeyResult(await createKey(p));
        setProject(p);
      }
      setStep(2);
    } catch (e) {
      addToast(e.message || 'Failed to create project', 'error');
    }
    setLoading(false);
  };

  const handleFinish = () => {
    onCreated(project);
  };

  const handleRegenerate = async () => {
    if (!project) return;
    setLoading(true);
    try {
      applyKeyResult(await createKey(project));
    } catch (e) {
      addToast(e.message || 'Failed to regenerate key', 'error');
    }
    setLoading(false);
  };

  const winSnippet = `powershell -NoProfile -ExecutionPolicy Bypass -Command "& { irm ${serverUrl}/install.ps1 -OutFile $env:TEMP\\soc-install.ps1; & $env:TEMP\\soc-install.ps1 -ApiKey ${apiKey} -ApiBase ${serverUrl}; Remove-Item $env:TEMP\\soc-install.ps1 }"`;
  const linuxSnippet = `curl -sfL ${serverUrl}/install.sh | bash -s -- --api-key ${apiKey} --api-base ${serverUrl}`;

  const snippet = type === 'website' ? scriptTag : systemTab === 'windows' ? winSnippet : linuxSnippet;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-soc-overlay/60"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.9, opacity: 0 }}
        className="glass-elevated rounded-xl p-6 w-full max-w-lg mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        {step === 1 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-soc-slate">New Project</h2>
            <div>
              <label className="text-sm text-soc-muted block mb-1">Name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-soc-accent"
              />
            </div>
            <div>
              <label className="text-sm text-soc-muted block mb-2">Type</label>
              <div className="space-y-3">
                {[
                  { id: 'website', label: 'Website', icon: Globe, desc: 'Monitor a website via the JavaScript browser snippet.' },
                  { id: 'system', label: 'System', icon: Monitor, desc: 'Monitor a Windows or Linux machine via the install agent.' },
                ].map((opt) => {
                  const isSelected = type === opt.id;
                  const Icon = opt.icon;
                  return (
                    <button
                      key={opt.id}
                      onClick={() => setType(opt.id)}
                      className={`relative flex items-start gap-4 p-4 rounded-xl border text-left transition-all duration-200 w-full focus:outline-none focus-visible:ring-2 focus-visible:ring-soc-accent ${isSelected
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
                        <p className={`text-sm font-medium ${isSelected ? 'text-soc-slate' : 'text-soc-muted'}`}>{opt.label}</p>
                        <p className="text-xs text-soc-muted/70 mt-0.5">{opt.desc}</p>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
            <div>
              <label className="text-sm text-soc-muted block mb-1">SOC Server URL</label>
              <input
                value={serverUrl}
                onChange={(e) => setServerUrl(e.target.value)}
                className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-soc-accent"
                placeholder={window.location.origin}
              />
              <p className="text-xs text-soc-muted/60 mt-1">
                {type === 'website'
                  ? 'The website snippet host comes from the backend\'s PUBLIC_BACKEND_URL; this URL only drives system agent commands.'
                  : 'Use localhost for same-machine, or your LAN IP for remote agents.'}
              </p>
            </div>
            <div>
              <label className="text-sm text-soc-muted block mb-1">Description (optional)</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-soc-accent"
                rows={2}
              />
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button onClick={onClose} className="text-sm text-soc-muted hover:text-soc-accent">Cancel</button>
              <button
                onClick={handleCreate}
                disabled={!name.trim() || loading}
                className="bg-soc-accent hover:bg-soc-accent-glow text-white px-4 py-2 rounded-lg text-sm disabled:opacity-50"
              >
                {loading ? 'Creating...' : 'Create Project'}
              </button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-soc-slate">API Key</h2>
            <div className="glass-card rounded-lg p-4">
              <p className="text-xs text-amber-600 mb-2 font-medium">
                We only show this once. Store it securely.
              </p>
              <div className="bg-soc-code border border-soc-border rounded px-3 py-2 font-mono text-xs break-all select-all">
                {apiKey}
              </div>
              <div className="flex gap-2 mt-3">
                <button
                  onClick={() => copyText(apiKey)}
                  className="text-xs bg-soc-panel hover:bg-soc-card px-3 py-1.5 rounded"
                >
                  Copy
                </button>
                <button
                  onClick={handleRegenerate}
                  className="text-xs bg-soc-panel hover:bg-soc-card px-3 py-1.5 rounded"
                >
                  Regenerate
                </button>
              </div>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => { setStep(1); }}
                className="text-sm text-soc-muted hover:text-soc-accent"
              >
                Back
              </button>
              <button
                onClick={() => setStep(3)}
                className="bg-soc-accent hover:bg-soc-accent-glow text-white px-4 py-2 rounded-lg text-sm"
              >
                Continue
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-soc-slate">Setup Instructions</h2>
            {type === 'system' && (
              <div className="flex gap-2">
                {['windows', 'linux'].map((t) => (
                  <button
                    key={t}
                    onClick={() => setSystemTab(t)}
                    className={`px-3 py-1 rounded text-xs border transition-colors ${systemTab === t
                      ? 'bg-soc-accent/30 border-soc-accent text-soc-accent-glow'
                      : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
                      }`}
                  >
                    {t === 'windows' ? 'Windows' : 'Linux'}
                  </button>
                ))}
              </div>
            )}
            {type === 'website' ? (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-sm text-soc-muted">Connect your website</p>
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
                    <p className="text-sm text-soc-muted mb-2">
                      Add this script tag before <code className="text-xs bg-soc-panel px-1 rounded">&lt;/head&gt;</code>:
                    </p>
                    <pre className="bg-soc-code border border-soc-border rounded-lg p-3 text-xs font-mono break-all select-all max-h-32 overflow-auto">
                      {snippet}
                    </pre>
                  </>
                ) : (
                  <>
                    <p className="text-xs text-soc-muted/70 mb-2">
                      Paste this into Cursor, Claude Code, or any IDE AI agent — it will wire up real
                      logging code in your website's codebase instead of a single script tag.
                    </p>
                    <pre className="bg-soc-code border border-soc-border rounded-lg p-3 text-xs font-mono break-all select-all whitespace-pre-wrap max-h-48 overflow-auto">
                      {aiAgentPrompt}
                    </pre>
                  </>
                )}
                <button
                  onClick={() => copyText(snippetTab === 'script' ? snippet : aiAgentPrompt)}
                  className="text-xs bg-soc-panel hover:bg-soc-card px-3 py-1.5 rounded mt-2"
                >
                  Copy {snippetTab === 'script' ? 'script tag' : 'prompt'}
                </button>
              </div>
            ) : (
              <div>
                <p className="text-sm text-soc-muted mb-2">
                  {systemTab === 'windows'
                    ? 'Run this in PowerShell as Administrator:'
                    : 'Run this on the target Linux machine:'}
                </p>
                <pre className="bg-soc-code border border-soc-border rounded-lg p-3 text-xs font-mono break-all select-all max-h-48 overflow-auto whitespace-pre-wrap">
                  {snippet}
                </pre>
                <button
                  onClick={() => copyText(snippet)}
                  className="text-xs bg-soc-panel hover:bg-soc-card px-3 py-1.5 rounded mt-2"
                >
                  Copy
                </button>
              </div>
            )}
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setStep(2)}
                className="text-sm text-soc-muted hover:text-soc-accent"
              >
                Back
              </button>
              <button
                onClick={handleFinish}
                className="bg-soc-accent hover:bg-soc-accent-glow text-white px-4 py-2 rounded-lg text-sm"
              >
                Go to Overview
              </button>
            </div>
          </div>
        )}
      </motion.div>
    </motion.div>
  );
}
