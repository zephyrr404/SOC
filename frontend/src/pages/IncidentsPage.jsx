import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { FileDown, Plus, ShieldAlert, X } from 'lucide-react';
import { api } from '../lib/api';
import { useProjectStore } from '../stores/projectStore';
import { useToastStore } from '../stores/toastStore';
import { PageHeader } from '../components/ui/PageHeader';

const SEV_CLASS = {
  critical: 'severity-critical', high: 'severity-high',
  medium: 'severity-medium', low: 'severity-low',
};

const STATUS_COLOR = {
  open: 'bg-red-50 text-red-600 border border-red-200',
  investigating: 'bg-amber-50 text-amber-600 border border-amber-200',
  contained: 'bg-blue-50 text-blue-600 border border-blue-200',
  resolved: 'bg-green-50 text-green-700 border border-green-200',
  false_positive: 'bg-soc-panel text-soc-muted border border-soc-border',
};

const SEV_BADGE = {
  critical: 'bg-red-500/[0.12] text-red-600',
  high: 'bg-amber-500/15 text-amber-600',
  medium: 'bg-sky-500/[0.12] text-sky-600',
  low: 'bg-emerald-500/[0.12] text-emerald-600',
};

export function agingLabel(incident) {
  if (!['open', 'investigating', 'contained'].includes(incident.status)) return null;
  const days = Math.floor((Date.now() - new Date(incident.created_at).getTime()) / 86400000);
  if (days < 1) return null;
  return { text: `Open ${days}d`, hot: days >= 7 };
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function IncidentsPage() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const pid = activeProject?.id;
  const navigate = useNavigate();
  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('medium');
  const [selected, setSelected] = useState(new Set());
  const [selMode, setSelMode] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState('');
  const [fStatus, setFStatus] = useState('');
  const [fSeverity, setFSeverity] = useState('');
  const [fAssignee, setFAssignee] = useState('');
  const [fTechnique, setFTechnique] = useState('');
  const [fTag, setFTag] = useState('');
  const [sort, setSort] = useState('severity');
  const [bulkStatus, setBulkStatus] = useState('');
  const [bulkAssignee, setBulkAssignee] = useState('');
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);

  const listParams = {
    ...(fStatus ? { status: fStatus } : {}),
    ...(fSeverity ? { severity: fSeverity } : {}),
    ...(!isNaN(Number(fAssignee)) && fAssignee !== '' ? { assigned_to: Number(fAssignee) } : {}),
    ...(fTechnique ? { technique_id: fTechnique } : {}),
    ...(fTag ? { tag: fTag } : {}),
    sort,
  };

  const { data: incidents, isLoading, isError, refetch } = useQuery({
    queryKey: ['incidents', pid, JSON.stringify(listParams)],
    queryFn: () => api.incidents.list(pid, listParams),
    enabled: !!pid,
  });

  const [createError, setCreateError] = useState('');

  const handleCreate = async () => {
    setCreateError('');
    try {
      // Blank titles are fine — the backend auto-generates one from context.
      await api.incidents.create(pid, { title: title.trim(), severity });
      setShowCreate(false);
      setTitle('');
      setSeverity('medium');
      refetch();
    } catch (err) {
      setCreateError(err.message || 'Failed to create incident');
    }
  };

  const bulkMutation = useMutation({
    mutationFn: (body) => api.incidents.bulk(pid, body),
    onSuccess: (r) => {
      addToast(`Bulk update: ${r.updated} of ${r.total} incidents`, 'success');
      setSelected(new Set());
      setBulkStatus('');
      setBulkAssignee('');
      queryClient.invalidateQueries({ queryKey: ['incidents', pid] });
    },
    onError: (err) => addToast(err.message || 'Bulk update failed', 'error'),
  });

  const toggleSelect = (id) => {
    setGenError('');
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleBulkPdf = async () => {
    if (!selected.size) return;
    setGenerating(true);
    setGenError('');
    try {
      if (selected.size === 1) {
        const id = [...selected][0];
        const blob = await api.incidents.reportPdf(pid, id);
        downloadBlob(blob, `incident-report-${id}.pdf`);
      } else {
        const blob = await api.incidents.bulkReports(pid, [...selected]);
        downloadBlob(blob, `incident-reports-${pid}.zip`);
      }
      clearSelection();
      setSelMode(false);
    } catch (err) {
      setGenError(err.message);
    } finally {
      setGenerating(false);
    }
  };

  const clearSelection = () => setSelected(new Set());

  const startSelection = () => {
    setGenError('');
    setSelMode(true);
  };

  const cancelSelection = () => {
    setSelMode(false);
    setSelected(new Set());
    setGenError('');
  };

  return (
    <div>
      <PageHeader
        title="Incidents"
        right={
          <div className="flex items-center gap-2">
            <button
              onClick={selMode ? handleBulkPdf : startSelection}
              disabled={generating}
              className="flex items-center gap-1.5 text-soc-muted bg-soc-card border border-soc-border hover:border-soc-accent/50 hover:text-soc-accent px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
            >
              <FileDown size={15} />
              {generating ? 'Generating…' : selMode ? `Generate PDF (${selected.size})` : 'Generate PDF'}
            </button>
            <button
              onClick={() => setShowCreate(true)}
              className="flex items-center gap-1.5 bg-soc-accent hover:bg-soc-accent-glow text-white px-4 py-2 rounded-lg text-sm font-medium"
            >
              <Plus size={15} />
              New Incident
            </button>
          </div>
        }
      />
      <div className="flex flex-wrap items-center gap-2 mb-4">
        <select value={fStatus} onChange={(e) => setFStatus(e.target.value)} className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 text-soc-muted focus:outline-none focus:border-soc-accent" title="Filter by status">
          <option value="">all statuses</option>
          {['open', 'investigating', 'contained', 'resolved', 'false_positive'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={fSeverity} onChange={(e) => setFSeverity(e.target.value)} className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 text-soc-muted focus:outline-none focus:border-soc-accent" title="Filter by severity">
          <option value="">all severities</option>
          {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input value={fAssignee} onChange={(e) => setFAssignee(e.target.value)} placeholder="assignee id…" className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 w-28 focus:outline-none focus:border-soc-accent" title="Filter by assignee user id" />
        <input value={fTechnique} onChange={(e) => setFTechnique(e.target.value)} placeholder="technique (T1110)…" className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 w-36 font-mono focus:outline-none focus:border-soc-accent" title="Filter by MITRE technique" />
        <input value={fTag} onChange={(e) => setFTag(e.target.value)} placeholder="tag…" className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 w-28 focus:outline-none focus:border-soc-accent" title="Filter by tag" />
        <select value={sort} onChange={(e) => setSort(e.target.value)} className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 text-soc-muted focus:outline-none focus:border-soc-accent" title="Sort order">
          <option value="severity">most urgent first</option>
          <option value="aging">oldest unresolved first</option>
          <option value="updated_at">recently updated</option>
          <option value="created_at">newest first</option>
        </select>
        {(fStatus || fSeverity || fAssignee || fTechnique || fTag) && (
          <button onClick={() => { setFStatus(''); setFSeverity(''); setFAssignee(''); setFTechnique(''); setFTag(''); }} className="flex items-center gap-1 text-[11px] text-soc-muted hover:text-red-600">
            <X size={12} /> clear filters
          </button>
        )}
      </div>
      {selMode && (
        <div className="sticky top-0 z-30 mb-4 flex flex-wrap items-center gap-2 glass-elevated rounded-xl px-4 py-2.5">
          <span className="text-xs font-medium text-soc-text">
            {selected.size === 0
              ? 'Select incidents to triage or export'
              : `${selected.size} selected`}
          </span>
          <select
            value={bulkStatus}
            onChange={(e) => setBulkStatus(e.target.value)}
            className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 focus:outline-none focus:border-soc-accent"
            title="Bulk status"
          >
            <option value="">set status…</option>
            {['open', 'investigating', 'contained', 'resolved', 'false_positive'].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <input
            value={bulkAssignee}
            onChange={(e) => setBulkAssignee(e.target.value)}
            placeholder="assign user id…"
            className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 w-32 focus:outline-none focus:border-soc-accent"
            title="Bulk assignee (user id)"
          />
          <button
            onClick={() => bulkMutation.mutate({
              incident_ids: [...selected],
              ...(bulkStatus ? { status: bulkStatus } : {}),
              ...(bulkAssignee !== '' && !isNaN(Number(bulkAssignee)) ? { assigned_to: Number(bulkAssignee) } : {}),
            })}
            disabled={bulkMutation.isPending || !selected.size || (!bulkStatus && bulkAssignee === '')}
            className="text-xs bg-soc-panel hover:bg-soc-card border border-soc-border text-soc-text px-3 py-1.5 rounded-lg disabled:opacity-50"
          >
            {bulkMutation.isPending ? 'Applying…' : 'Apply to selected'}
          </button>
          <button
            onClick={cancelSelection}
            className="text-xs text-soc-muted hover:text-soc-accent"
          >
            Cancel
          </button>
          <button
            onClick={handleBulkPdf}
            disabled={generating || !selected.size}
            className="ml-auto flex items-center gap-1.5 text-xs bg-soc-accent hover:bg-soc-accent-glow text-white px-3 py-1.5 rounded-lg disabled:opacity-50"
          >
            <FileDown size={13} />
            {generating ? 'Generating…' : `Generate PDF (${selected.size} selected)`}
          </button>
          {genError && <span className="text-xs text-red-600">{genError}</span>}
        </div>
      )}
      {isLoading ? (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="glass-card rounded-xl p-4 animate-pulse">
              <div className="h-4 bg-soc-panel rounded w-1/3 mb-2" />
              <div className="h-3 bg-soc-card rounded w-1/2" />
            </div>
          ))}
        </div>
      ) : isError ? (
        <div className="flex flex-col items-center justify-center py-16 text-soc-muted">
          <ShieldAlert size={28} strokeWidth={1.5} className="text-slate-400 mb-2" />
          <p className="text-sm text-red-600">Failed to load incidents</p>
          <button onClick={() => refetch()} className="mt-3 text-xs bg-white border border-soc-border hover:bg-soc-panel px-3 py-1.5 rounded transition-colors">
            Retry
          </button>
        </div>
      ) : incidents && incidents.length > 0 ? (
        <div className="space-y-3">
          {incidents.map((inc) => {
            const checked = selected.has(inc.id);
            return (
              <div
                key={inc.id}
                role="button"
                tabIndex={0}
                onClick={() => (selMode ? toggleSelect(inc.id) : navigate(`/incidents/${inc.id}`))}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    if (selMode) toggleSelect(inc.id);
                    else navigate(`/incidents/${inc.id}`);
                  }
                }}
                className={`block glass-card rounded-xl p-4 hover:border-soc-accent/40 hover:shadow-lift transition-all cursor-pointer ${SEV_CLASS[inc.severity] || ''} ${selMode && checked ? 'border-soc-accent shadow-lift' : ''}`}
              >
                <div className="flex items-center gap-3">
                  {selMode && (
                    <span
                      role="checkbox"
                      aria-checked={checked}
                      tabIndex={-1}
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleSelect(inc.id);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.stopPropagation();
                          toggleSelect(inc.id);
                        }
                      }}
                      className={`mt-0.5 w-[18px] h-[18px] shrink-0 rounded border flex items-center justify-center text-[10px] transition-colors ${
                        checked ? 'bg-soc-accent border-soc-accent text-white' : 'border-soc-border bg-white hover:border-soc-accent/50'
                      }`}
                    >
                      {checked ? '✔' : ''}
                    </span>
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <h3 className="font-semibold text-sm text-soc-text truncate">{inc.title}</h3>
                        {inc.description && (
                          <p className="text-xs text-soc-muted mt-0.5 truncate">{inc.description}</p>
                        )}
                        <div className="flex flex-wrap items-center gap-1 mt-1">
                          {(inc.hosts || []).slice(0, 2).map((h) => (
                            <span key={h} className="text-[10px] font-mono bg-soc-panel text-soc-muted px-1.5 py-0.5 rounded">{h}</span>
                          ))}
                          {(inc.technique_ids || []).slice(0, 2).map((t) => (
                            <span key={t} className="text-[10px] font-mono bg-soc-accent/10 text-soc-accent px-1.5 py-0.5 rounded">{t}</span>
                          ))}
                          {(inc.tags || []).slice(0, 3).map((t) => (
                            <span key={t} className="text-[10px] bg-soc-panel text-soc-muted px-1.5 py-0.5 rounded-full">#{t}</span>
                          ))}
                          {(() => { const a = agingLabel(inc); return a ? <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${a.hot ? 'bg-red-500/[0.12] text-red-600' : 'bg-amber-500/15 text-amber-600'}`}>{a.text}</span> : null; })()}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${SEV_BADGE[inc.severity] || ''}`}>
                          {inc.severity}
                        </span>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${STATUS_COLOR[inc.status] || ''}`}>
                          {inc.status}
                        </span>
                        <span className="text-xs text-soc-muted" title={`assigned to user ${inc.assigned_to ?? '—'}`}>
                          {inc.assigned_to != null ? `→ #${inc.assigned_to}` : ''}
                        </span>
                        <span className="text-xs text-soc-muted">{inc.evidence_count} evidence</span>
                        <span className="text-xs text-soc-muted-cool hidden xl:inline">
                          {(inc.updated_at || inc.created_at) ? new Date(inc.updated_at || inc.created_at).toLocaleDateString() : '—'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-16 text-soc-muted">
          <ShieldAlert size={28} strokeWidth={1.5} className="text-slate-400 mb-2" />
          <p className="text-sm">No incidents yet</p>
          <p className="text-xs mt-1">Create an incident from a Live Event or click "New Incident"</p>
        </div>
      )}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-soc-overlay/60">
          <div className="glass-elevated rounded-xl p-6 w-full max-w-md mx-4">
            <h2 className="text-lg font-semibold mb-4 text-soc-slate">New Incident</h2>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Incident title (blank = auto-generated)"
              className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm mb-3 focus:outline-none focus:border-soc-accent"
            />
              <div className="flex gap-2 mb-4">
                {['low', 'medium', 'high', 'critical'].map((s) => (
                  <button
                    key={s}
                    onClick={() => setSeverity(s)}
                    className={`px-3 py-1.5 rounded-full text-xs border font-medium ${
                      severity === s
                        ? 'bg-soc-accent border-soc-accent text-white'
                        : 'bg-white border-soc-border text-soc-muted'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            {createError && (
              <p className="text-xs text-red-600 mb-3">{createError}</p>
            )}
            <div className="flex justify-end gap-3">
              <button onClick={() => setShowCreate(false)} className="text-sm text-soc-muted">Cancel</button>
              <button
                onClick={handleCreate}
                className="bg-soc-accent hover:bg-soc-accent-glow text-white px-4 py-2 rounded-lg text-sm disabled:opacity-50"
              >
                Create
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
