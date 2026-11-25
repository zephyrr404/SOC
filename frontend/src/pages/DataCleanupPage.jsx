import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle, ArrowLeft, Database, FileClock,
  Loader2, RefreshCw, ScrollText, ShieldCheck, Trash2,
} from 'lucide-react';
import { api } from '../lib/api';
import { useToastStore } from '../stores/toastStore';
import { useProjectStore } from '../stores/projectStore';
import { formatLocalDate, formatLocalTime } from '../lib/time';
import { PageHeader } from '../components/ui/PageHeader';

const PRESETS = [
  { days: 7, label: 'Older than 7 days' },
  { days: 30, label: 'Older than 30 days' },
  { days: 90, label: 'Older than 90 days' },
];

function localNow() {
  const d = new Date();
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

function shortDate(iso) {
  if (!iso) return '—';
  let str = String(iso);
  if (!str.endsWith('Z') && !str.includes('+') && str.length >= 19) str = str + 'Z';
  const d = new Date(str);
  return isNaN(d.getTime()) ? str : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function CleanupPreviewList({ preview, scope, isPreviewing }) {
  if (isPreviewing && !preview) {
    return (
      <div className="flex items-center gap-2 py-8 justify-center text-soc-muted text-sm">
        <Loader2 size={16} className="animate-spin" /> Running preview…
      </div>
    );
  }
  const refreshing = isPreviewing && preview;
  if (!preview) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-soc-muted">
        {scope === 'events'
          ? <Database size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
          : <ScrollText size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />}
        <p className="text-sm text-center">
          Adjust the filters above — the preview runs automatically and shows exactly which rows will be deleted.
        </p>
      </div>
    );
  }
  const rows = preview.sample || [];
  return (
    <div>
      {refreshing && (
        <p className="flex items-center gap-1.5 text-[11px] text-soc-muted mb-2">
          <Loader2 size={12} className="animate-spin" /> Refreshing preview — counts below may be stale…
        </p>
      )}
      <div className={`flex items-start justify-between gap-3 mb-3 px-4 py-3 rounded-xl border ${
        preview.count > 0
          ? 'bg-amber-500/10 border-amber-500/30'
          : 'bg-soc-card border-soc-border'
      }`}>
        <div className={preview.count === 0 ? 'flex flex-col items-center text-center w-full' : undefined}>
          {preview.count === 0 && (
            scope === 'events'
              ? <Database size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
              : <ScrollText size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
          )}
          <p className="text-sm font-semibold text-soc-text">
            {preview.count > 0
              ? `This will delete ${preview.count.toLocaleString()} ${scope === 'events' ? 'event' : 'raw log'}${preview.count === 1 ? '' : 's'}`
              : 'Nothing matches these filters'}
          </p>
          {preview.count > 0 && (
            <p className="text-xs text-soc-muted mt-1">
              oldest: {shortDate(preview.oldest_match)} · newest: {shortDate(preview.newest_match)}
            </p>
          )}
          {preview.count === 0 && (
            <p className="text-xs text-soc-muted mt-1">
              No {scope === 'events' ? 'events' : 'raw logs'} exist older than the selected cutoff for this project yet —
              the newest data may still be inside the window. Try a wider preset or pick an Exact time.
            </p>
          )}
        </div>
        {preview.count > 0 && <AlertTriangle size={16} className="text-amber-600 shrink-0 mt-0.5" />}
      </div>

      {rows.length > 0 && (
        <div className="border border-soc-border rounded-xl overflow-hidden">
          <div className="px-4 py-2 bg-soc-card border-b border-soc-border text-[10px] uppercase tracking-wide text-soc-muted">
            Newest {rows.length} matching row{rows.length === 1 ? '' : 's'}
          </div>
          <div className="max-h-64 overflow-y-auto bg-soc-panel">
            {rows.map((e) => (
              <div key={e.id} className="flex items-center gap-3 px-4 py-1.5 text-xs border-b border-soc-border/60 last:border-0">
                <span className="text-soc-muted-cool w-40 shrink-0 font-mono">{formatLocalTime(e.timestamp)}</span>
                <span className="w-16 shrink-0 bg-soc-panel px-1.5 py-0.5 rounded text-center">{e.source || e.hostname || 'agent'}</span>
                {e.event_type && <span className="w-14 shrink-0 text-red-600/90">{e.event_type}</span>}
                <span className="truncate text-soc-muted">
                  {e.summary || e.raw_message || e.raw_url || e.message || e.event_type}
                </span>
              </div>
            ))}
          </div>
          {preview.count > rows.length && (
            <p className="px-4 py-2 text-[10px] text-soc-muted-cool border-t border-soc-border">
              Showing the newest {rows.length} of {preview.count} — all {preview.count} will be deleted.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export function DataCleanupPage() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const pid = activeProject?.id;
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);

  const [tab, setTab] = useState('events');
  const [timeMode, setTimeMode] = useState('preset');
  const [presetDays, setPresetDays] = useState(7);
  const [exactBefore, setExactBefore] = useState(localNow());

  const [preview, setPreview] = useState(null);
  const [refreshTick, setRefreshTick] = useState(0);
  const [isPreviewing, setIsPreviewing] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [confirmText, setConfirmText] = useState('');
  const [error, setError] = useState('');
  const [lastResult, setLastResult] = useState(null);
  const [lastEsSynced, setLastEsSynced] = useState(true);
  const previewAbort = useRef(0);

  const historyQuery = useQuery({
    queryKey: ['cleanup-history', pid],
    queryFn: () => api.projects.cleanupHistory(pid),
    enabled: !!pid && tab === 'history',
  });

  const filters = useMemo(() => {
    let before;
    if (timeMode === 'exact') {
      const d = new Date(exactBefore);
      before = isNaN(d.getTime()) ? null : d.toISOString();
    } else {
      before = new Date(Date.now() - presetDays * 24 * 60 * 60 * 1000).toISOString();
    }
    return { source: 'all', before };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeMode, presetDays, exactBefore, refreshTick]);

  const filtersKey = JSON.stringify(filters);
  const previewIsCurrent = preview && preview.key === filtersKey;
  const total = preview?.count ?? 0;

  const runPreview = useCallback(async (key) => {
    const f = JSON.parse(key);
    if (!f.before) {
      setError('Pick a valid date/time first.');
      return;
    }
    const token = ++previewAbort.current;
    setError('');
    setIsPreviewing(true);
    try {
      const res = tab === 'events'
        ? await api.events.cleanupPreview(pid, f)
        : await api.agentLogs.cleanupPreview(pid, f);
      if (token !== previewAbort.current) return;
      setPreview({ ...res, key });
      setLastResult(null);
    } catch (err) {
      if (token === previewAbort.current) setError(err.message || 'Failed to run preview');
    } finally {
      if (token === previewAbort.current) setIsPreviewing(false);
    }
  }, [pid, tab]);

  // Live preview: every filter change re-runs it, and the delete button stays
  // locked until the preview for the CURRENT filter state has actually run.
  useEffect(() => {
    const id = setTimeout(() => runPreview(filtersKey), 400);
    return () => clearTimeout(id);
  }, [filtersKey, runPreview]);

  const handleDelete = async () => {
    if (!previewIsCurrent || total === 0 || confirmText !== 'DELETE') return;
    setIsDeleting(true);
    setError('');
    try {
      const f = JSON.parse(preview.key);
      const res = tab === 'events'
        ? await api.events.cleanup(pid, f, preview.count)
        : await api.agentLogs.cleanup(pid, f, preview.count);
      addToast(`Deleted ${res.deleted_count.toLocaleString()} ${tab === 'events' ? 'event' : 'raw log'}${res.deleted_count === 1 ? '' : 's'}`, 'success');
      setLastResult(res.deleted_count);
      setLastEsSynced(res.es_synced ?? true);
      setConfirmText('');
      setPreview(null);
      queryClient.invalidateQueries({ queryKey: ['events', pid] });
      queryClient.invalidateQueries({ queryKey: ['sources', pid] });
      queryClient.invalidateQueries({ queryKey: ['cleanup-history', pid] });
      runPreview(filtersKey);
    } catch (err) {
      if (err.status === 409) {
        setError(`${err.message} Re-running preview with the current data…`);
        runPreview(filtersKey);
      } else {
        setError(err.message || 'Failed to delete logs');
      }
    } finally {
      setIsDeleting(false);
    }
  };

  const switchTab = (next) => {
    setTab(next);
    setPreview(null);
    setConfirmText('');
    setError('');
    setLastResult(null);
  };

  const tabBtn = (id, label, Icon) => (
    <button
      onClick={() => switchTab(id)}
      className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
        tab === id ? 'bg-soc-accent/10 text-soc-accent border border-soc-accent/25' : 'text-soc-muted border border-transparent hover:text-soc-accent hover:bg-soc-panel'
      }`}
    >
      <Icon size={15} /> {label}
    </button>
  );

  return (
    <div>
      <PageHeader
        title="Data Cleanup"
        right={
          <Link
            to={`/live-events`}
            className="flex items-center gap-1.5 text-xs text-soc-muted hover:text-soc-accent bg-white border border-soc-border hover:bg-soc-panel px-3 py-1.5 rounded-lg transition-colors"
          >
            <ArrowLeft size={14} /> Back to Live Events
          </Link>
        }
      />

      <div className="flex items-center gap-1.5 mb-4">
        {tabBtn('events', 'Events', Database)}
        {tabBtn('agentLogs', 'Raw agent logs', ScrollText)}
        {tabBtn('history', 'Cleanup History', FileClock)}
      </div>

      {tab === 'history' ? (
        <div className="glass-card rounded-xl p-4">
          <div className="flex items-center gap-2 mb-1">
            <ShieldCheck size={16} className="text-soc-accent" />
            <h2 className="text-sm font-semibold text-soc-slate">Cleanup History</h2>
          </div>
          <p className="text-xs text-soc-muted mb-4">
            Permanent audit trail of every cleanup executed on this project. These records live in the
            <code className="mx-1 px-1 py-0.5 bg-soc-panel rounded text-[10px]">audit_log</code> collection and
            <span className="text-soc-text"> cannot be deleted or edited</span> — not even by cleanup itself.
          </p>
          {historyQuery.isLoading ? (
            <p className="py-8 text-center text-sm text-soc-muted animate-pulse">Loading history…</p>
          ) : historyQuery.isError ? (
            <p className="py-8 text-center text-sm text-red-600">Failed to load cleanup history</p>
          ) : (historyQuery.data?.cleanups || []).length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-soc-muted">
              <FileClock size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
              <p className="text-sm text-center">No cleanups have been executed on this project yet.</p>
            </div>
          ) : (
            <div className="border border-soc-border rounded-xl overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-soc-card text-soc-muted text-left">
                    <th className="px-4 py-2 font-medium">When</th>
                    <th className="px-4 py-2 font-medium">By</th>
                    <th className="px-4 py-2 font-medium">Scope</th>
                    <th className="px-4 py-2 font-medium">Source</th>
                    <th className="px-4 py-2 font-medium">Hostname</th>
                    <th className="px-4 py-2 font-medium">Cutoff (older than)</th>
                    <th className="px-4 py-2 font-medium text-right">Deleted</th>
                  </tr>
                </thead>
                <tbody>
                  {historyQuery.data.cleanups.map((c) => (
                    <tr key={c.id} className="border-t border-soc-border/60 text-soc-text">
                      <td className="px-4 py-2 font-mono whitespace-nowrap">{formatLocalDate(c.executed_at)}</td>
                      <td className="px-4 py-2">{c.username || `user #${c.user_id}`}</td>
                      <td className="px-4 py-2">
                        <span className="bg-soc-panel px-1.5 py-0.5 rounded text-[10px]">{c.scope}</span>
                      </td>
                      <td className="px-4 py-2">{c.source}</td>
                      <td className="px-4 py-2 font-mono">{c.hostname_filter || 'all'}</td>
                      <td className="px-4 py-2 font-mono whitespace-nowrap">{formatLocalDate(c.before_timestamp)}</td>
                      <td className="px-4 py-2 text-right font-semibold text-amber-600">
                        {(c.deleted_count ?? 0).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ) : (
        <>
          <div className="glass-card rounded-xl p-4 mb-4 space-y-4">
            <div>
              <label className="text-xs text-soc-muted mb-1.5 block">Delete older than</label>
                <div className="flex gap-1.5 flex-wrap">
                  <button
                    onClick={() => { setTimeMode('preset'); setPresetDays(7); }}
                    className={`px-2 py-1 rounded-lg text-[11px] border transition-colors ${
                      timeMode === 'preset' && presetDays === 7
                        ? 'bg-soc-accent border-soc-accent text-soc-on-accent'
                        : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
                    }`}
                  >
                    7 days
                  </button>
                  <button
                    onClick={() => { setTimeMode('preset'); setPresetDays(30); }}
                    className={`px-2 py-1 rounded-lg text-[11px] border transition-colors ${
                      timeMode === 'preset' && presetDays === 30
                        ? 'bg-soc-accent border-soc-accent text-soc-on-accent'
                        : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
                    }`}
                  >
                    30 days
                  </button>
                  <button
                    onClick={() => { setTimeMode('preset'); setPresetDays(90); }}
                    className={`px-2 py-1 rounded-lg text-[11px] border transition-colors ${
                      timeMode === 'preset' && presetDays === 90
                        ? 'bg-soc-accent border-soc-accent text-soc-on-accent'
                        : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
                    }`}
                  >
                    90 days
                  </button>
                  <button
                    onClick={() => setTimeMode('exact')}
                    className={`px-2 py-1 rounded-lg text-[11px] border transition-colors ${
                      timeMode === 'exact'
                        ? 'bg-soc-accent border-soc-accent text-soc-on-accent'
                        : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
                    }`}
                  >
                    Exact time…
                  </button>
                </div>
                {timeMode === 'exact' && (
                  <input
                    type="datetime-local"
                    value={exactBefore}
                    onChange={(e) => setExactBefore(e.target.value)}
                    className="mt-2 w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm text-soc-text focus:outline-none focus:border-soc-accent"
                  />
                )}
              </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setRefreshTick((t) => t + 1)}
                disabled={isPreviewing}
                className="flex items-center gap-2 text-xs bg-soc-panel hover:bg-soc-panel text-soc-text px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
              >
                {isPreviewing ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                Refresh preview
              </button>
              {!previewIsCurrent && (
                <span className="text-[11px] text-amber-600">
                  Filters changed — delete is locked until the preview above is refreshed.
                </span>
              )}
            </div>
          </div>

          <div className="glass-card rounded-xl p-4 mb-4">
            <CleanupPreviewList preview={preview} scope={tab} isPreviewing={isPreviewing} />
          </div>

          {error && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/25 rounded-xl">
              <p className="text-xs text-red-600">{error}</p>
            </div>
          )}

          {lastResult !== null && (
            <div className="mb-4 p-3 bg-green-600/10 border border-green-600/25 rounded-xl">
              <p className="text-xs text-green-700">
                Deleted {lastResult.toLocaleString()} {tab === 'events' ? 'event' : 'raw log'}{lastResult === 1 ? '' : 's'}.
                Live Events and the audit history have been refreshed.
              </p>
              {!lastEsSynced && (
                <p className="text-[11px] text-amber-600 mt-1">
                  Search index was unreachable — deleted rows may still appear in search-backed views until it recovers.
                </p>
              )}
            </div>
          )}

          <div className="glass-card rounded-xl p-4 border border-red-500/25">
            <h2 className="text-sm font-semibold text-red-600 flex items-center gap-2 mb-1">
              <Trash2 size={15} /> Danger zone
            </h2>
            <p className="text-xs text-soc-muted mb-3">
              Deleting is permanent, cannot be undone, and is recorded in the audit trail.
              Type <code className="px-1 py-0.5 bg-soc-panel rounded text-[10px]">DELETE</code> to arm the button.
            </p>
            <div className="flex flex-wrap items-center gap-3">
              <input
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                placeholder="Type DELETE"
                autoComplete="off"
                className="w-44 bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-red-500/40"
              />
              <button
                onClick={handleDelete}
                disabled={!previewIsCurrent || total === 0 || confirmText !== 'DELETE' || isDeleting}
                className="flex items-center gap-2 text-xs bg-red-500/[0.12] hover:bg-red-500/15 text-red-600 border border-red-500/25 px-4 py-2 rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                title={
                  !previewIsCurrent
                    ? 'Preview must run for the current filters first'
                    : total === 0
                      ? 'Nothing to delete'
                      : 'Type DELETE to confirm'
                }
              >
                {isDeleting ? <Loader2 size={14} className="animate-spin" /> : <Trash2 size={14} />}
                {isDeleting
                  ? 'Deleting…'
                  : `Permanently delete ${total.toLocaleString()} ${tab === 'events' ? 'event' : 'log'}${total === 1 ? '' : 's'}`}
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
