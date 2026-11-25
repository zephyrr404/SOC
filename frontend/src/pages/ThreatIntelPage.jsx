import { useState, useMemo, useEffect, useRef } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Link2, BarChart2, ShieldAlert, GitBranch, Monitor, Globe, MapPin, Radar, X, Network } from 'lucide-react';
import { forceSimulation, forceLink, forceManyBody, forceCenter, forceCollide } from 'd3-force';
import {
  ResponsiveContainer, Tooltip,
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid, Legend,
} from 'recharts';
import { api } from '../lib/api';
import { useProjectStore } from '../stores/projectStore';
import { formatLocalTime, formatLocalDate, formatRelative } from '../lib/time';
import { useToastStore } from '../stores/toastStore';
import { CreateIncidentModal } from '../components/CreateIncidentModal';
import { PageHeader } from '../components/ui/PageHeader';

const COLORS = ['#2563EB', '#4F46E5', '#0D9488', '#B45309', '#7C3AED', '#0284C7', '#DC2626', '#EA580C'];
const WINDOWS = [
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
];
const SEVERITIES = [
  { value: '', label: 'any severity' },
  { value: 'low', label: 'low+' },
  { value: 'medium', label: 'medium+' },
  { value: 'high', label: 'high+' },
  { value: 'critical', label: 'critical' },
];
const TRIAGE_STATUSES = ['new', 'acknowledged', 'investigating', 'resolved', 'false_positive'];
const GRAPH_COLORS = {
  ip: '#2563EB', host: '#4F46E5', user: '#0D9488',
  event_type: '#B45309', technique: '#DC2626', incident: '#7C3AED',
};

function flagEmoji(countryCode) {
  if (!countryCode || !/^[A-Za-z]{2}$/.test(countryCode)) return '';
  const cp = [...countryCode.toUpperCase()].map((c) => 127397 + c.charCodeAt(0));
  return String.fromCodePoint(...cp);
}

function sevPill(eventType) {
  const t = eventType || '';
  if (t === 'critical') return 'bg-red-500/[0.12] text-red-600';
  if (t === 'high') return 'bg-amber-500/15 text-amber-600';
  if (t === 'medium') return 'bg-yellow-500/15 text-yellow-600';
  if (t === 'low') return 'bg-blue-500/[0.12] text-blue-600';
  return 'bg-soc-panel text-soc-muted';
}

function statusPill(status) {
  const s = status || 'new';
  if (s === 'resolved') return 'bg-green-600/[0.12] text-green-700';
  if (s === 'false_positive') return 'bg-soc-panel text-soc-muted';
  if (s === 'investigating') return 'bg-amber-500/15 text-amber-600';
  if (s === 'acknowledged') return 'bg-blue-500/[0.12] text-blue-600';
  return 'bg-red-500/[0.12] text-red-600';
}

function sourceBadge(source) {
  const s = source || 'unknown';
  if (s === 'website') return 'badge-website';
  if (s === 'linux') return 'badge-linux';
  return 'badge-system';
}

function bucketLabel(iso, window) {
  if (!iso) return '';
  if (window === '24h') return formatLocalTime(iso);
  return formatLocalDate(iso);
}

function techniqueIdOf(technique) {
  // "T1110 - Brute Force" -> "T1110"; already-bare ids pass through.
  const t = String(technique || '');
  const m = t.match(/^(T\d+(?:\.\d+)?)/);
  return m ? m[1] : t;
}

function EnrichmentNote() {
  return (
    <div className="text-[11px] text-soc-muted bg-soc-panel/60 border border-soc-border/40 rounded-lg px-3 py-2 mt-1">
      Waiting on IP enrichment — see backend setup. These sections light up automatically once{' '}
      <code className="font-mono text-soc-accent-glow">enriched.ip</code> is populated on ingested events.
    </div>
  );
}

function TriageControls({ pid, event, onChanged }) {
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const tri = event.triage || {};
  const [status, setStatus] = useState(tri.status || 'new');
  const [severity, setSeverity] = useState(tri.severity_override || 'auto');
  useEffect(() => {
    setStatus((event.triage || {}).status || 'new');
    setSeverity((event.triage || {}).severity_override || 'auto');
  }, [event.id, event.triage]);

  const patch = useMutation({
    mutationFn: (body) => api.threatIntel.triage(pid, event.id, body),
    onSuccess: (r) => {
      queryClient.invalidateQueries({ queryKey: ['threat-matches', pid] });
      queryClient.invalidateQueries({ queryKey: ['threat-flagged', pid] });
      queryClient.invalidateQueries({ queryKey: ['threat-bucket', pid] });
      onChanged?.(r.triage);
    },
    onError: (err) => addToast(err.message, 'error'),
  });

  return (
    <span className="flex items-center gap-1.5 shrink-0">
      <span className={`text-[10px] px-1.5 py-0.5 rounded ${sevPill(severity === 'auto' ? event.severity || event.event_type : severity)}`}>
        {severity === 'auto' ? (event.severity || event.event_type) : severity}
      </span>
      <select
        value={status}
        disabled={patch.isPending}
        onChange={(e) => { setStatus(e.target.value); patch.mutate({ status: e.target.value }); }}
        className={`text-[10px] px-1.5 py-0.5 rounded border border-soc-border bg-soc-card focus:outline-none focus:border-soc-accent disabled:opacity-50 ${statusPill(status)}`}
        title="Triage status"
      >
        {TRIAGE_STATUSES.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
      </select>
      <select
        value={severity}
        disabled={patch.isPending}
        onChange={(e) => { setSeverity(e.target.value); patch.mutate({ severity: e.target.value }); }}
        className="text-[10px] px-1.5 py-0.5 rounded border border-soc-border bg-soc-card text-soc-muted focus:outline-none focus:border-soc-accent disabled:opacity-50"
        title="Severity override (auto = bucket from risk score)"
      >
        <option value="auto">auto sev</option>
        <option value="low">low</option>
        <option value="medium">medium</option>
        <option value="high">high</option>
        <option value="critical">critical</option>
      </select>
    </span>
  );
}

function MatchRow({ m, pid, onOpenIncident, feedbackPending, onFeedback }) {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const [assignee, setAssignee] = useState(m.triage?.assigned_to || '');
  const [notes, setNotes] = useState(m.triage?.analyst_notes || '');
  useEffect(() => {
    setAssignee(m.triage?.assigned_to || '');
    setNotes(m.triage?.analyst_notes || '');
  }, [m.id, m.triage]);

  const saveMeta = useMutation({
    mutationFn: (body) => api.threatIntel.triage(pid, m.id, body),
    onSuccess: () => {
      addToast('Analyst notes saved', 'success');
      queryClient.invalidateQueries({ queryKey: ['threat-matches', pid] });
    },
    onError: (err) => addToast(err.message, 'error'),
  });

  return (
    <div className="px-3 py-2 text-sm rounded-lg bg-soc-card border border-soc-border/60">
      <div className="flex items-center gap-3">
        <span className="text-xs text-soc-muted-cool w-14 shrink-0">{formatLocalTime(m.timestamp)}</span>
        <span className={`shrink-0 text-[10px] px-1.5 py-0.5 rounded ${sourceBadge(m.source)}`}>{m.source}</span>
        <span className="text-xs font-mono text-red-600 shrink-0">{m.ip || '—'}</span>
        <span className="flex-1 truncate text-soc-muted">{m.summary}</span>
        <TriageControls pid={pid} event={m} />
        <button
          onClick={() => setOpen((v) => !v)}
          className="text-xs text-soc-muted hover:text-soc-accent shrink-0 transition-colors"
          title="Analyst assignee + notes"
        >
          {open ? '▾ notes' : '▸ notes'}
        </button>
        <button
          onClick={() => onOpenIncident(m)}
          className="text-xs bg-soc-panel hover:bg-soc-card text-soc-muted hover:text-soc-accent px-2 py-1 rounded shrink-0 transition-colors"
        >
          + Incident
        </button>
        <button
          onClick={() => onFeedback(m.id)}
          disabled={feedbackPending}
          className="text-xs bg-soc-panel hover:bg-red-500/10 text-soc-muted hover:text-red-600 px-2 py-1 rounded shrink-0 transition-colors disabled:opacity-50"
          title="Suppress this indicator for this project (feed stays untouched)"
        >
          Not a threat
        </button>
      </div>
      {open && (
        <div className="flex flex-wrap items-center gap-2 mt-2 pt-2 border-t border-soc-border/40">
          <span className={`text-[10px] px-1.5 py-0.5 rounded ${m.matched?.source === 'manual' ? 'badge-manual' : 'badge-feed'}`}>
            {m.matched?.source} · {m.matched?.category}
          </span>
          <input
            value={assignee}
            onChange={(e) => setAssignee(e.target.value)}
            placeholder="assignee (e.g. admin)"
            className="text-xs bg-soc-panel border border-soc-border rounded px-2 py-1 w-40 focus:outline-none focus:border-soc-accent"
          />
          <input
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="analyst notes…"
            className="text-xs bg-soc-panel border border-soc-border rounded px-2 py-1 flex-1 min-w-[200px] focus:outline-none focus:border-soc-accent"
          />
          <button
            onClick={() => saveMeta.mutate({ assigned_to: assignee, analyst_notes: notes })}
            disabled={saveMeta.isPending}
            className="text-xs bg-soc-accent hover:bg-soc-accent-glow text-white px-2.5 py-1 rounded transition-colors disabled:opacity-50"
          >
            {saveMeta.isPending ? 'Saving…' : 'Save'}
          </button>
          {(m.triage?.assigned_to || m.triage?.analyst_notes) && (
            <span className="text-[10px] text-soc-muted">
              {m.triage?.assigned_to ? `assigned: ${m.triage.assigned_to}` : ''}
              {m.triage?.assigned_to && m.triage?.analyst_notes ? ' · ' : ''}
              {m.triage?.analyst_notes || ''}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

function CorrelationGraph({ data, loading, onSeedHost, onSeedTechnique }) {
  const navigate = useNavigate();
  const svgRef = useRef(null);
  const simRef = useRef(null);
  const [positions, setPositions] = useState({});
  const [selected, setSelected] = useState(null);
  const [search, setSearch] = useState('');
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const dragRef = useRef(null);
  const panRef = useRef(null);

  const nodes = data?.nodes ?? [];
  const edges = data?.edges ?? [];
  const nodeById = useMemo(() => Object.fromEntries(nodes.map((n) => [n.id, n])), [nodes]);
  const neighborIds = useMemo(() => {
    if (!selected) return null;
    const set = new Set([selected]);
    edges.forEach((e) => {
      if (e.source_id === selected) set.add(e.target_id);
      if (e.target_id === selected) set.add(e.source_id);
    });
    return set;
  }, [selected, edges]);

  useEffect(() => {
    setSelected(null);
    if (!nodes.length) { setPositions({}); return; }
    const W = 900, H = 420;
    const simNodes = nodes.map((n) => ({ id: n.id, x: W / 2 + (Math.random() - 0.5) * 200, y: H / 2 + (Math.random() - 0.5) * 160 }));
    const sim = forceSimulation(simNodes)
      .force('link', forceLink(edges.map((e) => ({ ...e, source: e.source_id, target: e.target_id }))).id((d) => d.id).distance(90).strength(0.6))
      .force('charge', forceManyBody().strength(-220))
      .force('center', forceCenter(W / 2, H / 2))
      .force('collide', forceCollide().radius((d) => 14 + Math.sqrt((nodeById[d.id]?.degree || 0)) * 4));
    simRef.current = sim;
    let alive = true;
    sim.on('tick', () => {
      if (!alive) return;
      const pos = {};
      simNodes.forEach((n) => { pos[n.id] = { x: n.x, y: n.y }; });
      setPositions(pos);
    });
    return () => { alive = false; sim.on('tick', null); sim.stop(); simRef.current = null; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  const radius = (n) => 6 + Math.min(14, Math.sqrt(n.degree || 0) * 3.5);
  const edgeWidth = (e) => 0.8 + Math.min(4, Math.sqrt(e.weight || 1));

  const onNodeDown = (e, n) => {
    e.stopPropagation();
    const sim = simRef.current;
    if (!sim) return;
    const sn = sim.nodes().find((d) => d.id === n.id);
    if (sn) { sn.fx = sn.x; sn.fy = sn.y; }
    dragRef.current = n.id;
    sim.alphaTarget(0.3).restart();
  };
  const onSvgMove = (e) => {
    const svg = svgRef.current;
    if (!svg) return;
    const pt = svg.createSVGPoint();
    pt.x = e.clientX; pt.y = e.clientY;
    const loc = pt.matrixTransform(svg.getScreenCTM().inverse());
    const gx = (loc.x - view.x) / view.k, gy = (loc.y - view.y) / view.k;
    if (dragRef.current && simRef.current) {
      const sn = simRef.current.nodes().find((d) => d.id === dragRef.current);
      if (sn) { sn.fx = gx; sn.fy = gy; }
    } else if (panRef.current) {
      setView((v) => ({ ...v, x: v.x + e.movementX, y: v.y + e.movementY }));
    }
  };
  const endDrag = () => {
    if (dragRef.current && simRef.current) {
      const sn = simRef.current.nodes().find((d) => d.id === dragRef.current);
      if (sn) { sn.fx = null; sn.fy = null; }
      simRef.current.alphaTarget(0);
      dragRef.current = null;
    }
    panRef.current = null;
  };
  const onWheel = (e) => {
    setView((v) => ({ ...v, k: Math.min(3, Math.max(0.4, v.k * (e.deltaY > 0 ? 0.9 : 1.1))) }));
  };

  const searched = search.trim().toLowerCase();
  const matchIds = searched ? nodes.filter((n) => n.label.toLowerCase().includes(searched)).map((n) => n.id) : [];
  const sel = selected ? nodeById[selected] : null;
  const selEdges = selected ? edges.filter((e) => e.source_id === selected || e.target_id === selected) : [];
  const selEventIds = [...new Set(selEdges.flatMap((e) => e.event_ids || []))].slice(0, 10);

  const seedFromNode = (n) => {
    if (n.type === 'host') onSeedHost(n.label);
    else if (n.type === 'technique') onSeedTechnique(techniqueIdOf(n.label));
  };

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && matchIds.length) setSelected(matchIds[0]); }}
          placeholder="search node… (Enter jumps)"
          className="text-xs bg-soc-card border border-soc-border rounded-lg px-2.5 py-1.5 w-52 focus:outline-none focus:border-soc-accent"
        />
        {searched && <span className="text-[10px] text-soc-muted">{matchIds.length} match{matchIds.length === 1 ? '' : 'es'}</span>}
        <div className="flex items-center gap-1 ml-auto">
          <button onClick={() => setView((v) => ({ ...v, k: Math.min(3, v.k * 1.2) }))} className="text-xs px-2 py-1 rounded border border-soc-border text-soc-muted hover:text-soc-accent">+</button>
          <button onClick={() => setView((v) => ({ ...v, k: Math.max(0.4, v.k * 0.85) }))} className="text-xs px-2 py-1 rounded border border-soc-border text-soc-muted hover:text-soc-accent">−</button>
          <button onClick={() => { setView({ x: 0, y: 0, k: 1 }); setSelected(null); }} className="text-xs px-2 py-1 rounded border border-soc-border text-soc-muted hover:text-soc-accent">reset</button>
        </div>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 mb-2">
        {Object.entries(GRAPH_COLORS).map(([t, c]) => (
          <span key={t} className="flex items-center gap-1.5 text-[10px] text-soc-muted">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: c }} />{t}
          </span>
        ))}
        <span className="ml-auto text-[10px] text-soc-muted">node size = degree · edge width = weight · drag to rearrange · scroll to zoom</span>
      </div>
      <div className="flex gap-3 flex-col lg:flex-row">
        <div className="flex-1 min-w-0 border border-soc-border/50 rounded-xl bg-soc-panel/30 overflow-hidden">
          {loading ? (
            <div className="h-[420px] animate-pulse bg-soc-card/60" />
          ) : !nodes.length ? (
            <div className="flex flex-col items-center justify-center h-[240px] text-soc-muted">
              <Network size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
              <p className="text-xs text-center">No graph nodes in this window — widen the window or clear filters</p>
            </div>
          ) : (
            <svg
              ref={svgRef}
              viewBox="0 0 900 420"
              className="w-full h-[420px] select-none cursor-grab"
              onMouseMove={onSvgMove}
              onMouseUp={endDrag}
              onMouseLeave={endDrag}
              onMouseDown={(e) => { if (e.target.tagName === 'svg' || e.target.tagName === 'rect') { panRef.current = true; setSelected(null); } }}
              onWheel={onWheel}
            >
              <rect x={-2000} y={-2000} width={5000} height={5000} fill="transparent" />
              <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
                {edges.map((e, i) => {
                  const a = positions[e.source_id], b = positions[e.target_id];
                  if (!a || !b) return null;
                  const dim = neighborIds && !(neighborIds.has(e.source_id) && neighborIds.has(e.target_id));
                  return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#94A3B8" strokeWidth={edgeWidth(e)} opacity={dim ? 0.15 : 0.55} />;
                })}
                {nodes.map((n) => {
                  const p = positions[n.id];
                  if (!p) return null;
                  const dim = neighborIds && !neighborIds.has(n.id);
                  const hl = searched && n.label.toLowerCase().includes(searched);
                  return (
                    <g key={n.id} transform={`translate(${p.x},${p.y})`} opacity={dim ? 0.15 : 1}
                       onMouseDown={(ev) => onNodeDown(ev, n)}
                       onClick={(ev) => { ev.stopPropagation(); setSelected(n.id); }}
                       className="cursor-pointer">
                      <circle r={radius(n)} fill={GRAPH_COLORS[n.type] || '#64748B'}
                              stroke={selected === n.id ? '#0F172A' : hl ? '#0F172A' : 'white'}
                              strokeWidth={selected === n.id || hl ? 2.5 : 1.5} />
                      <text y={radius(n) + 11} textAnchor="middle" fontSize={9.5} fill="#475569">
                        {n.label.length > 22 ? `${n.label.slice(0, 21)}…` : n.label}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          )}
        </div>
        <div className="lg:w-64 shrink-0 border border-soc-border/50 rounded-xl p-3 bg-soc-card/40 text-xs">
          {!sel ? (
            <p className="text-soc-muted">Click a node to inspect it — neighbors highlight, everything else fades. Host and technique nodes can seed the page filters.</p>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full shrink-0" style={{ background: GRAPH_COLORS[sel.type] }} />
                <span className="font-semibold text-soc-text break-all">{sel.label}</span>
              </div>
              <p className="text-soc-muted">type: {sel.type} · degree: {sel.degree} · avg risk: {sel.risk_contribution}</p>
              {Object.entries(sel.meta || {}).filter(([, v]) => v !== '' && v !== null && v !== undefined).map(([k, v]) => (
                <p key={k} className="text-soc-muted">{k}: <span className="text-soc-text">{String(v)}</span></p>
              ))}
              {(sel.type === 'host' || sel.type === 'technique') && (
                <button onClick={() => seedFromNode(sel)} className="w-full text-xs bg-soc-accent hover:bg-soc-accent-glow text-white px-2 py-1.5 rounded-lg transition-colors">
                  Filter page to this {sel.type}
                </button>
              )}
              {selEventIds.length > 0 && (
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-soc-muted mb-1">raw events ({selEventIds.length})</p>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {selEventIds.map((id) => (
                      <Link key={id} to={`/live-events?query=${encodeURIComponent(id)}`} className="block font-mono text-[10px] text-soc-accent hover:underline truncate" title={id}>
                        {id}
                      </Link>
                    ))}
                  </div>
                </div>
              )}
              <button onClick={() => navigate('/incidents')} className="w-full text-xs border border-soc-border hover:border-soc-accent/50 text-soc-muted hover:text-soc-accent px-2 py-1.5 rounded-lg transition-colors">
                Pivot to Incidents
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function ThreatIntelPage() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const pid = activeProject?.id;
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);

  const [window, setWindow] = useState('24h');
  const [narrativeHours, setNarrativeHours] = useState(24);
  const [createIncidentModal, setCreateIncidentModal] = useState({ open: false, initialTitle: '', initialDescription: '', initialSeverity: null });
  const [indicatorPage, setIndicatorPage] = useState(1);
  const [indicatorFeed, setIndicatorFeed] = useState('');
  const [attachChain, setAttachChain] = useState(null);
  // Shared cross-panel filter state (deep-linkable: ?host=&technique=).
  // Synced both ways: landing links seed the filters, and in-page changes
  // rewrite the URL so links always reflect what you see.
  const [searchParams, setSearchParams] = useSearchParams();
  const [hostFilter, setHostFilterState] = useState(() => searchParams.get('host') || '');
  const [techniqueFilter, setTechniqueFilterState] = useState(() => searchParams.get('technique') || '');
  const setHostFilter = (v) => {
    setHostFilterState(v);
    const next = new URLSearchParams(searchParams);
    if (v) next.set('host', v); else next.delete('host');
    setSearchParams(next, { replace: true });
  };
  const setTechniqueFilter = (v) => {
    setTechniqueFilterState(v);
    const next = new URLSearchParams(searchParams);
    if (v) next.set('technique', v); else next.delete('technique');
    setSearchParams(next, { replace: true });
  };
  // Honor deep-links that arrive while the page is already mounted
  // (e.g. host chips on Incident Detail).
  useEffect(() => {
    const h = searchParams.get('host') || '';
    const t = searchParams.get('technique') || '';
    setHostFilterState((cur) => (cur === h ? cur : h));
    setTechniqueFilterState((cur) => (cur === t ? cur : t));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);
  const [feedFilter, setFeedFilter] = useState('');
  const [minSeverity, setMinSeverity] = useState('');
  const [hostSort, setHostSort] = useState({ key: 'risk', dir: -1 });
  const [drawerBucket, setDrawerBucket] = useState(null);
  const [graphWeight, setGraphWeight] = useState(1);
  const [expandedIp, setExpandedIp] = useState(null);
  const [allowForm, setAllowForm] = useState({ indicator: '', type: 'ip', reason: '' });
  const prevFeedCount = useRef(null);

  const filters = useMemo(() => ({
    ...(hostFilter ? { host: hostFilter } : {}),
    ...(techniqueFilter ? { techniqueId: techniqueFilter } : {}),
    ...(minSeverity ? { minSeverity } : {}),
  }), [hostFilter, techniqueFilter, minSeverity]);
  const filtersKey = JSON.stringify(filters);

  const clearFilters = () => {
    setHostFilter(''); setTechniqueFilter(''); setFeedFilter(''); setMinSeverity(''); setIndicatorFeed(''); setDrawerBucket(null);
  };

  // Escape closes the bucket drawer.
  useEffect(() => {
    if (!drawerBucket) return;
    const onKey = (e) => { if (e.key === 'Escape') setDrawerBucket(null); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [drawerBucket]);
  const hasFilters = hostFilter || techniqueFilter || feedFilter || minSeverity;

  const { data: tacticsData } = useQuery({
    queryKey: ['threat-tactics', pid, window, filtersKey],
    queryFn: () => api.threatIntel.tactics(pid, window, filters),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: timelineData } = useQuery({
    queryKey: ['threat-timeline', pid, window, filtersKey],
    queryFn: () => api.threatIntel.timeline(pid, window, filters),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: narrativesData } = useQuery({
    queryKey: ['threat-narratives', pid, narrativeHours, filtersKey],
    queryFn: () => api.threatIntel.narratives(pid, narrativeHours, filters),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: topHostsData } = useQuery({
    queryKey: ['threat-top-hosts', pid, window, filtersKey],
    queryFn: () => api.threatIntel.topHosts(pid, window, filters),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: knownIpsData, isLoading: knownIpsLoading } = useQuery({
    queryKey: ['threat-known-ips', pid, window, filtersKey],
    queryFn: () => api.threatIntel.knownIps(pid, window, filters),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: geoData } = useQuery({
    queryKey: ['threat-geo', pid, window, filtersKey],
    queryFn: () => api.threatIntel.geo(pid, window, filters),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: graphData, isLoading: graphLoading } = useQuery({
    queryKey: ['threat-graph', pid, window, filtersKey, graphWeight],
    queryFn: () => api.threatIntel.graph(pid, window, filters, graphWeight),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: bucketData, isLoading: bucketLoading } = useQuery({
    queryKey: ['threat-bucket', pid, window, drawerBucket, filtersKey],
    queryFn: () => api.threatIntel.bucket(pid, window, drawerBucket, filters),
    enabled: !!pid && !!drawerBucket,
  });

  const { data: indData, isLoading: indLoading } = useQuery({
    queryKey: ['threat-indicators', pid],
    queryFn: () => api.threatIntel.indicators(pid),
    enabled: !!pid,
    refetchInterval: 30000,
  });

  const { data: matchData, isLoading: matchLoading } = useQuery({
    queryKey: ['threat-matches', pid],
    queryFn: () => api.threatIntel.matches(pid),
    enabled: !!pid,
    refetchInterval: 30000,
  });

  const { data: allIndData } = useQuery({
    queryKey: ['threat-all-indicators', pid, indicatorPage, indicatorFeed],
    queryFn: () => api.threatIntel.allIndicators(pid, { page: indicatorPage, pageSize: 50, sourceFeed: indicatorFeed }),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: allowData } = useQuery({
    queryKey: ['threat-allowlist', pid],
    queryFn: () => api.threatIntel.allowlist(pid),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: openIncidents } = useQuery({
    queryKey: ['incidents', pid],
    queryFn: () => api.incidents.list(pid),
    enabled: !!pid && !!attachChain,
  });

  const attachChainMutation = useMutation({
    mutationFn: ({ incidentId }) =>
      api.incidents.attachChain(incidentId, {
        hostname: attachChain.hostname,
        start_time: attachChain.start_time,
        end_time: attachChain.end_time,
      }),
    onSuccess: (r, vars) => {
      addToast(`Attached ${r.attached} events from chain to incident #${vars.incidentId}`, 'success');
      setAttachChain(null);
    },
    onError: (err) => addToast(err.message, 'error'),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['threat-indicators', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-matches', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-all-indicators', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-tactics', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-timeline', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-narratives', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-top-hosts', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-known-ips', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-geo', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-graph', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-allowlist', pid] });
  };

  const refreshMutation = useMutation({
    mutationFn: () => api.threatIntel.refresh(pid),
    onSuccess: (r) => {
      const prev = prevFeedCount.current;
      const delta = prev === null ? null : r.count - prev;
      prevFeedCount.current = r.count;
      addToast(
        r.error ? `Feed refresh failed: ${r.error}`
          : `Feeds refreshed — ${r.count} indicators${delta === null ? '' : ` (${delta >= 0 ? '+' : ''}${delta} since last refresh)`}`,
        r.error ? 'error' : 'success'
      );
      invalidate();
    },
    onError: (err) => addToast(err.message, 'error'),
  });

  const feedbackMutation = useMutation({
    mutationFn: ({ matchId }) => api.threatIntel.feedback(pid, matchId, true),
    onSuccess: (r) => {
      addToast(`Suppressed ${r.value} for this project`, 'success');
      invalidate();
    },
    onError: (err) => addToast(err.message, 'error'),
  });

  const allowAddMutation = useMutation({
    mutationFn: () => api.threatIntel.allowlistAdd(pid, allowForm),
    onSuccess: (r) => {
      addToast(`Allowlisted ${r.indicator} — it will no longer flag as a threat`, 'success');
      setAllowForm({ indicator: '', type: 'ip', reason: '' });
      invalidate();
    },
    onError: (err) => addToast(err.message, 'error'),
  });

  const allowRemoveMutation = useMutation({
    mutationFn: (indicator) => api.threatIntel.allowlistRemove(pid, indicator),
    onSuccess: (r) => {
      addToast(`Removed ${r.indicator} from allowlist`, 'success');
      invalidate();
    },
    onError: (err) => addToast(err.message, 'error'),
  });

  const indicators = indData?.indicators ?? [];
  const allMatches = matchData?.events ?? [];
  const matches = feedFilter ? allMatches.filter((m) => (m.matched?.source || '') === feedFilter) : allMatches;
  const tactics = tacticsData?.tactics ?? [];
  const buckets = timelineData?.buckets ?? [];
  const narratives = narrativesData?.narratives ?? [];
  const hosts = topHostsData?.hosts ?? [];
  const knownIps = knownIpsData?.ips ?? [];
  const countries = geoData?.countries ?? [];
  const allowlist = allowData?.allowlist ?? [];
  const feeds = allIndData?.feeds ?? [];
  const loadedFeedCount = feeds.filter((f) => f.last_sync).length;
  const totalIndicators = allIndData?.total ?? 0;
  const lastSync = allIndData?.last_sync;
  const feedError = allIndData?.error;
  useEffect(() => {
    if (prevFeedCount.current === null && totalIndicators > 0) prevFeedCount.current = totalIndicators;
  }, [totalIndicators]);

  const toEvent = (m) => ({
    id: m.id,
    summary: m.summary,
    raw: {},
    event_type: m.event_type,
  });

  const openIncident = (m) => {
    const sev = m.event_type === 'critical' || m.event_type === 'high' ? m.event_type : null;
    setCreateIncidentModal({ open: true, initialTitle: '', initialDescription: '', initialSeverity: sev, event: toEvent(m) });
  };

  const openChainIncident = (n) => {
    const steps = n.chain.map((s) => `- [${formatLocalTime(s.time)}] ${s.tactic || '—'}${s.technique ? ` (${s.technique})` : ''}: ${s.summary}`).join('\n');
    const sev = n.chain.some((s) => s.event_type === 'critical' || s.event_type === 'high') ? 'high' : 'medium';
    setCreateIncidentModal({
      open: true,
      initialTitle: `Attack chain on ${n.hostname} (${n.event_count} events, ${formatLocalDate(n.start_time)} ${formatLocalTime(n.start_time)})`,
      initialDescription: `Correlated attack narrative for host ${n.hostname}:\n${steps}`,
      initialSeverity: sev,
      event: null,
    });
  };

  const timelineChart = useMemo(() => {
    return buckets.map((b) => ({
      label: bucketLabel(b.bucket_start, window),
      bucket_start: b.bucket_start,
      count: b.event_count,
      avg: b.avg_risk_score ?? 0,
    }));
  }, [buckets, window]);

  const onChartClick = (state) => {
    // Index first (display labels can collide, e.g. two buckets rendering
    // the same time in 24h mode); label match is the fallback.
    const idx = state?.activeTooltipIndex;
    if (Number.isInteger(idx) && timelineChart[idx]) {
      setDrawerBucket(timelineChart[idx].bucket_start);
      return;
    }
    const label = state?.activeLabel;
    if (!label) return;
    const hit = timelineChart.find((b) => b.label === label);
    if (hit) setDrawerBucket(hit.bucket_start);
  };

  const tacticsTotal = tactics.reduce((a, t) => a + t.count, 0);
  const tacticMax = Math.max(1, ...tactics.flatMap((t) => t.techniques.map((x) => x.count)));

  const sortedHosts = useMemo(() => {
    const arr = [...hosts];
    const { key, dir } = hostSort;
    arr.sort((a, b) => {
      const av = key === 'risk' ? a.risk_total : key === 'events' ? a.event_count : new Date(a.last_seen || 0).getTime();
      const bv = key === 'risk' ? b.risk_total : key === 'events' ? b.event_count : new Date(b.last_seen || 0).getTime();
      return (av - bv) * dir;
    });
    return arr;
  }, [hosts, hostSort]);
  const sortBy = (key) => setHostSort((s) => (s.key === key ? { key, dir: -s.dir } : { key, dir: -1 }));

  const geoMax = Math.max(1, ...countries.map((c) => c.event_count));

  const pageCount = Math.max(1, Math.ceil(totalIndicators / 50));
  const feedOptions = useMemo(() => {
    const names = new Set(feeds.map((f) => f.name));
    if (totalIndicators > 0) names.add('manual');
    return ['', ...Array.from(names)];
  }, [feeds, totalIndicators]);

  const clickFeedPill = (name) => {
    // Click-to-filter: the browsable list narrows to this feed; matched
    // events narrow to its source class (manual vs feed).
    setIndicatorFeed(name);
    setIndicatorPage(1);
    setFeedFilter(name === 'manual' ? 'manual' : 'feed');
  };

  const narrativeSummary = (n) => {
    const tactics = [...new Set(n.chain.map((s) => s.tactic).filter(Boolean))];
    return `${n.hostname}: ${tactics.length ? tactics.join(' → ') : 'activity'} across ${n.event_count} events`;
  };

  return (
    <div>
      <PageHeader title="Threat Intelligence" />

      {/* 1. Feed status bar */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-soc-text">Threat Feed</h2>
              <span className="badge-feed text-[10px] px-1.5 py-0.5 rounded">feed</span>
            </div>
            <p className="text-xs text-soc-muted mt-0.5">
              {feeds.length ? `${feeds.length} feeds, last updated ${lastSync ? formatRelative(lastSync) : 'never'}` : 'loading…'}
            </p>
          </div>
          <div className="text-xs text-soc-muted-cool">
            <span className="font-medium">{totalIndicators}</span> indicators loaded
          </div>
          {feedError && (
            <div className="text-xs text-red-600" title={feedError}>
              ⚠ Last refresh failed
            </div>
          )}
          <button
            onClick={() => refreshMutation.mutate()}
            disabled={refreshMutation.isPending}
            className="ml-auto text-xs bg-white border border-soc-border hover:bg-soc-panel text-soc-muted hover:text-soc-accent px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
          >
            {refreshMutation.isPending ? 'Refreshing…' : 'Refresh Feed'}
          </button>
        </div>
        <div className="flex flex-wrap gap-2 mt-3">
          {feeds.map((f) => {
            const active = indicatorFeed === f.name;
            return (
              <button
                key={f.name}
                onClick={() => (active ? (setIndicatorFeed(''), setFeedFilter('')) : clickFeedPill(f.name))}
                className={`flex items-center gap-1.5 text-[10px] px-2 py-1 rounded-lg border transition-colors ${
                  active ? 'border-soc-accent/60 bg-soc-accent/10' : 'border-soc-border/50 bg-soc-panel/50 hover:border-soc-accent/40'
                }`}
                title={f.error || `Last sync ${f.last_sync ? formatRelative(f.last_sync) : 'never'} — click to filter the page to this feed`}
              >
                <span className="font-medium text-soc-text">{f.name}</span>
                <span className="text-soc-muted">{f.count}</span>
                {f.error ? (
                  <span className="text-red-600" title={f.error}>⚠ failed</span>
                ) : (
                  <span className="w-1.5 h-1.5 rounded-full bg-soc-sage" />
                )}
              </button>
            );
          })}
          {totalIndicators > 0 && (
            <button
              onClick={() => (indicatorFeed === 'manual' ? (setIndicatorFeed(''), setFeedFilter('')) : clickFeedPill('manual'))}
              className={`flex items-center gap-1.5 text-[10px] px-2 py-1 rounded-lg border transition-colors ${
                indicatorFeed === 'manual' ? 'border-soc-accent/60 bg-soc-accent/10' : 'border-soc-border/50 bg-soc-panel/50 hover:border-soc-accent/40'
              }`}
              title="Click to filter the page to manually added indicators"
            >
              <span className="font-medium text-soc-text">manual</span>
            </button>
          )}
        </div>
      </div>

      {/* Window + severity selectors */}
      <div className="flex flex-wrap items-center gap-1.5 mb-3">
        {WINDOWS.map((w) => (
          <button
            key={w.value}
            onClick={() => setWindow(w.value)}
            className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${
              window === w.value
                ? 'bg-soc-accent border-soc-accent text-white'
                : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
            }`}
          >
            {w.label}
          </button>
        ))}
        <select
          value={minSeverity}
          onChange={(e) => setMinSeverity(e.target.value)}
          className="ml-2 text-xs bg-soc-card border border-soc-border rounded-full px-2.5 py-1 text-soc-muted focus:outline-none focus:border-soc-accent"
          title="Minimum severity — filters every panel below"
        >
          {SEVERITIES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
        <span className="ml-auto text-[10px] font-medium text-green-700">
          {loadedFeedCount}/{feeds.length || '—'} feeds synced
        </span>
      </div>

      {/* Active cross-filters */}
      {hasFilters && (
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <span className="text-[10px] uppercase tracking-wide text-soc-muted">filters:</span>
          {hostFilter && (
            <button onClick={() => setHostFilter('')} className="flex items-center gap-1 text-[11px] bg-soc-accent/10 border border-soc-accent/30 text-soc-accent px-2 py-0.5 rounded-full hover:bg-soc-accent/20" title="Clear host filter">
              host: {hostFilter} <X size={12} />
            </button>
          )}
          {techniqueFilter && (
            <button onClick={() => setTechniqueFilter('')} className="flex items-center gap-1 text-[11px] bg-soc-accent/10 border border-soc-accent/30 text-soc-accent px-2 py-0.5 rounded-full hover:bg-soc-accent/20" title="Clear technique filter">
              technique: {techniqueFilter} <X size={12} />
            </button>
          )}
          {feedFilter && (
            <button onClick={() => { setFeedFilter(''); setIndicatorFeed(''); }} className="flex items-center gap-1 text-[11px] bg-soc-accent/10 border border-soc-accent/30 text-soc-accent px-2 py-0.5 rounded-full hover:bg-soc-accent/20" title="Clear feed filter">
              feed: {feedFilter} <X size={12} />
            </button>
          )}
          {minSeverity && (
            <button onClick={() => setMinSeverity('')} className="flex items-center gap-1 text-[11px] bg-soc-accent/10 border border-soc-accent/30 text-soc-accent px-2 py-0.5 rounded-full hover:bg-soc-accent/20" title="Clear severity filter">
              severity: {minSeverity}+ <X size={12} />
            </button>
          )}
          <button onClick={clearFilters} className="text-[11px] text-soc-muted hover:text-red-600 hover:underline">clear all</button>
        </div>
      )}

      {/* 2. Attack Timeline */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">Attack Timeline</h2>
          <span className="text-[10px] text-soc-muted">volume + avg risk · {timelineData?.source === 'elasticsearch' ? 'Elasticsearch' : 'Mongo fallback'} · click a bar to drill down</span>
        </div>
        {timelineChart.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-4 text-soc-muted">
            <BarChart2 size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
            <p className="text-xs text-center">No events in this window</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <ComposedChart data={timelineChart} margin={{ top: 4, right: 8, left: -16, bottom: 0 }} onClick={onChartClick} style={{ cursor: 'pointer' }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.12)" />
              <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#94A3B8' }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
              <YAxis yAxisId="count" tick={{ fontSize: 10, fill: '#94A3B8' }} tickLine={false} axisLine={false} />
              <YAxis yAxisId="risk" orientation="right" tick={{ fontSize: 10, fill: '#94A3B8' }} tickLine={false} axisLine={false} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: '#FFFFFF', border: '1px solid #E4E7EB', borderRadius: 10, color: '#0F172A', fontSize: 11, boxShadow: '0 8px 24px -8px rgba(15,23,42,0.18)' }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Bar yAxisId="count" dataKey="count" name="events" fill="#2563EB" radius={[3, 3, 0, 0]} maxBarSize={28} />
              <Line yAxisId="risk" type="monotone" dataKey="avg" name="avg risk" stroke="#DC2626" strokeWidth={1.8} dot={false} />
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* 3. Tactics Observed — ATT&CK matrix */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">Tactics Observed (MITRE ATT&CK)</h2>
          <span className="text-[10px] text-soc-muted">{tacticsTotal} mapped events in window · click a cell to filter</span>
        </div>
        {tactics.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-4 text-soc-muted">
            <ShieldAlert size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
            <p className="text-xs text-center">
              No ATT&CK-mapped activity yet — failed logons (T1110), service installs (T1543.003) and log clears (T1070.001) will appear here.
            </p>
          </div>
        ) : (
          <div className="flex gap-3 overflow-x-auto pb-1">
            {tactics.map((t, i) => (
              <div key={t.tactic} className="min-w-[190px] flex-1 rounded-xl border border-soc-border/40 bg-soc-panel/30 overflow-hidden">
                <div className="flex items-center gap-2 px-3 py-2 border-b border-soc-border/30">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ background: COLORS[i % COLORS.length] }} />
                  <span className="text-xs font-semibold text-soc-text truncate">{t.tactic}</span>
                  <span className="ml-auto text-[10px] text-soc-muted shrink-0">{t.count}</span>
                </div>
                <div className="p-1.5 space-y-1">
                  {t.techniques.map((tech) => {
                    const tid = techniqueIdOf(tech.technique);
                    const active = techniqueFilter === tid;
                    const intensity = Math.max(0.12, tech.count / tacticMax);
                    return (
                      <button
                        key={tech.technique}
                        onClick={() => setTechniqueFilter(active ? '' : tid)}
                        className={`w-full text-left px-2 py-1.5 rounded-lg border text-[11px] transition-colors ${
                          active ? 'border-soc-accent bg-soc-accent/15 text-soc-accent' : 'border-transparent hover:border-soc-accent/40 text-soc-text'
                        }`}
                        style={active ? undefined : { background: `rgba(37,99,235,${(intensity * 0.35).toFixed(2)})` }}
                        title={`${tech.technique} — ${tech.count} events. Click to filter the page.`}
                      >
                        <span className="block font-mono truncate">{tech.technique}</span>
                        <span className="block text-[10px] text-soc-muted">{tech.count} events</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
        {tactics.length > 0 && (
          <p className="text-[10px] text-soc-muted mt-2">Cell shade = frequency. Hover any cell for the full technique name.</p>
        )}
      </div>

      {/* 4. Attack Narratives */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3 gap-3">
          <h2 className="text-sm font-semibold text-soc-text">Attack Narratives</h2>
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-soc-muted">lookback</span>
            {[6, 24, 72].map((h) => (
              <button
                key={h}
                onClick={() => setNarrativeHours(h)}
                className={`px-2 py-0.5 rounded-full text-[10px] border transition-colors ${
                  narrativeHours === h
                    ? 'bg-soc-accent border-soc-accent text-white'
                    : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
                }`}
              >
                {h}h
              </button>
            ))}
          </div>
        </div>
        {narratives.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-4 text-soc-muted">
            <GitBranch size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
            <p className="text-xs text-center">
              No correlated chains yet — 3+ events from one host within 2h (escalating tactics or high risk) become a narrative here.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {narratives.map((n) => (
              <div key={`${n.hostname}-${n.start_time}`} className="border border-soc-border/40 rounded-xl bg-soc-panel/40 overflow-hidden">
                <div className="flex items-center gap-3 px-4 py-2.5 bg-soc-panel/60 border-b border-soc-border/30 flex-wrap">
                  <button onClick={() => setHostFilter(n.hostname)} className="text-xs font-semibold font-mono text-soc-text hover:text-soc-accent" title="Filter page to this host">
                    {n.hostname}
                  </button>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded ${sevPill(n.severity)}`}>{n.severity}</span>
                  <span className="text-[10px] text-soc-muted">
                    {formatLocalDate(n.start_time)} {formatLocalTime(n.start_time)} → {formatLocalTime(n.end_time)} · {n.event_count} events
                  </span>
                  <div className="flex items-center gap-2 ml-auto">
                    <button
                      onClick={() => setAttachChain(n)}
                      className="text-xs bg-soc-card border border-soc-border/70 hover:border-soc-accent/50 text-soc-text px-2.5 py-1 rounded transition-colors"
                    >
                      Attach to Incident
                    </button>
                    <button
                      onClick={() => openChainIncident(n)}
                      className="text-xs bg-soc-accent hover:bg-soc-accent-glow text-white px-2.5 py-1 rounded transition-colors"
                    >
                      Create Incident from chain
                    </button>
                  </div>
                </div>
                <p className="px-4 pt-2 text-xs text-soc-muted italic">{narrativeSummary(n)}</p>
                <div className="px-4 py-3">
                  {n.chain.map((s, i) => (
                    <div key={i} className="flex gap-3">
                      <div className="flex flex-col items-center">
                        <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${s.event_type === 'critical' || s.event_type === 'high' ? 'bg-red-500' : 'bg-soc-accent'}`} />
                        {i < n.chain.length - 1 && <div className="w-px flex-1 bg-soc-border/50" />}
                      </div>
                      <div className="pb-3 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-[10px] text-soc-muted-cool font-mono">{formatLocalTime(s.time)}</span>
                          {s.tactic && (
                            <span className={`text-[10px] px-1.5 py-0.5 rounded ${sevPill(s.event_type)}`}>{s.tactic}</span>
                          )}
                          {s.technique ? (
                            <button
                              onClick={() => setTechniqueFilter(techniqueIdOf(s.technique))}
                              className="text-[10px] px-1.5 py-0.5 rounded bg-soc-card text-soc-accent-glow font-mono hover:border hover:border-soc-accent/50"
                              title="Filter page to this technique"
                            >
                              {s.technique}
                            </button>
                          ) : null}
                          <Link
                            to={`/live-events?query=${encodeURIComponent(s.summary.slice(0, 40))}`}
                            className="text-[10px] text-soc-muted hover:text-soc-accent"
                          >
                            open in events
                          </Link>
                        </div>
                        <p className="text-xs text-soc-muted mt-1 break-words">{s.summary}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 4b. Correlation Graph */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
          <h2 className="text-sm font-semibold text-soc-text">Correlation Graph</h2>
          <div className="flex items-center gap-2">
            <label className="text-[10px] text-soc-muted" title="Hide weak links to declutter dense graphs">
              min weight {graphWeight}
            </label>
            <input
              type="range" min={1} max={10} value={graphWeight}
              onChange={(e) => setGraphWeight(Number(e.target.value))}
              className="w-28 accent-soc-accent"
            />
            {hostFilter && <span className="text-[10px] text-soc-muted">seeded on host {hostFilter}</span>}
          </div>
        </div>
        <CorrelationGraph
          data={graphData}
          loading={graphLoading}
          onSeedHost={(h) => { setHostFilter(h); addToast(`Graph seeded — page filtered to host ${h}`, 'success'); }}
          onSeedTechnique={(t) => { setTechniqueFilter(t); addToast(`Graph seeded — page filtered to ${t}`, 'success'); }}
        />
        {graphData?.truncated && (
          <p className="text-[10px] text-amber-600 mt-2">
            Showing top {graphData.showing.nodes} of {graphData.totals.nodes} nodes — narrow the window, raise min weight, or filter to a host.
          </p>
        )}
      </div>

      {/* 5. Top Risk Hosts */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">Top Risk Hosts</h2>
          <span className="text-[10px] text-soc-muted">accumulated risk · {window} window · click a host to filter + seed the graph</span>
        </div>
        {hosts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-4 text-soc-muted">
            <Monitor size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
            <p className="text-xs text-center">No agent events in this window</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <div className="min-w-[620px]">
              <div className="grid grid-cols-[2rem_1.4fr_1fr_0.7fr_1fr_0.7fr] gap-3 px-3 py-2 text-[10px] uppercase tracking-wide text-soc-muted border-b border-soc-border/60">
                <span>#</span>
                <button onClick={() => sortBy('risk')} className="text-left hover:text-soc-accent">host / risk {hostSort.key === 'risk' ? (hostSort.dir === -1 ? '↓' : '↑') : ''}</button>
                <span>risk share</span>
                <button onClick={() => sortBy('events')} className="text-left hover:text-soc-accent">events {hostSort.key === 'events' ? (hostSort.dir === -1 ? '↓' : '↑') : ''}</button>
                <button onClick={() => sortBy('seen')} className="text-left hover:text-soc-accent">last seen {hostSort.key === 'seen' ? (hostSort.dir === -1 ? '↓' : '↑') : ''}</button>
                <span>os</span>
              </div>
              <div className="divide-y divide-soc-border/40">
                {sortedHosts.slice(0, 12).map((h, i) => {
                  const pct = Math.max(2, Math.round((h.risk_total / (sortedHosts[0].risk_total || 1)) * 100));
                  const active = hostFilter === h.hostname;
                  return (
                    <button
                      key={h.hostname}
                      onClick={() => setHostFilter(active ? '' : h.hostname)}
                      className={`group w-full grid grid-cols-[2rem_1.4fr_1fr_0.7fr_1fr_0.7fr] gap-3 items-center text-sm rounded-lg px-3 py-1.5 transition-colors text-left ${
                        active ? 'bg-soc-accent/10 border border-soc-accent/40' : 'hover:bg-soc-panel border border-transparent'
                      }`}
                      title="Filter the page + seed the correlation graph on this host"
                    >
                      <span className="text-[10px] text-soc-muted">{i + 1}</span>
                      <span className="font-mono text-xs truncate group-hover:text-soc-accent">{h.hostname} <span className="text-soc-accent font-semibold">{h.risk_total}</span></span>
                      <span className="h-2 bg-soc-panel rounded-full overflow-hidden">
                        <span className={`block h-full rounded-full ${h.risk_total >= 500 ? 'bg-red-500/70' : h.risk_total >= 200 ? 'bg-amber-500/70' : 'bg-soc-accent/40'}`} style={{ width: `${pct}%` }} />
                      </span>
                      <span className="text-xs text-soc-muted">{h.event_count} ev</span>
                      <span className="text-[10px] text-soc-muted-cool truncate">{h.last_seen ? formatRelative(h.last_seen) : '—'}</span>
                      <span className="text-[10px] text-soc-muted truncate">{h.os_type || '—'}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 6. Known Threat IPs + Geo Breakdown */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">Known Threat IPs</h2>
          <span className={`text-xs px-2 py-0.5 rounded-full ${knownIps.length > 0 ? 'bg-red-50 text-red-600 border border-red-200' : 'bg-soc-panel text-soc-muted'}`}>
            {knownIpsData?.total ?? knownIps.length} ips
          </span>
        </div>
        {(knownIps.length === 0 && countries.length === 0) && <EnrichmentNote />}
        {knownIpsLoading ? (
          <div className="space-y-2 mt-2">{[1, 2, 3].map((i) => <div key={i} className="h-9 bg-soc-panel rounded-lg animate-pulse" />)}</div>
        ) : knownIps.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-4 text-soc-muted">
            <Globe size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
            <p className="text-xs text-center">
              No indicators have matched this project's events yet — feed indicators will appear here once they do
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto mt-2">
            <div className="min-w-[680px]">
              <div className="grid grid-cols-[1.2fr_0.6fr_0.6fr_1fr_0.8fr_0.6fr_auto] gap-3 px-3 py-2 text-[10px] uppercase tracking-wide text-soc-muted border-b border-soc-border/60">
                <span>IP</span><span>Events</span><span>Avg risk</span><span>Hosts</span><span>Geo</span><span>Bad</span><span></span>
              </div>
              <div className="divide-y divide-soc-border/60">
                {knownIps.map((item) => (
                  <div key={item.ip}>
                    <div className="grid grid-cols-[1.2fr_0.6fr_0.6fr_1fr_0.8fr_0.6fr_auto] gap-3 px-3 py-2 items-center text-sm">
                      <button onClick={() => setExpandedIp(expandedIp === item.ip ? null : item.ip)} className="font-mono text-xs text-soc-text truncate text-left hover:text-soc-accent" title="Open enrichment card">
                        {item.ip}
                      </button>
                      <span className="text-xs text-soc-muted">{item.event_count}</span>
                      <span className="text-xs font-medium text-soc-text">{item.avg_risk}</span>
                      <span className="text-[10px] text-soc-muted truncate" title={(item.hosts || []).join(', ')}>{(item.hosts || []).join(', ') || '—'}</span>
                      <span className="text-xs text-soc-muted truncate">{item.country ? `${flagEmoji(item.country)} ${item.country}${item.city ? ` · ${item.city}` : ''}` : '—'}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded w-fit ${item.is_known_bad ? 'bg-red-500/[0.12] text-red-600' : 'bg-soc-panel text-soc-muted'}`}>
                        {item.is_known_bad ? 'known-bad' : 'observed'}
                      </span>
                      <button
                        onClick={() => api.threatIntel.allowlistAdd(pid, { indicator: item.ip, type: 'ip', reason: 'allowlisted from Known Threat IPs' }).then(() => { addToast(`Allowlisted ${item.ip}`, 'success'); invalidate(); }).catch((e) => addToast(e.message, 'error'))}
                        className="text-[10px] text-soc-muted hover:text-soc-accent border border-soc-border hover:border-soc-accent/40 px-2 py-0.5 rounded transition-colors"
                        title="Mark as known-good infrastructure (never flags again)"
                      >
                        Allowlist
                      </button>
                    </div>
                    {expandedIp === item.ip && (
                      <div className="mx-3 mb-2 px-3 py-2 rounded-lg bg-soc-panel/60 border border-soc-border/40 text-xs text-soc-muted space-y-1">
                        <p>first seen: <span className="text-soc-text font-mono">{item.first_seen ? formatLocalDate(item.first_seen) : '—'}</span> · last seen: <span className="text-soc-text font-mono">{item.last_seen ? formatLocalDate(item.last_seen) : '—'}</span></p>
                        <p>max risk: <span className="text-soc-text">{item.max_risk}</span> · threat-match hits: <span className="text-soc-text">{item.threat_matches}</span></p>
                        <p>hosts: <span className="text-soc-text">{(item.hosts || []).join(', ') || '—'}</span></p>
                        <Link to={`/live-events?query=${encodeURIComponent(item.ip)}`} className="text-soc-accent hover:underline">open in events →</Link>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Geo Breakdown */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <h2 className="text-sm font-semibold mb-3 text-soc-text">Geo Breakdown</h2>
        {countries.length === 0 ? (
          <>
            <div className="flex flex-col items-center justify-center py-4 text-soc-muted">
              <MapPin size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
              <p className="text-xs text-center">No geo data yet — requires IP enrichment</p>
            </div>
            <EnrichmentNote />
          </>
        ) : (
          <div className="space-y-1.5">
            {countries.map((c) => (
              <div key={c.country} className="flex items-center gap-3 text-xs">
                <span className="w-40 truncate shrink-0">{flagEmoji(c.country)} {c.country}</span>
                <div className="flex-1 h-2 bg-soc-panel rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-soc-accent/60" style={{ width: `${Math.max(2, Math.round((c.event_count / geoMax) * 100))}%` }} />
                </div>
                <span className="text-soc-muted w-24 text-right shrink-0">{c.event_count} ev · {c.ip_count} ip</span>
              </div>
            ))}
            {(geoData?.unknown_country_events || 0) > 0 && (
              <p className="text-[10px] text-soc-muted pt-1">+ {geoData.unknown_country_events} events without country (private IPs / no GeoIP DB)</p>
            )}
          </div>
        )}
      </div>

      {/* Allowlist manager */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">IOC Allowlist</h2>
          <span className="text-xs px-2 py-0.5 rounded-full bg-soc-panel text-soc-muted">{allowlist.length} entries</span>
        </div>
        <p className="text-[11px] text-soc-muted mb-3">Known-good infrastructure (scanners, CI runners) — allowlisted values never appear as threats for this project.</p>
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <input
            value={allowForm.indicator}
            onChange={(e) => setAllowForm((f) => ({ ...f, indicator: e.target.value }))}
            placeholder="IP, domain or hash"
            className="text-xs bg-soc-card border border-soc-border rounded-lg px-2.5 py-1.5 w-52 font-mono focus:outline-none focus:border-soc-accent"
          />
          <select
            value={allowForm.type}
            onChange={(e) => setAllowForm((f) => ({ ...f, type: e.target.value }))}
            className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 focus:outline-none focus:border-soc-accent"
          >
            <option value="ip">ip</option>
            <option value="domain">domain</option>
            <option value="hash">hash</option>
          </select>
          <input
            value={allowForm.reason}
            onChange={(e) => setAllowForm((f) => ({ ...f, reason: e.target.value }))}
            placeholder="reason (e.g. internal scanner)"
            className="text-xs bg-soc-card border border-soc-border rounded-lg px-2.5 py-1.5 flex-1 min-w-[180px] focus:outline-none focus:border-soc-accent"
          />
          <button
            onClick={() => allowForm.indicator.trim() && allowAddMutation.mutate()}
            disabled={!allowForm.indicator.trim() || allowAddMutation.isPending}
            className="text-xs bg-soc-accent hover:bg-soc-accent-glow text-white px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
          >
            {allowAddMutation.isPending ? 'Adding…' : 'Allowlist'}
          </button>
        </div>
        {allowlist.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {allowlist.map((a) => (
              <span key={a.indicator} className="flex items-center gap-1.5 text-[11px] font-mono bg-soc-panel border border-soc-border/60 rounded-full pl-2.5 pr-1 py-0.5" title={a.reason || ''}>
                {a.indicator}
                <span className="text-soc-muted">· {a.type}</span>
                <button
                  onClick={() => allowRemoveMutation.mutate(a.indicator)}
                  disabled={allowRemoveMutation.isPending}
                  className="text-soc-muted hover:text-red-600 p-0.5 disabled:opacity-50"
                  title={a.reason ? `Remove (reason was: ${a.reason})` : 'Remove from allowlist'}
                >
                  <X size={12} />
                </button>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Matched Events */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">Matched Events</h2>
          <span className={`text-xs px-2 py-0.5 rounded-full ${matches.length > 0 ? 'bg-red-500/[0.12] text-red-600' : 'bg-soc-panel text-soc-muted'}`}>
            {matches.length} matching events{feedFilter ? ` · feed: ${feedFilter}` : ''}
          </span>
        </div>
        {matchLoading ? (
          <div className="space-y-2">{[1, 2, 3].map((i) => <div key={i} className="h-9 bg-soc-panel rounded-lg animate-pulse" />)}</div>
        ) : matches.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-4 text-soc-muted">
            <Radar size={24} strokeWidth={1.5} className="text-slate-400 mb-2" />
            <p className="text-xs text-center">
              No events currently match the indicator list
            </p>
          </div>
        ) : (
          <div className="space-y-1.5 max-h-96 overflow-y-auto">
            {matches.map((m) => (
              <MatchRow
                key={m.id}
                m={m}
                pid={pid}
                onOpenIncident={openIncident}
                feedbackPending={feedbackMutation.isPending}
                onFeedback={(id) => feedbackMutation.mutate({ matchId: id })}
              />
            ))}
          </div>
        )}
      </div>

      {/* 7. Browsable indicator list */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
          <h2 className="text-sm font-semibold text-soc-text">Indicator List</h2>
          <div className="flex items-center gap-2">
            <select
              value={indicatorFeed}
              onChange={(e) => { setIndicatorFeed(e.target.value); setIndicatorPage(1); setFeedFilter(e.target.value === 'manual' ? 'manual' : e.target.value ? 'feed' : ''); }}
              className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 focus:outline-none focus:border-soc-accent"
            >
              <option value="">all source feeds</option>
              {feedOptions.filter(Boolean).map((f) => (
                <option key={f} value={f}>{f}</option>
              ))}
            </select>
            <span className="text-[10px] text-soc-muted">{totalIndicators} loaded</span>
          </div>
        </div>
        <div className="overflow-x-auto">
          <div className="min-w-[560px]">
            <div className="grid grid-cols-[1.2fr_1fr_1fr_auto] gap-3 px-3 py-2 text-[10px] uppercase tracking-wide text-soc-muted border-b border-soc-border/60">
              <span>Value</span>
              <span>Category</span>
              <span>Source feed</span>
              <span>Loaded</span>
            </div>
            <div className="divide-y divide-soc-border/60">
              {(allIndData?.indicators ?? []).map((item) => (
                <div key={`${item.source_feed}-${item.value}`} className="grid grid-cols-[1.2fr_1fr_1fr_auto] gap-3 px-3 py-2 items-center text-sm">
                  <span className="font-mono text-xs text-soc-text truncate" title={item.value}>{item.value}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-soc-panel text-soc-muted w-fit">{item.category}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded w-fit ${item.source_feed === 'manual' ? 'badge-manual' : 'badge-feed'}`}>
                    {item.source_feed}
                  </span>
                  <span className="text-[10px] text-soc-muted-cool">{item.loaded_at ? formatLocalDate(item.loaded_at) : '—'}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
        {pageCount > 1 && (
          <div className="flex items-center justify-center gap-2 mt-3">
            <button
              onClick={() => setIndicatorPage((p) => Math.max(1, p - 1))}
              disabled={indicatorPage <= 1}
              className="text-xs px-2.5 py-1 rounded-lg border border-soc-border text-soc-muted hover:text-soc-accent disabled:opacity-40"
            >
              Prev
            </button>
            <span className="text-[10px] text-soc-muted">page {indicatorPage} / {pageCount}</span>
            <button
              onClick={() => setIndicatorPage((p) => Math.min(pageCount, p + 1))}
              disabled={indicatorPage >= pageCount}
              className="text-xs px-2.5 py-1 rounded-lg border border-soc-border text-soc-muted hover:text-soc-accent disabled:opacity-40"
            >
              Next
            </button>
          </div>
        )}
      </div>

      {/* Bucket drill-down drawer */}
      {drawerBucket && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 bg-soc-overlay/60"
          onClick={() => setDrawerBucket(null)}
        >
          <motion.div
            initial={{ x: 420 }}
            animate={{ x: 0 }}
            transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            className="absolute right-0 top-0 bottom-0 w-full max-w-md bg-white border-l border-soc-border shadow-lift flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-4 border-b border-soc-border">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-soc-text">Bucket events</h2>
                <button onClick={() => setDrawerBucket(null)} className="text-soc-muted hover:text-soc-text"><X size={16} /></button>
              </div>
              <p className="text-[11px] text-soc-muted mt-0.5 font-mono">{drawerBucket} · {bucketData?.total ?? '…'} events</p>
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-1.5">
              {bucketLoading ? (
                [1, 2, 3].map((i) => <div key={i} className="h-14 bg-soc-panel rounded-lg animate-pulse" />)
              ) : (bucketData?.events ?? []).length === 0 ? (
                <p className="text-xs text-soc-muted text-center py-8">No events in this bucket under the active filters.</p>
              ) : (
                (bucketData?.events ?? []).map((ev) => (
                  <div key={ev.id} className="rounded-lg bg-soc-card border border-soc-border/60 px-3 py-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] text-soc-muted-cool font-mono">{formatLocalTime(ev.timestamp)}</span>
                      <span className="text-[10px] text-soc-muted">{ev.hostname}</span>
                      <TriageControls pid={pid} event={ev} onChanged={() => queryClient.invalidateQueries({ queryKey: ['threat-bucket', pid] })} />
                    </div>
                    <p className="text-xs text-soc-muted mt-1 break-words">{ev.summary}</p>
                    <div className="flex items-center gap-2 mt-1">
                      {ev.technique && <span className="text-[10px] font-mono text-soc-accent-glow">{ev.technique}</span>}
                      <Link to={`/live-events?query=${encodeURIComponent(ev.id)}`} className="text-[10px] text-soc-muted hover:text-soc-accent">open in events →</Link>
                    </div>
                  </div>
                ))
              )}
            </div>
          </motion.div>
        </motion.div>
      )}

      <CreateIncidentModal
        open={createIncidentModal.open}
        event={createIncidentModal.event}
        projectId={pid}
        initialSeverity={createIncidentModal.initialSeverity}
        initialTitle={createIncidentModal.initialTitle}
        initialDescription={createIncidentModal.initialDescription}
        onClose={() => setCreateIncidentModal({ open: false, initialTitle: '', initialDescription: '', initialSeverity: null, event: null })}
      />

      {attachChain && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-soc-overlay/60 p-4"
          onClick={() => setAttachChain(null)}
        >
          <motion.div
            initial={{ scale: 0.95 }}
            animate={{ scale: 1 }}
            className="glass-elevated rounded-xl w-full max-w-md flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-4 border-b border-soc-border">
              <h2 className="text-lg font-semibold text-soc-text">Attach chain to incident</h2>
              <p className="text-xs text-soc-muted mt-0.5">
                {attachChain.hostname} · {attachChain.event_count} events · {formatLocalDate(attachChain.start_time)} {formatLocalTime(attachChain.start_time)} → {formatLocalTime(attachChain.end_time)}
              </p>
            </div>
            <div className="p-3 border-b border-soc-border">
              <button
                onClick={() => {
                  setAttachChain(null);
                  openChainIncident(attachChain);
                }}
                className="w-full text-left text-sm text-soc-accent hover:underline px-2 py-1.5 rounded hover:bg-soc-panel"
              >
                + Create new incident from this chain
              </button>
            </div>
            <div className="max-h-64 overflow-y-auto p-2 space-y-1">
              <p className="text-[10px] uppercase tracking-wide text-soc-muted px-2 pt-1">Open incidents</p>
              {(openIncidents || []).filter((i) => i.status !== 'resolved' && i.status !== 'false_positive').length === 0 ? (
                <p className="text-xs text-soc-muted px-2 py-2">No open incidents — create one first.</p>
              ) : (
                (openIncidents || [])
                  .filter((i) => i.status !== 'resolved' && i.status !== 'false_positive')
                  .map((i) => (
                    <button
                      key={i.id}
                      onClick={() => attachChainMutation.mutate({ incidentId: i.id })}
                      disabled={attachChainMutation.isPending}
                      className="w-full flex items-center gap-2 px-2 py-2 rounded-lg hover:bg-soc-panel text-left transition-colors disabled:opacity-50"
                    >
                      <Link2 size={13} className="text-soc-muted shrink-0" />
                      <span className="flex-1 min-w-0">
                        <span className="block text-sm text-soc-text truncate">{i.title}</span>
                        <span className="block text-[10px] text-soc-muted">
                          #{i.id} · {i.severity} · {i.evidence_count} evidence
                        </span>
                      </span>
                      {attachChainMutation.isPending && attachChainMutation.variables?.incidentId === i.id && (
                        <span className="text-[10px] text-soc-muted">Attaching…</span>
                      )}
                    </button>
                  ))
              )}
            </div>
            <div className="p-3 border-t border-soc-border flex justify-end">
              <button onClick={() => setAttachChain(null)} className="text-sm text-soc-muted">Cancel</button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
}
