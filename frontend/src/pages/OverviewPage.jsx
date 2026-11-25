import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { BarChart2, Zap, Monitor, PieChart as PieChartIcon, ShieldAlert } from 'lucide-react';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { api } from '../lib/api';
import { useProjectStore } from '../stores/projectStore';
import { useWebSocket } from '../hooks/useWebSocket';
import { formatLocalTime, formatChartBucket, toDate } from '../lib/time';
import { CreateIncidentModal } from '../components/CreateIncidentModal';
import { PageHeader } from '../components/ui/PageHeader';

const RANGES = [
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
  { label: '30d', hours: 720 },
];

const HEALTH_META = {
  healthy: { label: 'Healthy', cls: 'text-green-700', dot: 'bg-soc-sage', detail: 'Elasticsearch up, events flowing' },
  degraded: { label: 'Degraded', cls: 'text-amber-600', dot: 'bg-amber-500', detail: 'Elasticsearch down — Mongo fallback active' },
  no_data: { label: 'No Data', cls: 'text-soc-muted', dot: 'bg-soc-muted', detail: 'No events received recently' },
};

function AgentDot({ lastSeenAt }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(id);
  }, []);
  // Shared UTC-assuming parser (same as every formatted time on the page).
  const seen = toDate(lastSeenAt);
  if (!seen) {
    return <span className="w-2 h-2 rounded-full bg-soc-muted" title="Never seen" />;
  }
  const elapsedMin = (now - seen.getTime()) / 60000;
  const cls = elapsedMin < 2 ? 'bg-soc-sage' : elapsedMin < 10 ? 'bg-amber-500' : 'bg-red-500';
  return <span className={`w-2 h-2 rounded-full ${cls}`} title={`Last seen ${Math.round(elapsedMin)}m ago`} />;
}

function MiniFeedItem({ event }) {
  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg bg-soc-card border border-soc-border/60 text-xs ${SEV[event.event_type] || ''}`}>
      <span className="text-soc-muted-cool shrink-0 w-16">{formatLocalTime(event.timestamp)}</span>
      <span className={`shrink-0 text-[10px] px-1.5 py-0.5 rounded ${event.source === 'website' ? 'badge-website' : event.source === 'linux' ? 'badge-linux' : 'badge-system'}`}>{event.source}</span>
      <span className="flex-1 truncate text-soc-muted">{event.summary || event.raw?.message || event.event_type}</span>
    </div>
  );
}

const SEV = {
  critical: 'severity-critical', high: 'severity-high',
  medium: 'severity-medium', low: 'severity-low',
};

export function OverviewPage() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const pid = activeProject?.id;
  const navigate = useNavigate();
  const [rangeHours, setRangeHours] = useState(24);
  const [liveEvents, setLiveEvents] = useState([]);
  const liveRef = useRef([]);
  const [incidentModal, setIncidentModal] = useState(false);

  const { data: ov, isLoading } = useQuery({
    queryKey: ['overview', pid, rangeHours],
    queryFn: () => api.projects.overview(pid, rangeHours),
    enabled: !!pid,
    refetchInterval: 30000,
  });

  const { connected } = useWebSocket(pid, useCallback((event) => {
    liveRef.current = [event, ...liveRef.current].slice(0, 8);
    setLiveEvents(liveRef.current);
  }, []));

  const health = ov?.ingest_health?.status || 'no_data';
  const healthMeta = HEALTH_META[health] || HEALTH_META.no_data;
  const statCards = [
    {
      label: 'Events', value: ov?.events_in_range ?? '—',
      color: 'text-soc-accent', to: `/live-events`,
      sub: `last ${rangeHours}h`,
    },
    {
      label: 'Open Incidents', value: ov?.open_incidents ?? '—',
      color: 'text-soc-critical', to: `/incidents`,
      sub: 'unresolved',
    },
    {
      label: 'Active Alerts', value: ov?.alerts_in_range ?? '—',
      color: 'text-soc-high', to: `/live-events?severity=high`,
      sub: 'critical + high, last ' + rangeHours + 'h',
    },
    {
      label: 'Ingest Health', value: healthMeta.label,
      color: healthMeta.cls, to: `/live-events`,
      sub: healthMeta.detail, dot: healthMeta.dot,
    },
  ];

  const agents = ov?.agents || [];

  return (
    <div className="space-y-6">
      <PageHeader
        title={activeProject?.name || 'Overview'}
        right={
          <div className="flex items-center gap-2">
            {RANGES.map((r) => (
              <button
                key={r.hours}
                onClick={() => setRangeHours(r.hours)}
                className={`px-3 py-1.5 rounded-full text-xs font-medium border transition-colors ${
                  rangeHours === r.hours
                    ? 'bg-soc-accent border-soc-accent text-white'
                    : 'bg-white border-soc-border text-soc-muted hover:text-soc-accent hover:border-soc-accent/40'
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
        }
      />

      {/* Stat cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((stat) => (
          <button
            key={stat.label}
            onClick={() => navigate(stat.to)}
            className="glass-card rounded-xl p-4 text-left hover:border-soc-accent/40 hover:shadow-lift transition-all group"
          >
            <div className="flex items-center gap-2">
              {stat.dot && <span className={`w-2 h-2 rounded-full ${stat.dot} animate-pulse`} />}
              <p className="tracked-label mb-1">{stat.label}</p>
            </div>
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
            <p className="text-[10px] text-soc-muted/70 mt-1 group-hover:text-soc-muted">{stat.sub}</p>
          </button>
        ))}
      </div>

      {/* Quick actions */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-soc-muted mr-1">Quick actions:</span>
        <button onClick={() => navigate(`/api-keys`)} className="chip">Generate API Key</button>
        <button onClick={() => navigate(`/integrations`)} className="chip">Install Agent</button>
        <button onClick={() => setIncidentModal(true)} className="chip">New Incident</button>
        <Link to={`/threat-intel`} className="chip ml-auto">
          View full Threat Intelligence →
        </Link>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Chart */}
        <div className="glass-card rounded-xl p-5 xl:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-soc-text">Event Volume</h2>
            <span className="tracked-label">Last {rangeHours}h</span>
          </div>
          {isLoading ? (
            <div className="h-[200px] animate-pulse bg-soc-card rounded-lg" />
          ) : ov?.chart?.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={(ov.chart || []).map((b) => ({ ...b, date: formatChartBucket(b.date) }))}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E4E7EB" />
                <XAxis dataKey="date" stroke="#64748B" fontSize={10} minTickGap={24} />
                <YAxis stroke="#64748B" fontSize={10} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: '#FFFFFF', border: '1px solid #E4E7EB', borderRadius: 10, color: '#0F172A', boxShadow: '0 8px 24px -8px rgba(15,23,42,0.18)' }}
                />
                <Line type="monotone" dataKey="count" stroke="#2563EB" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-soc-muted">
              <BarChart2 size={28} strokeWidth={1.5} className="text-slate-400 mb-2" />
              <p className="text-sm">No event data in this range</p>
            </div>
          )}
        </div>

        {/* Live mini-feed */}
        <div className="glass-card rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-soc-text">Live Activity</h2>
            <span className={`flex items-center gap-1.5 text-[10px] font-medium ${connected ? 'text-green-700' : 'text-soc-muted'}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-soc-sage animate-pulse' : 'bg-amber-500'}`} />
              {connected ? 'live' : 'connecting'}
            </span>
          </div>
          <div className="space-y-1.5 max-h-[200px] overflow-y-auto">
            {liveEvents.length > 0 ? (
              liveEvents.map((ev, i) => <MiniFeedItem key={ev.id || i} event={ev} />)
            ) : (
              <div className="flex flex-col items-center justify-center py-12 text-soc-muted">
                <Zap size={28} strokeWidth={1.5} className="text-slate-400 mb-2" />
                <p className="text-xs">Waiting for live events…</p>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Agents */}
        <div className="glass-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-3 text-soc-text">Agents</h2>
          {agents.length > 0 ? (
            <div className="space-y-2">
              {agents.map((a) => (
                <button
                  key={a.id}
                  onClick={() => navigate(`/live-events?host=${encodeURIComponent(a.hostname || '')}`)}
                  className="w-full flex items-center gap-3 p-2.5 rounded-lg bg-soc-card border border-soc-border/60 hover:bg-soc-panel transition-colors text-left"
                >
                  <AgentDot lastSeenAt={a.last_seen_at} />
                  <span className="flex-1 min-w-0">
                    <span className="block text-sm truncate">{a.hostname || `Agent #${a.id}`}</span>
                    <span className="block text-[10px] text-soc-muted/60 truncate">
                      {a.os_type || 'unknown OS'} {a.ip_address ? `· ${a.ip_address}` : ''}
                    </span>
                  </span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 ${
                    a.status === 'active' ? 'bg-green-600/[0.12] text-green-700' : 'bg-soc-panel text-soc-muted'
                  }`}>
                    {a.status}
                  </span>
                </button>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-10 text-soc-muted">
              <Monitor size={28} strokeWidth={1.5} className="text-slate-400 mb-2" />
              <p className="text-xs">No agents enrolled</p>
              <button onClick={() => navigate(`/integrations`)} className="text-xs text-soc-accent mt-2 hover:underline">
                Install an agent →
              </button>
            </div>
          )}
        </div>

        {/* Event severity */}
        <div className="glass-card rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-soc-text">Event Severity Breakdown</h2>
          </div>
          {(() => {
            const SEV_COLORS = { critical: '#DC2626', high: '#EA580C', medium: '#D97706', low: '#0284C7', info: '#64748B' };
            const SEV_LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
            const dist = ov?.severity_distribution || {};
            const total = Object.values(dist).reduce((a, b) => a + b, 0);
            const sevData = ['critical', 'high', 'medium', 'low', 'info']
              .filter((k) => dist[k])
              .map((k) => ({
                label: SEV_LABELS[k],
                color: SEV_COLORS[k],
                count: dist[k],
                pct: total ? Math.round((dist[k] / total) * 100) : 0,
              }));
            if (sevData.length === 0) {
              return (
                <div className="flex flex-col items-center justify-center py-10 text-soc-muted">
                  <PieChartIcon size={28} strokeWidth={1.5} className="text-slate-400 mb-2" />
                  <p className="text-xs">No severity data in this range</p>
                </div>
              );
            }
            return (
              <div className="flex items-center gap-3">
                <ResponsiveContainer width="55%" height={180}>
                  <PieChart>
                    <Pie
                      data={sevData}
                      dataKey="count"
                      nameKey="label"
                      innerRadius={45}
                      outerRadius={70}
                      paddingAngle={2}
                      strokeWidth={0}
                    >
                      {sevData.map((s) => (
                        <Cell key={s.label} fill={s.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ background: '#FFFFFF', border: '1px solid #E4E7EB', borderRadius: 10, color: '#0F172A', boxShadow: '0 8px 24px -8px rgba(15,23,42,0.18)' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex-1 space-y-2">
                  {sevData.map((s) => (
                    <div key={s.label} className="flex items-center justify-between text-xs">
                      <span className="flex items-center gap-1.5">
                        <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: s.color }} />
                        {s.label}
                      </span>
                      <span className="text-soc-muted/60">
                        {s.count} · {s.pct}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}
        </div>

        {/* Recent incidents */}
        <div className="glass-card rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-soc-text">Recent Incidents</h2>
            <Link to={`/incidents`} className="text-[10px] text-soc-accent hover:underline">
              view all →
            </Link>
          </div>
          <IncidentList pid={pid} />
        </div>
      </div>

      <CreateIncidentModal
        open={incidentModal}
        event={null}
        projectId={pid}
        onClose={() => setIncidentModal(false)}
      />
    </div>
  );
}

function IncidentList({ pid }) {
  const { data: incidents, isLoading } = useQuery({
    queryKey: ['incidents', pid],
    queryFn: () => api.incidents.list(pid),
    enabled: !!pid,
  });
  const navigate = useNavigate();
  if (isLoading) {
    return <div className="space-y-2">{[1, 2, 3].map((i) => <div key={i} className="h-10 bg-soc-card rounded-lg animate-pulse" />)}</div>;
  }
  if (!incidents || incidents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-soc-muted">
        <ShieldAlert size={28} strokeWidth={1.5} className="text-slate-400 mb-2" />
        <p className="text-xs">No incidents reported</p>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {incidents.slice(0, 5).map((inc) => (
        <button
          key={inc.id}
          onClick={() => navigate(`/incidents/${inc.id}`)}
          className={`w-full flex items-center justify-between p-2.5 rounded-lg bg-soc-card border border-soc-border/60 hover:bg-soc-panel transition-colors text-left ${SEV[inc.severity] || ''}`}
        >
          <span className="text-sm truncate flex-1 min-w-0">{inc.title}</span>
          <span className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 ml-2 ${
            inc.status === 'open' ? 'bg-red-500/[0.12] text-red-600' :
            inc.status === 'investigating' ? 'bg-amber-500/15 text-amber-600' :
            'bg-green-600/[0.12] text-green-700'
          }`}>
            {inc.status}
          </span>
        </button>
      ))}
    </div>
  );
}
