import { useState, useCallback, useRef, useEffect, memo, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { useVirtualizer } from '@tanstack/react-virtual';
import { Zap, ShieldAlert } from 'lucide-react';
import { api } from '../lib/api';
import { useWebSocket } from '../hooks/useWebSocket';
import { useProjectStore } from '../stores/projectStore';
import { formatLocalTime } from '../lib/time';
import { CreateIncidentModal } from '../components/CreateIncidentModal';
import { PageHeader } from '../components/ui/PageHeader';

const MAX_EVENTS = 200;
const FLUSH_INTERVAL_MS = 250;
const ANIMATED_ROWS = 2;
const PAGE_SIZE = 100;
// History pages may accumulate beyond the live cap so "Load older" never
// fetches rows that are immediately thrown away.
const HISTORY_CAP = 1000;

const SEVERITY_CLASS = {
  critical: 'severity-critical', high: 'severity-high',
  medium: 'severity-medium', low: 'severity-low',
};

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low', 'info'];

function riskBadgeClass(score) {
  if (score >= 70) return 'bg-red-500/[0.12] text-red-600';
  if (score >= 40) return 'bg-amber-500/15 text-amber-600';
  if (score >= 15) return 'bg-blue-500/[0.12] text-blue-600';
  return 'bg-soc-panel text-soc-muted';
}

function flagEmoji(countryCode) {
  if (!countryCode || !/^[A-Za-z]{2}$/.test(countryCode)) return '';
  const cp = [...countryCode.toUpperCase()].map((c) => 127397 + c.charCodeAt(0));
  return String.fromCodePoint(...cp);
}

function GeoChip({ event }) {
  const ip = event.enriched?.ip;
  const country = event.enriched?.geo?.country;
  const city = event.enriched?.geo?.city;
  if (!ip) return null;
  const flag = flagEmoji(country);
  return (
    <span
      className="text-xs text-soc-muted/80 shrink-0 font-mono truncate max-w-[160px]"
      title={[ip, country, city].filter(Boolean).join(' · ')}
    >
      {flag && <span className="mr-1">{flag}</span>}
      {ip}
      {country && <span className="ml-1.5 text-soc-muted/60">{country}{city ? ` - ${city}` : ''}</span>}
    </span>
  );
}

function eventSummary(event) {
  return event.summary || event.raw?.message || event.raw?.url || event.event_type;
}

function parsedRows(event) {
  const rows = [];
  for (const [key, value] of Object.entries(event.parsed || {})) {
    if (value !== '' && value !== null && value !== undefined) rows.push([key, String(value)]);
  }
  return rows;
}

function enrichedRows(event) {
  const rows = [];
  const enriched = event.enriched || {};
  if (enriched.ip) rows.push(['ip', String(enriched.ip)]);
  if (enriched.geo) {
    const geo = [
      enriched.geo.country,
      enriched.geo.city,
      enriched.geo.lat != null ? `${enriched.geo.lat}, ${enriched.geo.lon}` : null,
    ].filter(Boolean).join(' · ');
    if (geo) rows.push(['geo', geo]);
  }
  if (enriched.threat_match) rows.push(['threat_match', 'true']);
  if (enriched.detected_attacks) rows.push(['detected_attacks', String(enriched.detected_attacks)]);
  if (enriched.risk_score != null) rows.push(['risk_score', String(enriched.risk_score)]);
  if (enriched.user_agent_parsed) rows.push(['user_agent', String(enriched.user_agent_parsed)]);
  if (enriched.form) {
    const form = enriched.form;
    const label = form.name || form.action || '(unnamed form)';
    rows.push(['form', String(label)]);
    if (form.timing_ms != null) rows.push(['form_timing_ms', String(form.timing_ms)]);
    if (Array.isArray(form.validation_errors) && form.validation_errors.length) {
      rows.push(['validation_errors', form.validation_errors.join('; ')]);
    }
    if (Array.isArray(form.fields) && form.fields.length) {
      const fieldSummary = form.fields
        .map((f) => `${f.name} (${f.type})${f.filled ? ' filled' : ' empty'}${f.length != null ? ` ${f.length}c` : ''}`)
        .join(', ');
      rows.push(['fields', fieldSummary]);
    }
  }
  return rows;
}

function DataGrid({ title, rows }) {
  if (!rows.length) return null;
  return (
    <div className="mb-3">
      <h4 className="text-xs text-soc-muted uppercase tracking-wide mb-2">{title}</h4>
      <div className="grid grid-cols-2 gap-x-8 gap-y-1">
        {rows.map(([key, value]) => (
          <div key={key} className="flex items-start justify-between gap-4 text-xs">
            <span className="text-soc-muted shrink-0">{key}</span>
            <span className="font-mono text-soc-text text-right break-all">{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

const EventRow = memo(
  function EventRow({ event, isNewest, expanded, onToggle, onCreateIncident }) {
    const parsed = parsedRows(event);
    const enriched = enrichedRows(event);
    const tags = event.tags || [];

    const content = (
      <div className="border-b border-soc-border/60 hover:bg-soc-card">
        <div
          className={`flex items-center gap-4 px-4 py-2.5 text-sm cursor-pointer ${SEVERITY_CLASS[event.event_type] || ''}`}
          onClick={onToggle}
        >
          <span className="text-xs text-soc-muted-cool w-16 shrink-0">
            {formatLocalTime(event.timestamp)}
          </span>
          <span className={`w-24 shrink-0 text-xs px-1.5 py-0.5 rounded ${event.source === 'website' ? 'badge-website' : event.source === 'linux' ? 'badge-linux' : 'badge-system'}`}>
            {event.source}
          </span>
          {(event.category === 'heartbeat' || event.category === 'lifecycle') && (
            <span className={`shrink-0 text-[10px] px-1.5 py-0.5 rounded ${event.category === 'heartbeat' ? 'bg-blue-500/[0.12] text-blue-600' : 'bg-soc-panel text-soc-muted'}`}>
              {event.category}
            </span>
          )}
          <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${
            event.event_type === 'critical' ? 'bg-red-500/[0.12] text-red-600' :
            event.event_type === 'high' ? 'bg-amber-500/15 text-amber-600' :
            event.event_type === 'medium' ? 'bg-yellow-500/15 text-yellow-600' :
            'bg-blue-500/[0.12] text-blue-600'
          }`}>
            {event.event_type}
          </span>
          <span className="flex-1 truncate text-soc-muted">
            {eventSummary(event)}
          </span>
          {typeof event.enriched?.risk_score === 'number' && (
            <span
              className={`text-xs px-1.5 py-0.5 rounded font-semibold shrink-0 ${riskBadgeClass(event.enriched.risk_score)}`}
              title="Risk score (0-100)"
            >
              {event.enriched.risk_score}
            </span>
          )}
          <GeoChip event={event} />
          {event.raw?.hostname && (
            <span className="text-xs text-soc-muted/60 shrink-0 font-mono truncate max-w-[100px]" title={event.raw.hostname}>
              {event.raw.hostname}
            </span>
          )}
          <div className="flex gap-2 shrink-0">
            <button
              onClick={(e) => {
                e.stopPropagation();
                onCreateIncident();
              }}
              className="text-xs bg-soc-panel hover:bg-soc-panel px-2 py-1 rounded"
            >
              + Incident
            </button>
          </div>
        </div>
        {expanded && (
          <div className="bg-soc-card px-4 py-3">
            <div className="mb-3">
              <h4 className="text-xs text-soc-muted uppercase tracking-wide mb-2">Summary</h4>
              <p className="text-xs font-mono text-soc-text break-all">{eventSummary(event)}</p>
            </div>
            <DataGrid title="Parsed Fields" rows={parsed} />
            <DataGrid title="Enriched" rows={enriched} />
            {tags.length > 0 && (
              <div className="mb-3">
                <h4 className="text-xs text-soc-muted uppercase tracking-wide mb-2">Tags</h4>
                <div className="flex flex-wrap gap-1.5">
                  {tags.map((t) => (
                    <span key={t} className="text-[10px] bg-soc-panel px-2 py-0.5 rounded-full font-mono">{t}</span>
                  ))}
                </div>
              </div>
            )}
            <div>
              <h4 className="text-xs text-soc-muted uppercase tracking-wide mb-2">Raw Event</h4>
              <pre className="bg-soc-code border border-soc-border rounded-lg px-4 py-3 text-xs font-mono overflow-auto max-h-48 whitespace-pre-wrap break-all">
                {JSON.stringify(event.raw ?? {}, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    );

    if (isNewest) {
      return (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
        >
          {content}
        </motion.div>
      );
    }
    return content;
  },
  (prev, next) =>
    prev.event?.id === next.event?.id &&
    prev.expanded === next.expanded &&
    prev.isNewest === next.isNewest
);

export function LiveEventsPage() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const pid = activeProject?.id;
  const [searchParams, setSearchParams] = useSearchParams();
  const hostParam = searchParams.get('host') || '';
  const severityParam = searchParams.get('severity') || 'all';
  const queryParam = searchParams.get('query') || '';
  const categoryParam = searchParams.get('category') || 'all';

  const [searchText, setSearchText] = useState(queryParam);
  const [debouncedQuery, setDebouncedQuery] = useState(queryParam);
  const [expanded, setExpanded] = useState(null);
  const [events, setEvents] = useState([]);
  const [sortBy, setSortBy] = useState('time');
  const parentRef = useRef(null);
  const pendingRef = useRef([]);
  const eventsRef = useRef([]);

  useEffect(() => {
    eventsRef.current = events;
  }, [events]);

  const [total, setTotal] = useState(0);
  const [loadedCount, setLoadedCount] = useState(0);
  const [loadingOlder, setLoadingOlder] = useState(false);

  useEffect(() => {
    if (queryParam !== searchText) {
      setSearchText(queryParam);
      setDebouncedQuery(queryParam);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queryParam]);

  useEffect(() => {
    const id = setTimeout(() => setDebouncedQuery(searchText), 300);
    return () => clearTimeout(id);
  }, [searchText]);

  const activeSeverity = SEVERITIES.includes(severityParam) ? severityParam : 'all';
  const activeCategory = ['all', 'security_event', 'heartbeat', 'lifecycle'].includes(categoryParam) ? categoryParam : 'all';
  const filters = {
    query: debouncedQuery || undefined,
    event_type: activeSeverity !== 'all' ? activeSeverity : undefined,
    host: hostParam || undefined,
    category: activeCategory !== 'all' ? activeCategory : undefined,
  };
  const hasFilters = Boolean(filters.query || filters.event_type || filters.host || filters.category);
  const filtersKey = JSON.stringify(filters);

  const { data: initial, isLoading, isError, refetch: refetchInitial } = useQuery({
    queryKey: ['events', pid, filtersKey],
    queryFn: () => api.events.list(pid, { ...filters, size: PAGE_SIZE }),
    enabled: !!pid,
  });

  useEffect(() => {
    const list = (initial?.events || []).slice(0, MAX_EVENTS);
    setEvents(list);
    setLoadedCount(list.length);
    setTotal(initial?.total ?? 0);
    setExpanded(null);
  }, [initial, filtersKey]);

  const matchesFilters = useCallback((e) => {
    if (activeSeverity !== 'all' && e.event_type !== activeSeverity) return false;
    // Mirror the server predicate exactly: 'all' is the curated feed
    // (security_event or uncategorized website docs), raw buckets are exact.
    if (activeCategory === 'heartbeat' || activeCategory === 'lifecycle') {
      if (e.category !== activeCategory) return false;
    } else if (activeCategory === 'security_event') {
      if (e.category !== 'security_event') return false;
    } else if (e.category && e.category !== 'security_event') {
      return false;
    }
    if (hostParam) {
      const h = (e.hostname || e.raw?.hostname || '').toLowerCase();
      if (!h.includes(hostParam.toLowerCase())) return false;
    }
    if (debouncedQuery) {
      const haystack = `${e.summary || ''} ${e.raw?.message || ''} ${e.raw?.url || ''}`.toLowerCase();
      if (!haystack.includes(debouncedQuery.toLowerCase())) return false;
    }
    return true;
  }, [activeSeverity, activeCategory, hostParam, debouncedQuery]);

  const { connected } = useWebSocket(pid, useCallback((event) => {
    pendingRef.current.push(event);
    if (pendingRef.current.length > MAX_EVENTS * 2) {
      pendingRef.current.splice(0, pendingRef.current.length - MAX_EVENTS);
    }
  }, []));

  useEffect(() => {
    const id = setInterval(() => {
      if (pendingRef.current.length === 0) return;
      const batch = pendingRef.current.splice(0, pendingRef.current.length);
      if (batch.length > MAX_EVENTS) batch.length = MAX_EVENTS;
      setEvents((prev) => {
        const seen = new Set(prev.map((e) => e.id));
        const fresh = batch.filter((e) => !seen.has(e.id) && matchesFilters(e));
        return [...fresh, ...prev].slice(0, HISTORY_CAP);
      });
      // Only jump to top when the user is already near it — never yank the
      // scrollbar while they read history below.
      if (parentRef.current && parentRef.current.scrollTop < 120) {
        parentRef.current.scrollTop = 0;
      }
    }, FLUSH_INTERVAL_MS);
    return () => clearInterval(id);
  }, [matchesFilters]);

  const loadOlder = useCallback(async () => {
    if (loadingOlder) return;
    setLoadingOlder(true);
    try {
      // Derive filters from the key so the callback never closes over a
      // stale filter object when only its contents changed.
      const liveFilters = JSON.parse(filtersKey);
      const res = await api.events.list(pid, { ...liveFilters, size: PAGE_SIZE, offset: loadedCount });
      const older = res.events || [];
      const seen = new Set(eventsRef.current.map((e) => e.id));
      const fresh = older.filter((e) => !seen.has(e.id));
      if (fresh.length > 0) {
        setEvents([...eventsRef.current, ...fresh].slice(0, HISTORY_CAP));
        setLoadedCount((c) => c + fresh.length);
      }
      if (res.total != null) setTotal(res.total);
    } catch {
      // ignore fetch errors; button remains for retry
    } finally {
      setLoadingOlder(false);
    }
  }, [pid, loadedCount, loadingOlder, filtersKey]);

  const setSeverity = (sev) => {
    const next = new URLSearchParams(searchParams);
    if (sev === 'all') next.delete('severity');
    else next.set('severity', sev);
    setSearchParams(next, { replace: true });
  };

  const setCategory = (cat) => {
    const next = new URLSearchParams(searchParams);
    if (!cat || cat === 'all') next.delete('category');
    else next.set('category', cat);
    setSearchParams(next, { replace: true });
  };

  const clearHost = () => {
    const next = new URLSearchParams(searchParams);
    next.delete('host');
    setSearchParams(next, { replace: true });
  };

  const clearAll = () => {
    setSearchText('');
    setDebouncedQuery('');
    setSearchParams({}, { replace: true });
  };

  const displayEvents = useMemo(() => {
    if (sortBy !== 'risk') return events;
    return [...events].sort((a, b) => (b.enriched?.risk_score ?? -1) - (a.enriched?.risk_score ?? -1));
  }, [events, sortBy]);

  const virtualizer = useVirtualizer({
    count: displayEvents.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 40,
    overscan: 8,
  });

  const [createIncidentModal, setCreateIncidentModal] = useState({ open: false, event: null });

  return (
    <div>
      <PageHeader
        title="Live Events"
        right={
          <div className="flex items-center gap-3">
            <span className={`flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full border ${
              connected
                ? 'bg-green-50 border-green-200 text-green-700'
                : 'bg-red-50 border-red-200 text-red-600'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-soc-sage animate-pulse' : 'bg-red-500'}`} />
              {connected ? 'Live' : 'Disconnected'}
            </span>
            {events.length > 0 && (
              <button
                onClick={() => { setEvents([]); setLoadedCount(0); setTotal(0); refetchInitial(); }}
                className="text-xs text-soc-muted hover:text-soc-accent bg-white border border-soc-border hover:bg-soc-panel px-2.5 py-1 rounded-lg transition-colors"
                title="Clear the list and reload from the newest events"
              >
                Clear
              </button>
            )}
          </div>
        }
      />

      <div className="glass-card rounded-xl p-3 mb-4 space-y-2.5">
        <div className="flex items-center gap-2">
          <input
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            placeholder="Search summary, message, or URL…"
            className="flex-1 bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-soc-accent"
          />
          {hostParam && (
            <span className="flex items-center gap-1.5 text-xs bg-soc-accent/15 border border-soc-accent/30 text-soc-accent px-2 py-1.5 rounded-lg">
              host: {hostParam}
              <button onClick={clearHost} className="hover:text-soc-text" title="Clear host filter">✕</button>
            </span>
          )}
          <select
            value={activeCategory}
            onChange={(e) => setCategory(e.target.value)}
            className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 text-soc-muted focus:outline-none focus:border-soc-accent shrink-0"
            title="Event stream: security detections or raw agent logs"
          >
            <option value="all">security feed</option>
            <option value="security_event">security only</option>
            <option value="heartbeat">heartbeats</option>
            <option value="lifecycle">raw agent logs</option>
          </select>
          {hasFilters && (
            <button onClick={clearAll} className="text-xs text-soc-muted hover:text-soc-accent bg-soc-card hover:bg-soc-panel px-2 py-1.5 rounded-lg">
              Clear all
            </button>
          )}
        </div>
        <div className="flex items-center gap-1.5 flex-wrap">
          {SEVERITIES.map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverity(sev)}
              className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${
                activeSeverity === sev
                  ? 'bg-soc-accent border-soc-accent text-white'
                  : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
              }`}
            >
              {sev}
            </button>
          ))}
          {hasFilters && (
            <span className="text-[10px] text-soc-muted/60 ml-auto">
              {loadedCount} of {total} matching events
            </span>
          )}
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="ml-auto text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1 text-soc-muted focus:outline-none focus:border-soc-accent"
            title="Sort order"
          >
            <option value="time">Newest first</option>
            <option value="risk">Risk score (high to low)</option>
          </select>
        </div>
      </div>

      <div className="glass-card rounded-xl overflow-hidden">
        <div ref={parentRef} className="max-h-[70vh] overflow-y-auto">
          {isLoading ? (
            <div className="space-y-1 p-4">
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="h-10 bg-soc-card rounded-lg animate-pulse" />
              ))}
            </div>
          ) : isError ? (
            <div className="flex flex-col items-center justify-center py-16 text-soc-muted">
              <ShieldAlert size={28} strokeWidth={1.5} className="text-slate-400 mb-2" />
              <p className="text-sm text-red-600">Failed to load events</p>
            </div>
          ) : events.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-soc-muted">
              <Zap size={28} strokeWidth={1.5} className="text-slate-400 mb-2" />
              <p className="text-sm">{hasFilters ? 'No events match your filters' : 'No events received yet'}</p>
              <p className="text-xs mt-1">
                {hasFilters
                  ? 'Try clearing the filters above'
                  : 'Agent events go to the project of the agent key used at install time'}
              </p>
              <button
                onClick={() => refetchInitial()}
                className="text-xs text-soc-accent hover:underline mt-2"
              >
                Reload
              </button>
            </div>
          ) : (
            <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
              {virtualizer.getVirtualItems().map((vi) => {
                const event = displayEvents[vi.index];
                if (!event) return null;
                return (
                  <div
                    key={event.id}
                    data-index={vi.index}
                    ref={virtualizer.measureElement}
                    style={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      width: '100%',
                      transform: `translateY(${vi.start}px)`,
                    }}
                  >
                    <EventRow
                      event={event}
                      isNewest={vi.index < ANIMATED_ROWS}
                      expanded={expanded === event.id}
                      onToggle={() => setExpanded(expanded === event.id ? null : event.id)}
                      onCreateIncident={() => setCreateIncidentModal({ open: true, event })}
                    />
                  </div>
                );
              })}
            </div>
          )}
          {loadedCount < total && events.length > 0 && (
            <div className="p-3 text-center">
              <button
                onClick={loadOlder}
                disabled={loadingOlder}
                className="text-xs text-soc-muted hover:text-soc-accent bg-soc-card hover:bg-soc-panel px-3 py-1.5 rounded transition-colors disabled:opacity-50"
              >
                {loadingOlder
                  ? 'Loading older events…'
                  : `Load older (${total - loadedCount} remaining)`}
              </button>
            </div>
          )}
        </div>
      </div>
      <CreateIncidentModal
        open={createIncidentModal.open}
        event={createIncidentModal.event}
        projectId={pid}
        onClose={() => setCreateIncidentModal({ open: false, event: null })}
      />
    </div>
  );
}
