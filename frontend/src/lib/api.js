const BASE = '/api';

export async function request(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    const e = new Error(err.detail || 'Request failed');
    e.status = res.status;
    throw e;
  }
  return res.json();
}

export async function requestFile(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, { credentials: 'include', ...opts });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    const e = new Error(err.detail || 'Request failed');
    e.status = res.status;
    throw e;
  }
  return res.blob();
}

export const WS_BASE = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`;

// Shared threat-intel cross-filter query builder (window + host + technique + severity).
export function threatQuery(window = '24h', filters = {}) {
  const q = new URLSearchParams({ window });
  if (filters.host) q.set('host', filters.host);
  if (filters.techniqueId) q.set('technique_id', filters.techniqueId);
  if (filters.minSeverity) q.set('min_severity', filters.minSeverity);
  return q;
}

const WEBSITE_KEYS_STORAGE = 'soc_website_keys';

export function saveWebsiteKey(projectId, key) {
  try {
    const stored = JSON.parse(localStorage.getItem(WEBSITE_KEYS_STORAGE) || '{}');
    stored[String(projectId)] = key;
    localStorage.setItem(WEBSITE_KEYS_STORAGE, JSON.stringify(stored));
  } catch {
    // storage unavailable — the key just won't be remembered for later fills
  }
}

export function getWebsiteKey(projectId) {
  try {
    const stored = JSON.parse(localStorage.getItem(WEBSITE_KEYS_STORAGE) || '{}');
    return stored[String(projectId)] || null;
  } catch {
    return null;
  }
}

export const api = {
  health: () => request('/health'),
  auth: {
    register: (body) =>
      request('/auth/register', { method: 'POST', body: JSON.stringify(body) }),
    login: (body) =>
      request('/auth/login', { method: 'POST', body: JSON.stringify(body) }),
    logout: () => request('/auth/logout', { method: 'POST' }),
    me: () => request('/auth/me'),
    meRaw: () => fetch(`${BASE}/auth/me`, { credentials: 'include' }),
    updateMe: (body) =>
      request('/auth/me', { method: 'PATCH', body: JSON.stringify(body) }),
    changePassword: (body) =>
      request('/auth/change-password', { method: 'POST', body: JSON.stringify(body) }),
  },
  projects: {
    list: () => request('/projects'),
    get: (id) => request(`/projects/${id}`),
    current: () => request('/projects/current'),
    select: (id) => request(`/projects/${id}/select`, { method: 'POST' }),
    create: (body) =>
      request('/projects', { method: 'POST', body: JSON.stringify(body) }),
    delete: (id) => request(`/projects/${id}`, { method: 'DELETE' }),
    createApiKey: (projectId, label) =>
      request(`/projects/${projectId}/api-keys`, { method: 'POST', body: JSON.stringify({ label }) }).then(
        (r) => ({
          id: r.id,
          label: r.label,
          key: r.key,
          created_at: r.created_at,
          script_tag: r.script_tag,
          ai_agent_prompt: r.ai_agent_prompt,
        })
      ),
    listApiKeys: (projectId) => request(`/projects/${projectId}/api-keys`),
    revokeApiKey: (keyId) =>
      request(`/api-keys/${keyId}`, { method: 'DELETE' }),
    integrationSnippet: (projectId) => {
      const storedKey = getWebsiteKey(projectId);
      const headers = storedKey ? { 'X-API-Key': storedKey } : {};
      return request(`/projects/${projectId}/integration-snippet`, { headers }).then((r) => ({
        snippet: r.snippet,
        script_tag: r.script_tag,
        ai_agent_prompt: r.ai_agent_prompt,
        backend_url: r.backend_url,
      }));
    },
    websiteSetupPrompt: (projectId, apiKey) => {
      const headers = apiKey ? { 'X-API-Key': apiKey } : {};
      return request(`/projects/${projectId}/website-setup-prompt`, { headers }).then(
        (r) => ({ prompt: r.prompt })
      );
    },
    overview: (projectId, hours = 24) =>
      request(`/projects/${projectId}/overview?hours=${hours}`),
    sources: (projectId) => request(`/projects/${projectId}/sources`),
    cleanupHistory: (projectId) => request(`/projects/${projectId}/cleanup-history`),
  },
  events: {
    list: (projectId, params) => {
      const clean = {};
      for (const [k, v] of Object.entries(params || {})) {
        if (v !== undefined && v !== null && v !== '') clean[k] = v;
      }
      const q = Object.keys(clean).length ? '?' + new URLSearchParams(clean).toString() : '';
      return request(`/projects/${projectId}/events${q}`);
    },
    get: (eventId) => request(`/events/${eventId}`),
    cleanupPreview: (projectId, filters) =>
      request(`/projects/${projectId}/events/cleanup/preview`, {
        method: 'POST',
        body: JSON.stringify(filters),
      }).then((r) => ({
        count: r.count,
        sample: r.sample,
        oldest_match: r.oldest_match,
        newest_match: r.newest_match,
      })),
    cleanup: (projectId, filters, expectedCount) =>
      request(`/projects/${projectId}/events/cleanup`, {
        method: 'DELETE',
        body: JSON.stringify({ ...filters, expected_count: expectedCount }),
      }).then((r) => ({ deleted_count: r.deleted_count, es_synced: r.es_synced ?? true })),
  },
  agentLogs: {
    cleanupPreview: (projectId, filters) =>
      request(`/projects/${projectId}/agent-logs/cleanup/preview`, {
        method: 'POST',
        body: JSON.stringify(filters),
      }).then((r) => ({
        count: r.count,
        sample: r.sample,
        oldest_match: r.oldest_match,
        newest_match: r.newest_match,
      })),
    cleanup: (projectId, filters, expectedCount) =>
      request(`/projects/${projectId}/agent-logs/cleanup`, {
        method: 'DELETE',
        body: JSON.stringify({ ...filters, expected_count: expectedCount }),
      }).then((r) => ({ deleted_count: r.deleted_count, es_synced: r.es_synced ?? true })),
  },
  threatIntel: {
    flagged: (projectId, limit = 50) =>
      request(`/projects/${projectId}/threat-intel/flagged?limit=${limit}`),
    indicators: (projectId, source = 'all') =>
      request(`/projects/${projectId}/threat/indicators?source=${source}`),
    matches: (projectId, limit = 200) =>
      request(`/projects/${projectId}/threat/matches?limit=${limit}`),
    correlation: (projectId) =>
      request(`/projects/${projectId}/threat/correlation`),
    refresh: (projectId) =>
      request(`/projects/${projectId}/threat/refresh`, { method: 'POST' }),
    tactics: (projectId, window = '24h', filters = {}) =>
      request(`/projects/${projectId}/threat-intel/tactics?${threatQuery(window, filters)}`),
    timeline: (projectId, window = '24h', filters = {}) =>
      request(`/projects/${projectId}/threat-intel/timeline?${threatQuery(window, filters)}`),
    narratives: (projectId, hours = 24, filters = {}) => {
      const q = new URLSearchParams({ hours });
      if (filters.host) q.set('host', filters.host);
      if (filters.techniqueId) q.set('technique_id', filters.techniqueId);
      if (filters.minSeverity) q.set('min_severity', filters.minSeverity);
      return request(`/projects/${projectId}/threat-intel/narratives?${q}`);
    },
    topHosts: (projectId, window = '24h', filters = {}) =>
      request(`/projects/${projectId}/threat-intel/top-hosts?${threatQuery(window, filters)}`),
    knownIps: (projectId, window = '24h', filters = {}) =>
      request(`/projects/${projectId}/threat-intel/known-ips?${threatQuery(window, filters)}`),
    geo: (projectId, window = '24h', filters = {}) =>
      request(`/projects/${projectId}/threat-intel/geo?${threatQuery(window, filters)}`),
    graph: (projectId, window = '24h', filters = {}, minWeight = 1) => {
      const q = new URLSearchParams(threatQuery(window, filters));
      q.set('min_weight', minWeight);
      return request(`/projects/${projectId}/threat-intel/graph?${q}`);
    },
    bucket: (projectId, window = '24h', bucketStart, filters = {}) => {
      const q = new URLSearchParams({ window, bucket_start: bucketStart });
      if (filters.host) q.set('host', filters.host);
      if (filters.techniqueId) q.set('technique_id', filters.techniqueId);
      if (filters.minSeverity) q.set('min_severity', filters.minSeverity);
      return request(`/projects/${projectId}/threat-intel/timeline/bucket?${q}`);
    },
    triage: (projectId, eventId, body) =>
      request(`/projects/${projectId}/threat-intel/events/${eventId}/triage`, {
        method: 'PATCH',
        body: JSON.stringify(body),
      }),
    allowlist: (projectId) =>
      request(`/projects/${projectId}/threat-intel/allowlist`),
    allowlistAdd: (projectId, body) =>
      request(`/projects/${projectId}/threat-intel/allowlist`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    allowlistRemove: (projectId, indicator) =>
      request(`/projects/${projectId}/threat-intel/allowlist/${encodeURIComponent(indicator)}`, {
        method: 'DELETE',
      }),
    allIndicators: (projectId, { page = 1, pageSize = 50, sourceFeed = '' } = {}) => {
      const q = new URLSearchParams({ page, page_size: pageSize });
      if (sourceFeed) q.set('source_feed', sourceFeed);
      return request(`/projects/${projectId}/threat-intel/indicators?${q}`);
    },
    feedback: (projectId, matchId, isFalsePositive = true) =>
      request(`/projects/${projectId}/threat-intel/matches/${matchId}/feedback`, {
        method: 'POST',
        body: JSON.stringify({ is_false_positive: isFalsePositive }),
      }),
  },
  incidents: {
    list: (projectId, params = {}) => {
      const q = new URLSearchParams();
      ['status', 'severity', 'assigned_to', 'technique_id', 'host', 'tag', 'sort'].forEach((k) => {
        if (params[k] !== undefined && params[k] !== '' && params[k] !== null) q.set(k, params[k]);
      });
      const qs = q.toString();
      return request(`/projects/${projectId}/incidents${qs ? `?${qs}` : ''}`);
    },
    create: (projectId, body) =>
      request(`/projects/${projectId}/incidents`, { method: 'POST', body: JSON.stringify(body) }),
    get: (incidentId) => request(`/incidents/${incidentId}`),
    update: (incidentId, body) =>
      request(`/incidents/${incidentId}`, { method: 'PATCH', body: JSON.stringify(body) }),
    resolve: (incidentId, resolutionNote) =>
      request(`/incidents/${incidentId}/resolve`, {
        method: 'POST', body: JSON.stringify({ resolution_note: resolutionNote }),
      }),
    related: (incidentId) => request(`/incidents/${incidentId}/related`),
    bulk: (projectId, body) =>
      request(`/projects/${projectId}/incidents/bulk`, { method: 'POST', body: JSON.stringify(body) }),
    listEvidence: (incidentId) => request(`/incidents/${incidentId}/evidence`),
    addEvidence: (incidentId, body) =>
      request(`/incidents/${incidentId}/evidence`, { method: 'POST', body: JSON.stringify(body) }),
    attachChain: (incidentId, body) =>
      request(`/incidents/${incidentId}/evidence/chain`, { method: 'POST', body: JSON.stringify(body) }),
    addNote: (incidentId, body) =>
      request(`/incidents/${incidentId}/notes`, { method: 'POST', body: JSON.stringify(body) }),
    activity: (incidentId) => request(`/incidents/${incidentId}/activity`),
    addMitigation: (projectId, incidentId, text, suggested = false) =>
      request(`/projects/${projectId}/incidents/${incidentId}/mitigation`, {
        method: 'POST', body: JSON.stringify({ text, suggested }),
      }),
    toggleMitigation: (projectId, incidentId, itemId, done) =>
      request(`/projects/${projectId}/incidents/${incidentId}/mitigation/${itemId}`, {
        method: 'PATCH', body: JSON.stringify({ done }),
      }),
    mitigationSuggestions: (projectId, incidentId, techniqueId = '') =>
      request(`/projects/${projectId}/incidents/${incidentId}/mitigation/suggestions${techniqueId ? `?technique_id=${encodeURIComponent(techniqueId)}` : ''}`),
    reportPdf: (projectId, incidentId) =>
      requestFile(`/projects/${projectId}/incidents/${incidentId}/report`, { method: 'POST' }),
    bulkReports: (projectId, incidentIds) =>
      requestFile(`/projects/${projectId}/incidents/reports/bulk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident_ids: incidentIds }),
      }),
    exportPdf: (incidentId) => requestFile(`/incidents/${incidentId}/export/pdf`),
  },
  agents: {
    createKey: (label, projectId) =>
      request('/agents/keys', { method: 'POST', body: JSON.stringify({ label, project_id: projectId }) }),
    listKeys: (projectId) =>
      request(`/agents/keys${projectId != null ? `?project_id=${encodeURIComponent(projectId)}` : ''}`),
    revokeKey: (keyId) =>
      request(`/agents/keys/${keyId}`, { method: 'DELETE' }),
    listLogs: (limit = 50, offset = 0, params = {}) => {
      const q = new URLSearchParams({ limit, offset });
      ['hostname', 'category', 'project_id', 'query'].forEach((k) => {
        if (params[k] !== undefined && params[k] !== '' && params[k] !== null) q.set(k, params[k]);
      });
      return request(`/agents/logs?${q}`);
    },
  },
};
