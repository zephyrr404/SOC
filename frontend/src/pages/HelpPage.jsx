import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  BookOpen, Rocket, Globe, Activity, Radar, ShieldAlert, KeyRound, Monitor,
  Eraser, Search, ChevronDown, ArrowRight, LifeBuoy, AlertCircle, ListChecks,
} from 'lucide-react';
import { PageHeader } from '../components/ui/PageHeader';

const STEPS = [
  { n: 1, title: 'Create a project', desc: 'One project per monitored surface — a website or a system.', to: '/workspace' },
  { n: 2, title: 'Connect a source', desc: 'Paste the AI prompt or run the agent installer.', to: '/integrations' },
  { n: 3, title: 'Watch events flow', desc: 'Page views and detections land in Live Events.', to: '/live-events' },
  { n: 4, title: 'Triage and close', desc: 'Attach evidence, mitigate, resolve with a note.', to: '/incidents' },
];

const SECTIONS = [
  {
    id: 'start', icon: Rocket, title: 'Getting started',
    keywords: 'begin setup first steps project workspace',
    body: (
      <>
        <p>Create a <Link to="/workspace" className="text-soc-accent hover:underline">project in the Workspace</Link>, select it, then open <Link to="/integrations" className="text-soc-accent hover:underline">Integrations</Link> to connect your first source. Events start flowing into <Link to="/live-events" className="text-soc-accent hover:underline">Live Events</Link> within seconds — no restart needed.</p>
        <p>A website project and a system project are set up differently (see below), but everything downstream — detection, threat intel, incidents, cleanup — works the same for both.</p>
      </>
    ),
  },
  {
    id: 'website', icon: Globe, title: 'Connecting a website',
    keywords: 'website snippet telemetry javascript page view js error env key',
    body: (
      <>
        <p>On the <Link to="/integrations" className="text-soc-accent hover:underline">Integrations page</Link>, copy the <strong>AI agent prompt</strong> and paste it into Cursor, Claude Code, or any IDE agent. It wires real telemetry code (page views + JS errors) into your site — never an inline script tag.</p>
        <ul className="list-disc pl-5 space-y-1">
          <li>The site reads <code>SOC_SERVER_URL</code> and <code>SOC_API_KEY</code> from its own env convention — the host is never hardcoded.</li>
          <li>Events POST to <code>/ingest/event</code> with an <code>X-API-Key</code> header. The key alone identifies the project — no project ID is sent.</li>
          <li>Telemetry fails silently: if the SOC is unreachable, your site keeps working normally.</li>
        </ul>
      </>
    ),
  },
  {
    id: 'agents', icon: Monitor, title: 'System agents (Windows / Linux)',
    keywords: 'agent install windows linux powershell shell enroll heartbeat system',
    body: (
      <>
        <p>Generate an <strong>agent key</strong> on the <Link to="/api-keys" className="text-soc-accent hover:underline">API Keys page</Link>, then run the installer from <Link to="/integrations" className="text-soc-accent hover:underline">Integrations</Link> as admin: PowerShell on Windows (scheduled task tails Security / Application / System logs), shell on Linux (systemd timer or cron).</p>
        <ul className="list-disc pl-5 space-y-1">
          <li>The green dot on the Overview means a heartbeat within 2 minutes; amber is 10 minutes; red is stale.</li>
          <li>A key can only ever enroll one machine — a second box needs its own key.</li>
          <li>Revoking a key stops that agent cold (403 on next enroll); the dashboard keeps its history.</li>
        </ul>
      </>
    ),
  },
  {
    id: 'events', icon: Activity, title: 'Live Events & detection',
    keywords: 'live events detections rules risk score filters sqli xss ssrf severity',
    body: (
      <>
        <p>Every event is scored 0–100 by the rule engine (SQLi, XSS, SSRF, IDOR, command injection, open redirect and more) and bucketed critical / high / medium / low. Use the severity, source, and host filters — or click any row for the full enriched view with MITRE mapping, geo, and threat matches.</p>
        <p>Anything worth tracking becomes an incident in one click (<strong>+ Incident</strong>), carrying the event along as evidence.</p>
      </>
    ),
  },
  {
    id: 'intel', icon: Radar, title: 'Threat Intelligence',
    keywords: 'threat intel feed timeline tactics narratives graph hosts ips geo allowlist',
    body: (
      <>
        <p>The <Link to="/threat-intel" className="text-soc-accent hover:underline">Threat Intelligence page</Link> aggregates the selected window (24h / 7d / 30d): feed status, attack timeline (click a bar to drill into that bucket), ATT&CK tactic matrix, attack narratives, a correlation graph of IPs → hosts → users → techniques → incidents, top risk hosts, known threat IPs, and geo breakdown.</p>
        <ul className="list-disc pl-5 space-y-1">
          <li>Clicking a host or technique filters <em>every</em> panel — the graph can seed filters too; clicking a feed pill narrows Matched Events and the Indicator List.</li>
          <li>Matched events support inline triage (status, severity override, assignee, notes).</li>
          <li>Internal scanners showing up as threats? Add them to the <strong>IOC allowlist</strong> — they never flag again for that project.</li>
        </ul>
      </>
    ),
  },
  {
    id: 'incidents', icon: ShieldAlert, title: 'Incidents',
    keywords: 'incident evidence mitigation resolve notes activity related triage',
    body: (
      <>
        <p>Incidents collect evidence (single events or whole correlated chains), a mitigation checklist with technique-based suggestions, notes, and a server-side activity log of every change. Titles auto-generate from context (e.g. “Brute Force on SHUBHAM”) when left blank.</p>
        <ul className="list-disc pl-5 space-y-1">
          <li>Closing an incident <strong>requires a resolution note</strong> — resolved or false positive, the record shows why.</li>
          <li>The Related panel surfaces other incidents sharing a host, IP, user, or technique.</li>
          <li>The list view filters by status / severity / assignee / technique / tag and supports <strong>bulk assign + status</strong> via selection mode.</li>
          <li>Single incidents export to PDF; selections export as a zip.</li>
        </ul>
      </>
    ),
  },
  {
    id: 'keys', icon: KeyRound, title: 'API keys',
    keywords: 'api key revoke website agent keys one-time reveal rate limit',
    body: (
      <>
        <p>Two kinds of keys: <strong>website keys</strong> (browser ingest only, rate-limited) and <strong>agent keys</strong> (one machine each). Both are revealed exactly once at creation — store them immediately.</p>
        <p>Revoke a key the moment it may be compromised. Revocation is instant and permanent; historical events stay put.</p>
      </>
    ),
  },
  {
    id: 'cleanup', icon: Eraser, title: 'Data cleanup',
    keywords: 'cleanup delete retention preview history audit',
    body: (
      <>
        <p><Link to="/data-cleanup" className="text-soc-accent hover:underline">Data Cleanup</Link> deletes events or raw agent logs older than a cutoff. The preview always runs first and the delete button stays locked until it matches your current filters — type <code>DELETE</code> to arm it.</p>
        <ul className="list-disc pl-5 space-y-1">
          <li>If data arrived between preview and confirm, you get a 409 and the preview re-runs — confirm clicks can never delete a different set than shown.</li>
          <li>Every cleanup is written to an immutable <strong>Cleanup History</strong> that cleanup itself cannot touch.</li>
        </ul>
      </>
    ),
  },
  {
    id: 'trouble', icon: LifeBuoy, title: 'Troubleshooting',
    keywords: 'troubleshoot no events error 401 403 cors https degraded elasticsearch fix help',
    body: (
      <>
        <ul className="space-y-2">
          <li><strong>No events arriving?</strong> Check the key belongs to the selected project, the SOC URL is reachable from the source, and (for browsers) that the page is served over HTTPS when the SOC is HTTPS.</li>
          <li><strong>401 / 403 from ingest?</strong> Wrong, revoked, or cross-project key — generate a fresh one on the API Keys page.</li>
          <li><strong>“Degraded” ingest health?</strong> Elasticsearch is down and the platform is on its Mongo fallback. Charts still work; timelines just compute a little slower.</li>
          <li><strong>Cleanup shows “Nothing matches”?</strong> All data is newer than the cutoff — try Exact time or check you are in the right project.</li>
          <li><strong>Agent dot red?</strong> No heartbeat for 10+ minutes — check the scheduled task / timer on that machine.</li>
        </ul>
      </>
    ),
  },
];

export function HelpPage() {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState('start');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return SECTIONS;
    return SECTIONS.filter(
      (s) => s.title.toLowerCase().includes(q) || s.keywords.includes(q)
    );
  }, [query]);

  return (
    <div lang="en" className="max-w-4xl mx-auto">
      <PageHeader title="Help & Documentation" />

      {/* Hero */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="relative overflow-hidden rounded-xl border border-soc-border mb-6"
      >
        <div className="absolute inset-0 bg-gradient-to-r from-soc-accent/15 via-soc-accent/5 to-transparent" />
        <div className="relative p-6 sm:p-8">
          <div className="flex items-center gap-3 mb-2">
            <span className="w-10 h-10 rounded-xl bg-soc-accent text-white flex items-center justify-center shadow-lift shrink-0">
              <BookOpen size={20} strokeWidth={2} />
            </span>
            <div>
              <h2 className="text-xl font-bold text-soc-text">SOC Platform Guide</h2>
              <p className="text-xs text-soc-muted">From first project to closed incident</p>
            </div>
          </div>
          <div className="relative mt-4 max-w-md">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-soc-muted" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search topics — try “agent”, “cleanup”, “401”…"
              className="w-full bg-white/80 border border-soc-border rounded-lg pl-9 pr-3 py-2 text-sm text-soc-text placeholder:text-soc-muted/50 focus:outline-none focus:border-soc-accent"
            />
          </div>
        </div>
      </motion.div>

      {/* Quick start */}
      <div className="flex items-center gap-2 mb-3">
        <ListChecks size={15} className="text-soc-accent" />
        <h2 className="text-sm font-semibold text-soc-text">Quick start</h2>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        {STEPS.map((s, i) => (
          <motion.div
            key={s.n}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25, delay: i * 0.05 }}
          >
            <Link
              to={s.to}
              className="glass-card rounded-xl p-4 block h-full hover:border-soc-accent/40 hover:shadow-lift transition-all group"
            >
              <span className="w-7 h-7 rounded-full bg-soc-accent/[0.12] text-soc-accent text-xs font-bold flex items-center justify-center mb-2">
                {s.n}
              </span>
              <p className="text-sm font-semibold text-soc-text group-hover:text-soc-accent transition-colors">{s.title}</p>
              <p className="text-xs text-soc-muted mt-1">{s.desc}</p>
              <span className="inline-flex items-center gap-1 text-[11px] text-soc-accent mt-2">
                Open <ArrowRight size={11} />
              </span>
            </Link>
          </motion.div>
        ))}
      </div>

      {/* Sections */}
      <div className="space-y-3">
        {filtered.length === 0 && (
          <div className="glass-card rounded-xl p-8 text-center">
            <AlertCircle size={24} strokeWidth={1.5} className="text-slate-400 mb-2 mx-auto" />
            <p className="text-sm text-soc-muted">No topics match “{query}”. Try “agent”, “key”, or “incident”.</p>
          </div>
        )}
        {filtered.map((s) => {
          const Icon = s.icon;
          const isOpen = open === s.id;
          return (
            <div key={s.id} className="glass-card rounded-xl overflow-hidden">
              <button
                onClick={() => setOpen(isOpen ? null : s.id)}
                className="w-full flex items-center gap-3 p-4 text-left hover:bg-soc-panel/50 transition-colors"
              >
                <span className="w-8 h-8 rounded-lg bg-soc-tint-steel border border-soc-accent/20 flex items-center justify-center shrink-0">
                  <Icon size={15} className="text-soc-accent" strokeWidth={2} />
                </span>
                <span className="text-sm font-semibold text-soc-text flex-1">{s.title}</span>
                <ChevronDown size={16} className={`text-soc-muted transition-transform ${isOpen ? 'rotate-180' : ''}`} />
              </button>
              <AnimatePresence initial={false}>
                {isOpen && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.22 }}
                  >
                    <div className="px-4 pb-5 pt-1 text-sm text-soc-muted leading-relaxed space-y-2.5 text-justify hyphens-auto [&_code]:px-1 [&_code]:py-0.5 [&_code]:bg-soc-panel [&_code]:rounded [&_code]:text-[11px] [&_code]:font-mono [&_strong]:text-soc-text [&_strong]:font-semibold">
                      {s.body}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </div>
  );
}
