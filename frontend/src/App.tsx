import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import {
  Activity, AlertTriangle, ArrowDown, ArrowRight, ArrowUpRight, Bell, Building2,
  ChartNoAxesCombined, Check, ChevronDown, CircleHelp, ClipboardList, Clock3, Eye,
  FileChartColumn, FileText, Globe2, GraduationCap, HeartPulse, Home, Landmark,
  Layers3, Menu, Puzzle, RefreshCw, Search, Settings, Shield, ShieldAlert,
  ShieldCheck, ShoppingBag, SlidersHorizontal, X,
} from 'lucide-react'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { WorldExposureMap } from './components/WorldExposureMap'
import { FunctionalPage } from './pages/AnalystPages'
import { api, type AuditRecord, type HealthStatus, type OverviewData } from './services/api'

const navigation = [
  { label: 'Overview', path: '/', icon: Home, group: 'COMMAND CENTRE' },
  { label: 'Extension Inventory', path: '/inventory', icon: Puzzle, group: 'COMMAND CENTRE' },
  { label: 'Permission Intelligence', path: '/permissions', icon: Layers3, group: 'COMMAND CENTRE' },
  { label: 'Global Exposure Map', path: '/exposure', icon: Globe2, group: 'COMMAND CENTRE' },
  { label: 'Activity & Events', path: '/activity', icon: Activity, group: 'COMMAND CENTRE' },
  { label: 'Permission Risk Analysis', path: '/risk-analysis', icon: ShieldAlert, group: 'RISK INTELLIGENCE' },
  { label: 'Purpose Alignment', path: '/purpose-alignment', icon: ShieldCheck, group: 'RISK INTELLIGENCE' },
  { label: 'Extension Comparison', path: '/comparison', icon: SlidersHorizontal, group: 'RISK INTELLIGENCE' },
  { label: 'Sector Analysis', path: '/sectors', icon: Building2, group: 'RISK INTELLIGENCE' },
  { label: 'Privacy & Compliance', path: '/privacy', icon: Eye, group: 'GOVERNANCE' },
  { label: 'Reports & Evidence', path: '/reports', icon: FileChartColumn, group: 'GOVERNANCE' },
  { label: 'Audit History', path: '/audit', icon: ClipboardList, group: 'GOVERNANCE' },
  { label: 'Settings', path: '/settings', icon: Settings, group: 'SYSTEM' },
  { label: 'About BrowserGuard', path: '/about', icon: CircleHelp, group: 'SYSTEM' },
]

const metricIcons = [Puzzle, AlertTriangle, Shield, Eye]

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const [search, setSearch] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchExtensions, setSearchExtensions] = useState<Array<{ id: number; name: string; risk_score: number }>>([])
  const [searchError, setSearchError] = useState('')
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [toast, setToast] = useState('')
  const [overview, setOverview] = useState<OverviewData | null>(null)
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [activity, setActivity] = useState<AuditRecord[]>([])
  const [overviewError, setOverviewError] = useState('')
  const [lastUpdated, setLastUpdated] = useState('—')
  const [range, setRange] = useState<'24h' | '7d' | '30d'>('24h')
  const [refreshKey, setRefreshKey] = useState(0)
  const location = useLocation()
  const searchInputRef = useRef<HTMLInputElement>(null)
  const searchResults = useMemo(() => navigation.filter((item) => item.label.toLowerCase().includes(search.toLowerCase())), [search])

  useEffect(() => {
    function handleSearchShortcut(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        searchInputRef.current?.focus()
      }
    }
    window.addEventListener('keydown', handleSearchShortcut)
    return () => window.removeEventListener('keydown', handleSearchShortcut)
  }, [])

  useEffect(() => {
    function refreshAfterChange() {
      setRefreshKey((value) => value + 1)
    }
    window.addEventListener('browserguard:refresh', refreshAfterChange)
    return () => window.removeEventListener('browserguard:refresh', refreshAfterChange)
  }, [])

  useEffect(() => {
    let active = true
    const timer = window.setTimeout(() => {
      if (search.trim().length < 2) { setSearchExtensions([]); setSearchError(''); return }
      api.extensions(`search=${encodeURIComponent(search.trim())}&per_page=5`)
        .then((result) => { if (active) { setSearchExtensions(result.items); setSearchError('') } })
        .catch((failure: unknown) => { if (active) setSearchError(failure instanceof Error ? failure.message : 'Extension search failed.') })
    }, 250)
    return () => { active = false; window.clearTimeout(timer) }
  }, [search])

  useEffect(() => {
    let active = true
    setOverviewError('')
    Promise.all([api.health(), api.overview(range), api.events('activity')]).then(([status, summary, events]) => {
      if (!active) return
      setHealth(status)
      setOverview(summary)
      setActivity(events.items)
      setLastUpdated(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))
    }).catch((failure: unknown) => {
      if (active) {
        setHealth(null)
        setOverviewError(failure instanceof Error ? failure.message : 'Dashboard data could not be loaded.')
      }
    })
    return () => { active = false }
  }, [refreshKey, range])

  function notify(message: string) {
    setToast(message)
    window.dispatchEvent(new CustomEvent('browserguard:refresh'))
    window.setTimeout(() => setToast(''), 3500)
  }

  const closeMobileSidebar = () => setSidebarOpen(false)
  const activityCount = activity.length
  const groupedEvents = activity.slice(0, 5).map(toActivityEvent)

  return (
    <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''}`}>
      {sidebarOpen && <button className="mobile-backdrop" aria-label="Close navigation" onClick={closeMobileSidebar} />}
      <aside className={`sidebar ${sidebarOpen ? 'mobile-open' : ''}`}>
        <Link to="/" className="brand" onClick={closeMobileSidebar}>
          <div className="brand-mark"><Shield size={24} strokeWidth={2.2} /><span /></div>
          <div className="brand-copy"><strong>Browser<span>Guard</span></strong><small>Global Extension Security Intelligence</small></div>
        </Link>
        <nav className="side-nav" aria-label="Main navigation">
          {['COMMAND CENTRE', 'RISK INTELLIGENCE', 'GOVERNANCE', 'SYSTEM'].map((group) => (
            <div className="nav-group" key={group}>
              <p className="nav-group-title">{group}</p>
              {navigation.filter((item) => item.group === group).map(({ label, path, icon: Icon }) => (
                <Link key={path} to={path} className={`nav-item ${location.pathname === path ? 'active' : ''}`} onClick={closeMobileSidebar}>
                  <Icon size={16} strokeWidth={1.8} /><span>{label}</span>
                </Link>
              ))}
            </div>
          ))}
        </nav>
        <div className="system-status">
          <div className="status-heading">System status <Activity size={17} /></div>
          <div><i className={`status-dot ${overviewError ? 'status-error' : ''}`} />API connection {overviewError ? 'unavailable' : health?.database.status === 'connected' ? 'operational' : 'checking'}</div>
        </div>
        <button className="collapse-button" type="button" onClick={() => setCollapsed((value) => !value)} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
          <ArrowDown size={14} className={collapsed ? 'rotate-side' : ''} /><span>Collapse menu</span>
        </button>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div className="topbar-left">
            <button className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => setSidebarOpen(true)}><Menu size={19} /></button>
            <div className="global-search">
              <Search size={17} />
              <input
                ref={searchInputRef}
                aria-label="Search BrowserGuard"
                placeholder="Search extensions, permissions, or threats..."
                value={search}
                onFocus={() => setSearchOpen(true)}
                onChange={(event) => setSearch(event.target.value)}
                onKeyDown={(event) => { if (event.key === 'Escape') { setSearch(''); setSearchOpen(false) } }}
              />
              {search && <button type="button" className="clear-search" onClick={() => setSearch('')} aria-label="Clear search"><X size={14} /></button>}
              <kbd>Ctrl + K</kbd>
              {searchOpen && search && (
                <div className="search-results">
                  <small>APPLICATION SECTIONS</small>
                  {searchResults.map((item) => <Link key={item.path} to={item.path} onClick={() => { setSearch(''); setSearchOpen(false) }}>{item.label}<ArrowRight size={14} /></Link>)}
                  {searchExtensions.map((extension) => <Link key={extension.id} to="/inventory" onClick={() => { setSearch(''); setSearchOpen(false) }}>{extension.name}<span>Score {extension.risk_score}</span></Link>)}
                  {!searchResults.length && !searchExtensions.length && <p>{searchError || 'No matching sections or analyzed extensions.'}</p>}
                </div>
              )}
            </div>
          </div>
          <div className="topbar-right">
            <div className="engine-status" title={health ? `API v${health.api_version} · ${health.database_counts.extensions ?? 0} extensions stored` : overviewError}><i className={`status-dot ${overviewError ? 'status-error' : ''}`} /> <span>{overviewError ? 'Engine Offline' : health ? 'Engine Online' : 'Engine Checking'}</span></div>
            <div className="workspace-switch" title="Local analysis workspace">Research Lab <ChevronDown size={13} /></div>
            <div className="topbar-divider" />
            <div className="notification-wrap">
              <button className="icon-button notification-button" aria-label={`Notifications, ${activityCount} activity records`} onClick={() => setNotificationsOpen((open) => !open)}><Bell size={18} />{activityCount > 0 && <i>{Math.min(9, activityCount)}</i>}</button>
              {notificationsOpen && <div className="notification-popover"><div><strong>Recent activity</strong><span>{activityCount} records</span></div>{groupedEvents.length ? groupedEvents.slice(0, 3).map((event) => <p key={event.id}>{event.title}</p>) : <p>No activity recorded.</p>}<Link to="/activity" onClick={() => setNotificationsOpen(false)}>Open activity history</Link></div>}
            </div>
            <div className="topbar-divider profile-divider" />
            <div className="profile-button" title="Local analyst session; authentication is not configured" aria-label="Local analyst profile">A</div>
          </div>
        </header>
        <main className="main-content" onClick={() => { if (searchOpen) setSearchOpen(false) }}>
          <Routes>
            <Route path="/" element={<Overview data={overview} events={groupedEvents} error={overviewError} onRefresh={() => setRefreshKey((value) => value + 1)} updatedAt={lastUpdated} range={range} onRangeChange={setRange} />} />
            {navigation.filter((item) => item.path !== '/').map((item) => <Route key={item.path} path={item.path} element={<FunctionalPage item={item} onNotice={notify} />} />)}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
        <footer className="app-footer"><span>BrowserGuard v1.0.0&nbsp; | &nbsp;Cybersecurity Specialization Project</span><span><CircleHelp size={13} /> Scores reflect static manifest analysis, not a malware probability.</span></footer>
      </div>
      {toast && <div className="toast-message" role="status"><Check size={16} />{toast}</div>}
    </div>
  )
}

interface ActivityItemData {
  id: string
  time: string
  title: string
  detail: string
  level: string
}

function toActivityEvent(record: AuditRecord): ActivityItemData {
  const detail = record.description || Object.entries(record.detail).map(([key, value]) => `${key.replaceAll('_', ' ')}: ${String(value)}`).join(' · ')
  const level = ['critical', 'high', 'moderate', 'medium', 'low'].includes(record.severity) ? record.severity : 'info'
  return {
    id: String(record.id),
    time: new Date(record.created_at).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }),
    title: record.action.replaceAll('_', ' '),
    detail: detail || (record.extension_id ? `Extension #${record.extension_id}` : 'BrowserGuard analyst activity'),
    level,
  }
}

interface OverviewProps {
  data: OverviewData | null
  events: ActivityItemData[]
  error: string
  updatedAt: string
  range: '24h' | '7d' | '30d'
  onRangeChange: (range: '24h' | '7d' | '30d') => void
  onRefresh: () => void
}

function Overview({ data, events, error, onRefresh, updatedAt, range, onRangeChange }: OverviewProps) {
  const [filter, setFilter] = useState('All events')
  const metricValues = [
    { label: 'Extensions analysed', value: data?.extensions_analysed ?? '—', change: 'Stored analyses', tone: 'orange' },
    { label: 'Critical findings', value: data?.critical_findings ?? '—', change: 'Configured rules', tone: 'red' },
    { label: 'High-risk findings', value: data?.high_risk_findings ?? '—', change: 'Configured rules', tone: 'amber' },
    { label: 'Privacy exposure index', value: data?.privacy_exposure_index ?? '—', suffix: data ? '/100' : '', change: 'Mean exposure score', tone: 'green' },
  ] as const
  const secondary = [
    { label: 'Permission anomalies', value: data?.permission_anomalies ?? '—' },
    { label: 'Medium-risk extensions', value: data?.risk_counts.moderate ?? '—' },
    { label: 'Low-risk extensions', value: data?.risk_counts.low ?? '—' },
    { label: 'Reports generated', value: data?.reports_generated ?? '—' },
    { label: 'Extensions requiring review', value: data?.extensions_requiring_review ?? '—' },
  ]
  const filteredEvents = filter === 'All events' ? events : events.filter((event) => event.level === filter.toLowerCase())
  const trend = data?.trend ?? []
  const highRate = data?.extensions_analysed ? Math.round((((data.risk_counts.critical ?? 0) + (data.risk_counts.high ?? 0)) / data.extensions_analysed) * 100) : 0
  return (
    <div className="overview-page">
      <div className="page-heading">
        <div className="heading-copy"><div className="heading-symbol"><ChartNoAxesCombined size={22} /></div><div><h1>Security Overview</h1><p>Permission and privacy analysis of stored browser extension manifests.</p></div></div>
        <div className="heading-actions"><label className="range-select"><Clock3 size={14} /><select aria-label="Dashboard time range" value={range} onChange={(event) => { if (event.target.value === '24h' || event.target.value === '7d' || event.target.value === '30d') onRangeChange(event.target.value) }}><option value="24h">Last 24 Hours</option><option value="7d">Last 7 Days</option><option value="30d">Last 30 Days</option></select><ChevronDown size={13} /></label><span className="refresh-time">Updated {updatedAt}</span><button className="refresh-button" type="button" onClick={onRefresh}><RefreshCw size={14} />Refresh</button></div>
      </div>
      {error && <div className="error-state" role="alert"><AlertTriangle size={16} />{error}<button onClick={onRefresh}>Retry</button></div>}
      <section className="metric-grid" aria-label="Security metrics">
        {metricValues.map((metric, index) => {
          const Icon = metricIcons[index]
          return <article key={metric.label} className={`metric-card tone-${metric.tone}`}><div className="metric-icon"><Icon size={28} strokeWidth={2.1} /></div><div className="metric-content"><span>{metric.label}</span><div className="metric-value">{metric.value}<small>{'suffix' in metric ? metric.suffix : ''}</small><b className={metric.tone === 'green' ? 'stable' : ''}>{metric.change}</b></div></div><MiniTrend data={trend} tone={metric.tone} /></article>
        })}
      </section>
      <section className="secondary-metrics" aria-label="Additional security metrics">
        {secondary.map((metric) => <div key={metric.label}><span>{metric.label}</span><strong>{metric.value}</strong></div>)}
      </section>
      <div className="main-panels">
        <WorldExposureMap regions={data?.regions ?? []} notice={data?.regional_data_notice ?? 'No geographic metadata is available.'} />
        <ActivityPanel events={filteredEvents} filter={filter} setFilter={setFilter} />
      </div>
      <div className="bottom-panels">
        <RiskDistribution data={data?.risk_distribution ?? []} total={data?.extensions_analysed ?? 0} highRate={highRate} />
        <PermissionCategories data={data?.permission_categories ?? []} />
        <SectorRisk data={data?.sector_risk ?? []} />
        <QuickActions />
      </div>
      <section className="trend-panel panel">
        <div className="panel-heading compact-heading"><div><h2>High-risk analyses by day</h2><p>Stored analyses classified high or critical</p></div><Link className="text-link" to="/risk-analysis">Review analyses <ArrowRight size={12} /></Link></div>
        <div className="trend-chart">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trend} margin={{ top: 8, right: 12, left: -20, bottom: 0 }}>
              <defs><linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#d96a39" stopOpacity={0.28} /><stop offset="100%" stopColor="#d96a39" stopOpacity={0} /></linearGradient></defs>
              <CartesianGrid stroke="#382d26" strokeDasharray="3 5" vertical={false} />
              <XAxis dataKey="day" tickLine={false} axisLine={false} tick={{ fill: '#89786e', fontSize: 10 }} />
              <YAxis allowDecimals={false} tickLine={false} axisLine={false} tick={{ fill: '#89786e', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#201a17', border: '1px solid #49372b', borderRadius: 6, color: '#e9e2dc' }} />
              <Area type="monotone" dataKey="value" name="High-risk analyses" stroke="#d96a39" strokeWidth={2} fill="url(#trendFill)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </section>
      <section className="panel recent-analysis"><div className="panel-heading compact-heading"><div><h2>Recent analysis history</h2><p>Latest records stored in SQLite</p></div><Link to="/inventory" className="text-link">Open inventory <ArrowRight size={12} /></Link></div>{data?.recent_extensions.length ? <div className="recent-record-list">{data.recent_extensions.slice(0, 5).map((record) => <Link to="/inventory" key={record.id}><strong>{record.name}</strong><span>v{record.version}</span><ScoreText score={record.risk_score} /><span>{new Date(record.analyzed_at).toLocaleDateString()}</span></Link>)}</div> : <div className="overview-empty">No analyses are stored. Use <Link to="/inventory">Extension Inventory</Link> to upload a manifest.</div>}</section>
      <section className="panel frequent-permissions"><div className="panel-heading compact-heading"><div><h2>Most frequently requested permissions</h2><p>Occurrences across analyzed records</p></div><Link to="/permissions" className="text-link">Permission intelligence <ArrowRight size={12} /></Link></div>{data?.frequent_permissions.length ? <div className="frequent-list">{data.frequent_permissions.map((permission) => <div key={permission.name}><span>{permission.name}</span><i><b style={{ width: `${data.extensions_analysed ? permission.count / data.extensions_analysed * 100 : 0}%` }} /></i><strong>{permission.count}</strong></div>)}</div> : <div className="overview-empty">No permission declarations are available yet.</div>}</section>
    </div>
  )
}

function ScoreText({ score }: { score: number }) {
  return <strong className={`text-${score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low'}`}>{score}/100</strong>
}

function MiniTrend({ data, tone }: { data: Array<{ value: number }>; tone: string }) {
  const values = data.map((item) => item.value)
  const max = Math.max(1, ...values)
  const points = values.length ? values.map((value, index) => `${(index / Math.max(1, values.length - 1)) * 123},${24 - value / max * 20}`).join(' ') : ''
  return <svg className={`mini-trend ${tone}`} viewBox="0 0 123 26" aria-hidden="true"><polyline points={points} fill="none" stroke="currentColor" strokeWidth="1.5" /></svg>
}

function ActivityPanel({ events, filter, setFilter }: { events: ActivityItemData[]; filter: string; setFilter: (filter: string) => void }) {
  return <section className="panel activity-panel">
    <div className="panel-heading activity-heading"><div className="title-cluster"><Activity size={19} className="activity-wave" /><div><h2>Security activity feed</h2></div></div><span className="live-indicator"><i className="status-dot" />Persistent</span></div>
    <div className="activity-filter"><select value={filter} onChange={(event) => setFilter(event.target.value)} aria-label="Filter activity events"><option>All events</option><option>Critical</option><option>High</option><option>Moderate</option><option>Low</option></select><ChevronDown size={12} /></div>
    <div className="event-list">{events.map((event) => <ActivityItem key={event.id} event={event} />)}{!events.length && <div className="empty-events">No stored activity matches this filter.</div>}</div>
    <Link className="text-link view-events" to="/activity">View all events <ArrowRight size={13} /></Link>
  </section>
}

function ActivityItem({ event }: { event: ActivityItemData }) {
  return <article className="event-item"><i className={`event-node ${event.level}`} /><div className="event-copy"><time>{event.time}</time><strong>{event.title}</strong><span>{event.detail}</span></div><span className={`event-badge ${event.level}`}>{event.level.toUpperCase()}</span></article>
}

function RiskDistribution({ data, total, highRate }: { data: OverviewData['risk_distribution']; total: number; highRate: number }) {
  return <section className="panel risk-panel">
    <div className="panel-heading simple-heading"><div><h2>Risk distribution</h2><p>Analyzed extensions</p></div><Link className="subtle-icon-button" to="/risk-analysis" aria-label="Risk distribution details"><ArrowUpRight size={14} /></Link></div>
    <div className="risk-chart-wrap"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={data} dataKey="value" nameKey="name" innerRadius="58%" outerRadius="84%" paddingAngle={total ? 2 : 0} stroke="none">{data.map((item) => <Cell key={item.name} fill={item.color} />)}</Pie><Tooltip contentStyle={{ background: '#201a17', border: '1px solid #49372b', borderRadius: 6, color: '#e9e2dc' }} /></PieChart></ResponsiveContainer><div className="donut-label"><strong>{total ? `${highRate}%` : '0'}</strong><span>{total ? 'High +' : 'analyses'}</span></div></div>
    <div className="risk-legend">{data.map((item) => <div key={item.name}><i style={{ background: item.color }} /><span>{item.name}</span><b>{item.value}</b></div>)}</div>
  </section>
}

function PermissionCategories({ data }: { data: OverviewData['permission_categories'] }) {
  const colors = ['#d95d37', '#d98232', '#b69b76', '#74685e']
  return <section className="panel permission-panel">
    <div className="panel-heading simple-heading"><div><h2>Permission categories</h2><p>Recorded declaration occurrences</p></div><Link className="subtle-icon-button" to="/permissions" aria-label="Permission categories details"><ArrowUpRight size={14} /></Link></div>
    <div className="permission-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={data} margin={{ top: 12, right: 2, left: -22, bottom: 0 }}><CartesianGrid stroke="#382d26" strokeDasharray="3 5" vertical={false} /><XAxis dataKey="name" tickLine={false} axisLine={false} tick={{ fill: '#b5a69c', fontSize: 9 }} /><YAxis allowDecimals={false} tickLine={false} axisLine={false} tick={{ fill: '#89786e', fontSize: 9 }} /><Tooltip contentStyle={{ background: '#201a17', border: '1px solid #49372b', borderRadius: 6, color: '#e9e2dc' }} /><Bar dataKey="value" name="Declarations" radius={[4, 4, 0, 0]}>{data.map((entry, index) => <Cell key={entry.name} fill={colors[index % colors.length]} />)}</Bar></BarChart></ResponsiveContainer><div className="bar-labels">{data.map((item) => <span key={item.name}>{item.value}</span>)}</div></div>
  </section>
}

const sectorIcons = [Landmark, HeartPulse, GraduationCap, ShoppingBag, Building2, Shield]

function SectorRisk({ data }: { data: OverviewData['sector_risk'] }) {
  return <section className="panel sector-panel"><div className="panel-heading simple-heading"><div><h2>Sector-wise risk</h2><p>Mean scores from assigned records</p></div><Link className="text-link" to="/sectors">View details <ArrowRight size={12} /></Link></div>
    <div className="sector-list">{data.map((sector, index) => { const Icon = sectorIcons[index % sectorIcons.length]; return <div className="sector-row" key={sector.name}><Icon size={15} /><span>{sector.name}</span><div className="sector-bar"><i style={{ width: `${sector.score}%` }} /></div><b>{sector.extensions ? `${sector.score}/100` : '—'}</b></div> })}{!data.length && <p className="empty-events">No sector records.</p>}</div>
  </section>
}

function QuickActions() {
  const actions = [
    { title: 'Upload extension', icon: ArrowDown, className: 'upload-action', path: '/inventory' },
    { title: 'Run analysis', icon: ChartNoAxesCombined, path: '/inventory' },
    { title: 'Generate report', icon: FileText, path: '/reports' },
    { title: 'Compare extensions', icon: SlidersHorizontal, path: '/comparison' },
  ]
  return <section className="panel quick-panel"><div className="panel-heading simple-heading"><div><h2>Quick actions</h2><p>Analyst workflows</p></div></div><div className="quick-actions">{actions.map(({ title, icon: Icon, className, path }) => <Link key={title} className={className ?? ''} to={path}><Icon size={17} /><span>{title}</span></Link>)}</div></section>
}

export default App
