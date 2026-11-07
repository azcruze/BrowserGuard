import { useEffect, useMemo, useRef, useState } from 'react'
import type { ComponentType, FormEvent, ReactNode } from 'react'
import { ArrowDownToLine, ArrowUpRight, Check, ChevronDown, CircleAlert, Eye, FileText, LoaderCircle, RefreshCw, Search, Trash2, Upload, X } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Legend, PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { WorldExposureMap } from '../components/WorldExposureMap'
import { api, type AuditRecord, type ExtensionRecord, type PermissionDetail } from '../services/api'

interface PageDefinition {
  label: string
  path: string
  icon: ComponentType<{ size?: number; strokeWidth?: number }>
}

interface PageProps {
  item: PageDefinition
  onNotice: (message: string) => void
}

function useResource<T>(load: () => Promise<T>, dependencies: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [reloadId, setReloadId] = useState(0)
  useEffect(() => {
    let active = true
    setLoading(true)
    setError('')
    load().then((result) => { if (active) setData(result) }).catch((failure: unknown) => {
      if (active) setError(failure instanceof Error ? failure.message : 'The request could not be completed.')
    }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  // load() is intentionally refreshed using explicit dependencies and reload().
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...dependencies, reloadId])
  return { data, loading, error, reload: () => setReloadId((value) => value + 1) }
}

function PageHeader({ item, description }: { item: PageDefinition; description: string }) {
  const Icon = item.icon
  return <div className="page-heading"><div className="heading-copy"><div className="heading-symbol"><Icon size={21} /></div><div><h1>{item.label}</h1><p>{description}</p></div></div></div>
}

function EmptyState({ title, children, link }: { title: string; children: ReactNode; link?: string }) {
  return <div className="data-empty"><div><CircleAlert size={20} /></div><strong>{title}</strong><p>{children}</p>{link && <Link className="refresh-button" to={link}><Upload size={14} />Open extension inventory</Link>}</div>
}

function LoadingState() {
  return <div className="loading-state"><LoaderCircle size={18} />Loading records…</div>
}

function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="error-state" role="alert"><CircleAlert size={17} /><span>{message}</span>{retry && <button onClick={retry}>Retry</button>}</div>
}

function RiskBadge({ risk }: { risk: string }) {
  return <span className={`risk-chip risk-${risk.toLowerCase()}`}>{risk}</span>
}

function Score({ value }: { value: number }) {
  return <span className={`score-cell score-${value >= 75 ? 'critical' : value >= 50 ? 'high' : value >= 25 ? 'moderate' : 'low'}`}>{value}<small>/100</small></span>
}

function ExtensionsTable({ records, onSelect, onDelete, onReport, onReanalyze }: { records: ExtensionRecord[]; onSelect?: (record: ExtensionRecord) => void; onDelete?: (record: ExtensionRecord) => void; onReport?: (record: ExtensionRecord) => void; onReanalyze?: (record: ExtensionRecord) => void }) {
  if (!records.length) return <EmptyState title="No analyzed extensions"><>Upload a manifest.json or extension ZIP archive to begin a permission and privacy review.</></EmptyState>
  return <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Extension / publisher</th><th>Sector</th><th>Version</th><th>Permissions</th><th>Sensitive</th><th>Host scope</th><th>Risk score</th><th>Classification</th><th>Analyzed</th><th>Actions</th></tr></thead><tbody>
    {records.map((record) => <tr key={record.id} onClick={() => onSelect?.(record)} className={onSelect ? 'selectable-row' : ''}>
      <td><strong>{record.name}{record.is_benchmark && <span className="benchmark-label">Benchmark</span>}</strong><small>{record.publisher} · {record.extension_key}</small></td><td>{record.sector}</td><td>{record.version}</td><td>{record.permissions.all.length}</td><td>{record.permission_details.filter((item) => item.category === 'high').length}</td><td>{record.permissions.host.length + record.permissions.optional_host.length + record.permissions.content_matches.length}</td><td><Score value={record.risk_score} /></td><td><RiskBadge risk={record.risk_level} />{record.requires_review && <span className="review-label">Review</span>}</td><td>{formatDate(record.analyzed_at)}</td>
      <td className="table-actions">{onReanalyze && <button title="Reanalyze saved manifest" aria-label={`Reanalyze ${record.name}`} onClick={(event) => { event.stopPropagation(); onReanalyze(record) }}><RefreshCw size={14} /></button>}{onReport && <button title="Download report" aria-label={`Download report for ${record.name}`} onClick={(event) => { event.stopPropagation(); onReport(record) }}><ArrowDownToLine size={14} /></button>}{onDelete && <button title="Delete analysis" aria-label={`Delete ${record.name}`} onClick={(event) => { event.stopPropagation(); onDelete(record) }}><Trash2 size={14} /></button>}</td>
    </tr>)}
  </tbody></table></div>
}

function formatDate(value: string) {
  return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

function ExtensionDetail({ record, onClose, onReport }: { record: ExtensionRecord; onClose: () => void; onReport?: () => void }) {
  const findings = [
    ...record.findings,
    ...record.combinations.map((finding) => ({
      ...finding,
      explanation: finding.explanation || finding.potential_impact,
      recommendation: finding.recommended_action,
    })),
  ]
  return <div className="detail-backdrop" role="presentation" onClick={onClose}><section className="detail-drawer panel" role="dialog" aria-modal="true" aria-label={`${record.name} analysis details`} onClick={(event) => event.stopPropagation()}>
    <div className="detail-head"><div><span className="eyebrow">{record.is_benchmark ? 'SYNTHETIC BENCHMARK' : 'EXTENSION ANALYSIS'} · #{record.id}</span><h2>{record.name}</h2><p>{record.publisher} · {record.sector} · Version {record.version} · Manifest V{record.manifest_version}</p></div><button className="detail-close" onClick={onClose} aria-label="Close details"><X size={18} /></button></div>
    <div className="detail-score"><Score value={record.risk_score} /><RiskBadge risk={record.risk_level} /><span>{record.requires_review ? 'Analyst review required' : 'No configured review indicators'}</span></div>
    <div className="detail-score"><span>Privacy exposure: <b>{record.privacy_exposure_score ?? 'Not scored'}</b>/100</span><span>Purpose alignment: <b>{record.purpose_alignment_score ?? 'Not assessed'}</b>{record.purpose_alignment_score === null ? '' : '/100'}</span></div>
    <div className="detail-block"><h3>Declared access by type</h3>{([['Required permissions', record.permissions.required], ['Optional permissions', record.permissions.optional], ['Host permissions', record.permissions.host], ['Optional host permissions', record.permissions.optional_host], ['Content-script matches', record.permissions.content_matches]] as const).map(([label, permissions]) => <div className="permission-group" key={label}><strong>{label}</strong><PermissionTags values={permissions} /></div>)}</div>
    <div className="detail-block"><h3>Score contributions</h3>{Object.entries(record.score_breakdown).filter((entry): entry is [string, number] => typeof entry[1] === 'number' && entry[0] !== 'raw_score').map(([key, value]) => <div className="breakdown-row" key={key}><span>{key.replaceAll('_', ' ')}</span><b>{value}</b></div>)}</div>
    <div className="detail-block"><h3>Findings ({findings.length})</h3>{findings.length === 0 && <p className="muted-copy">No configured manifest rule findings. This is not a safety certification.</p>}{findings.map((finding, index) => <article className="finding-card" key={`${finding.title}-${index}`}><strong>{finding.title}</strong><p>{finding.explanation}</p><small>Evidence: {typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence)}</small><small>Recommended: {finding.recommendation}</small></article>)}</div>
    {record.purpose_findings.length > 0 && <div className="detail-block"><h3>Purpose alignment</h3><p className="muted-copy">{record.purpose}</p>{record.purpose_findings.map((item) => <div className="purpose-row" key={item.permission}><b>{item.permission}</b><span>{item.status}</span><p>{item.explanation}</p></div>)}</div>}
    {record.is_benchmark && <div className="detail-block"><h3>Benchmark metadata</h3><p>Synthetic fictional profile · publisher location: {record.publisher_country ?? 'Unassigned'}. This is not a real extension, publisher, user location, or threat origin.</p></div>}
    <div className="detail-block"><h3>Analysis evidence</h3><p className="hash-value">SHA-256 · {record.sha256}</p><p className="muted-copy">{formatDate(record.analyzed_at)} · Static manifest analysis; extension code is never executed.</p></div>
    {onReport && <button className="refresh-button" onClick={onReport}><FileText size={14} />Download PDF report</button>}
  </section></div>
}

function UploadForm({ onComplete }: { onComplete: (record: ExtensionRecord) => void }) {
  const fileInput = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [purpose, setPurpose] = useState('')
  const [sector, setSector] = useState('Unspecified')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [dragging, setDragging] = useState(false)
  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!file) { setError('Choose a manifest.json file or ZIP archive.'); return }
    setBusy(true)
    setError('')
    try {
      onComplete(await api.analyze(file, purpose, sector))
      setFile(null)
      setPurpose('')
      if (fileInput.current) fileInput.current.value = ''
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Analysis could not be completed.')
    } finally {
      setBusy(false)
    }
  }
  function choose(candidate?: File) {
    if (candidate) setFile(candidate)
  }
  return <form className="upload-workflow panel" onSubmit={(event) => void submit(event)}>
    <div className="upload-copy"><div className="upload-symbol"><Upload size={19} /></div><div><h2>Analyze an extension manifest</h2><p>Upload manifest.json or a ZIP archive. Files are parsed in memory; extension code is never run.</p></div></div>
    <label className={`drop-zone ${dragging ? 'drop-hover' : ''}`} onDragOver={(event) => { event.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); choose(event.dataTransfer.files[0]) }}>
      <input ref={fileInput} type="file" accept=".json,.zip,application/json,application/zip" onChange={(event) => choose(event.target.files?.[0])} />
      <Upload size={19} /><strong>{file ? file.name : 'Choose manifest.json or ZIP'}</strong><span>JSON up to 2 MB · ZIP upload up to 16 MB</span>
    </label>
    <label className="field-label">Declared purpose<input value={purpose} maxLength={2000} onChange={(event) => setPurpose(event.target.value)} placeholder="Describe the extension's intended function (optional)" /></label>
    <label className="field-label">Organization sector<select value={sector} onChange={(event) => setSector(event.target.value)}>{['Unspecified', 'Productivity', 'Shopping', 'Finance', 'Healthcare', 'Education', 'Communication', 'Entertainment', 'Developer Tools', 'Security', 'Accessibility'].map((value) => <option key={value}>{value}</option>)}</select></label>
    {error && <ErrorState message={error} />}
    <button className="refresh-button analyze-submit" type="submit" disabled={busy}>{busy ? <LoaderCircle className="spin" size={14} /> : <Search size={14} />}{busy ? 'Analyzing manifest…' : 'Analyze manifest'}</button>
  </form>
}

function useExtensions(search: string, risk = '', sector = '', page = 1) {
  const params = new URLSearchParams()
  if (search) params.set('search', search)
  if (risk) params.set('risk', risk)
  if (sector) params.set('sector', sector)
  params.set('page', String(page))
  return useResource(() => api.extensions(params.toString()), [search, risk, sector, page])
}

function InventoryPage({ item, onNotice }: PageProps) {
  const [search, setSearch] = useState('')
  const [risk, setRisk] = useState('')
  const [sort, setSort] = useState<'risk_score' | 'name' | 'analyzed_at'>('analyzed_at')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<ExtensionRecord | null>(null)
  const { data, loading, error, reload } = useExtensions(search, risk, '', page)
  const records = [...(data?.items ?? [])].sort((a, b) => sort === 'name' ? a.name.localeCompare(b.name) : sort === 'risk_score' ? b.risk_score - a.risk_score : b.analyzed_at.localeCompare(a.analyzed_at))
  async function remove(record: ExtensionRecord) {
    if (!window.confirm(`Delete analysis for “${record.name}”? This also removes its report records.`)) return
    try { await api.removeExtension(record.id); setSelected(null); reload(); onNotice('Extension analysis deleted.') } catch (failure) { onNotice(failure instanceof Error ? failure.message : 'Could not delete the analysis.') }
  }
  async function report(record: ExtensionRecord) {
    try { await api.download(`/extensions/${record.id}/report`, `browserguard-${record.id}-assessment.pdf`, 'POST'); onNotice('PDF assessment report downloaded.') } catch (failure) { onNotice(failure instanceof Error ? failure.message : 'Could not generate the report.') }
  }
  async function reanalyze(record: ExtensionRecord) {
    try { setSelected(await api.reanalyze(record.id)); reload(); onNotice(`${record.name} reanalyzed using current rules.`) } catch (failure) { onNotice(failure instanceof Error ? failure.message : 'Could not reanalyze the manifest.') }
  }
  return <><PageHeader item={item} description="Upload, search, review, and manage analyzed browser extension manifests." />
    <UploadForm onComplete={(record) => { setPage(1); reload(); setSelected(record); onNotice(`${record.name} analyzed and saved.`) }} />
    <section className="panel data-panel"><div className="data-panel-head"><div><h2>Analyzed extensions</h2><p>{data?.total ?? 0} records stored · synthetic benchmark records are labeled in the inventory</p></div><div className="table-filters"><label className="table-search"><Search size={14} /><input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} placeholder="Search extensions" /></label><label className="filter-select"><select value={risk} onChange={(event) => { setRisk(event.target.value); setPage(1) }}><option value="">All risk levels</option>{['critical', 'high', 'moderate', 'low'].map((value) => <option key={value} value={value}>{value}</option>)}</select><ChevronDown size={13} /></label><label className="filter-select"><select aria-label="Sort extensions" value={sort} onChange={(event) => setSort(event.target.value as typeof sort)}><option value="analyzed_at">Newest</option><option value="risk_score">Highest score</option><option value="name">Name</option></select></label></div></div>
      {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : <ExtensionsTable records={records} onSelect={setSelected} onDelete={(record) => void remove(record)} onReport={(record) => void report(record)} onReanalyze={(record) => void reanalyze(record)} />}
      {!!data?.pages && <div className="pagination"><span>Page {page} of {data.pages} · {data.total} records</span><button aria-label="Previous page" disabled={page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}><ChevronDown size={14} /></button><button aria-label="Next page" disabled={page >= data.pages} onClick={() => setPage((value) => value + 1)}><ChevronDown size={14} /></button></div>}
    </section>
    {selected && <ExtensionDetail record={selected} onClose={() => setSelected(null)} onReport={() => void report(selected)} />}
  </>
}

function PermissionsPage({ item }: PageProps) {
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<PermissionDetail | null>(null)
  const { data, loading, error, reload } = useResource(api.permissions)
  const entries = useMemo(() => (data?.catalog ?? []).filter((entry) => `${entry.name} ${entry.risk} ${entry.capability}`.toLowerCase().includes(search.toLowerCase())), [data, search])
  const permissionChart = (data?.catalog ?? []).filter((entry) => entry.count).sort((a, b) => (b.count ?? 0) - (a.count ?? 0)).slice(0, 10)
  const combinationChart = (data?.combinations ?? []).slice(0, 8)
  const categoryChart = ['high', 'medium', 'low', 'review'].map((category) => ({
    category,
    count: (data?.catalog ?? []).filter((entry) => entry.risk === category).reduce((sum, entry) => sum + (entry.count ?? 0), 0),
  }))
  return <><PageHeader item={item} description="Permission capabilities, privacy considerations, and manifest evidence." />
    <div className="analysis-summary"><div><span>Catalogued permissions</span><strong>{data?.catalog.length ?? '—'}</strong></div><div><span>Observed declarations</span><strong>{data ? data.permission_distribution.reduce((sum, item) => sum + item.count, 0) : '—'}</strong></div><div><span>Permission families</span><strong>{data?.combinations.length ?? '—'}</strong></div><div><span>Analyzed records</span><strong>{data?.analyses.length ?? '—'}</strong></div></div>
    <div className="intel-grid">
      <section className="panel chart-panel"><div className="data-panel-head"><div><h2>Most frequent permissions</h2><p>Actual extension-permission declarations</p></div></div><div className="intel-chart"><ResponsiveContainer width="100%" height={250}><BarChart data={permissionChart} layout="vertical" margin={{ left: 18, right: 20 }}><CartesianGrid stroke="#382d26" strokeDasharray="3 5" horizontal={false} /><XAxis type="number" allowDecimals={false} tick={{ fill: '#9e8e83', fontSize: 9 }} /><YAxis type="category" dataKey="name" width={120} tick={{ fill: '#d3c5ba', fontSize: 9 }} /><Tooltip /><Bar dataKey="count" fill="#db753e" radius={[0, 4, 4, 0]} /></BarChart></ResponsiveContainer></div></section>
      <section className="panel chart-panel"><div className="data-panel-head"><div><h2>Permission sensitivity</h2><p>Occurrences by analyzer category</p></div></div><div className="intel-chart"><ResponsiveContainer width="100%" height={250}><BarChart data={categoryChart} margin={{ left: 0, right: 12, bottom: 4 }}><CartesianGrid stroke="#382d26" strokeDasharray="3 5" vertical={false} /><XAxis dataKey="category" tick={{ fill: '#b5a69c', fontSize: 9 }} /><YAxis allowDecimals={false} tick={{ fill: '#9e8e83', fontSize: 9 }} /><Tooltip /><Bar dataKey="count" fill="#b88757" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></div></section>
    </div>
    <section className="panel data-panel"><div className="data-panel-head"><div><h2>Permission reference</h2><p>Rules are transparent heuristics; a declaration is not evidence that a capability is exercised.</p></div><label className="table-search"><Search size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search permissions" /></label></div>
      {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : entries.length ? <div className="permission-catalog">{entries.map((entry) => <button className="permission-catalog-item" key={entry.name} onClick={() => setSelected(entry)}><div><strong>{entry.name}</strong><RiskBadge risk={entry.risk ?? entry.category ?? 'review'} /></div><p>{entry.capability}</p><small>Impact: {entry.privacy_impact}</small><small>{entry.count ?? 0} occurrences · {entry.affected_extensions ?? 0} affected extensions · weight {entry.weight}</small></button>)}</div> : <EmptyState title="No matching permissions">Try another search term.</EmptyState>}
    </section>
    <section className="panel data-panel"><div className="data-panel-head"><div><h2>Observed sensitive combinations</h2><p>Configured rules found in stored extension manifests.</p></div></div><div className="combination-list">{combinationChart.map((entry) => <article key={entry.id}><strong>{entry.id.replaceAll('-', ' + ')}</strong><span>{entry.count} matching analyses</span><div className="permission-tags">{(data?.analyses ?? []).filter((record) => record.combinations.some((finding) => finding.id === entry.id)).slice(0, 4).map((record) => <span key={record.id}>{record.name}</span>)}</div></article>)}</div></section>
    <section className="panel data-panel"><div className="data-panel-head"><div><h2>Manifest observations</h2><p>Actual permission declarations from analyzed records.</p></div></div>{loading ? <LoadingState /> : error ? <ErrorState message={error} /> : <div className="permission-observations">{(data?.analyses ?? []).map((extension) => <article key={extension.id}><strong>{extension.name}</strong><span>{extension.permissions.all.length} declared permissions and origins</span><div className="permission-tags">{extension.permissions.all.map((permission) => <span key={permission}>{permission}</span>)}</div></article>)}{!data?.analyses.length && <EmptyState title="No manifest observations">Analyze an extension to see its declared permissions.</EmptyState>}</div>}</section>
    {selected && <div className="detail-backdrop" onClick={() => setSelected(null)}><section className="detail-drawer panel" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}><button className="detail-close" onClick={() => setSelected(null)} aria-label="Close permission details"><X size={18} /></button><span className="eyebrow">PERMISSION INTELLIGENCE</span><h2>{selected.name}</h2><RiskBadge risk={selected.risk ?? selected.category ?? 'review'} /><div className="detail-block"><h3>Access capability</h3><p>{selected.capability}</p></div><div className="detail-block"><h3>Potential privacy impact</h3><p>{selected.privacy_impact}</p></div><div className="detail-block"><h3>Recommended action</h3><p>{selected.recommended_action}</p></div></section></div>}
  </>
}

function RiskPage({ item }: PageProps) {
  const [risk, setRisk] = useState('')
  const [selected, setSelected] = useState<ExtensionRecord | null>(null)
  const { data, loading, error, reload } = useExtensions('', risk)
  const records = data?.items ?? []
  const scoreDistribution = [
    { band: 'Low', count: records.filter((record) => record.risk_level === 'low').length },
    { band: 'Moderate', count: records.filter((record) => record.risk_level === 'moderate').length },
    { band: 'High', count: records.filter((record) => record.risk_level === 'high').length },
    { band: 'Critical', count: records.filter((record) => record.risk_level === 'critical').length },
  ]
  const commonFindings = Object.entries(records.flatMap((record) => [...record.findings.map((finding) => finding.title), ...record.combinations.map((finding) => finding.title)]).reduce<Record<string, number>>((counts, title) => { counts[title] = (counts[title] ?? 0) + 1; return counts }, {})).sort((a, b) => b[1] - a[1]).slice(0, 6)
  return <><PageHeader item={item} description="Explainable priority scoring, rule evidence, and analyst review recommendations." />
    <div className="risk-method panel"><h2>Scoring method</h2><p>Manifest risk priority score (0–100), not a probability of malware. Weighted contributions are capped to reduce double counting: permission sensitivity ≤45, broad host scope ≤25, sensitive combinations ≤20, and purpose review ≤10.</p><div className="risk-thresholds">{[['Low', '0–24'], ['Moderate', '25–49'], ['High', '50–74'], ['Critical', '75–100']].map(([label, range]) => <span key={label}><RiskBadge risk={label.toLowerCase()} />{range}</span>)}</div></div>
    <div className="intel-grid">
      <section className="panel chart-panel"><div className="data-panel-head"><div><h2>Risk score distribution</h2><p>Counts derived from backend classifications</p></div></div><div className="intel-chart"><ResponsiveContainer width="100%" height={230}><BarChart data={scoreDistribution}><CartesianGrid stroke="#382d26" strokeDasharray="3 5" vertical={false} /><XAxis dataKey="band" tick={{ fill: '#b5a69c', fontSize: 9 }} /><YAxis allowDecimals={false} tick={{ fill: '#9e8e83', fontSize: 9 }} /><Tooltip /><Bar dataKey="count" fill="#dc713c" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></div></section>
      <section className="panel chart-panel"><div className="data-panel-head"><div><h2>Common configured findings</h2><p>Occurrences in the current record set</p></div></div><div className="finding-ranking">{commonFindings.map(([title, count]) => <div key={title}><span>{title}</span><b>{count}</b></div>)}</div></section>
    </div>
    <section className="panel data-panel"><div className="data-panel-head"><div><h2>Ranked extension assessments</h2><p>Ordered by computed backend risk score.</p></div><label className="filter-select"><select value={risk} onChange={(event) => setRisk(event.target.value)}><option value="">All risk levels</option>{['critical', 'high', 'moderate', 'low'].map((value) => <option key={value} value={value}>{value}</option>)}</select><ChevronDown size={13} /></label></div>{loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : <ExtensionsTable records={[...records].sort((a, b) => b.risk_score - a.risk_score)} onSelect={setSelected} />}</section>
    {selected && <ExtensionDetail record={selected} onClose={() => setSelected(null)} />}
  </>
}

function PurposePage({ item, onNotice }: PageProps) {
  const [selected, setSelected] = useState<ExtensionRecord | null>(null)
  const { data, loading, error, reload } = useExtensions('')
  const records = (data?.items ?? []).filter((record) => record.purpose)
  const averageAlignment = records.length ? Math.round(records.reduce((sum, record) => sum + (record.purpose_alignment_score ?? 0), 0) / records.length) : 0
  const justificationCount = records.reduce((sum, record) => sum + record.purpose_findings.filter((finding) => finding.status === 'requires_justification').length, 0)
  return <><PageHeader item={item} description="Compare an extension's stated purpose with its declared permissions using transparent keyword heuristics." />
    <div className="risk-method panel"><h2>Interpretation limits</h2><p>Matches indicate possible relevance, not necessity. Unmatched or uncatalogued permissions require analyst review; automated text comparison cannot determine whether a feature is legitimate.</p></div>
    <UploadForm onComplete={(record) => { reload(); setSelected(record); onNotice('Purpose assessment saved with manifest analysis.') }} />
    {!loading && !error && <div className="analysis-summary"><div><span>Purpose assessments</span><strong>{records.length}</strong></div><div><span>Average alignment</span><strong>{averageAlignment}/100</strong></div><div><span>Permissions to justify</span><strong>{justificationCount}</strong></div><div><span>Heuristic basis</span><strong>Keyword</strong></div></div>}
    <section className="panel data-panel">
      <div className="data-panel-head"><div><h2>Purpose assessments</h2><p>Stored purpose text, analyzer alignment score, and permission-level evidence.</p></div></div>
      {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : <div className="purpose-records">
        {records.map((record) => <button key={record.id} className="purpose-record" onClick={() => setSelected(record)}>
          <span><strong>{record.name}</strong><RiskBadge risk={record.risk_level} />{record.purpose_alignment_score === null ? <span>Not assessed</span> : <Score value={record.purpose_alignment_score} />}</span>
          <small>{record.purpose}</small>
          <span>{record.purpose_findings.filter((finding) => finding.status === 'relevant').length} possible matches · {record.purpose_findings.filter((finding) => finding.status === 'requires_justification').length} require justification · {record.purpose_findings.filter((finding) => finding.status === 'review').length} analyst reviews</span>
        </button>)}
        {!records.length && <EmptyState title="No purpose assessments">Upload a manifest and enter the extension's declared purpose to evaluate permission alignment.</EmptyState>}
      </div>}
    </section>
    {selected && <ExtensionDetail record={selected} onClose={() => setSelected(null)} />}
  </>
}

function ComparisonPage({ item }: PageProps) {
  const { data, loading, error, reload } = useExtensions('')
  const records = data?.items ?? []
  const [first, setFirst] = useState('')
  const [second, setSecond] = useState('')
  const [comparison, setComparison] = useState<Awaited<ReturnType<typeof api.compare>> | null>(null)
  const [message, setMessage] = useState('')
  const [reportBusy, setReportBusy] = useState(false)
  useEffect(() => {
    if (records.length < 2 || first || second) return
    const benchmark = records.filter((record) => record.is_benchmark).sort((a, b) => a.risk_score - b.risk_score)
    const candidates = benchmark.length >= 2 ? benchmark : [...records].sort((a, b) => a.risk_score - b.risk_score)
    setFirst(String(candidates[0].id))
    setSecond(String(candidates[candidates.length - 1].id === candidates[0].id ? candidates[1].id : candidates[candidates.length - 1].id))
  }, [records, first, second])
  useEffect(() => {
    if (!first || !second || first === second) return
    let active = true
    setMessage('')
    setComparison(null)
    api.compare([Number(first), Number(second)]).then((result) => {
      if (active) setComparison(result)
    }).catch((failure: unknown) => {
      if (active) {
        setComparison(null)
        setMessage(failure instanceof Error ? failure.message : 'Comparison failed.')
      }
    })
    return () => { active = false }
  }, [first, second])
  async function downloadComparison() {
    setReportBusy(true)
    try {
      await api.download('/compare/report', `browserguard-comparison-${first}-${second}.pdf`, 'POST', { ids: [Number(first), Number(second)] })
      setMessage('Comparison PDF downloaded and stored in Reports.')
    } catch (failure) {
      setMessage(failure instanceof Error ? failure.message : 'Comparison report could not be generated.')
    } finally {
      setReportBusy(false)
    }
  }
  const left = comparison?.extensions[0]
  const right = comparison?.extensions[1]
  const radarData = left && right ? [
    { metric: 'Risk', left: left.risk_score, right: right.risk_score },
    { metric: 'Privacy', left: left.privacy_exposure_score ?? 0, right: right.privacy_exposure_score ?? 0 },
    { metric: 'Purpose match', left: left.purpose_alignment_score ?? 0, right: right.purpose_alignment_score ?? 0 },
    { metric: 'Sensitive access', left: Math.min(100, left.permission_details.filter((permission) => permission.category === 'high').length * 15), right: Math.min(100, right.permission_details.filter((permission) => permission.category === 'high').length * 15) },
    { metric: 'Host scope', left: Math.min(100, (left.permissions.host.length + left.permissions.optional_host.length) * 20), right: Math.min(100, (right.permissions.host.length + right.permissions.optional_host.length) * 20) },
  ] : []
  const categoryData = left && right ? ['high', 'medium', 'low', 'review'].map((category) => ({
    category,
    [left.name]: left.permission_details.filter((permission) => permission.category === category).length,
    [right.name]: right.permission_details.filter((permission) => permission.category === category).length,
  })) : []
  return <><PageHeader item={item} description="Compare actual analyzed permission sets, scope, findings, and backend scores." />
    <form className="panel compare-form" onSubmit={(event) => event.preventDefault()}><label className="field-label">First extension<select required value={first} onChange={(event) => { if (event.target.value === second) setSecond(''); setFirst(event.target.value) }}><option value="">Select an analysis</option>{records.map((record) => <option value={record.id} key={record.id}>{record.name} · {record.risk_score}/100</option>)}</select></label><span className="compare-vs">VS</span><label className="field-label">Second extension<select required value={second} onChange={(event) => setSecond(event.target.value)}><option value="">Select an analysis</option>{records.map((record) => <option value={record.id} key={record.id} disabled={String(record.id) === first}>{record.name} · {record.risk_score}/100</option>)}</select></label><button className="refresh-button" type="button" disabled={!comparison || reportBusy} onClick={() => void downloadComparison()}>{reportBusy ? <LoaderCircle className="spin" size={14} /> : <FileText size={14} />}Export comparison PDF</button></form>
    {error && <ErrorState message={error} retry={reload} />}{message && <ErrorState message={message} />}
    {comparison && left && right && <><div className="comparison-cards">{comparison.extensions.map((record) => <article className="panel comparison-card" key={record.id}><span>{record.name}{record.is_benchmark && <small className="benchmark-label">Synthetic benchmark</small>} · v{record.version}</span><Score value={record.risk_score} /><RiskBadge risk={record.risk_level} /><p>{record.publisher} · {record.sector}</p><p>{record.permissions.all.length} declared permissions · {record.findings.length + record.combinations.length} configured findings</p><div className="comparison-evidence"><strong>Host access</strong><PermissionTags values={[...record.permissions.host, ...record.permissions.optional_host, ...record.permissions.content_matches]} /><strong>Combination findings</strong><PermissionTags values={record.combinations.map((finding) => finding.title)} /><strong>Privacy / purpose</strong><span>{record.privacy_exposure_score ?? 'Not scored'} / 100 · {record.purpose_alignment_score ?? 'Not assessed'}{record.purpose_alignment_score === null ? '' : ' / 100'}</span><strong>Detailed findings</strong><PermissionTags values={record.findings.map((finding) => finding.title)} /></div></article>)}</div>
      <div className="comparison-chart-grid">
        <section className="panel chart-panel"><div className="data-panel-head"><div><h2>Risk and exposure profile</h2><p>Backend score plus stored exposure scores</p></div></div><div className="intel-chart"><ResponsiveContainer width="100%" height={280}><RadarChart data={radarData}><PolarGrid stroke="#46372e" /><PolarAngleAxis dataKey="metric" tick={{ fill: '#b5a69c', fontSize: 9 }} /><Radar name={left.name} dataKey="left" stroke="#dc713c" fill="#dc713c" fillOpacity={0.24} /><Radar name={right.name} dataKey="right" stroke="#6eaa82" fill="#6eaa82" fillOpacity={0.2} /><Legend /><Tooltip /></RadarChart></ResponsiveContainer></div></section>
        <section className="panel chart-panel"><div className="data-panel-head"><div><h2>Permission category comparison</h2><p>Actual analyzer classification counts</p></div></div><div className="intel-chart"><ResponsiveContainer width="100%" height={280}><BarChart data={categoryData}><CartesianGrid stroke="#382d26" strokeDasharray="3 5" vertical={false} /><XAxis dataKey="category" tick={{ fill: '#b5a69c', fontSize: 9 }} /><YAxis allowDecimals={false} tick={{ fill: '#9e8e83', fontSize: 9 }} /><Tooltip /><Legend /><Bar dataKey={left.name} fill="#dc713c" radius={[4, 4, 0, 0]} /><Bar dataKey={right.name} fill="#6eaa82" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></div></section>
      </div>
      <div className="comparison-diff panel"><h2>Comparison summary</h2><p>{comparison.summary} Risk difference: {comparison.score_difference > 0 ? '+' : ''}{comparison.score_difference} points.</p><div className="diff-columns"><div><h3>Only {left.name}</h3><PermissionTags values={comparison.permission_differences.only_first} /></div><div><h3>Only {right.name}</h3><PermissionTags values={comparison.permission_differences.only_second} /></div><div><h3>Shared permissions</h3><PermissionTags values={comparison.permission_differences.shared} /></div></div><h3>Host scope comparison</h3><div className="diff-columns"><div><h3>Only {left.name}</h3><PermissionTags values={comparison.host_scope_differences.only_first} /></div><div><h3>Only {right.name}</h3><PermissionTags values={comparison.host_scope_differences.only_second} /></div><div><h3>Shared scope</h3><PermissionTags values={comparison.host_scope_differences.shared} /></div></div></div></>}
    {!loading && data && records.length < 2 && <EmptyState title="Not enough stored analyses">At least two analyzed extensions are required for comparison.</EmptyState>}
  </>
}

function PermissionTags({ values }: { values: string[] }) {
  return values.length ? <div className="permission-tags">{values.map((value) => <span key={value}>{value}</span>)}</div> : <p className="muted-copy">No entries.</p>
}

function SectorPage({ item }: PageProps) {
  const { data, loading, error, reload } = useResource(api.sectors)
  const [selected, setSelected] = useState('')
  const current = data?.items.find((sector) => sector.name === selected) ?? data?.items[0]
  const ext = useResource(() => api.extensions(`sector=${encodeURIComponent(current?.name ?? '')}`), [current?.name])
  useEffect(() => { if (!selected && data?.items[0]) setSelected(data.items[0].name) }, [data, selected])
  return <><PageHeader item={item} description="Review sector-specific manifest patterns from stored, classified assessments." /><p className="method-note">All sector metrics derive from persisted records. Synthetic benchmark entries are fictional and are not industry-wide risk estimates.</p>
    {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : <><div className="sector-cards">{(data?.items ?? []).map((sector) => <button className={`sector-card panel ${current?.name === sector.name ? 'selected-sector' : ''}`} key={sector.name} onClick={() => setSelected(sector.name)}><strong>{sector.name}</strong><Score value={sector.score} /><span>{sector.extensions} records · {sector.high_risk_extensions} high/critical</span><small>{sector.average_permission_count} permissions average · {sector.privacy_exposure} privacy</small></button>)}</div>{current && <section className="panel sector-details"><div className="data-panel-head"><div><h2>{current.name}</h2><p>{current.basis}</p></div><Score value={current.score} /></div><div className="analysis-summary"><div><span>Analyzed extensions</span><strong>{current.extensions}</strong></div><div><span>High-risk</span><strong>{current.high_risk_extensions}</strong></div><div><span>Critical</span><strong>{current.critical_extensions}</strong></div><div><span>Average permissions</span><strong>{current.average_permission_count}</strong></div><div><span>Privacy exposure</span><strong>{current.privacy_exposure}/100</strong></div></div><h3>Common sensitive permissions</h3><PermissionTags values={current.common_sensitive_permissions} /><h3>Sector review recommendations</h3><ul className="recommendation-list">{current.recommendations.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}</ul><h3>Permissions to consider</h3><PermissionTags values={current.relevant_permissions} /><h3>Assigned extension analyses</h3>{ext.loading ? <LoadingState /> : ext.error ? <ErrorState message={ext.error} retry={ext.reload} /> : <ExtensionsTable records={ext.data?.items ?? []} />}</section>}</>}
  </>
}

function ExposurePage({ item }: PageProps) {
  const { data, loading, error, reload } = useResource(api.overview)
  const regions = data?.regions ?? []
  return <><PageHeader item={item} description="Explore fictional publisher-location metadata assigned to synthetic benchmark records." /><div className="risk-method panel"><h2>Geographic attribution boundary</h2><p>Markers describe only fictional benchmark publisher locations. They do not represent users, hosting infrastructure, attack origins, or real-world extension publishers. Uploaded manifests have no location inferred.</p></div>{loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : <><WorldExposureMap regions={regions} notice={data?.regional_data_notice ?? 'No benchmark publisher metadata is available.'} /><section className="panel data-panel"><div className="data-panel-head"><div><h2>Publisher-location aggregates</h2><p>{regions.length} fictional countries · {regions.reduce((sum, region) => sum + region.extensions, 0)} benchmark analyses</p></div></div>{regions.length ? <div className="region-grid">{regions.map((region) => <article key={region.id}><strong>{region.name}</strong><RiskBadge risk={region.risk} /><span>{region.extensions} benchmark records · score {region.score}/100</span><small>High {region.risk_counts.high} · Critical {region.risk_counts.critical}</small></article>)}</div> : <EmptyState title="No benchmark locations">Initialize the built-in benchmark dataset to load its fictional publisher metadata.</EmptyState>}</section></>}</>
}

const checklistItems = [
  ['declared-purpose', 'The purpose and user-facing behavior are documented.'],
  ['required-access', 'Required permissions are limited to necessary capabilities.'],
  ['optional-access', 'Optional permissions are requested when a feature is used.'],
  ['host-scope', 'Host patterns are scoped to sites needed by the extension.'],
  ['retention', 'Data collection, storage, and retention are disclosed.'],
  ['user-choice', 'Users can understand and control sensitive access.'],
]

function PrivacyPage({ item }: PageProps) {
  const { data, loading, error, reload } = useExtensions('')
  const [checked, setChecked] = useState<string[]>(() => JSON.parse(localStorage.getItem('browserguard-review-checklist') ?? '[]') as string[])
  function toggle(key: string) {
    const updated = checked.includes(key) ? checked.filter((value) => value !== key) : [...checked, key]
    setChecked(updated)
    localStorage.setItem('browserguard-review-checklist', JSON.stringify(updated))
  }
  const findings = (data?.items ?? []).flatMap((record) => record.privacy_findings.map((finding) => ({ ...finding, extension: record.name })))
  const records = data?.items ?? []
  const privacyAverage = records.length ? Math.round(records.reduce((sum, record) => sum + (record.privacy_exposure_score ?? 0), 0) / records.length) : '—'
  const sensitiveCounts = ['history', 'cookies', 'scripting', 'webRequest', 'storage', 'proxy'].map((permission) => ({
    permission,
    count: records.filter((record) => record.permissions.all.includes(permission)).length,
  }))
  return <><PageHeader item={item} description="Review privacy-impact evidence, permission scope, and governance considerations." /><div className="risk-method panel"><h2>Review limitations</h2><p>This analyst checklist references data-minimization, purpose-limitation, transparency, and storage-limitation principles. It is not legal advice, a GDPR certification, or evidence of runtime data practices.</p></div>
    {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : <><div className="analysis-summary"><div><span>Average privacy exposure</span><strong>{privacyAverage}{typeof privacyAverage === 'number' ? '/100' : ''}</strong></div><div><span>Permission-linked findings</span><strong>{findings.length}</strong></div><div><span>Broad host declarations</span><strong>{records.filter((record) => record.score_breakdown.host_scope > 0).length}</strong></div><div><span>Records reviewed</span><strong>{records.length}</strong></div></div><section className="panel data-panel"><div className="data-panel-head"><div><h2>Sensitive access distribution</h2><p>Extension counts from persisted manifest declarations</p></div></div><div className="privacy-distribution">{sensitiveCounts.map((entry) => <div key={entry.permission}><strong>{entry.permission}</strong><span>{entry.count} extensions</span><i><b style={{ width: `${records.length ? entry.count / records.length * 100 : 0}%` }} /></i></div>)}</div></section></>}
    <section className="panel checklist-panel"><div className="data-panel-head"><div><h2>Privacy review checklist</h2><p>{checked.length} of {checklistItems.length} items reviewed · saved in this browser</p></div><button className="subtle-icon-button" onClick={() => { setChecked([]); localStorage.removeItem('browserguard-review-checklist') }} aria-label="Clear checklist"><X size={15} /></button></div>{checklistItems.map(([key, label]) => <label className="checklist-item" key={key}><input type="checkbox" checked={checked.includes(key)} onChange={() => toggle(key)} /><span>{label}</span><Check size={15} /></label>)}</section>
    <section className="panel data-panel"><div className="data-panel-head"><div><h2>Manifest privacy findings</h2><p>Derived from analyzed permissions and host declarations.</p></div></div>{loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : findings.length ? findings.map((finding, index) => <article className="finding-card" key={`${finding.extension}-${index}`}><strong>{finding.extension} · {finding.title}</strong><p>{finding.explanation}</p><small>{finding.recommendation}</small></article>) : <EmptyState title="No privacy findings stored">Analyze a manifest to see permission-related privacy considerations.</EmptyState>}</section>
  </>
}

function ReportsPage({ item }: PageProps) {
  const [search, setSearch] = useState('')
  const [type, setType] = useState('')
  const params = new URLSearchParams()
  if (search) params.set('search', search)
  if (type) params.set('type', type)
  const { data, loading, error, reload } = useResource(() => api.reports(params.toString()), [search, type])
  const [message, setMessage] = useState('')
  async function download(path: string, filename: string) {
    try { await api.download(path, filename); setMessage('Report downloaded.') } catch (failure) { setMessage(failure instanceof Error ? failure.message : 'Report download failed.') }
  }
  return <><PageHeader item={item} description="Search, filter, and download persisted PDF assessment and comparison reports." />{message && <p className="method-note">{message}</p>}
    <section className="panel data-panel"><div className="data-panel-head"><div><h2>Generated reports</h2><p>{data?.total ?? 0} report records stored with downloadable PDF evidence</p></div><div className="table-filters"><label className="table-search"><Search size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search extensions" /></label><label className="filter-select"><select aria-label="Filter report type" value={type} onChange={(event) => setType(event.target.value)}><option value="">All report types</option><option value="benchmark_risk_assessment">Benchmark assessment</option><option value="risk_assessment">Risk assessment</option><option value="comparison">Comparison</option></select></label></div></div>{loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : data?.items.length ? <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Report type</th><th>Extension</th><th>Generated</th><th>Action</th></tr></thead><tbody>{data.items.map((report) => <tr key={report.id}><td>{report.report_type.replaceAll('_', ' ')}</td><td>{report.extension}</td><td>{formatDate(report.created_at)}</td><td><div className="table-actions"><button title="Preview PDF" aria-label={`Preview report ${report.id}`} onClick={() => { if (!api.preview(report.download_url)) setMessage('Allow pop-ups to preview this PDF.') }}><Eye size={14} /></button><button title="Download PDF" aria-label={`Download report ${report.id}`} onClick={() => void download(report.download_url, `browserguard-${report.extension_id}-${report.report_type}.pdf`)}><ArrowDownToLine size={14} /></button></div></td></tr>)}</tbody></table></div> : <EmptyState title="No matching reports">Adjust your search or generate an assessment from an extension record.</EmptyState>}</section>
  </>
}

function ActivityPage({ item }: PageProps) {
  const isAudit = item.path === '/audit'
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const [severity, setSeverity] = useState('')
  const [message, setMessage] = useState('')
  const { data, loading, error, reload } = useResource(() => api.events(isAudit ? 'audit' : 'activity', search, category, severity), [isAudit, search, category, severity])
  const entries = data?.items ?? []
  async function exportCsv() {
    try { await api.download('/audit?format=csv', 'browserguard-audit.csv'); setMessage('Audit CSV exported.') } catch (failure) { setMessage(failure instanceof Error ? failure.message : 'Audit CSV export failed.') }
  }
  return <><PageHeader item={item} description={isAudit ? 'Persistent analyst and configuration actions recorded by the backend.' : 'Persistent manifest analysis and report activity.'} />{message && <p className="method-note" role="status">{message}</p>}
    <section className="panel data-panel"><div className="data-panel-head"><div><h2>{isAudit ? 'Audit events' : 'Activity events'}</h2><p>{data?.total ?? 0} matching persisted records</p></div><div className="table-filters"><label className="table-search"><Search size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search events" /></label><label className="filter-select"><select aria-label="Filter event category" value={category} onChange={(event) => setCategory(event.target.value)}><option value="">All categories</option>{['analysis', 'permission', 'privacy', 'risk', 'audit', 'report', 'settings', 'benchmark'].map((value) => <option key={value}>{value}</option>)}</select></label><label className="filter-select"><select aria-label="Filter event severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option>{['critical', 'high', 'moderate', 'low', 'info'].map((value) => <option key={value}>{value}</option>)}</select></label>{isAudit && <button className="refresh-button" onClick={() => void exportCsv()}><ArrowDownToLine size={13} />Export CSV</button>}</div></div>{loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : entries.length ? <div className="activity-records">{entries.map((record) => <AuditItem key={record.id} record={record} />)}</div> : <EmptyState title="No matching records">Change the search or filters to inspect other persisted events.</EmptyState>}</section>
  </>
}

function AuditItem({ record }: { record: AuditRecord }) {
  const title = record.action.replaceAll('_', ' ')
  const details = Object.entries(record.detail).map(([key, value]) => `${key.replaceAll('_', ' ')}: ${String(value)}`).join(' · ')
  return <article className="audit-record"><i className={`event-node ${record.severity}`} /><div><strong>{title} · {record.resource}</strong><p>{record.description}</p><small>{record.category} · {record.severity} · {record.result}{details ? ` · ${details}` : ''}</small></div><time>{formatDate(record.created_at)}</time></article>
}

function SettingsPage({ item, onNotice }: PageProps) {
  const { data, loading, error, reload } = useResource(api.settings)
  const [thresholds, setThresholds] = useState<Record<string, number>>({ low: 24, moderate: 49, high: 74 })
  const [weights, setWeights] = useState<Record<string, number>>({ permission_sensitivity: 45, host_scope: 25, permission_combinations: 20, purpose_alignment: 10 })
  const [permissionWeights, setPermissionWeights] = useState<Record<string, number>>({})
  const [restrictions, setRestrictions] = useState<Record<string, number>>({ upload_limit_mb: 16, manifest_limit_mb: 2, zip_entry_limit: 2000, zip_expanded_size_mb: 16 })
  const [purposeMatching, setPurposeMatching] = useState('keyword_heuristic')
  const [includeEvidence, setIncludeEvidence] = useState(true)
  const [message, setMessage] = useState('')
  useEffect(() => {
    if (!data) return
    setThresholds(data.risk_thresholds)
    setWeights(data.risk_weights)
    setPermissionWeights(Object.fromEntries(data.permission_rules.map((rule) => [rule.name, rule.weight])))
    setRestrictions(data.upload_restrictions)
    setPurposeMatching(String(data.analysis_settings.purpose_matching ?? 'keyword_heuristic'))
    setIncludeEvidence(data.report_preferences.include_manifest_evidence === true)
  }, [data])
  async function save(event: FormEvent) {
    event.preventDefault()
    try {
      await api.updateSettings({
        risk_thresholds: thresholds,
        risk_weights: weights,
        permission_weights: permissionWeights,
        upload_restrictions: restrictions,
        analysis_settings: { purpose_matching: purposeMatching, run_extension_code: false },
        report_preferences: { include_manifest_evidence: includeEvidence, format: 'pdf' },
      })
      setMessage('Risk, permission, analysis, upload, and report settings were saved.')
      onNotice('BrowserGuard settings saved.')
      reload()
    } catch (failure) { setMessage(failure instanceof Error ? failure.message : 'Settings could not be saved.') }
  }
  return <><PageHeader item={item} description="Persist score boundaries, analysis weights, permission rules, safe upload caps, and report preferences." />{loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : <form className="panel settings-form settings-stack" onSubmit={(event) => void save(event)}>
    <section><h2>Risk thresholds and contribution weights</h2><p>Stored scores do not change retroactively; reanalyze a record to apply new settings.</p><div className="threshold-fields">{[['low', 'Low maximum'], ['moderate', 'Moderate maximum'], ['high', 'High maximum']].map(([key, label]) => <label className="field-label" key={key}>{label}<input type="number" min={0} max={99} value={thresholds[key] ?? 0} onChange={(event) => setThresholds((current) => ({ ...current, [key]: Number(event.target.value) }))} /></label>)}</div><div className="threshold-fields">{Object.entries(weights).map(([key, value]) => <label className="field-label" key={key}>{key.replaceAll('_', ' ')} cap<input type="number" min={0} max={100} value={value} onChange={(event) => setWeights((current) => ({ ...current, [key]: Number(event.target.value) }))} /></label>)}</div><p className="method-note">Contribution caps must total no more than 100. Thresholds must be strictly increasing.</p></section>
    <section><h2>Permission rule weights</h2><p>Override catalog contribution weights for new analyses. Leave unchanged to use the analyzer defaults.</p><div className="rule-weight-grid">{(data?.permission_rules ?? []).map((rule) => <label className="field-label" key={rule.name}>{rule.name} · {rule.risk}<input type="number" min={0} max={50} value={permissionWeights[rule.name] ?? rule.weight} onChange={(event) => setPermissionWeights((current) => ({ ...current, [rule.name]: Number(event.target.value) }))} /></label>)}</div></section>
    <section><h2>Analysis and safe upload settings</h2><div className="settings-options"><label className="field-label">Purpose matching<select value={purposeMatching} onChange={(event) => setPurposeMatching(event.target.value)}><option value="keyword_heuristic">Keyword heuristic</option><option value="disabled">Disabled</option></select></label><div className="setting-fixed">Extension code execution <strong>Always disabled</strong><small>BrowserGuard analyzes manifests only.</small></div></div><div className="threshold-fields">{Object.entries(restrictions).map(([key, value]) => <label className="field-label" key={key}>{key.replaceAll('_', ' ')}<input type="number" min={1} max={key === 'manifest_limit_mb' ? 2 : key === 'zip_entry_limit' ? 2000 : 16} value={value} onChange={(event) => setRestrictions((current) => ({ ...current, [key]: Number(event.target.value) }))} /></label>)}</div><p className="method-note">Caps can be reduced but never raised beyond the platform limits.</p></section>
    <section><h2>Report preferences</h2><label className="checklist-item"><input type="checkbox" checked={includeEvidence} onChange={(event) => setIncludeEvidence(event.target.checked)} /><span>Include detailed manifest evidence in generated PDFs</span><Check size={15} /></label><p className="method-note">Reports are stored as downloadable PDF files in SQLite.</p></section>
    {message && <p className="method-note" role="status">{message}</p>}<button className="refresh-button" type="submit">Save all settings</button></form>}</>
}

function AboutPage({ item }: PageProps) {
  return <><PageHeader item={item} description="A static manifest review and permission intelligence tool." /><section className="panel about-card"><h2>BrowserGuard</h2><p>Browser extension manifest analysis for cybersecurity education and analyst review. The application stores uploaded manifests and analysis records locally in SQLite.</p><h3>Analysis boundaries</h3><ul><li>Manifest JSON is parsed; extension scripts are never executed.</li><li>Permission declarations represent possible capabilities, not proof of actual behavior.</li><li>Purpose matching and risk weights are configurable heuristics that require human review.</li><li>BrowserGuard does not geolocate users, certify legal compliance, or estimate malware probability.</li></ul><h3>Architecture</h3><p>React and TypeScript frontend · Flask REST API · SQLAlchemy and SQLite · Python rule-based analyzer · ReportLab PDF reports.</p><div className="about-links"><Link to="/inventory" className="refresh-button"><Upload size={14} />Analyze a manifest</Link><Link to="/risk-analysis" className="refresh-button"><ArrowUpRight size={14} />Review scoring</Link></div></section></>
}

export function FunctionalPage({ item, onNotice }: PageProps) {
  switch (item.path) {
    case '/inventory': return <InventoryPage item={item} onNotice={onNotice} />
    case '/permissions': return <PermissionsPage item={item} onNotice={onNotice} />
    case '/risk-analysis': return <RiskPage item={item} onNotice={onNotice} />
    case '/purpose-alignment': return <PurposePage item={item} onNotice={onNotice} />
    case '/comparison': return <ComparisonPage item={item} onNotice={onNotice} />
    case '/sectors': return <SectorPage item={item} onNotice={onNotice} />
    case '/exposure': return <ExposurePage item={item} onNotice={onNotice} />
    case '/privacy': return <PrivacyPage item={item} onNotice={onNotice} />
    case '/reports': return <ReportsPage item={item} onNotice={onNotice} />
    case '/activity':
    case '/audit': return <ActivityPage item={item} onNotice={onNotice} />
    case '/settings': return <SettingsPage item={item} onNotice={onNotice} />
    default: return <AboutPage item={item} onNotice={onNotice} />
  }
}
