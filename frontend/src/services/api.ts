const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '/api'

export interface PermissionDetail {
  name: string
  source?: string
  category?: string
  risk?: string
  capability: string
  privacy_impact: string
  why_it_matters: string
  recommended_action: string
  weight: number
  count?: number
  affected_extensions?: number
}

export interface CombinationFinding {
  id: string
  title: string
  permissions: string[]
  explanation: string
  potential_impact: string
  evidence: Record<string, unknown>
  recommended_action: string
  weight: number
}

export interface Finding {
  kind: string
  severity: string
  title: string
  evidence: string | Record<string, unknown>
  explanation: string
  recommendation: string
}

export interface ExtensionRecord {
  id: number
  name: string
  version: string
  manifest_version: number
  description: string
  original_filename: string
  sha256: string
  extension_key: string
  purpose: string
  sector: string
  publisher: string
  publisher_country: string | null
  publisher_latitude: number | null
  publisher_longitude: number | null
  is_benchmark: boolean
  privacy_exposure_score: number | null
  purpose_alignment_score: number | null
  manifest: Record<string, unknown>
  permissions: {
    required: string[]
    optional: string[]
    host: string[]
    optional_host: string[]
    content_matches: string[]
    all: string[]
  }
  permission_details: PermissionDetail[]
  findings: Finding[]
  combinations: CombinationFinding[]
  purpose_findings: Array<{ permission: string; status: string; explanation: string }>
  privacy_findings: Finding[]
  score_breakdown: {
    permission_sensitivity: number
    host_scope: number
    permission_combinations: number
    purpose_alignment: number
    raw_score: number
    method: string
    thresholds: Record<string, number>
  }
  risk_score: number
  risk_level: string
  requires_review: boolean
  analyzed_at: string
}

export interface OverviewData {
  extensions_analysed: number
  risk_counts: Record<string, number>
  permission_anomalies: number
  privacy_exposure_index: number
  critical_findings: number
  high_risk_findings: number
  reports_generated: number
  extensions_requiring_review: number
  risk_distribution: Array<{ name: string; value: number; color: string }>
  permission_categories: Array<{ name: string; value: number }>
  frequent_permissions: Array<{ name: string; count: number; category: string }>
  recent_extensions: ExtensionRecord[]
  activity: AuditRecord[]
  regions: Array<{ id: string; name: string; x: number; y: number; extensions: number; score: number; risk: string; risk_counts: Record<string, number>; basis: string }>
  regional_data_notice: string
  sector_risk: SectorRecord[]
  trend: Array<{ day: string; value: number }>
}

export interface AuditRecord {
  id: number
  extension_id: number | null
  action: string
  detail: Record<string, unknown>
  category: string
  severity: string
  result: string
  description: string
  resource: string
  created_at: string
}

export interface SectorRecord {
  name: string
  extensions: number
  score: number
  relevant_permissions: string[]
  high_risk_extensions: number
  critical_extensions: number
  average_permission_count: number
  privacy_exposure: number
  common_sensitive_permissions: string[]
  recommendations: string[]
  basis: string
}

export interface HealthStatus {
  status: string
  service: string
  database: { status: string; error?: string }
  database_counts: Record<string, number>
  api_version: string
}

export interface SettingsData {
  risk_thresholds: Record<string, number>
  risk_weights: Record<string, number>
  permission_weights: Record<string, number>
  analysis_settings: Record<string, unknown>
  report_preferences: Record<string, unknown>
  upload_restrictions: Record<string, number>
  permission_rules: Array<{ name: string; risk: string; weight: number; capability: string }>
}

export interface PagedExtensions {
  items: ExtensionRecord[]
  page: number
  per_page: number
  total: number
  pages: number
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, init)
  } catch {
    throw new Error('Cannot reach the BrowserGuard API. Start the Flask backend and retry.')
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { error?: string } | null
    throw new Error(body?.error ?? `Request failed (${response.status}).`)
  }
  return response.json() as Promise<T>
}

export const api = {
  health: () => request<HealthStatus>('/health'),
  overview: (range: '24h' | '7d' | '30d' = '7d') => request<OverviewData>(`/overview?range=${range}`),
  extensions: (params = '') => request<PagedExtensions>(`/extensions${params ? `?${params}` : ''}`),
  extension: (id: number) => request<ExtensionRecord>(`/extensions/${id}`),
  analyze: (file: File, purpose: string, sector: string) => {
    const body = new FormData()
    body.append('file', file)
    body.append('purpose', purpose)
    body.append('sector', sector)
    return request<ExtensionRecord>('/analyze', { method: 'POST', body })
  },
  removeExtension: (id: number) => request<{ deleted: boolean }>(`/extensions/${id}`, { method: 'DELETE' }),
  reanalyze: (id: number) => request<ExtensionRecord>(`/extensions/${id}/reanalyze`, { method: 'POST' }),
  compare: (ids: number[]) => request<{
    extensions: ExtensionRecord[]
    permission_differences: { only_first: string[]; only_second: string[]; shared: string[] }
    host_scope_differences: { only_first: string[]; only_second: string[]; shared: string[] }
    score_difference: number
    privacy_exposure: [number | null, number | null]
    purpose_alignment: [number | null, number | null]
    summary: string
  }>('/compare', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }) }),
  permissions: () => request<{
    catalog: PermissionDetail[]
    analyses: ExtensionRecord[]
    permission_distribution: Array<{ name: string; count: number; category: string }>
    combinations: Array<{ id: string; count: number }>
  }>('/permissions'),
  sectors: () => request<{ items: SectorRecord[]; methodology: string }>('/sectors'),
  events: (kind: 'activity' | 'audit', search = '', category = '', severity = '') => {
    const params = new URLSearchParams()
    if (search) params.set('search', search)
    if (category) params.set('category', category)
    if (severity) params.set('severity', severity)
    const query = params.toString()
    return request<{ items: AuditRecord[]; total: number }>(`/${kind}${query ? `?${query}` : ''}`)
  },
  reports: (params = '') => request<{ items: Array<{ id: number; extension_id: number; extension: string; report_type: string; created_at: string; download_url: string }>; total: number }>(`/reports${params ? `?${params}` : ''}`),
  settings: () => request<SettingsData>('/settings'),
  updateSettings: (values: Record<string, unknown>) => request<Record<string, unknown>>('/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(values) }),
  async download(path: string, filename: string, method: 'GET' | 'POST' = 'GET', body?: unknown) {
    let response: Response
    try {
      response = await fetch(`${API_BASE}${path}`, {
        method,
        headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      })
    } catch {
      throw new Error('Cannot reach the BrowserGuard API. Start the Flask backend and retry.')
    }
    if (!response.ok) {
      const body = await response.json().catch(() => null) as { error?: string } | null
      throw new Error(body?.error ?? `Download failed (${response.status}).`)
    }
    const url = URL.createObjectURL(await response.blob())
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  },
  preview(path: string) {
    const preview = window.open(`${API_BASE}${path}?inline=1`, '_blank')
    if (preview) preview.opener = null
    return preview
  },
}
