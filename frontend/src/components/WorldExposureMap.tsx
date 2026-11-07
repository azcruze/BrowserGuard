import { useMemo, useState } from 'react'
import { Crosshair, Minus, Plus } from 'lucide-react'

const continents = [
  'M89 88l23-19 31 4 14 15 34 3 11 15-16 13-7 21-18 6-7 23-19 10-12-7-10 10-8-17-15-6-4-22-17-10 5-18-14-10z',
  'M180 190l18 6 8 17-3 17 12 13-6 28-14 17-6 31-15 24-10-13 3-25-10-23 4-23-8-24 8-20-4-21z',
  'M364 90l23-11 20 8 14-4 14 12 23-1 7 12-10 10-20-2-12 12-17 1-7 12-22-4-15-15-21 2-12-11 7-14z',
  'M408 139l21 6 15 18-3 22 13 14-5 24-16 23-7 31-12 10-12-15 5-21-9-24 7-17-12-20 1-28z',
  'M473 94l22-18 34 5 17 16 24-4 27 13 31-6 20 14-5 17-26 3-7 16-21 8-18-7-17 12-20-3-7 19-17 8-14-14-19 3-14-16-21 4-9-17 11-16-8-16 17-12z',
  'M647 250l25-9 24 6 11 18-12 17-28 4-22-13z',
]

interface Props {
  regions: Array<{
    id: string
    name: string
    x?: number
    y?: number
    risk: string
    extensions: number
    score: number
    risk_counts?: Record<string, number>
    basis?: string
  }>
  notice: string
}

export function WorldExposureMap({ regions, notice }: Props) {
  const [selected, setSelected] = useState<Props['regions'][number] | null>(null)
  const [zoom, setZoom] = useState(1)
  const [riskFilter, setRiskFilter] = useState('all')
  const visibleRegions = useMemo(() => regions.filter((region) => riskFilter === 'all' || region.risk === riskFilter), [regions, riskFilter])

  return (
    <section className="panel map-panel">
      <div className="panel-heading map-heading">
        <div className="title-cluster">
          <div className="panel-icon globe-icon"><Crosshair size={19} /></div>
          <div>
              <h2>Global exposure map</h2>
              <p>Fictional benchmark publisher metadata · not threat origins</p>
          </div>
        </div>
        <div className="map-legend" aria-label="Risk level legend">
              {regions.length > 0 && (['critical', 'high', 'moderate', 'low'] as const).map((level) => (
            <span key={level}><i className={`legend-dot ${level}`} />{level}</span>
          ))}
              <select aria-label="Filter publisher locations by risk" value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}>
                <option value="all">All risks</option>
                {['critical', 'high', 'moderate', 'low'].map((level) => <option value={level} key={level}>{level}</option>)}
              </select>
        </div>
      </div>
      <div className="map-canvas">
        <div className="map-grid" />
        <svg className="world-map" viewBox="0 0 760 370" role="img" aria-label="World map with fictional benchmark publisher locations, not threat origins.">
          <defs>
            <pattern id="mapTexture" width="7" height="7" patternUnits="userSpaceOnUse">
              <path d="M0 6L6 0" stroke="#594438" strokeWidth=".45" opacity=".34" />
            </pattern>
          </defs>
          <g transform={`translate(${380 - 380 * zoom} ${185 - 185 * zoom}) scale(${zoom})`}>
            {continents.map((path) => (
              <g key={path}>
                <path d={path} fill="#27231f" stroke="#564238" strokeWidth="1.2" />
                <path d={path} fill="url(#mapTexture)" opacity=".7" />
              </g>
            ))}
            <path d="M0 125h760M0 185h760M0 245h760M190 0v370M380 0v370M570 0v370" className="map-lines" />
            {visibleRegions.map((region) => (
              <g
                key={region.id}
                className={`map-marker-group ${selected?.id === region.id ? 'selected' : ''}`}
                transform={`translate(${(region.x ?? 50) * 7.6} ${(region.y ?? 50) * 3.7})`}
                role="button"
                tabIndex={0}
                aria-label={`Select ${region.name}: ${region.extensions} benchmark publishers, ${region.risk} risk`}
                onClick={() => setSelected(region)}
                onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelected(region) } }}
              >
                <circle r="25" className={`marker-halo ${region.risk}`} />
                <circle r="15" className={`marker-pulse ${region.risk}`} />
                <circle r="8" className={`marker-core ${region.risk}`} />
              </g>
            ))}
          </g>
        </svg>
        <div className="map-zoom" aria-label="Map controls">
          <button type="button" aria-label="Zoom in" onClick={() => setZoom((current) => Math.min(1.45, current + 0.15))}><Plus size={17} /></button>
          <button type="button" aria-label="Zoom out" onClick={() => setZoom((current) => Math.max(0.85, current - 0.15))}><Minus size={17} /></button>
          <button type="button" aria-label="Reset map zoom" onClick={() => setZoom(1)}><Crosshair size={15} /></button>
        </div>
        <div className={`region-tooltip ${selected ? '' : 'no-region'}`} aria-live="polite">
          {selected ? <>
            <strong>{selected.name}</strong>
            <span>Risk level: <b className={`text-${selected.risk === 'moderate' ? 'medium' : selected.risk}`}>{selected.risk}</b></span>
            <span>Benchmark extensions: <b>{selected.extensions}</b></span>
            <span>Exposure score: <b>{selected.score}/100</b></span>
            <span>High / critical: <b>{(selected.risk_counts?.high ?? 0) + (selected.risk_counts?.critical ?? 0)}</b></span>
            {selected.basis && <span>{selected.basis}</span>}
          </> : <><strong>No regional records</strong><span>{notice}</span></>}
        </div>
        <span className="map-disclaimer">Synthetic publisher metadata only. No user or threat origin is inferred.</span>
      </div>
    </section>
  )
}
