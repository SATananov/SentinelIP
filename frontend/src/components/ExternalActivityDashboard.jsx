import { useEffect, useMemo, useRef, useState } from 'react'
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { loadInvestigationPerimeterDetail, loadPerimeterDashboard, loadPerimeterHostCorrelations } from '../services/perimeterApi.js'
import { buildReviewEvidenceContext } from '../services/reviewEvidenceContext.js'
import InvestigationPivotActions from './InvestigationPivotActions.jsx'
import { explicitRecordPivots } from '../services/investigationPivots.js'

function formatObserved(value) {
  if (!value) return '—'
  return value.replace('T', ' ').replace('+00:00', ' UTC')
}

function formatBucket(value) {
  return value ? value.slice(5, 13).replace('T', ' ') : ''
}

const PERIMETER_DETAIL_FIELDS = [
  ['event_type', 'Event type'], ['detection_type', 'Detection type'], ['correlation_type', 'Correlation type'],
  ['state', 'State'], ['confidence', 'Confidence'], ['site_id', 'Site ID'], ['scope_id', 'Scope ID'],
  ['device_id', 'Device ID'], ['source_ip', 'Source IP'], ['destination_ip', 'Destination IP'],
  ['destination_port', 'Destination port'], ['direction', 'Direction'], ['action', 'Action'],
  ['protocol', 'Protocol'], ['observed_at', 'Observed'], ['first_seen', 'First seen'], ['last_seen', 'Last seen'],
]

function ExternalActivityDashboard({ refreshSignal, onStartReview, reviewIntakeSubmitting = false,
  investigationRequest = null, onOpenInvestigationContext = null }) {
  const [data, setData] = useState(null)
  const [siteId, setSiteId] = useState('')
  const [sourceType, setSourceType] = useState('')
  const [timeRange, setTimeRange] = useState('24h')
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [hostResult, setHostResult] = useState(null)
  const [hostError, setHostError] = useState(null)
  const [investigationDetail, setInvestigationDetail] = useState(null)
  const [investigationDetailError, setInvestigationDetailError] = useState('')
  const investigationGeneration = useRef(0)

  useEffect(() => {
    const request = investigationRequest
    if (!request) return undefined
    const supported = ['PERIMETER_EVENT', 'PERIMETER_DETECTION', 'PERIMETER_POLICY_CORRELATION', 'PERIMETER_HOST_CORRELATION']
    const generation = ++investigationGeneration.current
    const controller = new AbortController()
    if (!supported.includes(request.kind)) return () => controller.abort()
    if (request.item?.site_id) {
      queueMicrotask(() => {
        if (investigationGeneration.current === generation) setSiteId(String(request.item.site_id))
      })
    }
    loadInvestigationPerimeterDetail(request.kind, request.id, controller.signal)
      .then((record) => {
        if (!controller.signal.aborted && investigationGeneration.current === generation) {
          setInvestigationDetail({ kind: request.kind, id: request.id, record, nonce: request.nonce })
        }
      })
      .catch((error) => {
        if (!controller.signal.aborted && investigationGeneration.current === generation && error.name !== 'AbortError') {
          setInvestigationDetailError({ nonce: request.nonce, message: error.message || 'Perimeter detail is unavailable.' })
        }
      })
    return () => controller.abort()
  }, [investigationRequest])

  useEffect(() => {
    const controller = new AbortController()
    loadPerimeterHostCorrelations({ siteId, limit: 8, offset: 0 }, controller.signal)
      .then((result) => { if (!controller.signal.aborted) {
        setHostResult({ siteId, correlations: result.correlations })
        setHostError(null)
      } })
      .catch((err) => { if (!controller.signal.aborted && err.name !== 'AbortError') setHostError({ siteId, message: err.message }) })
    return () => controller.abort()
  }, [siteId])

  const filters = useMemo(() => ({
    siteId,
    sourceType,
    timeRange,
  }), [siteId, sourceType, timeRange])

  useEffect(() => {
    const controller = new AbortController()

    async function load() {
      setLoading(true)
      setError(null)
      try {
        setData(await loadPerimeterDashboard(filters, controller.signal))
      } catch (err) {
        if (err.name !== 'AbortError') setError(err.message)
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }

    load()
    return () => controller.abort()
  }, [filters, refreshSignal])

  const summary = data?.summary || {}
  const options = data?.options || { sites: [], source_types: [] }
  const hostLoading = hostResult?.siteId !== siteId && hostError?.siteId !== siteId
  const hostCorrelations = hostResult?.siteId === siteId ? hostResult.correlations : []

  return (
    <section className="panel external-activity-panel" id="external-activity">
      <div className="panel-heading external-activity-heading">
        <div>
          <p className="panel-kicker">Perimeter Monitoring</p>
          <h2>External Activity</h2>
          <p className="external-activity-note">
            Factual inbound perimeter evidence for review. Activity is not automatically classified as an attack or compromise.
          </p>
        </div>
        <span className="panel-count">{loading ? '…' : summary.inbound_total || 0}</span>
      </div>

      <div className="external-filters">
        <label>
          <span>Site</span>
          <select value={siteId} onChange={(event) => setSiteId(event.target.value)}>
            <option value="">All sites</option>
            {options.sites.map((site) => (
              <option key={site.id} value={site.id}>{site.name}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Source</span>
          <select value={sourceType} onChange={(event) => setSourceType(event.target.value)}>
            <option value="">All sources</option>
            {options.source_types.map((source) => (
              <option key={source} value={source}>{source}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Window</span>
          <select value={timeRange} onChange={(event) => setTimeRange(event.target.value)}>
            <option value="1h">1 hour</option>
            <option value="6h">6 hours</option>
            <option value="24h">24 hours</option>
            <option value="72h">72 hours</option>
            <option value="7d">7 days</option>
            <option value="all">All evidence</option>
          </select>
        </label>
      </div>

      {error && <div className="error-box">{error}</div>}
      {investigationDetailError?.nonce === investigationRequest?.nonce && <div className="error-box" role="alert">{investigationDetailError.message}</div>}
      {investigationDetail?.nonce === investigationRequest?.nonce && <aside className="investigation-domain-detail" aria-label="Selected perimeter record">
        <div className="panel-heading"><h3>{investigationDetail.kind.replaceAll('_', ' ')} · {investigationDetail.id}</h3>
          <button type="button" onClick={() => setInvestigationDetail(null)}>Close detail</button></div>
        <dl>{PERIMETER_DETAIL_FIELDS.filter(([key]) => {
          const value = investigationDetail.record?.[key]
          return (typeof value === 'string' || typeof value === 'number') && value !== ''
        }).map(([key, label]) => <div key={key}><dt>{label}</dt><dd>{investigationDetail.record[key]}</dd></div>)}</dl>
        <InvestigationPivotActions pivots={explicitRecordPivots(investigationDetail.kind, investigationDetail.record)}
          onNavigate={onOpenInvestigationContext} />
      </aside>}

      <div className="external-summary-grid">
        <article><span>Inbound</span><strong>{summary.inbound_total || 0}</strong></article>
        <article><span>Blocked</span><strong>{summary.blocked || 0}</strong></article>
        <article><span>Rejected</span><strong>{summary.rejected || 0}</strong></article>
        <article><span>Allowed</span><strong>{summary.allowed || 0}</strong></article>
        <article><span>Unique Sources</span><strong>{summary.unique_sources || 0}</strong></article>
        <article><span>Host Linked</span><strong>{summary.host_linked || 0}</strong></article>
        <article><span>Repeated Signals</span><strong>{summary.repeated_detections || 0}</strong></article>
        <article><span>Policy Changes</span><strong>{summary.policy_correlations || 0}</strong></article>
      </div>

      <div className="external-dashboard-grid">
        <article className="external-subpanel external-chart-panel">
          <h3>Inbound timeline</h3>
          {data?.timeline?.length ? (
            <div className="external-chart">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data.timeline}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#2b303a" />
                  <XAxis dataKey="bucket" tickFormatter={formatBucket} stroke="#7f8798" />
                  <YAxis allowDecimals={false} stroke="#7f8798" />
                  <Tooltip contentStyle={{ background: '#15181f', border: '1px solid #343a46', borderRadius: '8px' }} />
                  <Legend />
                  <Line type="monotone" dataKey="blocked" name="Blocked" stroke="#e45865" dot={false} />
                  <Line type="monotone" dataKey="rejected" name="Rejected" stroke="#e9ad46" dot={false} />
                  <Line type="monotone" dataKey="allowed" name="Allowed" stroke="#5d8eff" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : <p className="empty-state">No inbound timeline data.</p>}
        </article>

        <article className="external-subpanel">
          <h3>Top external sources</h3>
          <div className="external-list">
            {data?.top_sources?.length ? data.top_sources.map((item) => (
              <div className="external-list-row" key={item.source_ip}>
                <span className="mono">{item.source_ip}</span>
                <strong>{item.total}</strong>
                <small>{item.blocked} blocked · {item.allowed} allowed</small>
              </div>
            )) : <p className="empty-state">No external source data.</p>}
          </div>
        </article>

        <article className="external-subpanel">
          <h3>Top destination ports</h3>
          <div className="external-list">
            {data?.top_ports?.length ? data.top_ports.map((item) => (
              <div className="external-list-row" key={`${item.protocol}-${item.destination_port}`}>
                <span>{item.protocol} <b className="mono">{item.destination_port}</b></span>
                <strong>{item.total}</strong>
              </div>
            )) : <p className="empty-state">No destination-port data.</p>}
          </div>
        </article>

        <article className="external-subpanel">
          <h3>Repeated inbound review</h3>
          <div className="external-list">
            {data?.repeated_detections?.length ? data.repeated_detections.map((item) => (
              <div className="external-list-row" key={item.id}>
                <span className="mono">{item.source_ip} → {item.destination_ip}:{item.destination_port || '—'}</span>
                <strong>{item.event_count} events</strong>
                <small>{item.site_name} · {item.action}</small>
                {Number.isSafeInteger(item.id) && item.id > 0 && <button className="security-detail-close" type="button"
                  disabled={reviewIntakeSubmitting}
                  onClick={() => onStartReview?.(buildReviewEvidenceContext('PERIMETER_DETECTION', item))}>Start Review</button>}
              </div>
            )) : <p className="empty-state">No repeated-attempt review signals.</p>}
          </div>
        </article>

        <article className="external-subpanel external-wide">
          <h3>Policy correlations</h3>
          <div className="external-list">
            {data?.policy_correlations?.length ? data.policy_correlations.map((item) => (
              <div className="external-list-row external-policy-row" key={item.id}>
                <span>{item.correlation_type.replaceAll('_', ' ')}</span>
                <span className="mono">{item.source_ip} → {item.destination_ip}:{item.destination_port || '—'}</span>
                <small>{item.site_name} · {item.allow_count} allowed · {item.blocked_count} blocked</small>
                {Number.isSafeInteger(item.id) && item.id > 0 && <button className="security-detail-close" type="button"
                  disabled={reviewIntakeSubmitting}
                  onClick={() => onStartReview?.(buildReviewEvidenceContext('PERIMETER_POLICY_CORRELATION', item))}>Start Review</button>}
              </div>
            )) : <p className="empty-state">No policy-transition correlations.</p>}
          </div>
        </article>

        <article className="external-subpanel external-wide">
          <h3>Host correlations</h3>
          {hostError?.siteId === siteId && <div className="error-box" role="alert">{hostError.message}</div>}
          {hostLoading ? <p className="empty-state">Loading host correlations…</p>
            : hostCorrelations.length === 0 ? <p className="empty-state">No host correlations.</p>
              : <div className="external-list">
                {hostCorrelations.map((item) => <div className="external-list-row" key={item.id}>
                  <span>Site #{item.site_id} · Device #{item.device_id}</span>
                  <strong>{item.correlation_type.replaceAll('_', ' ')}</strong>
                  <small>{item.destination_ip}:{item.destination_port || '—'} · {formatObserved(item.observed_at)}</small>
                  {Number.isSafeInteger(item.id) && item.id > 0 && <button className="security-detail-close" type="button"
                    disabled={reviewIntakeSubmitting}
                    onClick={() => onStartReview?.(buildReviewEvidenceContext('PERIMETER_HOST_CORRELATION', item))}>Start Review</button>}
                </div>)}
              </div>}
        </article>

        <article className="external-subpanel external-wide">
          <h3>Recent inbound activity</h3>
          <div className="external-activity-table-wrap">
            <table className="external-activity-table">
              <thead><tr><th>Time</th><th>Site / Source</th><th>Remote</th><th>Destination</th><th>Action</th><th>Host</th></tr></thead>
              <tbody>
                {data?.recent_activity?.map((item) => (
                  <tr key={item.id}>
                    <td>{formatObserved(item.observed_at)}</td>
                    <td>{item.site_name}<small>{item.source_type}</small></td>
                    <td className="mono">{item.source_ip}</td>
                    <td className="mono">{item.destination_ip}:{item.destination_port || '—'} <small>{item.protocol}</small></td>
                    <td><span className={`external-action action-${item.action.toLowerCase()}`}>{item.action}</span></td>
                    <td>{item.device_id ? <><strong>#{item.device_id}</strong><small>{item.device_hostname || item.device_vendor || 'Inventory device'}</small></> : <span className="muted">Not linked</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data?.recent_activity?.length && <p className="empty-state">No recent inbound activity.</p>}
          </div>
        </article>
      </div>
    </section>
  )
}

export default ExternalActivityDashboard
