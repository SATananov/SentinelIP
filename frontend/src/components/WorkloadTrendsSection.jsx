import { useEffect, useRef, useState } from 'react'
import {
  CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'

import { loadIncidentReviewTrends } from '../services/securityApi.js'
import { formatSiteWorkloadAge } from '../services/incidentReviewFormat.js'
import { createOperationsRequestGuard } from '../services/incidentReviewRequestGuard.js'

const AGE_LABELS = { LT_1H: '< 1h', H1_24: '1h–24h', D1_3: '1d–3d', D3_7: '3d–7d', GT_7D: '> 7d' }
const WINDOWS = ['24h', '7d', '30d', '90d']

function formatTrendTick(value, window) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return window === '24h'
    ? new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }).format(date)
    : new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' }).format(date)
}

function WorkloadTrendsSection({ refreshSignal }) {
  const [expanded, setExpanded] = useState(false)
  const [window, setWindow] = useState('30d')
  const [request, setRequest] = useState({ data: null, dataKey: null, error: null, errorKey: null, loading: false, loadingKey: null })
  const requestKey = window
  const requestGuard = useRef(createOperationsRequestGuard())

  useEffect(() => {
    if (!expanded) return undefined
    const guard = requestGuard.current
    const generation = guard.begin('trends')
    const controller = new AbortController()
    Promise.resolve()
      .then(() => {
        if (controller.signal.aborted) return null
        setRequest((current) => ({ ...current, error: null, errorKey: null, loading: true, loadingKey: requestKey }))
        return loadIncidentReviewTrends(window, controller.signal)
      })
      .then((data) => {
        if (!controller.signal.aborted && guard.isCurrent('trends', generation) && data) setRequest({ data, dataKey: requestKey, error: null, errorKey: null, loading: false, loadingKey: requestKey })
      })
      .catch((error) => {
        if (!controller.signal.aborted && guard.isCurrent('trends', generation) && error.name !== 'AbortError') {
          setRequest((current) => ({ ...current, error: error.message, errorKey: requestKey, loading: false, loadingKey: requestKey }))
        }
      })
      .finally(() => {
        if (!controller.signal.aborted && guard.isCurrent('trends', generation)) setRequest((current) => ({ ...current, loading: false }))
      })
    return () => { controller.abort(); guard.invalidate('trends') }
  }, [expanded, window, requestKey, refreshSignal])

  const trendData = request.dataKey === requestKey ? request.data : null
  const trendError = request.errorKey === requestKey ? request.error : null
  const trendLoading = request.loadingKey === requestKey ? request.loading : expanded && !trendData && !trendError
  const snapshot = trendData?.current_snapshot

  return (
    <details className="review-workload-trends review-secondary-section" onToggle={(event) => setExpanded(event.currentTarget.open)}>
      <summary><h3>Workload Trends</h3></summary>
      <p className="security-layer-copy">Closure and reopen series reflect recorded workflow events. Current workload and aging are present-state values.</p>
      <label className="review-secondary-control"><span>Time window</span><select value={window} onChange={(event) => setWindow(event.target.value)}>
        {WINDOWS.map((value) => <option key={value} value={value}>{value}</option>)}
      </select></label>
      {trendError && <div className="error-box">{trendError}</div>}
      {trendLoading && trendData && <p className="security-layer-copy" role="status">Updating workload trends…</p>}
      {trendLoading && !trendData ? <p className="security-empty">Loading workload trends…</p>
        : trendError && !trendData ? null : trendData && <>
          <p className="security-layer-copy">Historical activity · {trendData.window_start.replace('T', ' ').replace('+00:00', 'Z')} to {trendData.window_end.replace('T', ' ').replace('+00:00', 'Z')} UTC</p>
          <div className="review-trend-chart" role="img" aria-label={`Historical review workload trends for ${trendData.window}`}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendData.series} margin={{ top: 8, right: 18, bottom: 4, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#303642" />
                <XAxis dataKey="bucket_start" tickFormatter={(value) => formatTrendTick(value, trendData.window)} minTickGap={24} stroke="#8d95a5" />
                <YAxis allowDecimals={false} width={36} stroke="#8d95a5" />
                <Tooltip labelFormatter={(value) => `${formatTrendTick(value, trendData.window)} UTC`} />
                <Legend />
                <Line type="monotone" dataKey="reviews_created" name="Reviews Created" stroke="#70a7ff" dot={false} isAnimationActive={false} />
                <Line type="monotone" dataKey="review_close_events" name="Review Closures" stroke="#64c9a5" dot={false} isAnimationActive={false} />
                <Line type="monotone" dataKey="review_reopen_events" name="Review Reopens" stroke="#d6ae62" dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="review-trend-current">
            <section aria-labelledby="review-current-workload-title"><h4 id="review-current-workload-title">Current Workload</h4>
              <div className="review-trend-cards">
                {[['Open', 'open_count'], ['In Review', 'in_review_count'], ['Closed', 'closed_count'], ['Unresolved', 'unresolved_count'], ['Needs Attention', 'reviews_needing_attention'], ['Oldest Active Review', 'oldest_active_age_seconds']].map(([label, key]) => <article key={key}><span>{label}</span><strong>{key === 'oldest_active_age_seconds' ? (snapshot[key] === null ? '—' : formatSiteWorkloadAge(snapshot[key])) : snapshot[key]}</strong></article>)}
              </div>
              {snapshot.open_count + snapshot.in_review_count + snapshot.closed_count === 0 && <p className="security-empty">No reviews in the current workload snapshot.</p>}
            </section>
            <section aria-labelledby="review-current-aging-title"><h4 id="review-current-aging-title">Current Aging</h4>
              <div className="review-trend-aging">{Object.entries(snapshot.age_buckets).map(([key, count]) => <article key={key}><span>{AGE_LABELS[key]}</span><strong>{count}</strong></article>)}</div>
            </section>
          </div>
        </>}
    </details>
  )
}

export default WorkloadTrendsSection
