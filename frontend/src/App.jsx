import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
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

import SecurityReviewPanel from './components/SecurityReviewPanel.jsx'
import NetworkWorkspace from './components/NetworkWorkspace.jsx'
import RemoteSensorFleet from './components/RemoteSensorFleet.jsx'
import ExternalActivityDashboard from './components/ExternalActivityDashboard.jsx'
import ExternalExposureDashboard from './components/ExternalExposureDashboard.jsx'
import InvestigationLookup from './components/InvestigationLookup.jsx'
import DataLifecycle from './components/DataLifecycle.jsx'
import { createInvestigationNavigationRequest, investigationPanelForKind } from './services/investigationNavigation.js'
import {
  clearReviewIntakeRequest,
  createReviewIntakeRequest,
  isValidReviewEvidenceContext,
} from './services/reviewEvidenceContext.js'

import './App.css'

const API_BASE = 'http://127.0.0.1:8000'

function App() {
  const reviewIntakeToken = useRef(0)
  const [reviewIntakeRequest, setReviewIntakeRequest] = useState(null)
  const [reviewIntakeSubmitting, setReviewIntakeSubmitting] = useState(false)
  const [investigationNavigation, setInvestigationNavigation] = useState(null)
  const investigationNavigationNonce = useRef(0)
  const [health, setHealth] = useState(null)

  const [overview, setOverview] = useState({
    total_events: 0,
    severity: {
      INFO: 0,
      WARNING: 0,
      ALERT: 0,
    },
    top_ips: [],
    event_types: [],
  })

  const [alerts, setAlerts] = useState([])
  const [events, setEvents] = useState([])
  const [eventsTotal, setEventsTotal] = useState(0)
  const [timeline, setTimeline] = useState([])
  const [sourceIps, setSourceIps] = useState([])

  const [error, setError] = useState(null)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const startReviewFromEvidence = useCallback((evidence) => {
    if (reviewIntakeSubmitting || !isValidReviewEvidenceContext(evidence)) return
    reviewIntakeToken.current += 1
    setReviewIntakeRequest(createReviewIntakeRequest(reviewIntakeToken.current, evidence))
  }, [reviewIntakeSubmitting])

  const clearReviewIntake = useCallback((token) => {
    setReviewIntakeRequest((current) => clearReviewIntakeRequest(current, token))
  }, [])

  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [ipFilter, setIpFilter] = useState('ALL')
  const [timeRange, setTimeRange] = useState('all')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(5)

  const openInvestigationContext = useCallback((kind, id, context = {}, query = null) => {
    investigationNavigationNonce.current += 1
    const destinationId = String(id ?? '')
    const item = {
      entity_type: context.entity_type ?? kind,
      entity_id: destinationId,
      destination_kind: kind,
      destination_id: destinationId,
      ...context,
    }
    const request = createInvestigationNavigationRequest(item, query, investigationNavigationNonce.current)
    if (!request) return
    setInvestigationNavigation(request)
    if (request.kind === 'LEGACY_EVENT' && query?.queryType === 'IP_ADDRESS' && query.value) {
      setIpFilter(query.value)
      setTimeRange('all')
      setPage(1)
    }
    const destinationPanelId = investigationPanelForKind(request.kind)
    window.requestAnimationFrame(() => document.getElementById(destinationPanelId)?.scrollIntoView({ behavior: 'smooth', block: 'start' }))
  }, [])

  const openInvestigationResult = useCallback((item, query) => {
    openInvestigationContext(item.destination_kind, item.destination_id, item, query)
  }, [openInvestigationContext])

  const offset = (page - 1) * pageSize

  const totalPages = Math.max(
    1,
    Math.ceil(eventsTotal / pageSize),
  )

  const eventsUrl = useMemo(() => {
    const params = new URLSearchParams({
      limit: String(pageSize),
      offset: String(offset),
      time_range: timeRange,
    })

    if (severityFilter !== 'ALL') {
      params.set('severity', severityFilter)
    }

    if (ipFilter !== 'ALL') {
      params.set('source_ip', ipFilter)
    }

    return `${API_BASE}/events?${params.toString()}`
  }, [
    pageSize,
    offset,
    timeRange,
    severityFilter,
    ipFilter,
  ])

  const exportParams = useMemo(() => {
    const params = new URLSearchParams({
      time_range: timeRange,
    })

    if (severityFilter !== 'ALL') {
      params.set('severity', severityFilter)
    }

    if (ipFilter !== 'ALL') {
      params.set('source_ip', ipFilter)
    }

    return params.toString()
  }, [
    severityFilter,
    ipFilter,
    timeRange,
  ])

  const loadData = useCallback(async () => {
    try {
      setIsRefreshing(true)
      setError(null)

      const [
        healthResponse,
        overviewResponse,
        alertsResponse,
        eventsResponse,
        timelineResponse,
        sourceIpsResponse,
      ] = await Promise.all([
        fetch(`${API_BASE}/health`),
        fetch(`${API_BASE}/overview`),
        fetch(`${API_BASE}/alerts?limit=5`),
        fetch(eventsUrl),
        fetch(`${API_BASE}/stats/timeline?limit=30`),
        fetch(`${API_BASE}/source-ips`),
      ])

      if (
        !healthResponse.ok ||
        !overviewResponse.ok ||
        !alertsResponse.ok ||
        !eventsResponse.ok ||
        !timelineResponse.ok ||
        !sourceIpsResponse.ok
      ) {
        throw new Error('API request failed')
      }

      const [
        healthData,
        overviewData,
        alertsData,
        eventsData,
        timelineData,
        sourceIpsData,
      ] = await Promise.all([
        healthResponse.json(),
        overviewResponse.json(),
        alertsResponse.json(),
        eventsResponse.json(),
        timelineResponse.json(),
        sourceIpsResponse.json(),
      ])

      setHealth(healthData)
      setOverview(overviewData)
      setAlerts(alertsData.alerts)
      setEvents(eventsData.events)
      setEventsTotal(eventsData.total)
      setTimeline(timelineData.items)
      setSourceIps(sourceIpsData.items)
      setLastUpdated(new Date())
    } catch (err) {
      setError(err.message)
      setHealth(null)
    } finally {
      setIsRefreshing(false)
    }
  }, [eventsUrl])

  useEffect(() => {
    const initialLoad = setTimeout(() => {
      loadData()
    }, 0)

    const interval = setInterval(() => {
      loadData()
    }, 5000)

    return () => {
      clearTimeout(initialLoad)
      clearInterval(interval)
    }
  }, [loadData])

  function severityClass(value) {
    return `severity-badge severity-${value.toLowerCase()}`
  }

  function formatUpdatedTime(value) {
    if (!value) {
      return 'Waiting for first update'
    }

    return value.toLocaleTimeString()
  }

  function formatTimelineLabel(value) {
    if (!value) {
      return ''
    }

    return value.slice(11)
  }

  function handlePageSizeChange(event) {
    setPageSize(Number(event.target.value))
    setPage(1)
  }

  function handleSeverityChange(event) {
    setSeverityFilter(event.target.value)
    setPage(1)
  }

  function handleIpChange(event) {
    setIpFilter(event.target.value)
    setPage(1)
  }

  function handleTimeRangeChange(event) {
    setTimeRange(event.target.value)
    setPage(1)
  }

  function clearFilters() {
    setSeverityFilter('ALL')
    setIpFilter('ALL')
    setTimeRange('all')
    setPage(1)
  }

  function previousPage() {
    setPage((current) => Math.max(1, current - 1))
  }

  function nextPage() {
    setPage((current) =>
      Math.min(totalPages, current + 1),
    )
  }

  function exportCsv() {
    window.location.href = (
      `${API_BASE}/export/events.csv?${exportParams}`
    )
  }

  function exportJson() {
    window.open(
      `${API_BASE}/export/events.json?${exportParams}`,
      '_blank',
      'noopener,noreferrer',
    )
  }

  function exportPdf() {
    window.location.href = (
      `${API_BASE}/export/report.pdf?${exportParams}`
    )
  }

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div>
          <p className="eyebrow">
            Security Monitoring
          </p>

          <h1>SentinelIP</h1>

          <p className="subtitle">
            Network visibility, monitoring, threat detection, correlation, and incident review
          </p>
        </div>

        <div className="header-actions">
          <div
            className={`status ${
              health?.status === 'ok'
                ? 'online'
                : 'offline'
            }`}
          >
            <span className="status-dot" />

            {health?.status === 'ok'
              ? 'API Online'
              : 'API Offline'}
          </div>

          <button
            className="refresh-button"
            type="button"
            onClick={loadData}
            disabled={isRefreshing}
          >
            {isRefreshing
              ? 'Refreshing...'
              : 'Refresh now'}
          </button>

          <span className="last-updated">
            Last updated: {formatUpdatedTime(lastUpdated)}
          </span>
        </div>
      </header>

      {error && (
        <div className="error-box">
          {error}
        </div>
      )}

      <section className="cards">
        <article className="card total-card">
          <span>Total Events</span>
          <strong>{overview.total_events}</strong>
        </article>

        <article className="card info-card">
          <span>INFO</span>
          <strong>{overview.severity.INFO}</strong>
        </article>

        <article className="card warning-card">
          <span>WARNING</span>
          <strong>{overview.severity.WARNING}</strong>
        </article>

        <article className="card alert-card">
          <span>ALERT</span>
          <strong>{overview.severity.ALERT}</strong>
        </article>
      </section>

      <InvestigationLookup onOpenResult={openInvestigationResult} />
      <DataLifecycle />

      <NetworkWorkspace investigationRequest={investigationNavigation} onOpenInvestigationContext={openInvestigationContext} />

      <RemoteSensorFleet investigationRequest={investigationNavigation} onOpenInvestigationContext={openInvestigationContext} />

      <SecurityReviewPanel
        refreshSignal={lastUpdated}
        investigationRequest={investigationNavigation}
        onOpenInvestigationContext={openInvestigationContext}
        reviewIntakeRequest={reviewIntakeRequest}
        onStartReview={startReviewFromEvidence}
        onClearReviewIntake={clearReviewIntake}
        onReviewIntakeSubmitting={setReviewIntakeSubmitting}
        reviewIntakeSubmitting={reviewIntakeSubmitting}
      />

      <ExternalActivityDashboard
        refreshSignal={lastUpdated}
        investigationRequest={investigationNavigation}
        onOpenInvestigationContext={openInvestigationContext}
        onStartReview={startReviewFromEvidence}
        reviewIntakeSubmitting={reviewIntakeSubmitting}
      />

      <ExternalExposureDashboard
        refreshSignal={lastUpdated}
        investigationRequest={investigationNavigation}
        onOpenInvestigationContext={openInvestigationContext}
        onStartReview={startReviewFromEvidence}
        reviewIntakeSubmitting={reviewIntakeSubmitting}
      />

      <section className="panel" id="legacy-events-history">
        <div className="panel-heading">
          <div>
            <p className="panel-kicker">
              Analytics
            </p>

            <h2>Events over time</h2>
          </div>
        </div>

        {timeline.length === 0 ? (
          <p className="empty-state">
            No timeline data.
          </p>
        ) : (
          <div className="timeline-chart">
            <ResponsiveContainer
              width="100%"
              height="100%"
            >
              <LineChart data={timeline}>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#2b303a"
                />

                <XAxis
                  dataKey="minute"
                  tickFormatter={formatTimelineLabel}
                  stroke="#7f8798"
                />

                <YAxis
                  allowDecimals={false}
                  stroke="#7f8798"
                />

                <Tooltip
                  contentStyle={{
                    background: '#15181f',
                    border: '1px solid #343a46',
                    borderRadius: '8px',
                  }}
                />

                <Legend />

                <Line
                  type="monotone"
                  dataKey="total"
                  name="Total"
                  stroke="#d7dbe4"
                  strokeWidth={2}
                  dot={false}
                />

                <Line
                  type="monotone"
                  dataKey="info"
                  name="INFO"
                  stroke="#5d8eff"
                  strokeWidth={2}
                  dot={false}
                />

                <Line
                  type="monotone"
                  dataKey="warning"
                  name="WARNING"
                  stroke="#e9ad46"
                  strokeWidth={2}
                  dot={false}
                />

                <Line
                  type="monotone"
                  dataKey="alert"
                  name="ALERT"
                  stroke="#e45865"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </section>

      <section className="analytics-grid">
        <article className="panel">
          <div className="panel-heading">
            <div>
              <p className="panel-kicker">
                Network Activity
              </p>

              <h2>Top Source IPs</h2>
            </div>
          </div>

          {overview.top_ips.length === 0 ? (
            <p className="empty-state">
              No source IP data.
            </p>
          ) : (
            <div className="simple-list">
              {overview.top_ips.map((item) => (
                <div
                  className="list-row"
                  key={item.source_ip}
                >
                  <span className="mono">
                    {item.source_ip}
                  </span>

                  <strong>
                    {item.event_total} events
                  </strong>
                </div>
              ))}
            </div>
          )}
        </article>

        <article className="panel">
          <div className="panel-heading">
            <div>
              <p className="panel-kicker">
                Event Analytics
              </p>

              <h2>Event Types</h2>
            </div>
          </div>

          {overview.event_types.length === 0 ? (
            <p className="empty-state">
              No event type data.
            </p>
          ) : (
            <div className="simple-list">
              {overview.event_types.map((item) => (
                <div
                  className="list-row"
                  key={item.event_type}
                >
                  <span>
                    {item.event_type}
                  </span>

                  <strong>
                    {item.total}
                  </strong>
                </div>
              ))}
            </div>
          )}
        </article>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="panel-kicker">
              Detection
            </p>

            <h2>Recent Alerts</h2>
          </div>

          <span className="panel-count">
            {alerts.length}
          </span>
        </div>

        {alerts.length === 0 ? (
          <div className="empty-state alert-empty">
            No alerts recorded.
          </div>
        ) : (
          <div className="alert-list">
            {alerts.map((alert) => (
              <article
                className="alert-item"
                key={alert.id}
              >
                <div className="alert-item-top">
                  <span
                    className={severityClass(
                      alert.severity,
                    )}
                  >
                    {alert.severity}
                  </span>

                  <span className="event-time">
                    {alert.timestamp}
                  </span>
                </div>

                <strong>
                  {alert.message}
                </strong>

                <div className="alert-meta">
                  <span>
                    Source:{' '}
                    <b className="mono">
                      {alert.source_ip}
                    </b>
                  </span>

                  <span>
                    Event: {alert.event_type}
                  </span>

                  <span>
                    Count: {alert.event_count}
                  </span>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-heading events-heading">
          <div>
            <p className="panel-kicker">
              Live History
            </p>

            <h2>Recent Events</h2>
          </div>

          <span className="panel-count">
            {eventsTotal}
          </span>
        </div>

        {investigationNavigation?.kind === 'LEGACY_EVENT' && (
          <p className="investigation-truncated" role="status">
            Events are filtered by the exact IP lookup context. Event {investigationNavigation.id}
            {events.some((event) => String(event.id) === investigationNavigation.id)
              ? ' is on this page.'
              : ' is not on the current page; use the existing event filters and pagination to locate it.'}
          </p>
        )}

        <div className="filters">
          <label>
            <span>Severity</span>

            <select
              value={severityFilter}
              onChange={handleSeverityChange}
            >
              <option value="ALL">
                All severities
              </option>

              <option value="INFO">
                INFO
              </option>

              <option value="WARNING">
                WARNING
              </option>

              <option value="ALERT">
                ALERT
              </option>
            </select>
          </label>

          <label>
            <span>Source IP</span>

            <select
              value={ipFilter}
              onChange={handleIpChange}
            >
              <option value="ALL">
                All source IPs
              </option>

              {sourceIps.map((ip) => (
                <option
                  key={ip}
                  value={ip}
                >
                  {ip}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>Time range</span>

            <select
              value={timeRange}
              onChange={handleTimeRangeChange}
            >
              <option value="15m">
                Last 15 minutes
              </option>

              <option value="1h">
                Last 1 hour
              </option>

              <option value="24h">
                Last 24 hours
              </option>

              <option value="all">
                All time
              </option>
            </select>
          </label>

          <label>
            <span>Page size</span>

            <select
              value={pageSize}
              onChange={handlePageSizeChange}
            >
              <option value="5">
                5
              </option>

              <option value="10">
                10
              </option>

              <option value="20">
                20
              </option>

              <option value="50">
                50
              </option>
            </select>
          </label>

          <button
            className="clear-filters"
            type="button"
            onClick={clearFilters}
          >
            Clear filters
          </button>
        </div>

        <div className="export-toolbar">
          <div>
            <p className="export-label">
              Export current filtered dataset
            </p>
          </div>

          <div className="export-actions">
            <button
              type="button"
              onClick={exportCsv}
            >
              Export CSV
            </button>

            <button
              type="button"
              onClick={exportJson}
            >
              Export JSON
            </button>

            <button
              type="button"
              onClick={exportPdf}
            >
              Export PDF
            </button>
          </div>
        </div>

        {events.length === 0 ? (
          <p className="empty-state">
            No events match the selected filters.
          </p>
        ) : (
          <div className="event-table">
            <div className="event-row event-head">
              <span>Time</span>
              <span>Severity</span>
              <span>Source IP</span>
              <span>Event</span>
              <span>Count</span>
            </div>

            {events.map((event) => (
              <div
                className={investigationNavigation?.kind === 'LEGACY_EVENT' && String(event.id) === investigationNavigation.id ? 'event-row investigation-event-selected' : 'event-row'}
                key={event.id}
              >
                <span className="event-time">
                  {event.timestamp}
                </span>

                <span>
                  <span
                    className={severityClass(
                      event.severity,
                    )}
                  >
                    {event.severity}
                  </span>
                </span>

                <span className="mono">
                  {event.source_ip}
                </span>

                <span>
                  {event.event_type}
                </span>

                <span className="event-count">
                  {event.event_count}
                </span>
              </div>
            ))}
          </div>
        )}

        <div className="pagination">
          <span className="pagination-summary">
            {eventsTotal === 0
              ? 'No matching events'
              : (
                `Page ${page} of ${totalPages} · ` +
                `${eventsTotal} matching events`
              )}
          </span>

          <div className="pagination-actions">
            <button
              type="button"
              onClick={previousPage}
              disabled={page === 1}
            >
              Previous
            </button>

            <button
              type="button"
              onClick={nextPage}
              disabled={page >= totalPages}
            >
              Next
            </button>
          </div>
        </div>
      </section>

      <footer className="dashboard-footer">
        Automatic refresh every 5 seconds
      </footer>
    </div>
  )
}

export default App
