import { useEffect, useMemo, useState } from 'react'
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

import './App.css'

const API_BASE = 'http://127.0.0.1:8000'

function App() {
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
  const [timeline, setTimeline] = useState([])
  const [error, setError] = useState(null)

  const [isRefreshing, setIsRefreshing] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [ipFilter, setIpFilter] = useState('ALL')

  async function loadData() {
    try {
      setIsRefreshing(true)
      setError(null)

      const [
        healthResponse,
        overviewResponse,
        alertsResponse,
        eventsResponse,
        timelineResponse,
      ] = await Promise.all([
        fetch(`${API_BASE}/health`),
        fetch(`${API_BASE}/overview`),
        fetch(`${API_BASE}/alerts?limit=5`),
        fetch(`${API_BASE}/events?limit=100`),
        fetch(`${API_BASE}/stats/timeline?limit=30`),
      ])

      if (
        !healthResponse.ok ||
        !overviewResponse.ok ||
        !alertsResponse.ok ||
        !eventsResponse.ok ||
        !timelineResponse.ok
      ) {
        throw new Error('API request failed')
      }

      const [
        healthData,
        overviewData,
        alertsData,
        eventsData,
        timelineData,
      ] = await Promise.all([
        healthResponse.json(),
        overviewResponse.json(),
        alertsResponse.json(),
        eventsResponse.json(),
        timelineResponse.json(),
      ])

      setHealth(healthData)
      setOverview(overviewData)
      setAlerts(alertsData.alerts)
      setEvents(eventsData.events)
      setTimeline(timelineData.items)
      setLastUpdated(new Date())
    } catch (err) {
      setError(err.message)
      setHealth(null)
    } finally {
      setIsRefreshing(false)
    }
  }

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
  }, [])

  const sourceIps = useMemo(() => {
    return [...new Set(events.map((event) => event.source_ip))].sort()
  }, [events])

  const filteredEvents = useMemo(() => {
    return events.filter((event) => {
      const matchesSeverity =
        severityFilter === 'ALL' ||
        event.severity === severityFilter

      const matchesIp =
        ipFilter === 'ALL' ||
        event.source_ip === ipFilter

      return matchesSeverity && matchesIp
    })
  }, [events, severityFilter, ipFilter])

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

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div>
          <p className="eyebrow">Security Monitoring</p>
          <h1>SentinelIP</h1>

          <p className="subtitle">
            Live SSH security events and detection overview
          </p>
        </div>

        <div className="header-actions">
          <div
            className={`status ${
              health?.status === 'ok' ? 'online' : 'offline'
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
            {isRefreshing ? 'Refreshing...' : 'Refresh now'}
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

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="panel-kicker">Analytics</p>
            <h2>Events over time</h2>
          </div>
        </div>

        {timeline.length === 0 ? (
          <p className="empty-state">
            No timeline data.
          </p>
        ) : (
          <div className="timeline-chart">
            <ResponsiveContainer width="100%" height="100%">
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
              <p className="panel-kicker">Network Activity</p>
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
              <p className="panel-kicker">Event Analytics</p>
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
            <p className="panel-kicker">Detection</p>
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
                    className={severityClass(alert.severity)}
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
            <p className="panel-kicker">Live History</p>
            <h2>Recent Events</h2>
          </div>

          <span className="panel-count">
            {filteredEvents.length}/{events.length}
          </span>
        </div>

        <div className="filters">
          <label>
            <span>Severity</span>

            <select
              value={severityFilter}
              onChange={(event) =>
                setSeverityFilter(event.target.value)
              }
            >
              <option value="ALL">All severities</option>
              <option value="INFO">INFO</option>
              <option value="WARNING">WARNING</option>
              <option value="ALERT">ALERT</option>
            </select>
          </label>

          <label>
            <span>Source IP</span>

            <select
              value={ipFilter}
              onChange={(event) =>
                setIpFilter(event.target.value)
              }
            >
              <option value="ALL">All source IPs</option>

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

          <button
            className="clear-filters"
            type="button"
            onClick={() => {
              setSeverityFilter('ALL')
              setIpFilter('ALL')
            }}
          >
            Clear filters
          </button>
        </div>

        {filteredEvents.length === 0 ? (
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

            {filteredEvents.map((event) => (
              <div
                className="event-row"
                key={event.id}
              >
                <span className="event-time">
                  {event.timestamp}
                </span>

                <span>
                  <span
                    className={severityClass(event.severity)}
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
      </section>

      <footer className="dashboard-footer">
        Automatic refresh every 5 seconds
      </footer>
    </div>
  )
}

export default App
