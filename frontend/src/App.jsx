import { useEffect, useMemo, useState } from 'react'
import './App.css'

const API_BASE = 'http://127.0.0.1:8000'

function App() {
  const [health, setHealth] = useState(null)
  const [severity, setSeverity] = useState([])
  const [topIps, setTopIps] = useState([])
  const [alerts, setAlerts] = useState([])
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)

  async function loadData() {
    try {
      setError(null)

      const [
        healthResponse,
        severityResponse,
        topIpsResponse,
        alertsResponse,
        eventsResponse,
      ] = await Promise.all([
        fetch(`${API_BASE}/health`),
        fetch(`${API_BASE}/stats/severity`),
        fetch(`${API_BASE}/stats/top-ips?limit=5`),
        fetch(`${API_BASE}/alerts?limit=5`),
        fetch(`${API_BASE}/events?limit=10`),
      ])

      if (
        !healthResponse.ok ||
        !severityResponse.ok ||
        !topIpsResponse.ok ||
        !alertsResponse.ok ||
        !eventsResponse.ok
      ) {
        throw new Error('API request failed')
      }

      const [
        healthData,
        severityData,
        topIpsData,
        alertsData,
        eventsData,
      ] = await Promise.all([
        healthResponse.json(),
        severityResponse.json(),
        topIpsResponse.json(),
        alertsResponse.json(),
        eventsResponse.json(),
      ])

      setHealth(healthData)
      setSeverity(severityData.items)
      setTopIps(topIpsData.items)
      setAlerts(alertsData.alerts)
      setEvents(eventsData.events)
    } catch (err) {
      setError(err.message)
      setHealth(null)
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

  const severitySummary = useMemo(() => {
    const summary = {
      INFO: 0,
      WARNING: 0,
      ALERT: 0,
    }

    for (const item of severity) {
      if (item.severity in summary) {
        summary[item.severity] = item.total
      }
    }

    return summary
  }, [severity])

  const totalEvents = useMemo(
    () =>
      severitySummary.INFO +
      severitySummary.WARNING +
      severitySummary.ALERT,
    [severitySummary],
  )

  function severityClass(value) {
    return `severity-badge severity-${value.toLowerCase()}`
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

        <div
          className={`status ${
            health?.status === 'ok' ? 'online' : 'offline'
          }`}
        >
          <span className="status-dot" />
          {health?.status === 'ok' ? 'API Online' : 'API Offline'}
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
          <strong>{totalEvents}</strong>
        </article>

        <article className="card info-card">
          <span>INFO</span>
          <strong>{severitySummary.INFO}</strong>
        </article>

        <article className="card warning-card">
          <span>WARNING</span>
          <strong>{severitySummary.WARNING}</strong>
        </article>

        <article className="card alert-card">
          <span>ALERT</span>
          <strong>{severitySummary.ALERT}</strong>
        </article>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="panel-kicker">Network Activity</p>
            <h2>Top Source IPs</h2>
          </div>
        </div>

        {topIps.length === 0 ? (
          <p className="empty-state">No source IP data.</p>
        ) : (
          <div className="simple-list">
            {topIps.map((item) => (
              <div className="list-row" key={item.source_ip}>
                <span className="mono">{item.source_ip}</span>
                <strong>{item.event_total} events</strong>
              </div>
            ))}
          </div>
        )}
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
              <article className="alert-item" key={alert.id}>
                <div className="alert-item-top">
                  <span className={severityClass(alert.severity)}>
                    {alert.severity}
                  </span>

                  <span className="event-time">
                    {alert.timestamp}
                  </span>
                </div>

                <strong>{alert.message}</strong>

                <div className="alert-meta">
                  <span>
                    Source: <b className="mono">{alert.source_ip}</b>
                  </span>
                  <span>Event: {alert.event_type}</span>
                  <span>Count: {alert.event_count}</span>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="panel-kicker">Live History</p>
            <h2>Recent Events</h2>
          </div>

          <span className="panel-count">
            {events.length}
          </span>
        </div>

        {events.length === 0 ? (
          <p className="empty-state">No events recorded.</p>
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
              <div className="event-row" key={event.id}>
                <span className="event-time">
                  {event.timestamp}
                </span>

                <span>
                  <span className={severityClass(event.severity)}>
                    {event.severity}
                  </span>
                </span>

                <span className="mono">
                  {event.source_ip}
                </span>

                <span>{event.event_type}</span>

                <span className="event-count">
                  {event.event_count}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>

      <footer className="dashboard-footer">
        Auto-refresh every 5 seconds
      </footer>
    </div>
  )
}

export default App
