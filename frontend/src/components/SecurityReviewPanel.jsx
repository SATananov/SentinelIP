import { useEffect, useState } from 'react'

import {
  loadSecurityDetail,
  loadSecurityOverview,
} from '../services/securityApi.js'
import IncidentReviewSection from './IncidentReviewSection.jsx'

const KIND_LABELS = {
  threat: 'Threat',
  correlation: 'Correlation',
  incident: 'Incident Review',
}

function humanize(value) {
  if (!value) return '—'

  return String(value)
    .replaceAll('_', ' ')
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function compactTime(value) {
  if (!value) return '—'
  return value.replace('T', ' ').replace('+00:00', 'Z')
}

function badgeClass(value) {
  if (!value) return 'security-badge'

  return (
    'security-badge security-badge-' +
    String(value).toLowerCase().replaceAll('_', '-')
  )
}

function EmptyState({ children }) {
  return <p className="security-empty">{children}</p>
}

function SummaryCard({ label, value, note, className = '' }) {
  return (
    <article className={`security-summary-card ${className}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </article>
  )
}

function SecurityList({ kind, items, onSelect }) {
  if (items.length === 0) {
    return (
      <EmptyState>
        No persisted {KIND_LABELS[kind].toLowerCase()} records.
      </EmptyState>
    )
  }

  return (
    <div className="security-record-list">
      {items.map((item) => {
        const type = (
          item.threat_type ??
          item.correlation_type ??
          item.incident_type
        )
        const state = item.state ?? item.status
        const time = item.last_seen ?? item.opened_at ?? item.first_seen

        return (
          <button
            className="security-record"
            key={`${kind}-${item.id}`}
            type="button"
            onClick={() => onSelect(kind, item.id)}
          >
            <span className="security-record-id">#{item.id}</span>

            <span className="security-record-main">
              <strong>{humanize(type)}</strong>
              <small>{compactTime(time)}</small>
            </span>

            <span className="security-record-badges">
              {state && (
                <span className={badgeClass(state)}>
                  {humanize(state)}
                </span>
              )}

              {item.severity && (
                <span className={badgeClass(item.severity)}>
                  {humanize(item.severity)}
                </span>
              )}

              {item.priority && (
                <span className={badgeClass(item.priority)}>
                  {humanize(item.priority)}
                </span>
              )}
            </span>
          </button>
        )
      })}
    </div>
  )
}

function DetailField({ label, value, mono = false }) {
  if (value === null || value === undefined || value === '') {
    return null
  }

  return (
    <div className="security-detail-field">
      <span>{label}</span>
      <strong className={mono ? 'mono' : undefined}>{value}</strong>
    </div>
  )
}

function DetailJson({ label, value }) {
  if (!value) return null

  return (
    <div className="security-json-block">
      <span>{label}</span>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </div>
  )
}

function SecurityDetail({
  selection,
  detail,
  loading,
  error,
  onClose,
}) {
  if (!selection) return null

  const type = (
    detail?.threat_type ??
    detail?.correlation_type ??
    detail?.incident_type
  )
  const state = detail?.state ?? detail?.status

  return (
    <div className="security-detail-shell">
      <div className="security-detail-heading">
        <div>
          <p className="panel-kicker">Read-only persisted record</p>
          <h3>{KIND_LABELS[selection.kind]} #{selection.id}</h3>
        </div>

        <button
          className="security-detail-close"
          type="button"
          onClick={onClose}
        >
          Close
        </button>
      </div>

      {loading && (
        <p className="security-empty">Loading persisted record…</p>
      )}

      {error && <p className="security-detail-error">{error}</p>}

      {detail && !loading && (
        <>
          <div className="security-detail-grid">
            <DetailField label="Type" value={humanize(type)} />
            <DetailField label="State" value={humanize(state)} />
            <DetailField
              label="Severity"
              value={humanize(detail.severity)}
            />
            <DetailField
              label="Confidence"
              value={humanize(detail.confidence)}
            />
            <DetailField
              label="Priority"
              value={humanize(detail.priority)}
            />
            <DetailField
              label="Source IP"
              value={detail.source_ip}
              mono
            />
            <DetailField
              label="Hostname"
              value={detail.hostname}
              mono
            />
            <DetailField
              label="Device ID"
              value={detail.device_id}
              mono
            />
            <DetailField
              label="Sensor ID"
              value={detail.sensor_id}
              mono
            />
            <DetailField
              label="First seen"
              value={compactTime(detail.first_seen)}
            />
            <DetailField
              label="Last seen"
              value={compactTime(detail.last_seen)}
            />
            <DetailField
              label="Opened at"
              value={compactTime(detail.opened_at)}
            />
            <DetailField
              label="Rule"
              value={
                detail.rule_id
                  ? `${detail.rule_id} v${detail.rule_version}`
                  : null
              }
              mono
            />
          </div>

          {detail.title && (
            <div className="security-detail-copy">
              <span>Title</span>
              <strong>{detail.title}</strong>
            </div>
          )}

          {detail.reason && (
            <div className="security-detail-copy">
              <span>Persisted reason</span>
              <p>{detail.reason}</p>
            </div>
          )}

          {detail.recommendation && (
            <div className="security-detail-copy">
              <span>Persisted recommendation</span>
              <p>{detail.recommendation}</p>
            </div>
          )}

          <DetailJson label="Evidence" value={detail.evidence} />
          <DetailJson
            label="Correlated entities"
            value={detail.entities}
          />
          <DetailJson
            label="Incident correlations"
            value={detail.correlations}
          />
        </>
      )}
    </div>
  )
}

function SecurityReviewPanel({ refreshSignal }) {
  const [data, setData] = useState({
    threats: { total: 0, threats: [] },
    correlations: { total: 0, correlations: [] },
    incidents: { total: 0, incidents: [] },
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selection, setSelection] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState(null)

  useEffect(() => {
    const controller = new AbortController()

    async function load() {
      try {
        setLoading(true)
        setError(null)
        const result = await loadSecurityOverview(controller.signal)
        setData(result)
      } catch (err) {
        if (err.name !== 'AbortError') {
          setError(err.message)
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false)
        }
      }
    }

    load()

    return () => controller.abort()
  }, [refreshSignal])

  async function selectRecord(kind, id) {
    setSelection({ kind, id })
    setDetail(null)
    setDetailError(null)
    setDetailLoading(true)

    try {
      const result = await loadSecurityDetail(kind, id)
      setDetail(result)
    } catch (err) {
      setDetailError(err.message)
    } finally {
      setDetailLoading(false)
    }
  }

  function closeDetail() {
    setSelection(null)
    setDetail(null)
    setDetailError(null)
  }

  return (
    <section className="security-layer">
      <div className="security-layer-heading">
        <div>
          <p className="panel-kicker">Deterministic Security Pipeline</p>
          <h2>Threats, Correlations & Incident Reviews</h2>
          <p className="security-layer-copy">
            Persisted backend interpretations only. The dashboard does not
            run detection, correlation, or incident creation.
          </p>
        </div>

        <span className="read-only-chip">Read only</span>
      </div>

      {error && (
        <div className="security-load-error">
          Security read API: {error}
        </div>
      )}

      <div className="security-summary-grid">
        <SummaryCard
          className="security-summary-threat"
          label="Threats"
          value={data.threats.total}
          note="Anomalous / suspected"
        />
        <SummaryCard
          className="security-summary-correlation"
          label="Correlations"
          value={data.correlations.total}
          note="Related evidence patterns"
        />
        <SummaryCard
          className="security-summary-incident"
          label="Incident Reviews"
          value={data.incidents.total}
          note="Open investigation records"
        />
      </div>

      <div className="security-columns">
        <article className="panel security-column">
          <div className="panel-heading">
            <div>
              <p className="panel-kicker">Threat Detection</p>
              <h3>Recent Threats</h3>
            </div>
            <span className="panel-count">{data.threats.total}</span>
          </div>

          {loading ? (
            <EmptyState>Loading threats…</EmptyState>
          ) : (
            <SecurityList
              kind="threat"
              items={data.threats.threats}
              onSelect={selectRecord}
            />
          )}
        </article>

        <article className="panel security-column">
          <div className="panel-heading">
            <div>
              <p className="panel-kicker">Correlation</p>
              <h3>Recent Correlations</h3>
            </div>
            <span className="panel-count">
              {data.correlations.total}
            </span>
          </div>

          {loading ? (
            <EmptyState>Loading correlations…</EmptyState>
          ) : (
            <SecurityList
              kind="correlation"
              items={data.correlations.correlations}
              onSelect={selectRecord}
            />
          )}
        </article>

        <article className="panel security-column">
          <div className="panel-heading">
            <div>
              <p className="panel-kicker">Investigation</p>
              <h3>Incident Reviews</h3>
            </div>
            <span className="panel-count">{data.incidents.total}</span>
          </div>

          {loading ? (
            <EmptyState>Loading incident reviews…</EmptyState>
          ) : (
            <SecurityList
              kind="incident"
              items={data.incidents.incidents}
              onSelect={selectRecord}
            />
          )}
        </article>
      </div>

      <IncidentReviewSection refreshSignal={refreshSignal} />

      <SecurityDetail
        selection={selection}
        detail={detail}
        loading={detailLoading}
        error={detailError}
        onClose={closeDetail}
      />
    </section>
  )
}

export default SecurityReviewPanel
