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
import HelpGuide from './components/HelpGuide.jsx'
import AboutSentinelIP from './components/AboutSentinelIP.jsx'
import useWorkspaceNavigation, { skipToWorkspaceMain } from './hooks/useWorkspaceNavigation.js'
import { createInvestigationNavigationRequest, investigationPanelForKind } from './services/investigationNavigation.js'
import { moduleForInvestigationKind, WORKSPACE_MODULES, workspaceHash } from './services/workspaceNavigation.js'
import { API_BASE } from './services/apiBase.js'
import {
  buildExportQuery,
  exportErrorMessage,
  isCustomExportRangeValid,
} from './services/exportRequest.js'
import {
  clearReviewIntakeRequest,
  createReviewIntakeRequest,
  isValidReviewEvidenceContext,
} from './services/reviewEvidenceContext.js'
import { createOperationsRequestGuard } from './services/incidentReviewRequestGuard.js'
import {
  buildEventsQuery,
  resolveSourceIpApply,
  topIpBasisLabel,
} from './services/sourceIpFilter.js'

import './App.css'

function App() {
  const { activeModule, helpTopic, navigateToModule, selectHelpTopic } = useWorkspaceNavigation()
  const previousOperationalModule = useRef('overview')
  const reviewIntakeToken = useRef(0)
  const [dashboardRequestGuard] = useState(createOperationsRequestGuard)
  const [reviewIntakeRequest, setReviewIntakeRequest] = useState(null)
  const [reviewIntakeSubmitting, setReviewIntakeSubmitting] = useState(false)
  const [investigationNavigation, setInvestigationNavigation] = useState(null)
  const investigationNavigationNonce = useRef(0)
  const [health, setHealth] = useState(null)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const mobileMenuButtonRef = useRef(null)

  useEffect(() => {
    const closeMobileMenu = () => setMobileMenuOpen(false)
    window.addEventListener('hashchange', closeMobileMenu)
    return () => window.removeEventListener('hashchange', closeMobileMenu)
  }, [])

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
  const [ipDraft, setIpDraft] = useState('')
  const [ipFilter, setIpFilter] = useState('')
  const [ipValidationError, setIpValidationError] = useState('')
  const [timeRange, setTimeRange] = useState('all')
  const [exportRangeMode, setExportRangeMode] = useState('preset')
  const [exportFromLocal, setExportFromLocal] = useState('')
  const [exportUntilLocal, setExportUntilLocal] = useState('')
  const [exportError, setExportError] = useState(null)
  const [exporting, setExporting] = useState(false)

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
    navigateToModule(moduleForInvestigationKind(request.kind))
    if (request.kind === 'LEGACY_EVENT' && query?.queryType === 'IP_ADDRESS' && query.value) {
      setIpDraft(query.value)
      setIpFilter(query.value)
      setIpValidationError('')
      setTimeRange('all')
      setPage(1)
    }
  }, [navigateToModule])

  useEffect(() => {
    if (!investigationNavigation) return undefined
    const destinationPanelId = investigationPanelForKind(investigationNavigation.kind)
    const frame = window.requestAnimationFrame(() => {
      document.getElementById(destinationPanelId)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    })
    return () => window.cancelAnimationFrame(frame)
  }, [activeModule, investigationNavigation])

  const openInvestigationResult = useCallback((item, query) => {
    openInvestigationContext(item.destination_kind, item.destination_id, item, query)
  }, [openInvestigationContext])

  const offset = (page - 1) * pageSize
  const topIpSampleLabel = topIpBasisLabel(overview.top_ips_basis)
  const modules = WORKSPACE_MODULES.filter(({ id }) => id !== 'data-lifecycle')
  const moduleHelpTopic = {
    overview: 'overview', 'scope-discovery': 'scope', 'remote-sensors': 'sensors',
    operations: 'operations', detections: 'detections', perimeter: 'perimeter',
    'events-analytics': 'events', 'data-lifecycle': 'lifecycle',
  }[activeModule] ?? 'getting-started'

  useEffect(() => {
    if (!['help', 'about'].includes(activeModule)) previousOperationalModule.current = activeModule
  }, [activeModule])

  useEffect(() => {
    if (activeModule !== 'help') return undefined
    const onKeyDown = (event) => {
      const target = event.target
      if (event.key === 'Escape'
          && !(target instanceof HTMLInputElement)
          && !(target instanceof HTMLTextAreaElement)
          && !(target instanceof HTMLSelectElement)
          && !target?.isContentEditable) {
        navigateToModule(previousOperationalModule.current)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [activeModule, navigateToModule])

  function handleModuleLink(event, moduleId) {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
    event.preventDefault()
    navigateToModule(moduleId)
  }

  function handleMobileMenuKeyDown(event) {
    if (event.key !== 'Escape') return
    event.preventDefault()
    event.stopPropagation()
    setMobileMenuOpen(false)
    mobileMenuButtonRef.current?.focus()
  }

  function selectMobileDestination(event, moduleId) {
    handleModuleLink(event, moduleId)
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
    setMobileMenuOpen(false)
    mobileMenuButtonRef.current?.focus()
  }

  const totalPages = Math.max(
    1,
    Math.ceil(eventsTotal / pageSize),
  )

  const eventsUrl = useMemo(() => {
    const params = buildEventsQuery({
      limit: pageSize,
      offset,
      timeRange,
      severity: severityFilter,
      sourceIp: ipFilter,
    })

    return `${API_BASE}/events?${params.toString()}`
  }, [
    pageSize,
    offset,
    timeRange,
    severityFilter,
    ipFilter,
  ])

  const exportParams = useMemo(() => {
    return buildExportQuery({
      rangeMode: exportRangeMode,
      timeRange,
      fromLocal: exportFromLocal,
      untilLocal: exportUntilLocal,
      severity: severityFilter,
      sourceIp: ipFilter || 'ALL',
    })
  }, [
    exportRangeMode,
    exportFromLocal,
    exportUntilLocal,
    severityFilter,
    ipFilter,
    timeRange,
  ])

  const loadData = useCallback(async () => {
    const requestId = dashboardRequestGuard.begin('dashboard')
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
        fetch(eventsUrl),
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

      if (!dashboardRequestGuard.isCurrent('dashboard', requestId)) return

      setHealth(healthData)
      setOverview(overviewData)
      setAlerts(alertsData.alerts)
      setEvents(eventsData.events)
      setEventsTotal(eventsData.total)
      setTimeline(timelineData.items)
      setLastUpdated(new Date())
    } catch (err) {
      if (dashboardRequestGuard.isCurrent('dashboard', requestId)) {
        setError(err.message)
        setHealth(null)
      }
    } finally {
      if (dashboardRequestGuard.isCurrent('dashboard', requestId)) {
        setIsRefreshing(false)
      }
    }
  }, [dashboardRequestGuard, eventsUrl])

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
      dashboardRequestGuard.invalidate('dashboard')
    }
  }, [dashboardRequestGuard, loadData])

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

  function handleIpDraftChange(event) {
    setIpDraft(event.target.value)
    setIpValidationError('')
  }

  function applyIpFilter(event) {
    event.preventDefault()
    const result = resolveSourceIpApply(ipDraft, ipFilter)
    if (result.error) {
      setIpValidationError(result.error)
      return
    }
    setIpDraft(result.draft)
    setIpFilter(result.applied)
    setIpValidationError('')
    setPage(1)
  }

  function clearIpFilter() {
    setIpDraft('')
    setIpFilter('')
    setIpValidationError('')
    setPage(1)
  }

  function handleTimeRangeChange(event) {
    setTimeRange(event.target.value)
    setPage(1)
  }

  function clearFilters() {
    setSeverityFilter('ALL')
    setIpDraft('')
    setIpFilter('')
    setIpValidationError('')
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

  async function downloadExport(format) {
    if (!exportParams || exporting) return
    setExportError(null)
    setExporting(true)
    const jsonWindow = format === 'json' ? window.open('about:blank', '_blank') : null
    if (jsonWindow) jsonWindow.opener = null

    const endpoint = {
      csv: '/export/events.csv',
      json: '/export/events.json',
      pdf: '/export/report.pdf',
    }[format]

    try {
      const response = await fetch(`${API_BASE}${endpoint}?${exportParams.toString()}`, {
        cache: 'no-store',
      })
      if (!response.ok) {
        if (jsonWindow) jsonWindow.close()
        setExportError(exportErrorMessage(response.status))
        return
      }

      const blob = await response.blob()
      const objectUrl = URL.createObjectURL(blob)
      if (format === 'json') {
        if (jsonWindow) jsonWindow.location.href = objectUrl
        else window.open(objectUrl, '_blank', 'noopener,noreferrer')
        window.setTimeout(() => URL.revokeObjectURL(objectUrl), 5 * 60 * 1000)
        return
      }

      const disposition = response.headers.get('content-disposition') || ''
      const filename = /filename="([^"]+)"/i.exec(disposition)?.[1]
        || `sentinelip-events.${format}`
      const link = document.createElement('a')
      link.href = objectUrl
      link.download = filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000)
    } catch {
      if (jsonWindow) jsonWindow.close()
      setExportError(exportErrorMessage(0))
    } finally {
      setExporting(false)
    }
  }

  const customExportRangeValid = exportRangeMode !== 'custom'
    || isCustomExportRangeValid(exportFromLocal, exportUntilLocal)
  const exportDisabled = !exportParams || !customExportRangeValid || exporting

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content" onClick={(event) => skipToWorkspaceMain(event, activeModule)}>Skip to main content</a>
      <aside className="app-sidebar" aria-label="Application sidebar">
        <a className="sidebar-brand" href={workspaceHash('overview')}
          onClick={(event) => handleModuleLink(event, 'overview')}>
          <img className="brand-mark" src="/favicon-48.png" alt="" width="38" height="38" />
          <span><strong>SentinelIP</strong><small>Security Operations</small></span>
        </a>
        <nav className="module-nav" aria-label="Main navigation">
          <p className="nav-label">Workspace</p>
          {modules.map(({ id, label }) => (
            <a key={id} href={workspaceHash(id)} aria-current={activeModule === id ? 'page' : undefined}
              onClick={(event) => handleModuleLink(event, id)}><NavIcon name={id} />{label}</a>
          ))}
          <div className="nav-divider" />
          <p className="nav-label">Local operator</p>
          <a className="operator-nav-link" href={workspaceHash('data-lifecycle')}
            aria-current={activeModule === 'data-lifecycle' ? 'page' : undefined}
            onClick={(event) => handleModuleLink(event, 'data-lifecycle')}><NavIcon name="data-lifecycle" />Data Lifecycle</a>
        </nav>
        <nav className="support-nav" aria-label="Support and information">
          <p className="nav-label">Support &amp; Information</p>
          {['help', 'about'].map((id) => {
            const label = id === 'help' ? 'Help & User Guide' : 'About SentinelIP'
            return <a key={id} href={workspaceHash(id)} aria-current={activeModule === id ? 'page' : undefined}
              onClick={(event) => handleModuleLink(event, id)}><NavIcon name={id} />{label}</a>
          })}
        </nav>
        <div className="mobile-workspace">
          <button ref={mobileMenuButtonRef} id="mobile-workspace-button" className="mobile-workspace-button"
            type="button" aria-label={`Workspace: ${WORKSPACE_MODULES.find(({ id }) => id === activeModule)?.label ?? (activeModule === 'help' ? 'Help & User Guide' : 'About SentinelIP')}`}
            aria-expanded={mobileMenuOpen} aria-controls="mobile-workspace-menu"
            onClick={() => setMobileMenuOpen((open) => !open)} onKeyDown={handleMobileMenuKeyDown}>
            <span><small>Workspace</small><strong>{WORKSPACE_MODULES.find(({ id }) => id === activeModule)?.label ?? (activeModule === 'help' ? 'Help & User Guide' : 'About SentinelIP')}</strong></span>
            <span className={`mobile-menu-indicator${mobileMenuOpen ? ' is-open' : ''}`} aria-hidden="true">⌄</span>
          </button>
          <nav id="mobile-workspace-menu" className="mobile-workspace-menu" aria-label="Workspace destinations"
            hidden={!mobileMenuOpen} inert={!mobileMenuOpen} onKeyDown={handleMobileMenuKeyDown}>
            <p className="mobile-menu-group-label">Workspace</p>
            {modules.map(({ id, label }) => <a key={id} href={workspaceHash(id)} aria-current={activeModule === id ? 'page' : undefined}
              onClick={(event) => selectMobileDestination(event, id)}><NavIcon name={id} />{label}<span className="mobile-destination-check" aria-hidden="true">{activeModule === id ? '✓' : ''}</span></a>)}
            <p className="mobile-menu-group-label">Local operator</p>
            <a href={workspaceHash('data-lifecycle')} aria-current={activeModule === 'data-lifecycle' ? 'page' : undefined}
              onClick={(event) => selectMobileDestination(event, 'data-lifecycle')}><NavIcon name="data-lifecycle" />Data Lifecycle<span className="mobile-destination-check" aria-hidden="true">{activeModule === 'data-lifecycle' ? '✓' : ''}</span></a>
            <p className="mobile-menu-group-label">Support &amp; Information</p>
            {['help', 'about'].map((id) => {
              const label = id === 'help' ? 'Help & User Guide' : 'About SentinelIP'
              return <a key={id} href={workspaceHash(id)} aria-current={activeModule === id ? 'page' : undefined}
                onClick={(event) => selectMobileDestination(event, id)}><NavIcon name={id} />{label}<span className="mobile-destination-check" aria-hidden="true">{activeModule === id ? '✓' : ''}</span></a>
            })}
          </nav>
        </div>
        <div className="sidebar-caption">Security Operations Workspace</div>
      </aside>

      <div className="workspace-column">
      <header className="dashboard-header">
        <div>
          <p className="eyebrow">Security Operations Platform</p>
          <h1>SentinelIP</h1>
          <p className="subtitle">Security Operations Workspace</p>
        </div>

        <div className="header-actions">
          <button className="header-help-button" type="button" onClick={() => navigateToModule('help', moduleHelpTopic)} aria-label={`Help for ${activeModule === 'help' ? 'current topic' : WORKSPACE_MODULES.find(({ id }) => id === activeModule)?.label ?? 'workspace'}`}>
            <NavIcon name="help" /> Help
          </button>
          <div
            className={`status ${
              health?.status === 'ok'
                ? 'online'
                : 'offline'
            }`}
            role="status"
            aria-live="polite"
          >
            <span className="status-dot" aria-hidden="true" />

            {health?.status === 'ok'
              ? 'API Online'
              : 'API Offline'}
          </div>

          <button
            className="refresh-button"
            type="button"
            onClick={loadData}
            disabled={isRefreshing}
            aria-label={isRefreshing ? 'Refreshing dashboard data' : 'Refresh dashboard data'}
          >
            {isRefreshing
              ? 'Refreshing...'
              : 'Refresh now'}
          </button>

          <span className="last-updated" aria-label={`Last updated ${formatUpdatedTime(lastUpdated)}`}>
            Last updated: {formatUpdatedTime(lastUpdated)}
          </span>
        </div>
      </header>

      <main id="main-content" className="dashboard" tabIndex="-1">
      {error && (
        <div className="error-box" role="alert">
          {error}
        </div>
      )}

      <section className="module-section workspace-module" id="module-overview" aria-labelledby="workspace-heading-overview"
        hidden={activeModule !== 'overview'} inert={activeModule !== 'overview'}>
      <div className="module-heading"><div><p className="panel-kicker">Workspace</p><h2 id="workspace-heading-overview" tabIndex="-1">Overview</h2></div>
        <p className="module-description">Current event volume and severity summary.</p></div>
      <section className="cards overview-kpis" aria-label="Event summary">
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

      <div className="overview-content-grid">
        <section className="panel activity-spark-panel" aria-labelledby="activity-spark-title">
          <div className="panel-heading"><div><p className="panel-kicker">Security activity</p><h2 id="activity-spark-title">Recent event volume</h2></div>
            <a className="text-link" href={workspaceHash('events-analytics')} onClick={(event) => handleModuleLink(event, 'events-analytics')}>View analytics</a></div>
          {timeline.length === 0 ? <p className="empty-state">No timeline data.</p> : (() => {
            const items = timeline.slice(-12)
            const max = Math.max(1, ...items.map((item) => Number(item.total) || 0))
            return <>
              <div className="activity-spark" aria-hidden="true">
                {items.map((item, index) => <span key={`${item.minute}-${index}`}
                  style={{ '--bar-height': `${Math.max(5, ((Number(item.total) || 0) / max) * 100)}%` }} />)}
              </div>
              <ol className="activity-accessible-values" aria-label="Displayed activity interval counts">
                {items.map((item, index) => <li key={`${item.minute}-${index}`}>
                  {item.minute}: {item.total} events
                </li>)}
              </ol>
              <details className="activity-interval-details">
                <summary>View activity interval values</summary>
                <ol className="activity-interval-list" aria-label="Displayed activity intervals">
                  {items.map((item, index) => <li key={`${item.minute}-${index}`}>
                    <time>{item.minute}</time><span>{item.total} events</span>
                  </li>)}
                </ol>
              </details>
            </>
          })()}
        </section>

        <section className="panel overview-alert-preview" aria-labelledby="overview-alerts-title">
          <div className="panel-heading"><div><p className="panel-kicker">Latest activity</p><h2 id="overview-alerts-title">Recent Alerts</h2></div></div>
          {alerts.length === 0 ? <p className="empty-state">No alerts recorded.</p> : <div className="alert-list">
            {alerts.slice(0, 3).map((alert) => <article className="alert-item overview-alert-item" key={alert.id}>
              <div className="alert-item-top"><span className={severityClass(alert.severity)}>{alert.severity}</span>
                <span className="event-time">{alert.timestamp}</span></div>
              <strong>{alert.message}</strong>
              <div className="overview-alert-meta">
                {alert.source_ip && <span>Source: {alert.source_ip}</span>}
                {alert.event_type && <span>Type: {alert.event_type}</span>}
                {Number(alert.event_count) > 1 && <span>Events: {alert.event_count}</span>}
              </div>
            </article>)}
          </div>}
          <a className="text-link" href={workspaceHash('events-analytics')} onClick={(event) => handleModuleLink(event, 'events-analytics')}>Open Events &amp; Analytics</a>
        </section>
      </div>
      <div className="overview-quick-links" aria-label="Quick links">
        {modules.slice(1).map(({ id, label }) => <a key={id} href={workspaceHash(id)} onClick={(event) => handleModuleLink(event, id)}>{label}<span aria-hidden="true">→</span></a>)}
      </div>
      </section>

      <section className="module-section workspace-module" id="module-scope-discovery" aria-labelledby="workspace-heading-scope-discovery"
        hidden={activeModule !== 'scope-discovery'} inert={activeModule !== 'scope-discovery'}>
        <div className="module-heading"><div><p className="panel-kicker">Authorized scope</p><h2 id="workspace-heading-scope-discovery" tabIndex="-1">Scope &amp; Discovery</h2></div></div>
        <InvestigationLookup onOpenResult={openInvestigationResult} />
      <NetworkWorkspace investigationRequest={investigationNavigation} onOpenInvestigationContext={openInvestigationContext} />
      </section>

      <section className="module-section workspace-module" id="module-remote-sensors" aria-labelledby="workspace-heading-remote-sensors"
        hidden={activeModule !== 'remote-sensors'} inert={activeModule !== 'remote-sensors'}>
        <div className="module-heading"><div><p className="panel-kicker">Fleet operations</p><h2 id="workspace-heading-remote-sensors" tabIndex="-1">Remote Sensors</h2></div></div>
      <RemoteSensorFleet investigationRequest={investigationNavigation} onOpenInvestigationContext={openInvestigationContext} />
      </section>

      <SecurityReviewPanel
        activeModule={activeModule}
        refreshSignal={lastUpdated}
        investigationRequest={investigationNavigation}
        onOpenInvestigationContext={openInvestigationContext}
        reviewIntakeRequest={reviewIntakeRequest}
        onStartReview={startReviewFromEvidence}
        onClearReviewIntake={clearReviewIntake}
        onReviewIntakeSubmitting={setReviewIntakeSubmitting}
        reviewIntakeSubmitting={reviewIntakeSubmitting}
      />

      <section className="module-section workspace-module" id="module-perimeter" aria-labelledby="workspace-heading-perimeter"
        hidden={activeModule !== 'perimeter'} inert={activeModule !== 'perimeter'}>
      <div className="module-heading"><div><p className="panel-kicker">Network edge</p><h2 id="workspace-heading-perimeter" tabIndex="-1">Perimeter</h2></div></div>
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
      </section>

      <section className="module-section workspace-module" id="module-events-analytics" aria-labelledby="workspace-heading-events-analytics"
        hidden={activeModule !== 'events-analytics'} inert={activeModule !== 'events-analytics'}>
      <div className="module-heading"><div><p className="panel-kicker">Event intelligence</p><h2 id="workspace-heading-events-analytics" tabIndex="-1">Events &amp; Analytics</h2></div></div>
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
              {topIpSampleLabel && (
                <p className="source-ip-basis" role="note">
                  {topIpSampleLabel}
                </p>
              )}
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
                    {item.event_total} {topIpSampleLabel ? 'recent events' : 'events'}
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

          <form className="source-ip-filter" onSubmit={applyIpFilter}>
            <label htmlFor="source-ip-filter-input">
              <span>Source IP</span>
              <input
                id="source-ip-filter-input"
                type="text"
                inputMode="text"
                autoComplete="off"
                maxLength={15}
                placeholder="192.0.2.1"
                value={ipDraft}
                onChange={handleIpDraftChange}
                aria-describedby={ipValidationError ? 'source-ip-filter-error' : undefined}
                aria-invalid={Boolean(ipValidationError)}
              />
            </label>
            <div className="source-ip-filter-actions">
              <button className="clear-filters" type="submit">
                Apply
              </button>
              <button
                className="clear-filters"
                type="button"
                onClick={clearIpFilter}
                disabled={!ipDraft && !ipFilter}
              >
                Clear IP
              </button>
            </div>
            {ipValidationError && (
              <p id="source-ip-filter-error" className="source-ip-filter-error" role="alert">
                {ipValidationError}
              </p>
            )}
          </form>

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
                All retained history
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
          <div className="export-settings">
            <p className="export-label">
              Export matching events (complete export; oversized results are rejected)
            </p>
            <label className="export-range-mode">
              <span>Export time range</span>
              <select
                value={exportRangeMode}
                onChange={(event) => {
                  setExportRangeMode(event.target.value)
                  setExportError(null)
                }}
              >
                <option value="preset">Use selected preset ({timeRange})</option>
                <option value="custom">Custom date range</option>
              </select>
            </label>
            {exportRangeMode === 'custom' && (
              <div className="export-custom-range">
                <label>
                  <span>Start (local time, inclusive)</span>
                  <input
                    type="datetime-local"
                    value={exportFromLocal}
                    onChange={(event) => {
                      setExportFromLocal(event.target.value)
                      setExportError(null)
                    }}
                  />
                </label>
                <label>
                  <span>End (local time, exclusive)</span>
                  <input
                    type="datetime-local"
                    value={exportUntilLocal}
                    onChange={(event) => {
                      setExportUntilLocal(event.target.value)
                      setExportError(null)
                    }}
                  />
                </label>
                <p className="export-range-help">Choose a valid range of 31 days or less.</p>
              </div>
            )}
          </div>

          <div className="export-actions">
            <button
              type="button"
              disabled={exportDisabled}
              onClick={() => downloadExport('csv')}
            >
              Export CSV
            </button>

            <button
              type="button"
              disabled={exportDisabled}
              onClick={() => downloadExport('json')}
            >
              Export JSON
            </button>

            <button
              type="button"
              disabled={exportDisabled}
              onClick={() => downloadExport('pdf')}
            >
              Export PDF
            </button>
          </div>
        </div>

        {exportError && (
          <p className="export-error" role="alert">
            {exportError}
          </p>
        )}

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
      </section>

      <section className="module-section workspace-module operator-module" id="module-data-lifecycle" aria-labelledby="workspace-heading-data-lifecycle"
        hidden={activeModule !== 'data-lifecycle'} inert={activeModule !== 'data-lifecycle'}>
        <div className="module-heading"><div><p className="panel-kicker">Local operator</p><h2 id="workspace-heading-data-lifecycle" tabIndex="-1">Data Lifecycle</h2></div></div>
        <DataLifecycle />
      </section>
      <section className="module-section workspace-module support-module" id="module-help" aria-labelledby="workspace-heading-help"
        hidden={activeModule !== 'help'} inert={activeModule !== 'help'}>
        <div className="module-heading"><div><p className="panel-kicker">Support &amp; Information</p><h2 id="workspace-heading-help" tabIndex="-1">Help &amp; User Guide</h2></div>
          <button type="button" className="text-link-button" onClick={() => navigateToModule(previousOperationalModule.current)}>Return to workspace</button></div>
        <HelpGuide topicId={helpTopic} onTopicChange={selectHelpTopic} />
      </section>
      <section className="module-section workspace-module support-module" id="module-about" aria-labelledby="workspace-heading-about"
        hidden={activeModule !== 'about'} inert={activeModule !== 'about'}>
        <div className="module-heading"><div><p className="panel-kicker">Support &amp; Information</p><h2 id="workspace-heading-about" tabIndex="-1">About SentinelIP</h2></div></div>
        <AboutSentinelIP />
      </section>
      </main>

      <footer className="dashboard-footer">
        <strong>Tanashi Studio™</strong>
        <span>Automatic refresh every 5 seconds</span>
        <span>© 2026 Tanashi Studio. All rights reserved.</span>
      </footer>
      </div>
    </div>
  )
}

export default App

function NavIcon({ name }) {
  const shared = { width: 18, height: 18, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round', strokeLinejoin: 'round', 'aria-hidden': true, focusable: false }
  const shapes = {
    overview: <><rect x="3" y="3" width="8" height="8" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="11" width="7" height="10" rx="1" /><rect x="3" y="14" width="8" height="7" rx="1" /></>,
    'scope-discovery': <><circle cx="12" cy="12" r="8.5" /><path d="M3.8 12h16.4M12 3.5a13 13 0 0 1 0 17M12 3.5a13 13 0 0 0 0 17" /></>,
    'remote-sensors': <><path d="M12 18v3M8 21h8M5 14a10 10 0 0 1 14 0M8 10a5.7 5.7 0 0 1 8 0M11 6a1.5 1.5 0 0 1 2 0" /><circle cx="12" cy="17" r="1" /></>,
    operations: <><rect x="5" y="4" width="14" height="17" rx="2" /><path d="M9 4.5V3h6v1.5M8 10h8M8 14h8M8 18h5" /></>,
    detections: <><path d="M12 3 20 6v5c0 5-3.4 8.2-8 10-4.6-1.8-8-5-8-10V6l8-3Z" /><path d="M12 8v5M12 16h.01" /></>,
    perimeter: <><circle cx="12" cy="12" r="8.5" /><path d="M12 12 19 7M12 4v2M20 12h-2M12 20v-2M4 12h2" /><circle cx="12" cy="12" r="2" /></>,
    'events-analytics': <><path d="M3 20h18M5 16l4-5 4 2 6-8" /><circle cx="5" cy="16" r="1" /><circle cx="9" cy="11" r="1" /><circle cx="13" cy="13" r="1" /><circle cx="19" cy="5" r="1" /></>,
    'data-lifecycle': <><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" /></>,
    help: <><circle cx="12" cy="12" r="9" /><path d="M9.7 9a2.4 2.4 0 1 1 4.4 1.3c-.9 1.1-2.1 1.4-2.1 3M12 17h.01" /></>,
    about: <><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></>,
  }
  return <svg className="nav-icon" {...shared}>{shapes[name]}</svg>
}
