import { useEffect, useMemo, useRef, useState } from 'react'
import { scrollToVisibleTarget } from '../hooks/useWorkspaceNavigation.js'

const HELP_TOPICS = [
  { id: 'getting-started', title: 'Getting Started', group: 'Workspace basics', keywords: 'navigation read-only local operator refresh api',
    text: 'Use the sidebar to move among the seven operational modules. The workspace retains module form and filter state while you visit Help. The header reports API Online or API Offline and offers a manual dashboard refresh. Most dashboards read from the configured local API; actions such as scans, task creation, incident review submission, and cleanup are separate state-changing workflows.', action: 'Read-only: navigate, inspect dashboards, and refresh data. State-changing: only explicit workflows that submit or apply an operation.' },
  { id: 'overview', title: 'Overview & severity', group: 'Workspace basics', keywords: 'dashboard events INFO WARNING ALERT severity indicators',
    text: 'Overview summarizes total events and INFO, WARNING, and ALERT counts, recent activity, and recent alerts. Severity labels describe recorded event or detection classifications; they do not by themselves confirm compromise. Use Events & Analytics to inspect matching event records and available context.', action: 'Read-only. Counts depend on available API data and current retained records.' },
  { id: 'scope', title: 'Scope & Discovery', group: 'Operations', keywords: 'authorized targets network scan discovery public hostname private',
    text: 'Review the configured private networks and scopes before discovery. Public IPv4 and hostname scopes require explicit authorization confirmation and remain subject to the server policy. Select an enabled, confirmed scope before starting discovery; service discovery is initiated for a selected discovered device. Only scan targets you own or are explicitly authorized to assess, and follow your organization’s approved scope and change process.', action: 'Read-only: inspect scope and device records. State-changing: creating or reauthorizing a scope and starting discovery/service discovery.' },
  { id: 'sensors', title: 'Remote Sensors & sites', group: 'Operations', keywords: 'remote sensor fleet site heartbeat task assigned scope',
    text: 'Use the fleet filters to find sensors by site, status, platform, or enabled state. Select a sensor to inspect its site, assignments, status, and supported capabilities. Task creation uses the server-provided eligible assigned scope and, for service discovery, a server-provided device/IP; an offline or pending sensor may only run a queued task if it claims it before expiry.', action: 'Read-only: fleet, site, task history, and detail views. State-changing: sensor/site management actions and explicit task creation.' },
  { id: 'operations', title: 'Operations & incident reviews', group: 'Review work', keywords: 'incident review case evidence submit create analyst',
    text: 'Operations contains incident reviews and review activity. Source evidence can open a review draft; it does not create a review until an operator submits the form. Review fields remain operator-controlled. Inspect evidence and the review history before recording a decision.', action: 'Read-only: search and inspect reviews and evidence. State-changing: submitting a review, updating review workflow fields, or adding an explicitly submitted review action.' },
  { id: 'detections', title: 'Detections & correlations', group: 'Review work', keywords: 'threat detection correlation web evidence',
    text: 'Detections presents available threat detections, correlations, and web detections with their recorded evidence. Open a detail view to inspect the underlying context. Correlations are review signals linking records; read them as evidence for investigation rather than a definitive conclusion.', action: 'Read-only: inspect detections and evidence. Starting a review opens a draft; submitting it changes review state.' },
  { id: 'perimeter', title: 'Perimeter monitoring', group: 'Monitoring', keywords: 'external exposure inbound site policy allow block reject',
    text: 'Perimeter combines External Activity evidence with external exposure inventory and change views. Use the available site, source, and time filters to narrow recorded observations. Allow, block, reject, and unknown values describe the available perimeter evidence; inbound activity or exposure changes are not by themselves proof of compromise. The dashboards are review-oriented and do not block traffic or initiate scans.', action: 'Read-only dashboards and filters. A Start Review action opens a draft; submission changes review state.' },
  { id: 'events', title: 'Events, filters & exports', group: 'Monitoring', keywords: 'events analytics severity source ip time range CSV JSON PDF export',
    text: 'Events & Analytics includes event history, severity and source-IP filters, a time range, page size, and pagination. Exports use the selected filters and either a preset window or a custom range of 31 days or less. CSV and JSON exports are limited to 5,000 rows; PDF is limited to 1,000. Oversized exports are rejected as a whole rather than silently truncated. Export endpoints require the configured local operator boundary.', action: 'Read-only: filtering and viewing. Exporting creates a local file or opens JSON in a tab; it does not edit event records.' },
  { id: 'lifecycle', title: 'Data Lifecycle & cleanup safety', group: 'Local operator', keywords: 'retention preview delete cleanup backup DNS web legacy perimeter',
    text: 'Load a counts-only preview to review the displayed policy and eligible rows. Preview is read-only and does not authorize deletion. Cleanup requires a separate confirmation and rechecks eligibility; flat-row batches delete at most 100 rows and perimeter cleanup at most 25 complete components. Legacy events use a 90-day policy; threat-referenced, malformed, and future rows are preserved. Deletion is permanent. Maintain and test a backup before applying cleanup; restoring replaces the database with its backup-time state. Deleted SQLite pages may be reused without shrinking the file.', action: 'Preview: read-only. Apply: destructive and state-changing. Read the displayed policy, eligibility, and confirmation carefully before each batch.' },
  { id: 'troubleshooting', title: 'Troubleshooting & missing data', group: 'Workspace basics', keywords: 'API Offline unavailable empty missing loading refresh local server',
    text: 'API Offline means the dashboard health check did not return a healthy response. Confirm the approved local API is running and that the frontend is pointed at the intended API base, then use Refresh now. Empty lists can also mean no matching retained records, restrictive filters, or an unavailable module-specific request. Clear or widen filters and retry. Help is bundled in the frontend, so it remains available while the API is offline.', action: 'Read-only troubleshooting: check status, adjust filters, and retry reads. Do not broaden scan scope to troubleshoot missing data.' },
]

export default function HelpGuide({ topicId, onTopicChange }) {
  const [query, setQuery] = useState('')
  const articleHeading = useRef(null)
  const shouldMoveToArticle = useRef(false)
  const selected = HELP_TOPICS.find((topic) => topic.id === topicId) ?? HELP_TOPICS[0]
  const results = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase()
    if (!normalized) return HELP_TOPICS
    return HELP_TOPICS.filter((topic) => `${topic.title} ${topic.group} ${topic.keywords} ${topic.text} ${topic.action}`.toLocaleLowerCase().includes(normalized))
  }, [query])

  useEffect(() => {
    if (!shouldMoveToArticle.current) return
    shouldMoveToArticle.current = false
    scrollToVisibleTarget(articleHeading.current, { focus: true, preserveVisible: true })
  }, [selected.id])

  function chooseTopic(topic) {
    if (topic.id === selected.id) return
    shouldMoveToArticle.current = true
    onTopicChange(topic.id)
  }

  return <div className="help-layout">
    <nav className="help-index panel" aria-label="Help topics">
      <label className="help-search-label" htmlFor="help-search">Search help</label>
      <input id="help-search" className="help-search" type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search topics or keywords" />
      <div className="help-topic-list" role="group" aria-label="Help articles">
        {results.map((topic) => <button key={topic.id} type="button" className={`help-topic-button${selected.id === topic.id ? ' active' : ''}`} aria-pressed={selected.id === topic.id} onClick={() => chooseTopic(topic)}>
          <span>{topic.title}</span><small>{topic.group}</small>
        </button>)}
        {results.length === 0 && <p className="help-empty" role="status">No help topics match “{query.trim()}”. Try a different keyword.</p>}
      </div>
    </nav>
    <article className="panel help-article" aria-labelledby="help-article-heading" aria-live="polite">
      <p className="panel-kicker">{selected.group}</p>
      <h3 id="help-article-heading" ref={articleHeading} tabIndex="-1">{selected.title}</h3>
      <p>{selected.text}</p>
      <div className="help-action-note"><strong>Action level</strong><p>{selected.action}</p></div>
    </article>
  </div>
}
