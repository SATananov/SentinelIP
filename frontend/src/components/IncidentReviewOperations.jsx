import { useEffect, useMemo, useState } from 'react'

import {
  loadIncidentReviewDevices,
  loadIncidentReviewOperations,
  loadIncidentReviewScopes,
  loadIncidentReviewSites,
} from '../services/securityApi.js'
import { formatReviewAge, formatSiteWorkloadAge } from '../services/incidentReviewFormat.js'
import {
  applyDeviceDrilldown,
  applyScopeDrilldown,
  applySiteContextToQueue,
  siteContextFromWorkloadRow,
} from '../services/incidentReviewOperationsState.js'

const AGE_LABELS = { LT_1H: '< 1h', H1_24: '1h–24h', D1_3: '1d–3d', D3_7: '3d–7d', GT_7D: '> 7d' }
const ATTENTION_SIGNALS = [
  ['HIGH_PRIORITY_UNRESOLVED', 'High-priority unresolved'],
  ['AGING_REVIEW', 'Review aging'],
  ['NO_RECENT_ACTIVITY', 'No recent activity'],
  ['REOPENED_REVIEW', 'Reopened review'],
  ['MISSING_SOURCE_EVIDENCE', 'Missing source evidence'],
  ['NO_LINKED_EVIDENCE', 'No linked evidence'],
]

function IncidentReviewOperations({ refreshSignal, onSelectReview }) {
  const [filters, setFilters] = useState({ sort: 'oldest_open', limit: 20, offset: 0 })
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [siteOptions, setSiteOptions] = useState({ sort: 'unresolved_desc', limit: 20, offset: 0 })
  const [siteData, setSiteData] = useState(null)
  const [siteLoading, setSiteLoading] = useState(false)
  const [siteError, setSiteError] = useState(null)
  const [selectedSiteContext, setSelectedSiteContext] = useState(null)
  const [workloadTab, setWorkloadTab] = useState('scopes')
  const [scopeOptions, setScopeOptions] = useState({ sort: 'unresolved_desc', limit: 20, offset: 0 })
  const [deviceOptions, setDeviceOptions] = useState({ sort: 'unresolved_desc', limit: 20, offset: 0 })
  const [scopeData, setScopeData] = useState(null)
  const [scopeLoading, setScopeLoading] = useState(false)
  const [scopeError, setScopeError] = useState(null)
  const [deviceData, setDeviceData] = useState(null)
  const [deviceLoading, setDeviceLoading] = useState(false)
  const [deviceError, setDeviceError] = useState(null)
  const query = useMemo(() => ({ ...filters }), [filters])

  useEffect(() => {
    const controller = new AbortController()
    Promise.resolve().then(() => {
      if (!controller.signal.aborted) { setLoading(true); setError(null) }
      return loadIncidentReviewOperations(query, controller.signal)
    })
      .then((result) => { if (!controller.signal.aborted) setData(result) })
      .catch((err) => { if (err.name !== 'AbortError') setError(err.message) })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [query, refreshSignal])

  useEffect(() => {
    const controller = new AbortController()
    Promise.resolve().then(() => {
      if (!controller.signal.aborted) { setSiteLoading(true); setSiteError(null) }
      return loadIncidentReviewSites(siteOptions, controller.signal)
    })
      .then((result) => { if (!controller.signal.aborted) setSiteData(result) })
      .catch((err) => { if (err.name !== 'AbortError') setSiteError(err.message) })
      .finally(() => { if (!controller.signal.aborted) setSiteLoading(false) })
    return () => controller.abort()
  }, [siteOptions, refreshSignal])

  const workloadContext = useMemo(() => selectedSiteContext ? {
    site_id: selectedSiteContext.site_id,
    unattributed_only: selectedSiteContext.unattributed_only,
  } : null, [selectedSiteContext])

  useEffect(() => {
    if (!workloadContext || workloadTab !== 'scopes') return undefined
    const controller = new AbortController()
    Promise.resolve().then(() => {
      if (!controller.signal.aborted) { setScopeLoading(true); setScopeError(null) }
      return loadIncidentReviewScopes(workloadContext, scopeOptions, controller.signal)
    })
      .then((result) => { if (!controller.signal.aborted) setScopeData(result) })
      .catch((err) => { if (err.name !== 'AbortError') setScopeError(err.message) })
      .finally(() => { if (!controller.signal.aborted) setScopeLoading(false) })
    return () => controller.abort()
  }, [workloadContext, workloadTab, scopeOptions, refreshSignal])

  useEffect(() => {
    if (!workloadContext || workloadTab !== 'devices') return undefined
    const controller = new AbortController()
    Promise.resolve().then(() => {
      if (!controller.signal.aborted) { setDeviceLoading(true); setDeviceError(null) }
      return loadIncidentReviewDevices(workloadContext, deviceOptions, controller.signal)
    })
      .then((result) => { if (!controller.signal.aborted) setDeviceData(result) })
      .catch((err) => { if (err.name !== 'AbortError') setDeviceError(err.message) })
      .finally(() => { if (!controller.signal.aborted) setDeviceLoading(false) })
    return () => controller.abort()
  }, [workloadContext, workloadTab, deviceOptions, refreshSignal])

  function updateFilter(key, value) {
    if (key === 'site_id') {
      setSelectedSiteContext(null)
      setScopeOptions((current) => ({ ...current, offset: 0 }))
      setDeviceOptions((current) => ({ ...current, offset: 0 }))
      setFilters((current) => {
        const next = { ...current, [key]: value, offset: 0 }
        for (const drilldown of ['unattributed_only','scope_id','device_id','unattributed_scope_only','unattributed_device_only']) delete next[drilldown]
        return next
      })
      return
    }
    setFilters((current) => ({ ...current, [key]: value, offset: 0 }))
  }

  function selectSite(siteRow) {
    const context = siteContextFromWorkloadRow(siteRow)
    setSelectedSiteContext(context)
    setScopeData(null)
    setDeviceData(null)
    setScopeError(null)
    setDeviceError(null)
    setScopeOptions((current) => ({ ...current, offset: 0 }))
    setDeviceOptions((current) => ({ ...current, offset: 0 }))
    setFilters((current) => applySiteContextToQueue(current, context))
  }

  function selectScope(scopeId) {
    setFilters((current) => applyScopeDrilldown(current, scopeId))
  }

  function selectDevice(deviceId) {
    setFilters((current) => applyDeviceDrilldown(current, deviceId))
  }

  function clearFilters() {
    setSelectedSiteContext(null)
    setScopeData(null)
    setDeviceData(null)
    setScopeOptions((current) => ({ ...current, offset: 0 }))
    setDeviceOptions((current) => ({ ...current, offset: 0 }))
    setFilters({ sort: 'oldest_open', limit: 20, offset: 0 })
  }

  const summary = data?.summary
  const page = data?.pagination
  const totalPages = page ? Math.max(1, Math.ceil(page.total / page.limit)) : 1
  const currentPage = page ? Math.floor(page.offset / page.limit) + 1 : 1

  return (
    <section className="panel review-operations">
      <div className="panel-heading"><div><p className="panel-kicker">Analyst Operations</p><h2>Review Queue</h2>
        <p className="security-layer-copy">Priority reflects analyst review workload. Review age is time since creation and does not indicate severity.</p>
        <p className="security-layer-copy">Attention signals describe analyst workflow conditions. They do not change review priority, state, or disposition.</p></div>
        <span className="panel-count">{loading ? '…' : page?.total ?? 0}</span></div>
      {summary && <div className="review-operations-cards">
        <article><span>Total Reviews</span><strong>{summary.total_reviews}</strong></article>
        <article><span>Open Reviews</span><strong>{summary.open_count}</strong></article>
        <article><span>In Review</span><strong>{summary.in_review_count}</strong></article>
        <article><span>Closed Reviews</span><strong>{summary.closed_count}</strong></article>
        <article><span>Unresolved</span><strong>{summary.unresolved_count}</strong></article>
        <article><span>Created · 24h</span><strong>{summary.created_last_24h}</strong></article>
        <article><span>Closed · 24h</span><strong>{summary.closed_last_24h}</strong></article>
      </div>}
      {summary && <div className="review-operations-breakdown">
        <div><strong>Priority</strong>{Object.entries(summary.priority_distribution).map(([key, count]) => <span key={key}>{key}: {count}</span>)}</div>
        <div><strong>Active Review Age</strong>{Object.entries(summary.active_age_buckets).map(([key, count]) => <span key={key}>{AGE_LABELS[key]}: {count}</span>)}</div>
        <div><strong>Disposition</strong>{Object.entries(summary.disposition_distribution).map(([key, count]) => <span key={key}>{key.replaceAll('_',' ')}: {count}</span>)}</div>
        <div><strong>Reviews by Site</strong>{summary.reviews_by_site.map(({ site_id, count }) => <span key={site_id ?? 'unattributed'}>{site_id === null ? 'Unattributed' : `Site ${site_id}`}: {count}</span>)}</div>
      </div>}
      <section className="review-site-workload" aria-labelledby="review-site-workload-title">
        <div className="review-site-workload-heading"><h3 id="review-site-workload-title">Site Workload</h3>
          <label><span>Sort sites</span><select value={siteOptions.sort} onChange={(event) => setSiteOptions((current) => ({ ...current, sort: event.target.value, offset: 0 }))}>
            {[
              ['unresolved_desc', 'Unresolved Reviews'], ['attention_desc', 'Needs Attention'],
              ['oldest_active', 'Oldest Active Review'], ['recent_activity', 'Latest Review Activity'],
              ['site_name', 'Site name'],
            ].map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select></label>
        </div>
        <p className="security-layer-copy">Global review workload by site. Counts are operational context and do not indicate site severity.</p>
        {siteError && <div className="error-box">{siteError}</div>}
        {siteLoading && !siteData ? <p className="security-empty">Loading site workload…</p> : siteError && !siteData ? null : !siteData?.sites?.length ? <p className="security-empty">No site workload to display.</p> : (
          <div className="review-queue-table-wrap"><table className="review-queue-table"><thead><tr>
            <th>Site</th><th>Unresolved</th><th>Needs Attention</th><th>High-Priority Unresolved</th><th>Oldest Active Review</th><th>Latest Review Activity</th>
          </tr></thead><tbody>{siteData.sites.map((site) => <tr key={site.site_id ?? 'unattributed'}>
            <td><button type="button" className="review-queue-select" aria-pressed={selectedSiteContext?.site_id === site.site_id} onClick={() => selectSite(site)}><strong>{site.site_name ?? `Site ${site.site_id}`}</strong><small>Select site workload</small></button></td>
            <td>{site.unresolved_reviews}</td><td>{site.reviews_needing_attention}</td><td>{site.high_priority_unresolved}</td>
            <td>{site.oldest_active_created_at ? `${formatSiteWorkloadAge(site.oldest_active_age_seconds)} · ${site.oldest_active_created_at.replace('T',' ').replace('+00:00','Z')}` : '—'}</td>
            <td>{site.latest_review_activity_at?.replace('T',' ').replace('+00:00','Z') || '—'}</td>
          </tr>)}</tbody></table></div>
        )}
        {siteData?.pagination && <div className="pagination"><span className="pagination-summary">{siteData.pagination.total ? `Page ${Math.floor(siteData.pagination.offset / siteData.pagination.limit) + 1} of ${Math.max(1, Math.ceil(siteData.pagination.total / siteData.pagination.limit))} · ${siteData.pagination.total} site groups` : 'No site groups'}</span><div className="pagination-actions">
          <button type="button" disabled={siteData.pagination.offset === 0} onClick={() => setSiteOptions((current) => ({ ...current, offset: Math.max(0, current.offset - current.limit) }))}>Previous</button>
          <button type="button" disabled={siteData.pagination.offset + siteData.pagination.limit >= siteData.pagination.total || siteData.pagination.offset >= 100000} onClick={() => setSiteOptions((current) => ({ ...current, offset: current.offset + current.limit }))}>Next</button>
        </div></div>}
      </section>
      <section className="review-attribution-workload" aria-labelledby="review-attribution-workload-title">
        <h3 id="review-attribution-workload-title">Scope &amp; Device Workload</h3>
        {!selectedSiteContext ? <p className="security-empty">Select a site to view scope and device workload.</p> : <>
          <p className="security-layer-copy">Selected context: {selectedSiteContext.site_id === null ? 'Unattributed' : `Site #${selectedSiteContext.site_id}`}. Workload reflects review attribution only.</p>
          <div className="review-workload-tabs" role="tablist" aria-label="Scope and device workload">
            <button type="button" role="tab" aria-selected={workloadTab === 'scopes'} onClick={() => setWorkloadTab('scopes')}>Scope Workload</button>
            <button type="button" role="tab" aria-selected={workloadTab === 'devices'} onClick={() => setWorkloadTab('devices')}>Device Workload</button>
          </div>
          {workloadTab === 'scopes' && <div role="tabpanel" className="review-workload-panel">
            <div className="review-site-workload-heading"><h4>Scope Workload</h4><label><span>Sort scopes</span><select value={scopeOptions.sort} onChange={(event) => setScopeOptions((current) => ({ ...current, sort: event.target.value, offset: 0 }))}>
              {['unresolved_desc','attention_desc','oldest_active','recent_activity','name'].map((sort) => <option key={sort} value={sort}>{sort.replaceAll('_',' ')}</option>)}
            </select></label></div>
            {scopeError && <div className="error-box">{scopeError}</div>}
            {scopeLoading && !scopeData ? <p className="security-empty">Loading scope workload…</p> : scopeError && !scopeData ? null : !scopeData?.scopes?.length ? <p className="security-empty">No scope workload in this site context.</p> : <div className="review-queue-table-wrap"><table className="review-queue-table"><thead><tr><th>Scope</th><th>Unresolved</th><th>Needs Attention</th><th>High-Priority Unresolved</th><th>Oldest Active Review</th><th>Latest Review Activity</th></tr></thead><tbody>
              {scopeData.scopes.map((scope) => <tr key={scope.scope_id ?? 'unattributed-scope'}><td><button type="button" className="review-queue-select" onClick={() => selectScope(scope.scope_id)}><strong>{scope.scope_id === null ? 'Unattributed' : scope.scope_name || scope.canonical_target || `Scope ID ${scope.scope_id}`}</strong>{(scope.scope_name && scope.canonical_target) ? <small>{scope.canonical_target}{scope.scope_type ? ` · ${scope.scope_type.replaceAll('_',' ')}` : ''}</small> : scope.scope_type && <small>{scope.scope_type.replaceAll('_',' ')}</small>}</button></td>
                <td>{scope.unresolved_reviews}</td><td>{scope.reviews_needing_attention}</td><td>{scope.high_priority_unresolved}</td><td>{scope.oldest_active_created_at ? `${formatSiteWorkloadAge(scope.oldest_active_age_seconds)} · ${scope.oldest_active_created_at.replace('T',' ').replace('+00:00','Z')}` : '—'}</td><td>{scope.latest_review_activity_at?.replace('T',' ').replace('+00:00','Z') || '—'}</td>
              </tr>)}
            </tbody></table></div>}
            {scopeData?.pagination && <div className="pagination"><span className="pagination-summary">{scopeData.pagination.total ? `Page ${Math.floor(scopeData.pagination.offset / scopeData.pagination.limit) + 1} of ${Math.max(1, Math.ceil(scopeData.pagination.total / scopeData.pagination.limit))} · ${scopeData.pagination.total} scope groups` : 'No scope groups'}</span><div className="pagination-actions">
              <button type="button" disabled={scopeData.pagination.offset === 0} onClick={() => setScopeOptions((current) => ({ ...current, offset: Math.max(0, current.offset - current.limit) }))}>Previous</button><button type="button" disabled={scopeData.pagination.offset + scopeData.pagination.limit >= scopeData.pagination.total || scopeData.pagination.offset >= 100000} onClick={() => setScopeOptions((current) => ({ ...current, offset: current.offset + current.limit }))}>Next</button>
            </div></div>}
          </div>}
          {workloadTab === 'devices' && <div role="tabpanel" className="review-workload-panel">
            <div className="review-site-workload-heading"><h4>Device Workload</h4><label><span>Sort devices</span><select value={deviceOptions.sort} onChange={(event) => setDeviceOptions((current) => ({ ...current, sort: event.target.value, offset: 0 }))}>
              {['unresolved_desc','attention_desc','oldest_active','recent_activity','label'].map((sort) => <option key={sort} value={sort}>{sort.replaceAll('_',' ')}</option>)}
            </select></label></div>
            {deviceError && <div className="error-box">{deviceError}</div>}
            {deviceLoading && !deviceData ? <p className="security-empty">Loading device workload…</p> : deviceError && !deviceData ? null : !deviceData?.devices?.length ? <p className="security-empty">No device workload in this site context.</p> : <div className="review-queue-table-wrap"><table className="review-queue-table"><thead><tr><th>Device</th><th>Unresolved</th><th>Needs Attention</th><th>High-Priority Unresolved</th><th>Oldest Active Review</th><th>Latest Review Activity</th></tr></thead><tbody>
              {deviceData.devices.map((device) => <tr key={device.device_id ?? 'unattributed-device'}><td><button type="button" className="review-queue-select" onClick={() => selectDevice(device.device_id)}><strong>{device.device_label}</strong>{device.hostname && <small>{device.hostname}</small>}</button></td>
                <td>{device.unresolved_reviews}</td><td>{device.reviews_needing_attention}</td><td>{device.high_priority_unresolved}</td><td>{device.oldest_active_created_at ? `${formatSiteWorkloadAge(device.oldest_active_age_seconds)} · ${device.oldest_active_created_at.replace('T',' ').replace('+00:00','Z')}` : '—'}</td><td>{device.latest_review_activity_at?.replace('T',' ').replace('+00:00','Z') || '—'}</td>
              </tr>)}
            </tbody></table></div>}
            {deviceData?.pagination && <div className="pagination"><span className="pagination-summary">{deviceData.pagination.total ? `Page ${Math.floor(deviceData.pagination.offset / deviceData.pagination.limit) + 1} of ${Math.max(1, Math.ceil(deviceData.pagination.total / deviceData.pagination.limit))} · ${deviceData.pagination.total} device groups` : 'No device groups'}</span><div className="pagination-actions">
              <button type="button" disabled={deviceData.pagination.offset === 0} onClick={() => setDeviceOptions((current) => ({ ...current, offset: Math.max(0, current.offset - current.limit) }))}>Previous</button><button type="button" disabled={deviceData.pagination.offset + deviceData.pagination.limit >= deviceData.pagination.total || deviceData.pagination.offset >= 100000} onClick={() => setDeviceOptions((current) => ({ ...current, offset: current.offset + current.limit }))}>Next</button>
            </div></div>}
          </div>}
        </>}
      </section>
      <div className="filters review-operations-filters">
        <label><span>State</span><select value={filters.state || ''} onChange={(e) => updateFilter('state', e.target.value)}><option value="">All states</option><option>OPEN</option><option>IN_REVIEW</option><option>CLOSED</option></select></label>
        <label><span>Priority</span><select value={filters.priority || ''} onChange={(e) => updateFilter('priority', e.target.value)}><option value="">All priorities</option>{['CRITICAL','HIGH','MEDIUM','LOW'].map((v) => <option key={v}>{v}</option>)}</select></label>
        <label><span>Disposition</span><select value={filters.disposition || ''} onChange={(e) => updateFilter('disposition', e.target.value)}><option value="">All dispositions</option>{['UNREVIEWED','EXPECTED_ACTIVITY','BENIGN','NEEDS_MONITORING','ACTION_REQUIRED','FALSE_POSITIVE','INCONCLUSIVE'].map((v) => <option key={v}>{v}</option>)}</select></label>
        <label><span>Review Age</span><select value={filters.age_bucket || ''} onChange={(e) => updateFilter('age_bucket', e.target.value)}><option value="">Any age</option>{Object.entries(AGE_LABELS).map(([v, label]) => <option key={v} value={v}>{label}</option>)}</select></label>
        {['site_id','scope_id','device_id'].map((key) => <label key={key}><span>{key.replace('_id','').replace('_',' ')}</span><input aria-label={key} type="number" min="1" value={filters[key] || ''} onChange={(e) => updateFilter(key, e.target.value)} placeholder="All" /></label>)}
        <label><span>Evidence</span><select value={filters.has_evidence === true ? 'true' : filters.has_evidence === false ? 'false' : ''} onChange={(e) => updateFilter('has_evidence', e.target.value === '' ? '' : e.target.value === 'true')}><option value="">Any</option><option value="true">Has evidence</option><option value="false">No evidence</option></select></label>
        <label><span>Needs attention</span><select value={filters.has_attention === true ? 'true' : filters.has_attention === false ? 'false' : ''} onChange={(e) => updateFilter('has_attention', e.target.value === '' ? '' : e.target.value === 'true')}><option value="">Any</option><option value="true">Needs attention</option><option value="false">No attention signals</option></select></label>
        <label><span>Attention signal</span><select value={filters.attention_signal || ''} onChange={(e) => updateFilter('attention_signal', e.target.value)}><option value="">All signals</option>{ATTENTION_SIGNALS.map(([code, label]) => <option key={code} value={code}>{label}</option>)}</select></label>
        <label><span>Sort</span><select value={filters.sort} onChange={(e) => updateFilter('sort', e.target.value)}>{[['oldest_open','Oldest open'],['newest','Newest'],['oldest','Oldest'],['priority','Priority'],['recently_updated','Recently updated']].map(([v,l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        <label className="review-operations-check"><input type="checkbox" checked={Boolean(filters.unresolved_only)} onChange={(e) => updateFilter('unresolved_only', e.target.checked)} /> Unresolved only</label>
        <button type="button" className="clear-filters" onClick={clearFilters}>Clear filters</button>
      </div>
      {error && <div className="error-box">{error}</div>}
      {loading && !data ? <p className="security-empty">Loading review queue…</p> : error && !data ? null : !data?.queue?.length ? <p className="security-empty">No reviews match the selected filters.</p> : (
        <div className="review-queue-table-wrap"><table className="review-queue-table"><thead><tr><th>Review</th><th>Attention</th><th>State</th><th>Priority</th><th>Disposition</th><th>Review Age</th><th>Evidence</th><th>Notes</th><th>Latest Activity</th></tr></thead><tbody>
          {data.queue.map((row) => <tr key={row.id}><td><button type="button" className="review-queue-select" onClick={() => onSelectReview(row.id)}><strong>{row.title}</strong><small>{row.incident_key}</small></button></td><td className="review-queue-attention" title={row.attention_signals.map((signal) => `${signal.label}: ${signal.reason}`).join('\n')} aria-label={row.attention_signals.map((signal) => `${signal.label}: ${signal.reason}`).join('. ')}>{row.has_attention ? <><strong>{row.attention_signals.slice(0, 2).map((signal) => signal.label).join(' · ')}</strong>{row.attention_signal_count > 2 && <small>+{row.attention_signal_count - 2} more</small>}</> : '—'}</td><td>{row.state.replaceAll('_',' ')}</td><td>{row.priority}</td><td>{row.disposition.replaceAll('_',' ')}</td><td>{formatReviewAge(row.age_seconds, row.age_bucket)}</td><td>{row.linked_evidence_count}</td><td>{row.note_count}</td><td>{row.latest_activity_at?.replace('T',' ').replace('+00:00','Z') || '—'}</td></tr>)}
        </tbody></table></div>
      )}
      {page && <div className="pagination"><span className="pagination-summary">{page.total ? `Page ${currentPage} of ${totalPages} · ${page.total} reviews` : 'No matching reviews'}</span><div className="pagination-actions"><button type="button" disabled={page.offset === 0} onClick={() => setFilters((c) => ({ ...c, offset: Math.max(0, c.offset - c.limit) }))}>Previous</button><button type="button" disabled={currentPage >= totalPages || page.offset >= 100000} onClick={() => setFilters((c) => ({ ...c, offset: c.offset + c.limit }))}>Next</button></div></div>}
      {summary && <p className="review-operations-activity">Recent Review Activity: {summary.recent_activity.length ? summary.recent_activity.slice(0, 5).map((item) => `${item.incident_key} · ${item.event_type.replaceAll('_',' ')} · ${item.created_at.replace('T',' ')}`).join('  |  ') : 'No review activity recorded.'}</p>}
    </section>
  )
}

export default IncidentReviewOperations
