import assert from 'node:assert/strict'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import test from 'node:test'
import { createServer } from 'vite'

async function renderComponent(modulePath, exportName, props) {
  const vite = await createServer({
    configFile: new URL('../vite.config.js', import.meta.url).pathname,
    server: { middlewareMode: true },
    appType: 'custom',
    logLevel: 'silent',
  })
  try {
    const module = await vite.ssrLoadModule(modulePath)
    return renderToStaticMarkup(createElement(module[exportName], props))
  } finally {
    await vite.close()
  }
}

test('inspection controls are inventory-bound, explicit and make no request during render', async () => {
  const originalFetch = globalThis.fetch
  let requests = 0
  globalThis.fetch = async () => { requests += 1; throw new Error('unexpected request') }
  try {
    const markup = await renderComponent('/src/components/HttpEndpointInspection.jsx', 'default', {
      scopeId: 4,
      device: { id: 8 },
      ports: [
        { id: 3, port_number: 80, transport: 'tcp', state: 'open' },
        { id: 4, port_number: 53, transport: 'udp', state: 'open' },
        { id: 5, port_number: 22, transport: 'tcp', state: 'closed' },
      ],
      authorizationConfirmed: false,
    })
    assert.match(markup, /Observed TCP port/)
    assert.match(markup, /80\/TCP/)
    assert.doesNotMatch(markup, /53\/TCP|22\/TCP/)
    assert.match(markup, /HTTP/)
    assert.match(markup, /HTTPS/)
    assert.match(markup, /Inspect selected port/)
    assert.match(markup, /disabled=""/)
    assert.match(markup, /Confirm the authorized assessment/)
    assert.equal(requests, 0)
  } finally { globalThis.fetch = originalFetch }
})

test('observation detail rendering escapes banners and hides unverified certificate facts', async () => {
  const item = {
    id: 19,
    scheme: 'https',
    observed_at: '2026-11-15T12:00:00+00:00',
    target_ip: '192.168.61.10',
    approved_hostname: null,
    source: 'https-tls-head-v1',
    outcome: 'TLS_VERIFICATION_FAILED',
    error_category: 'untrusted_certificate',
    status_code: null,
    response_headers: {},
    content_type: null,
    content_length: null,
    redirect_location: null,
    server_identifier: { value: '<script>secret</script>', confidence: 'LOW', source: 'http_response_header' },
    tls: {
      verification_status: 'FAILED',
      verification_name: '192.168.61.10',
      ip_address_verification: 'FAILED',
      protocol_version: null,
      certificate_subject: null,
      sha256_fingerprint: null,
    },
    scan: { run_id: 'fixture-run', target_id: 7, profile: 'http_endpoint_fingerprint',
      scanner: 'sentinelip-http-tls-fingerprint', status: 'FAILED', target_outcome: 'FAILED' },
  }
  const markup = await renderComponent('/src/components/HttpEndpointInspection.jsx', 'ObservationDetails', {
    item, portNumber: 443,
  })
  assert.match(markup, /TLS_VERIFICATION_FAILED/)
  assert.match(markup, /TLS verification status|Verification: FAILED/)
  assert.match(markup, /Certificate properties are hidden/)
  assert.match(markup, /Server header \(self-reported, low confidence\)/)
  assert.match(markup, /fixture-run/)
  assert.match(markup, /&lt;script&gt;secret&lt;\/script&gt;/)
  assert.doesNotMatch(markup, /<script>secret/)
  assert.doesNotMatch(markup, /sha256 fingerprint.*[a-f0-9]{64}/i)
  assert.doesNotMatch(markup, /vulnerability|confirmed finding/i)
})
