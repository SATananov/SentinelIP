import assert from 'node:assert/strict'
import test from 'node:test'

import { sendWebObservation } from '../src/api.js'

test('sends authenticated telemetry to the configured endpoint', async () => {
  let request
  const response = await sendWebObservation(
    {
      apiBaseUrl: 'http://127.0.0.1:8000',
      sensorId: 'browser-1',
      sensorToken: 'secret-token',
    },
    { external_event_id: 'event-1', event_type: 'NAVIGATION' },
    async (url, options) => {
      request = { url, options }
      return { ok: true, status: 202, json: async () => ({ id: 1 }) }
    },
  )

  assert.equal(response.id, 1)
  assert.equal(request.url, 'http://127.0.0.1:8000/telemetry/web')
  assert.equal(request.options.headers['X-SentinelIP-Sensor-ID'], 'browser-1')
  assert.equal(request.options.headers['X-SentinelIP-Sensor-Token'], 'secret-token')
  assert.equal(request.options.body.includes('secret-token'), false)
})

test('handles authentication failures and timeout errors', async () => {
  await assert.rejects(
    sendWebObservation(
      { apiBaseUrl: 'http://localhost:8000', sensorId: 'id', sensorToken: 'token' },
      {},
      async () => ({ ok: false, status: 401, json: async () => ({}) }),
    ),
    /HTTP 401/,
  )

  await assert.rejects(
    sendWebObservation(
      { apiBaseUrl: 'http://localhost:8000', sensorId: 'id', sensorToken: 'token' },
      {},
      async (_url, options) => {
        return await new Promise((_resolve, reject) => {
          options.signal.addEventListener('abort', () => {
            const error = new Error('The operation was aborted.')
            error.name = 'AbortError'
            reject(error)
          })
        })
      },
    ),
    { name: 'AbortError' },
  )
})