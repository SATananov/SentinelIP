import { loadConfig, saveConfig } from '../src/config.js'

const form = document.querySelector('#settings-form')
const apiBaseUrl = document.querySelector('#api-base-url')
const sensorId = document.querySelector('#sensor-id')
const sensorToken = document.querySelector('#sensor-token')
const privacyMode = document.querySelector('#privacy-mode')
const enabled = document.querySelector('#enabled')
const status = document.querySelector('#status')

loadConfig().then((config) => {
  apiBaseUrl.value = config.apiBaseUrl
  sensorId.value = config.sensorId
  privacyMode.value = config.privacyMode
  enabled.checked = config.enabled
  // The token is intentionally never loaded into the visible form.
  status.textContent = config.sensorId ? 'Configured. Enter a replacement token only when changing it.' : 'Not configured.'
})

form.addEventListener('submit', async (event) => {
  event.preventDefault()
  try {
    const current = await loadConfig()
    await saveConfig({
      apiBaseUrl: apiBaseUrl.value,
      sensorId: sensorId.value,
      sensorToken: sensorToken.value || current.sensorToken,
      privacyMode: privacyMode.value,
      enabled: enabled.checked,
    })
    sensorToken.value = ''
    status.textContent = 'Configuration saved.'
  } catch (error) {
    status.textContent = error.message
  }
})