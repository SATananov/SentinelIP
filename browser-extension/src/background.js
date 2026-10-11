import { loadConfig, updateStatus } from './config.js'
import { sendWebObservation } from './api.js'
import {
  buildDownloadObservation,
  buildFormSignalObservation,
  buildNavigationObservation,
  buildRedirectObservation,
} from './builders.js'
import { supportedPageUrl } from './sanitize.js'

const browserApi = globalThis.browser ?? globalThis.chrome
let sessionId = globalThis.crypto?.randomUUID?.() ?? `session-${Date.now()}`

async function emit(payload) {
  const config = await loadConfig()
  if (!config.enabled || !config.sensorId || !config.sensorToken) {
    return
  }

  try {
    await sendWebObservation(config, {
      ...payload,
      browser_session_id: sessionId,
    })
    await updateStatus({ state: 'DELIVERED', at: new Date().toISOString() })
  } catch (error) {
    await updateStatus({
      state: 'ERROR',
      category: error.category ?? 'DELIVERY',
      at: new Date().toISOString(),
    })
  }
}

if (browserApi?.webNavigation?.onCommitted) {
  browserApi.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0 || !supportedPageUrl(details.url)) {
      return
    }
    loadConfig().then((config) => {
      if (config.enabled) {
        emit(buildNavigationObservation({
          url: details.url,
          privacyMode: config.privacyMode,
          tabId: String(details.tabId),
        }))
      }
    })
  })
}

if (browserApi?.webNavigation?.onBeforeRedirect) {
  browserApi.webNavigation.onBeforeRedirect.addListener((details) => {
    if (details.frameId !== 0 || !supportedPageUrl(details.url) || !supportedPageUrl(details.redirectUrl)) {
      return
    }
    loadConfig().then((config) => {
      if (config.enabled) {
        emit(buildRedirectObservation({
          fromUrl: details.url,
          toUrl: details.redirectUrl,
          privacyMode: config.privacyMode,
          tabId: String(details.tabId),
        }))
      }
    })
  })
}

if (browserApi?.runtime?.onMessage) {
  browserApi.runtime.onMessage.addListener((message, sender) => {
    if (message?.type !== 'FORM_SIGNAL' || !sender?.tab?.url || typeof message.hasPasswordForm !== 'boolean') {
      return
    }
    loadConfig().then((config) => {
      if (config.enabled && supportedPageUrl(sender.tab.url)) {
        emit(buildFormSignalObservation({
          url: sender.tab.url,
          hasPasswordForm: message.hasPasswordForm,
          privacyMode: config.privacyMode,
          tabId: String(sender.tab.id),
        }))
      }
    })
  })
}

if (browserApi?.downloads?.onCreated) {
  browserApi.downloads.onCreated.addListener((download) => {
    if (!download?.url || !supportedPageUrl(download.url)) {
      return
    }
    loadConfig().then((config) => {
      if (config.enabled) {
        emit(buildDownloadObservation({
          url: download.url,
          filename: download.filename,
          mimeType: download.mime,
          sizeBytes: download.fileSize,
          privacyMode: config.privacyMode,
        }))
      }
    })
  })
}