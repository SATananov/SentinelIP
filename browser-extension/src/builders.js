import { createEventId } from './event-id.js'
import { sanitizeUrl, basename } from './sanitize.js'

function timestamp(value = new Date()) {
  return value.toISOString()
}

function baseEvent({ eventType, url, privacyMode, eventId, observedAt }) {
  const safeUrl = sanitizeUrl(url, privacyMode)
  return {
    external_event_id: eventId ?? createEventId(),
    observed_at: timestamp(observedAt),
    event_type: eventType,
    url: safeUrl.url,
    has_login_form: false,
    has_password_form: false,
    download_detected: false,
  }
}

export function buildNavigationObservation({ url, privacyMode = 'DOMAIN_ONLY', ...options }) {
  return baseEvent({
    eventType: 'NAVIGATION',
    url,
    privacyMode,
    ...options,
  })
}

export function buildRedirectObservation({ fromUrl, toUrl, privacyMode = 'DOMAIN_ONLY', ...options }) {
  const event = baseEvent({
    eventType: 'REDIRECT',
    url: toUrl,
    privacyMode,
    ...options,
  })
  const from = sanitizeUrl(fromUrl, 'DOMAIN_ONLY')
  const to = sanitizeUrl(toUrl, 'DOMAIN_ONLY')
  return {
    ...event,
    redirect_from_domain: from.hostname,
    redirect_to_domain: to.hostname,
  }
}

export function buildFormSignalObservation({ url, hasPasswordForm, privacyMode = 'DOMAIN_ONLY', ...options }) {
  return {
    ...baseEvent({
      eventType: 'FORM_SIGNAL',
      url,
      privacyMode,
      ...options,
    }),
    has_login_form: hasPasswordForm === true,
    has_password_form: hasPasswordForm === true,
  }
}

export function buildDownloadObservation({ url, filename, mimeType, sizeBytes, privacyMode = 'DOMAIN_ONLY', ...options }) {
  const metadata = {
    ...(basename(filename) ? { filename: basename(filename) } : {}),
    ...(mimeType ? { mime_type: mimeType } : {}),
    ...(Number.isFinite(sizeBytes) ? { size_bytes: sizeBytes } : {}),
  }
  return {
    ...baseEvent({
      eventType: 'DOWNLOAD_SIGNAL',
      url,
      privacyMode,
      ...options,
    }),
    download_detected: true,
    metadata,
  }
}