const browserApi = globalThis.browser ?? globalThis.chrome

function inspectFormSignals() {
  const hasPasswordForm = document.querySelector('input[type="password"]') !== null
  return {
    type: 'FORM_SIGNAL',
    hasPasswordForm,
  }
}

function sendSignal() {
  if (!browserApi?.runtime?.sendMessage) {
    return
  }
  browserApi.runtime.sendMessage(inspectFormSignals()).catch?.(() => {})
}

sendSignal()