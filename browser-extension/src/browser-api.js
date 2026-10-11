export function getBrowserApi() {
  return globalThis.browser ?? globalThis.chrome
}