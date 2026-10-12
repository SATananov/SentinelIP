import fs from 'node:fs'

const app = fs.readFileSync(
  new URL('../src/App.jsx', import.meta.url),
  'utf8',
)
const panel = fs.readFileSync(
  new URL('../src/components/SecurityReviewPanel.jsx', import.meta.url),
  'utf8',
)
const api = fs.readFileSync(
  new URL('../src/services/securityApi.js', import.meta.url),
  'utf8',
)

const checks = [
  [
    'dashboard integrates SecurityReviewPanel',
    app.includes('<SecurityReviewPanel'),
  ],
  [
    'reads all three security collections',
    [
      '/threats?limit=5&offset=0',
      '/correlations?limit=5&offset=0',
      '/incidents?limit=5&offset=0',
    ].every((path) => api.includes(path)),
  ],
  [
    'detail reads are GET-only',
    !api.match(/\bmethod\s*:/) &&
      !api.match(/\bPOST\b|\bPATCH\b|\bDELETE\b/),
  ],
  [
    'panel has no security engine semantics',
    !panel.match(
      /ThreatEngine|CorrelationEngine|IncidentEngine|open_review|evaluate_/,
    ),
  ],
  [
    'panel does not claim confirmation',
    !panel.match(
      /confirmed compromise|confirmed phishing|confirmed malware|attacker identified/i,
    ),
  ],
  [
    'read-only boundary is visible',
    panel.includes('Read only') &&
      panel.includes(
        'does not\n            run detection, correlation, or incident creation',
      ),
  ],
]

let failed = false

for (const [name, ok] of checks) {
  console.log(`${ok ? 'PASS' : 'FAIL'}: ${name}`)
  if (!ok) failed = true
}

if (failed) process.exit(1)
