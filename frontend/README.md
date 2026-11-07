# SentinelIP Frontend

This directory contains the React 19 / Vite dashboard for the local SentinelIP
FastAPI Core. It is a browser-based development frontend, **not** a packaged
desktop application. Backend services, security rules, persistence and operator
authorization remain separate and authoritative.

## Workspace

The app has seven workspace modules, plus operator and support destinations:

| Destination | Purpose |
| --- | --- |
| Overview | Backend event totals, recent activity (last 12 intervals), and up to three recent alerts |
| Scope & Discovery | Authorized scope, discovery, inventory and investigation lookup |
| Remote Sensors | Fleet and supported sensor/task management workflows |
| Operations | Workload and explicitly managed Incident Reviews |
| Detections | Existing detection and review context |
| Perimeter | Perimeter and external-exposure views |
| Events & Analytics | Event history, timeline, filters and bounded exports |
| Data Lifecycle | Separate local-operator data-retention/cleanup controls |
| Help & User Guide | Contextual help and searchable topics |
| About SentinelIP | Product information and Tanashi Studio™ attribution |

Desktop uses a sidebar. At narrow widths a collapsible **Workspace** menu
exposes all destinations with the active selection indicated. Navigation uses
`#workspace/<module>` hashes, supports direct links and browser Back/Forward,
and keeps existing modules mounted so normal UI state is preserved.

The Overview draws from the existing Core responses; it does not invent event
counts or trends. The activity preview uses up to 12 displayed timeline
intervals, with a text equivalent, and the alert preview uses up to three
items from the existing bounded alert request. Loading and polling remain
owned by `App.jsx` (five-second dashboard refresh in the current source).

## Run on Linux (development)

From the repository root, start Core in one terminal using the project's
existing Python virtual environment and installed requirements:

```bash
.venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```bash
cd frontend
npm ci
npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Open `http://127.0.0.1:5173/`. The frontend uses
`http://127.0.0.1:8000` by default when `VITE_SENTINELIP_API_BASE` is unset.
The local API allows the standard Vite `127.0.0.1:5173` origin. A different
port can produce a CORS failure unless it is explicitly supported. If the UI
shows **API Offline**, check the Core process and `GET /health` first.

These commands start development processes; they are not an installer,
autostart service or supported production deployment guide. Read the root
README for setup, authorization boundaries and database permission constraints.

## Verification

Run from `frontend/`:

```bash
npm run lint
node --test tests/*.test.js
npm run build
```

At the local `main` source checkpoint `1eec263` (2026-11-07), **194/194 Node
tests passed**, ESLint passed and the Vite build succeeded on Kali Linux. A
large JavaScript chunk warning remained non-blocking. This is not a claim that
all backend, sensor or user-interface paths have been end-to-end tested.

## Security and operator boundaries

The frontend presents backend-owned information and never establishes security
meaning on its own. Threat/correlation interpretation is deterministic in
Core; read-only security review must not be confused with explicit operator
workflows. Supported Incident Review actions can create or update records and
link evidence through bounded backend endpoints after deliberate user input.
Data Lifecycle and remote sensor operations likewise follow their existing
backend controls. The UI does not itself perform exploitation, credential
attacks, autonomous remediation or unauthorized network scans.

Do not commit credentials, live SQLite databases, generated `dist/` files, or
local virtual environments. Never assume that browsing to a management view
is authorization to trigger a state-changing operation.
