# SentinelIP Frontend

This directory contains the React/Vite dashboard for SentinelIP.

The frontend is a presentation layer over established SentinelIP backend state.
It does not create threat detections, correlations, or incident reviews, and it
does not perform remediation or network actions.

## Development

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Run lint checks:

```bash
npm run lint
```

Build the production bundle:

```bash
npm run build
```

## Security review views

The dashboard includes read-only views for persisted:

- threats
- correlations
- incident reviews

These views consume the bounded GET endpoints exposed by the FastAPI backend.
The backend remains authoritative for security interpretation.

## Scope

Frontend code should remain presentation-focused. Security meaning belongs in
the deterministic backend layers, and future UI changes should preserve that
boundary.
