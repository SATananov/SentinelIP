# Operator Boundary 21D — Deployment Contract

Phase 21 establishes a direct-local boundary for operator APIs while keeping authenticated remote sensor protocol routes reachable. SentinelIP does not currently authenticate human operators.

## Local development mode

Run the backend from the repository root:

```bash
python -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

Run the frontend from `frontend/` with `npm run dev`. With no API-base setting, it uses `http://127.0.0.1:8000`. This loopback-only HTTP mode is for local development; remote sensors cannot connect to it.

## Sensor-enabled Core mode

Sensor-enabled operation uses one network-reachable FastAPI/Uvicorn listener with TLS terminating directly at SentinelIP Core. For example, replacing the address and certificate paths with the deployment values:

```bash
python -m uvicorn api.main:app \
  --host 192.0.2.10 \
  --port 8443 \
  --ssl-certfile /path/to/core-cert.pem \
  --ssl-keyfile /path/to/core-key.pem
```

`192.0.2.10` is a documentation-only address; bind to the intended Core interface. The example is a deployment shape, not a certificate-generation procedure. Network binding is supported only with the Phase 21 operator route guards in place. TLS alone is not the operator boundary.

Set the frontend API base explicitly before starting/building Vite:

```bash
VITE_SENTINELIP_API_BASE=https://127.0.0.1:8443 npm run dev
```

In PowerShell, set `$env:VITE_SENTINELIP_API_BASE = 'https://127.0.0.1:8443'` before `npm run dev`. The frontend and local CLI must use the loopback URL `https://127.0.0.1:8443`; do not use the Core network hostname for operator APIs. `local_management` checks the direct peer and loopback URL host. The configured API base is explicit; the frontend does not infer a protocol or host.

Remote sensors use `https://core.example.internal:8443`. Sensor routes remain outside `local_management` and retain HTTPS `machine_transport`, sensor credentials, grants, and replay checks. Operator routes on the same listener remain direct-local-only.

## Certificate and transport requirements

The Core certificate must have a DNS Subject Alternative Name (SAN) matching the hostname used by remote sensors. When the local frontend connects to `https://127.0.0.1:8443`, the certificate must also have an IP SAN for `127.0.0.1`. DNS names and IP addresses are matched as different SAN types. The certificate issuer must be trusted by both the browser and each sensor. Keep normal TLS certificate and hostname verification enabled.

TLS terminates directly at Uvicorn/SentinelIP Core. Reverse-proxy TLS termination and trusted-proxy operation are unsupported: forwarded headers are rejected, no trusted proxy model exists, and sensor transport requires verified direct HTTPS semantics. Do not place a reverse proxy in front of this listener under the Phase 21 contract.

## Operator boundary, identity, and target authorization

Operator APIs require the existing `local_management` checks: loopback peer and host, an absent or approved local frontend Origin, and no forwarding, Authorization, or sensor identity/token headers. This establishes direct-local boundary conditions only. It does not identify a person, prove a username, or grant an administrator role. Remote browser/human administration is unsupported. CORS is a browser-origin policy, not authentication; TLS also does not authenticate a human operator.

`LOCAL_OPERATOR` in management audit means the request passed the direct-local operator boundary. It does not identify an individual. Incident Review `OPERATOR` remains generic review provenance. Scope and public-target authorization records constrain which targets SentinelIP may assess; they do not authenticate the caller.

## CORS and health

Allowed browser origins remain exactly `http://127.0.0.1:5173` and `http://localhost:5173`. Allowed methods are `GET`, `POST`, `PATCH`, `PUT`, and `DELETE`; `PUT` is included because the supported operator API exposes exposure-policy configuration. No network-host browser origin is allowed.

`GET /health` remains outside `local_management` and returns only `{"status":"ok","service":"SentinelIP"}`. It exposes no inventory, sensor, or operator data.

Sensor enrollment/registration, self/grant/heartbeat, perimeter-event ingestion, task claim and lifecycle, and web/DNS telemetry remain sensor-authenticated exceptions. They do not become operator routes and do not use the local boundary.

## Phase 21 verification and limits

The final route-class tests cover the fixed 21B control-plane and 21C analyst route sets, sensor exclusions, and the limited health route. The existing positive and negative boundary suites cover local peer/Host/Origin behavior and forbidden headers; sensor suites cover their separate authentication path. Local development remains unchanged when `VITE_SENTINELIP_API_BASE` is absent.

No human authentication, proxy trust, second listener, TLS certificate material, or schema migration is introduced. Schema remains version 44. Legacy export size, buffering, PDF escaping, and CSV formula risks remain separate maintenance work.
