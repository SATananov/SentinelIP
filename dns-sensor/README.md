# SentinelIP DNS Sensor — DNS TELEMETRY 01

SentinelIP DNS Sensor observes DNS evidence only and does not classify domains in DNS TELEMETRY 01.

## Architecture and scope

Local JSON-lines evidence → `DnsEventSource.events()` → strict parser → immutable
`DnsEvent` → authenticated standard-library client → `POST /telemetry/dns` → existing
backend ingestion → `dns_observations`.

Runtime code is isolated here and uses only Python's standard library (Python 3.10+).
No backend, frontend, or browser extension changes are required. Tests use pytest;
the backend contract test additionally uses the repository's existing dependencies.

Supported adapters are `JsonLineSource` over stdin (`stdin-jsonl`), an explicitly
opened local file (`file-jsonl`), or an in-memory fixture (`fixture-jsonl`). Collection
and parsing are separate. These adapters accept this documented interchange format;
they do not interpret arbitrary resolver text logs. The adapter chooses provenance,
not the input record. The backend stores `source="dns"`; adapter provenance is sent
as the supported `metadata.source` field, never an unsupported top-level field.

## Current live-source limitation

Read-only inspection on the implementation machine (Kali Linux 2026.3) found
NetworkManager active, systemd-resolved and dnsmasq inactive. The inspected journal
sample contained resolver initialization/routing and service lifecycle messages,
not usable query/answer/status records. No useful systemd-resolved/dnsmasq entries
were found in the bounded sample. This is not proof that every possible local log
is empty; it is insufficient evidence to implement a truthful live adapter here.
Live collection is deferred. Resolver configuration, debug logging and services
were not changed. No DNS lookup or real capture was started.

Future adapters may include systemd-resolved journal, NetworkManager or dnsmasq
logs **if** their actual records supply sufficient evidence. Packet capture requires
separate explicit review and is not implemented. No subprocess is used at runtime.

## Evidence format

One JSON object per line, for example this synthetic fixture (not a live observation):

```json
{"observed_at":"2026-01-01T00:00:00Z","queried_domain":"Login.Example.test.","query_type":"A","response_status":"NOERROR","resolved_addresses":["192.0.2.10"]}
```

Required fields: timezone-aware `observed_at`, `queried_domain`, `query_type`, and
explicit `response_status`. Missing status is rejected; success is never inferred.
Optional `resolved_addresses` defaults to an empty list; `resolver` (literal IP only)
and `ttl` default to null. Unknown fields and duplicate JSON keys are rejected.
There is no free-form metadata input. Addresses must be strings, are canonicalized
with `ipaddress`, and are deduplicated in first-observed order (up to 256 answers).
No DNS enrichment is performed. CNAME records can have no IP answers; alias targets
are outside this version's schema. An empty answer list does not imply NXDOMAIN.

Domains are trimmed, lowercased and have exactly one final root dot removed.
Stdlib IDNA converts Unicode names to ASCII and validates supplied punycode labels.
Malformed hostnames, multiple root dots, labels over 63 characters and names over
253 characters are rejected. No public suffix or registrable-domain inference is
performed; punycode receives no threat interpretation. Backend hostname constraints
also mean underscore service labels are outside this adapter's accepted format.

Query types: A, AAAA, CNAME, MX, TXT, PTR, OTHER. A nonempty unknown alphanumeric
source type maps to OTHER; absent/invalid type evidence is rejected.
Statuses: NOERROR, NXDOMAIN, SERVFAIL, REFUSED, OTHER, only when explicitly supplied.
TIMEOUT/ERROR and unrecognized statuses are rejected. TTL must be an actual JSON
integer from 0 through 2,147,483,647; booleans and numeric strings are rejected.
Timestamps normalize to UTC and may not exceed the backend's five-minute future allowance.

## Configuration and authentication

From the repository root, copy `dns-sensor/config.example.json` to the ignored
`dns-sensor/config.local.json`, restrict it with `chmod 600`, and edit locally.
Do not put a real token in the example or shell command line. Use a numeric positive
sensor database ID (not the sensor key) and the token returned when provisioning a
DNS sensor. Existing backend PBKDF2 authentication, retention, sensor-derived device
identity and event idempotency are reused unchanged. The sensor never sends device ID.

Only HTTP(S) origins at `localhost` or `127.0.0.1` are accepted; default is
`http://127.0.0.1:8000`. Localhost is pinned to literal 127.0.0.1 to avoid hostname
resolution. Paths, credentials, query strings, fragments and other hosts are rejected.
HTTPS, when selected, uses normal certificate verification for 127.0.0.1.
Environment HTTP proxies and redirects are disabled to keep credentials local.

`enabled` defaults to false and must be boolean. Disabled mode reads no evidence
and sends nothing. Config files are size bounded and errors do not echo contents.
The token is omitted from config repr, payloads and intentional logging. Credentials
are held in memory and sent only in `X-SentinelIP-Sensor-ID` and
`X-SentinelIP-Sensor-Token` headers. Treat config and local evidence as sensitive.
No pretend token encryption is provided; OS file permissions protect local storage.

## Running manually

These steps are documentation only; implementation/tests do not run a live sensor.

1. Provision a DNS sensor through the existing backend `database.telemetry.provision_sensor`
   function using sensor type `DNS`, an appropriate device binding (or null), privacy
   mode `DOMAIN_ONLY`, and retention days. Safely retain the returned numeric ID and
   one-time token in the restricted local config. No new provisioning endpoint is added.
2. Start your local SentinelIP API using the project's existing procedure.
3. Set `enabled` to true and submit an explicitly chosen synthetic fixture or already
   available structured local evidence. From `dns-sensor/` run:

   ```sh
   ../.venv/bin/python -m sentinelip_dns.runner --config config.local.json --file evidence.jsonl
   ```

   Omit `--file` to read JSON lines from stdin. EOF ends the run; Ctrl+C returns 130.
   No file tailing, daemon, service install or shell command construction is involved.
4. Inspect `dns_observations` using existing database tooling. The sample normalizes
   to `login.example.test`, A, NOERROR, `["192.0.2.10"]`, with `file-jsonl` provenance.
5. A future live test can involve a harmless lookup chosen and issued by the user
   **only after** a useful live source adapter exists. This version does not observe
   such a lookup automatically; do not treat the fixture as proof of live collection.

Each run processes at most 10,000 lines. Each line is limited to 65,536 characters;
an oversized line is rejected and ends the source without splitting it into events.
Use explicit smaller files for larger imports; no automatic continuation is provided.
Malformed ordinary records are counted/skipped; diagnostics never print source data.
The client accepts HTTP 202; 401/403/422 and other non-server failures are terminal.
Connection failures and HTTP 5xx receive at most three total attempts with 1- and
2-second waits and a five-second timeout per attempt. Response bodies are not read
or logged. Final submission failure drops that event and stops the source to avoid
retry storms. Exit status is 1 for malformed evidence, submission or input errors.

UUID4 IDs are generated once per parsed observation and reused unchanged during
retries. A manually re-imported line gets a new ID; deduplication across process
restarts/file replays is not promised. Persistent queues and replay checkpoints are deferred.

## Privacy and expected gaps

Collected fields are only observation time, queried domain, query type, explicit
response status, observed IP answers, optional resolver IP/TTL, generated event ID,
and fixed adapter provenance. DNS data itself is sensitive; minimize local evidence
retention and choose backend retention appropriately.

No HTTP URLs, paths, titles, browser history, cookies, credentials, form values,
keystrokes, request/response bodies, packet payloads, memory or screenshots are
collected. No browser table is queried and no browser/DNS correlation is performed.
There are no threat scores, reputation checks, malicious-domain conclusions,
phishing detection, malware/C2 classification, CVEs, incidents, external intelligence,
or runtime AI agents.

DNS-over-HTTPS may bypass local resolver/log sources, so some browser DNS activity
will not appear. This is expected. There is no DoH bypass, certificate installation,
MITM, proxying or TLS interception. There is no tcpdump, tshark, scapy, libpcap,
raw socket or packet capture adapter, and no enrichment DNS lookups.

## Tests

From the repository root, with existing dependencies in `.venv`:

```sh
.venv/bin/python -m pytest -q dns-sensor/tests
.venv/bin/python -m pytest -q tests
```

Or independently from `dns-sensor/`: `../.venv/bin/python -m pytest -q tests`.
The full repository discovery command `.venv/bin/python -m pytest -q` includes both
backend and DNS sensor tests. Browser regression: `cd browser-extension && npm test`.
Tests use synthetic inputs, mocked HTTP, and temporary SQLite storage for the
backend contract check. No real API, DNS traffic or Internet is needed; DNS sensor
tests explicitly block connection creation and hostname resolution.
