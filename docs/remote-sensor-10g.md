# Remote Sensor 10G: Windows adapter and service packaging

The Windows sensor uses the **same Core APIs, credentials, grants, tasks,
heartbeat, transport protection, polling/backoff, and result models as Linux**.
No Core route or database migration is added. Only `DISCOVER_NETWORK` and
`DISCOVER_SERVICES` are supported, for persisted Core-assigned `PRIVATE_NETWORK`
scopes (RFC1918 IPv4, /24 or narrower). There is no raw-target CLI, remote shell,
arbitrary command/script execution, public-target scan, or elevation mechanism.

## Prerequisites

Use Windows 10/11 or Windows Server with Windows PowerShell 5.1 and the NetTCPIP
module. Install 64-bit Python 3.10+ **for all users** in an administrator-owned
location readable by LocalService. Install pywin32 explicitly into that Python
using your normal approved package process (`packaging/windows/requirements.txt`).
Follow pywin32's system-wide service installation instructions if its service
host/DLL setup is required. The installer verifies dependencies but does not
fetch packages, scripts, Python, Nmap, NSSM, or any other executable.

Install Windows Nmap through your normal software-management process. Executable
resolution checks an explicit `SENTINEL_SENSOR_NMAP` path, the admin-owned service
registration's `NmapPath`, PATH's `nmap.exe`, and standard Program Files locations.
Only an existing, absolute, local `nmap.exe` with trusted ownership and no broad
write ACLs on its file/ancestors is accepted. Relative paths, network shares,
alternate streams, and reparse points are rejected. An unsafe candidate causes
failure; the sensor never executes a differently named binary as a fallback.

Nmap remains unprivileged. Service scans use `--unprivileged -Pn -n -sT -sV
--version-light`, the existing fixed 21 TCP ports, two retries, a 30-second host
limit and a 45-second process timeout. Host discovery uses `--unprivileged -sn
-n -PS80,443 --disable-arp-ping`, two retries, a 10-second host limit and a
30-second process timeout. Neither profile needs packet capture privileges;
Npcap/admin access is not granted. Filtering may prevent discovery of hosts that
do not answer the fixed TCP probes; this is not proof that they are absent.
See [Nmap on Windows](https://nmap.org/book/inst-windows.html) and
[Nmap host discovery](https://nmap.org/book/man-host-discovery.html).

## Installation and first run

Run the installer from a trusted repository checkout in an **elevated operator
PowerShell**. Elevation is for installation and protected provisioning only;
the running service uses `NT AUTHORITY\LocalService`, never Administrator or
LocalSystem. Use your organization's script-signing/execution-policy process;
the scripts do not bypass policy or relaunch themselves with elevation.

```powershell
.\packaging\windows\install.ps1 -PythonPath 'C:\Program Files\Python313\python.exe' -NmapPath 'C:\Program Files (x86)\Nmap\nmap.exe'
```

Adjust those prerequisite paths to the trusted installations on your host.
Installation creates a **manual-start** `SentinelIPSensor` service; it does not
start a scan or the service. Stop an existing service before reinstalling.
Active config/grant files are preserved. Examples have separate `*.example.json`
names so they cannot block first-run enrollment.

Paths are derived from Windows Known Folders, not caller-controlled ProgramData
strings:

| Purpose | Typical path |
|---|---|
| Application and launcher | `C:\Program Files\SentinelIP\Sensor\` |
| Credential/config | `C:\ProgramData\SentinelIP\Sensor\config.json` |
| Core-issued local grants | `C:\ProgramData\SentinelIP\Sensor\grants.json` |
| Minimal state/home | `C:\ProgramData\SentinelIP\Sensor\state\` |

1. In Core's local management API, create a Site and a one-time enrollment token.
2. From elevated operator PowerShell, enroll. The Core URL is configured here;
   the token is read by a no-echo prompt, never a command-line argument:

   ```powershell
   $sensor = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SentinelIP\Sensor\sentinelip-sensor.ps1'
   & $sensor enroll --core-url https://core.example.internal --name 'Office Windows sensor'
   ```

   A canonical UUID is generated once and persisted unless `--sensor-uuid` is
   supplied. Registration returns a dedicated machine credential. The CLI checks
   Core identity and retrieves the current grant before saving protected files.
   It never prints the credential or begins discovery. An empty grant is valid
   before the administrator assigns a scope. If registration succeeds but local
   provisioning fails, revoke that identity in Core and re-enroll with a fresh
   UUID/token; the credential is not recoverable from Core.
3. In Core, assign the sensor an enabled, authorized, confirmed private scope.
4. Fetch the current grant and validate the installation without scanning:

   ```powershell
   & $sensor refresh-grant
   & $sensor check-config
   & $sensor self-test
   & $sensor --version
   ```

   Self-test checks ACLs, config, credential, Nmap path, Core identity, and grant
   freshness; it never invokes Nmap or the interface query.
5. Start the already-installed service explicitly:

   ```powershell
   .\packaging\windows\install.ps1 -Action Start
   .\packaging\windows\install.ps1 -Action Status
   # Equivalently: Start-Service SentinelIPSensor; Get-Service SentinelIPSensor
   ```

Console `& $sensor run` is available for diagnosis but runs under the invoking
operator's identity; normal deployment uses LocalService. `--platform` is only
reported metadata. The actual OS determines the executor; unsupported OSes fail.

## Grant validation and interface discovery

Grants are fetched using the existing authenticated `GET /sensor/grant` and
refreshed on startup. They contain only sensor UUID plus the scope ID,
`PRIVATE_NETWORK` type, canonical CIDR and product capabilities. The operator
cannot enter a CIDR to self-authorize a scope.

Before each typed task, the adapter validates the local grant, identity,
capability and derived target, then runs one fixed, read-only PowerShell query
of `Get-NetIPInterface`/`Get-NetIPAddress`. Only connected, preferred IPv4
addresses in RFC1918 networks remain; loopback, link-local, inactive and public
interfaces are ignored. Malformed output fails closed. The grant must be a
subnet of a connected private interface network. A large interface subnet never
widens a Core grant or authorizes a scan. No task data enters the query.

The adapter then reuses shared host/service normalization, result checks and
inventory-compatible evidence. Core still revalidates assignment and scope at
claim/start/result submission. Stale local grants cannot authorize new work.

## ACLs and secrets

10G uses **ACL-protected files**, not custom encryption. DPAPI/credential vault
integration is deferred. File owners and access rules are verified with pywin32;
Windows never relies on Unix chmod. Null/unknown ACLs, untrusted owners and broad
read grants on secret files are rejected. Reparse points and alternate streams
are rejected. Atomic writes apply a native protected ACL before writing secret
bytes and replace the file only after a successful flush.

SYSTEM and Administrators manage files. LocalService has read/execute access to
application files and modify access to the protected data directory; ordinary
users have no access to credentials or grants. LocalService is a shared Windows
identity: other services running under that identity are within this deployment's
trust boundary. Isolating each service with a dedicated identity is a future
hardening option. Backups must preserve ACLs. Reinstall preserves the UUID and
credential; lost credentials require revocation and fresh enrollment.

TLS certificate verification remains mandatory, with HTTP only for explicit
loopback development. Timestamp, nonce, rate limit, body bounds, enrollment-token
separation and machine/management isolation are unchanged.

## Service lifecycle and logging

Use `install.ps1 -Action Stop`, `Restart`, or `Status` (or standard Windows
service commands). Stop/shutdown sets the existing runtime stop event, stops new
claims, and allows the current bounded task/result submission to finish. No
second polling loop or unmanaged worker threads are introduced.

Unexpected startup failure is reported without exception/secret text. SCM
recovery permits three delayed restarts (10, 30, 60 seconds), then no further
restart until the recovery counter resets after a day. Ordinary Core outages
use the shared runtime's bounded backoff. Installation selects manual startup;
an operator may explicitly configure automatic start after successful self-test.

Console logs use stdout/stderr. Service runtime records go to the Windows
Application Event Log through pywin32, retaining only existing bounded structured
status fields. View them in Event Viewer; credential/token/Authorization fields
and exception text are excluded.

```powershell
.\packaging\windows\uninstall.ps1
# Explicitly remove only known config/grant/example files too:
.\packaging\windows\uninstall.ps1 -Purge
```

Uninstall stops/removes the named service and known application modules. It
preserves config, grants and state by default, never deletes the enclosing
ProgramData/Program Files trees, and refuses reparse-point trees. Python, pywin32
and Nmap remain separately managed prerequisites.

## Troubleshooting and validation limits

- Missing Nmap: install it explicitly or supply a protected absolute path; no
  driver or elevated scan fallback is attempted.
- ACL error: reinstall/provision from an elevated trusted operator session and
  restore the documented ACLs. Do not make secrets readable by Users/Everyone.
- TLS/Core error: check certificate trust, host clock and connectivity.
- Grant/interface mismatch: verify the Core assignment and active adapter, then
  refresh the grant. Interface presence alone never grants authorization.
- Service host error: verify all-users Python/pywin32 setup and LocalService
  access to the interpreter, DLLs and application directory.

Automated verification on Linux uses mocked Windows APIs/subprocesses, shared
Core tests, and real PowerShell syntax parsing when available. It cannot prove
Windows SCM startup, live Windows ACL behavior, or actual Windows Nmap execution.
A native Windows installation/stop/restart and authorized private-LAN smoke test
remains a deployment validation step; no real scanning is part of automated tests.
