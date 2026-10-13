# Remote Sensor 10F: Linux installation and first-run provisioning

10F packages the existing 10A–10E sensor flow for Linux. The runtime supports
only bounded `DISCOVER_NETWORK` and `DISCOVER_SERVICES` tasks for current
Core-assigned `PRIVATE_NETWORK` scopes. It does not accept raw targets, shell
commands, arbitrary programs, scripts, public scopes, or arbitrary scan options.
Windows packaging is not included.

## Install

From a checked-out SentinelIP repository on the sensor host, install the
repository-local files as root:

```sh
sudo packaging/linux/install.sh
```

The installer checks Python 3.10+ and Nmap, copies the runtime to
`/opt/sentinelip-sensor`, installs `/usr/local/bin/sentinelip-sensor` and
`/etc/systemd/system/sentinelip-sensor.service`, and creates the dedicated
`sentinelip-sensor` system account. It does not download code, enable, or start
the service. Existing config and grant files are preserved on reinstall.

The account has no login shell, sudo access, or scanner Linux capabilities.
The current fixed Nmap profiles use unprivileged TCP connect operations; do not
grant raw-socket or broad Linux capabilities. Nmap documents TCP connect scan
as available without raw-packet privileges and unprivileged `-sn` using TCP
connect probes ([host discovery](https://nmap.org/book/man-host-discovery.html),
[port scan techniques](https://nmap.org/book/man-port-scanning-techniques.html)).
Service files are root-owned and
read-only. `/etc/sentinelip-sensor` is owned by the service account with mode
`0700`; `config.json` and `grants.json` are owned by that account with mode
`0600`, allowing explicit grant refresh to atomically replace its file. Runtime state is limited to `/var/lib/sentinelip-sensor` and
private temporary space. Logs go to journald.

For an unprivileged staging test, use `packaging/linux/install.sh --root
/absolute/staging/path`; it does not create host users or call systemd.

## Enroll and provision

1. Create a Site in Core's local management API and create a short-lived,
   one-time enrollment token for that Site.
2. Enroll interactively. The token is read with a no-echo prompt and is never
   accepted as a command-line argument or written to logs:

   ```sh
   sudo -u sentinelip-sensor sentinelip-sensor enroll \
     --core-url https://core.example.internal --name "Office sensor"
   ```

   The CLI generates and persists a UUID when omitted, registers through the
   existing one-time enrollment endpoint, authenticates with the returned
   machine credential, fetches the sensor's current grant, and writes protected
   config/grant files. It never prints the credential and does not start scans
   or the service. Use `--sensor-uuid` to supply an existing canonical UUID.
   Loopback HTTP is available only with explicit `--development-mode`.

3. In Core, assign this sensor an authorized, confirmed, enabled
   `PRIVATE_NETWORK` scope. Site and sensor identities alone do not grant a
   network. Core's authenticated `GET /sensor/grant` returns only this sensor's
   currently valid private assignments, canonical CIDRs, and compatible
   capabilities; the operator cannot enter a CIDR in the local config.
4. Synchronize the protected local grant explicitly:

   ```sh
   sudo -u sentinelip-sensor sentinelip-sensor refresh-grant
   ```

   The service also refreshes from Core on startup and fails closed if Core is
   unavailable or the grant response is malformed. It does not accept tasks
   until the current grant is fetched successfully. `self-test` compares local
   grant state to Core and performs no discovery.
5. Validate configuration and machine authentication:

   ```sh
   sudo -u sentinelip-sensor sentinelip-sensor check-config
   sudo -u sentinelip-sensor sentinelip-sensor self-test
   ```

6. Enable and start the service only after provisioning:

   ```sh
   sudo systemctl enable --now sentinelip-sensor.service
   systemctl status sentinelip-sensor.service
   journalctl -u sentinelip-sensor.service
   ```

Use `systemctl stop` and `systemctl restart` for normal lifecycle management.
The unit runs as `sentinelip-sensor`, has no Linux capabilities, enables
`NoNewPrivileges`, private temporary/devices, strict system protection with
write access limited to the config and state directories, and network-only
address families. SIGTERM stops new claims and lets an active
bounded scanner call finish.

## Configuration and credentials

The default paths are `/etc/sentinelip-sensor/config.json` and
`/etc/sentinelip-sensor/grants.json`. The config contains Core URL, sensor UUID,
machine credential, grant path, fixed runtime intervals, platform/version, and
the runtime's supported capabilities. Enrollment creates it with mode `0600`.
The credential may instead be supplied via `SENTINEL_SENSOR_CREDENTIAL`; that
environment value overrides the file credential. `SENTINEL_SENSOR_CONFIG`
selects a different config path. Protect service-manager environment secrets
with the same care as the config file. OS keyring integration is deferred.

The UUID is generated once during enrollment and saved in config. Reinstalling
the runtime preserves it. To replace a sensor identity, revoke/disable the old
sensor in Core and perform a new enrollment with a new UUID; do not delete the
config and accidentally enroll a duplicate identity.

Core URLs must use HTTPS, with normal certificate verification enabled. No TLS
downgrade or insecure-certificate option exists. HTTP is limited to explicit
loopback development. The service sends authenticated UUID, timestamp, and
nonce headers on each machine request. The enrollment token is one-time and is
never the long-lived credential. Revoke the machine credential in Core if the
host or credential is lost.

`sentinelip-sensor --version` reports the runtime version. No log file is
created; logs are JSON records sent to stdout/stderr for journald. Credentials,
enrollment tokens, and Authorization headers are not logged.

## Remove and troubleshoot

`sudo packaging/linux/uninstall.sh` stops/disables the unit and removes only
the known runtime files. It preserves config and grants by default. Explicit
`sudo packaging/linux/uninstall.sh --purge` also removes only those two known
files. The dedicated account is retained so preserved files do not become
orphaned; remove it separately only after confirming no files still depend on
it. `--root /absolute/staging/path` tests uninstall behavior without systemd.

- **TLS/certificate error:** check the Core URL, hostname, certificate chain,
  and host clock. Keep certificate verification enabled.
- **Invalid credential:** verify the saved sensor UUID/credential pair and
  confirm the sensor/site are enabled and the credential is not revoked.
- **Enrollment response lost or provisioning failed afterward:** no local
  credential is retained. Revoke the newly created sensor in Core before
  retrying enrollment with a new UUID.
- **Missing or stale grant:** assign an enabled private scope in Core and run
  `refresh-grant`; public scopes are intentionally excluded.
- **Core unavailable:** check DNS, routing, firewall, and HTTPS service health;
  runtime retries with bounded backoff and does not scan during outage.
- **Nmap missing:** install the distribution's Nmap package through the normal
  host-management process, then rerun `check-config`. The installer never
  installs packages automatically.
- **Permission failure:** verify config/grant mode `0600`, directory access for
  the service account, and root ownership of runtime files.

10F provides deployment only for the bounded 10D typed discovery contract. It
does not introduce remote shell, command execution, public Internet scanning,
or arbitrary job execution.
