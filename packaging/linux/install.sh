#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ROOT=''
while (($#)); do
  case "$1" in
    --root)
      (($# >= 2)) || { echo '--root requires a directory' >&2; exit 2; }
      ROOT="$2"
      shift 2
      ;;
    *) echo "unsupported option: $1" >&2; exit 2 ;;
  esac
done

if [[ -n "$ROOT" ]]; then
  [[ "$ROOT" = /* && "$ROOT" != / && "$ROOT" != *'/../'* && "$ROOT" != */.. ]] || {
    echo 'staging root must be an absolute non-root path without parent traversal' >&2; exit 2;
  }
  ROOT="$(mkdir -p -- "$ROOT" && cd -- "$ROOT" && pwd -P)"
  [[ "$ROOT" != / ]] || { echo 'staging root cannot be /' >&2; exit 2; }
  STAGED=1
else
  STAGED=0
  [[ "$(id -u)" -eq 0 ]] || { echo 'run install.sh as root or provide --root for staging' >&2; exit 1; }
  [[ -x /usr/bin/python3 ]] || { echo '/usr/bin/python3 is required by the service unit' >&2; exit 1; }
  /usr/bin/python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
    echo 'Python 3.10 or newer is required' >&2; exit 1;
  }
  command -v nmap >/dev/null || { echo 'Nmap is required; install it explicitly before continuing' >&2; exit 1; }
fi

for required in sensor/__init__.py sensor/__main__.py services/remote_sensor_executor.py \
  packaging/linux/sentinelip-sensor.service packaging/linux/example-config.json; do
  [[ -f "$SOURCE_DIR/$required" ]] || { echo "missing required file: $required" >&2; exit 1; }
done

make_dir() { mkdir -p -- "$1"; chmod "$2" "$1"; }
make_dir "$ROOT/opt/sentinelip-sensor" 0755
make_dir "$ROOT/etc/sentinelip-sensor" 0750
make_dir "$ROOT/var/lib/sentinelip-sensor" 0750
make_dir "$ROOT/usr/local/bin" 0755
make_dir "$ROOT/etc/systemd/system" 0755

rm -rf -- "$ROOT/opt/sentinelip-sensor/sensor" "$ROOT/opt/sentinelip-sensor/services"
mkdir -p -- "$ROOT/opt/sentinelip-sensor/sensor"
for module in __init__ __main__ client config runtime state version platforms; do
  install -m 0644 "$SOURCE_DIR/sensor/$module.py" "$ROOT/opt/sentinelip-sensor/sensor/$module.py"
done
mkdir -p -- "$ROOT/opt/sentinelip-sensor/services/scanner_adapters"
for module in remote_sensor_executor remote_sensor_models scan_models scanner \
  host_discovery service_discovery service_models target_policy public_target_policy sensor_transport; do
  install -m 0644 "$SOURCE_DIR/services/$module.py" "$ROOT/opt/sentinelip-sensor/services/$module.py"
done
install -m 0644 "$SOURCE_DIR/services/__init__.py" "$ROOT/opt/sentinelip-sensor/services/__init__.py"
install -m 0644 "$SOURCE_DIR/services/scanner_adapters/__init__.py" "$ROOT/opt/sentinelip-sensor/services/scanner_adapters/__init__.py"
install -m 0644 "$SOURCE_DIR/services/scanner_adapters/nmap_adapter.py" "$ROOT/opt/sentinelip-sensor/services/scanner_adapters/nmap_adapter.py"
find "$ROOT/opt/sentinelip-sensor/sensor" "$ROOT/opt/sentinelip-sensor/services" -type d -exec chmod 0755 {} +
find "$ROOT/opt/sentinelip-sensor/sensor" "$ROOT/opt/sentinelip-sensor/services" -type f -exec chmod 0644 {} +
install -m 0755 "$SOURCE_DIR/packaging/linux/sentinelip-sensor" "$ROOT/usr/local/bin/sentinelip-sensor"
install -m 0644 "$SOURCE_DIR/packaging/linux/sentinelip-sensor.service" "$ROOT/etc/systemd/system/sentinelip-sensor.service"
if [[ ! -e "$ROOT/etc/sentinelip-sensor/config.example.json" ]]; then
  install -m 0600 "$SOURCE_DIR/packaging/linux/example-config.json" "$ROOT/etc/sentinelip-sensor/config.example.json"
fi
if [[ ! -e "$ROOT/etc/sentinelip-sensor/grants.example.json" ]]; then
  install -m 0600 "$SOURCE_DIR/packaging/linux/example-grants.json" "$ROOT/etc/sentinelip-sensor/grants.example.json"
fi

if ((STAGED == 0)); then
  if ! getent group sentinelip-sensor >/dev/null; then
    groupadd --system sentinelip-sensor
  fi
  if ! id sentinelip-sensor >/dev/null 2>&1; then
    NOLOGIN=/usr/sbin/nologin
    [[ -x "$NOLOGIN" ]] || NOLOGIN=/sbin/nologin
    [[ -x "$NOLOGIN" ]] || NOLOGIN=/bin/false
    useradd --system --gid sentinelip-sensor --home-dir /var/lib/sentinelip-sensor \
      --no-create-home --shell "$NOLOGIN" sentinelip-sensor
  fi
  account="$(getent passwd sentinelip-sensor)"
  IFS=: read -r _ _ uid primary_gid _ _ _ login_shell <<<"$account"
  service_gid="$(getent group sentinelip-sensor | cut -d: -f3)"
  read -r -a memberships <<<"$(id -G sentinelip-sensor)"
  [[ "$uid" -gt 0 && "$primary_gid" = "$service_gid" \
     && ("$login_shell" = /usr/sbin/nologin || "$login_shell" = /sbin/nologin || "$login_shell" = /bin/false) \
     && "${#memberships[@]}" -eq 1 && "${memberships[0]}" = "$service_gid" ]] || {
    echo 'existing sentinelip-sensor account is not a restricted, non-login service account' >&2; exit 1;
  }
  install -d -o sentinelip-sensor -g sentinelip-sensor -m 0700 /var/lib/sentinelip-sensor
  chown -R root:root /opt/sentinelip-sensor /usr/local/bin/sentinelip-sensor /etc/systemd/system/sentinelip-sensor.service
  chown sentinelip-sensor:sentinelip-sensor /etc/sentinelip-sensor
  chmod 0700 /etc/sentinelip-sensor
  chown sentinelip-sensor:sentinelip-sensor /etc/sentinelip-sensor/config.example.json /etc/sentinelip-sensor/grants.example.json
  chmod 0600 /etc/sentinelip-sensor/config.example.json /etc/sentinelip-sensor/grants.example.json
  systemctl daemon-reload
else
  chown -R "$(id -u):$(id -g)" "$ROOT/opt/sentinelip-sensor" "$ROOT/usr/local/bin/sentinelip-sensor" \
    "$ROOT/etc/systemd/system/sentinelip-sensor.service" "$ROOT/etc/sentinelip-sensor" "$ROOT/var/lib/sentinelip-sensor"
  chmod 0700 "$ROOT/etc/sentinelip-sensor"
fi

echo 'SentinelIP Sensor files installed. Enroll/configure before enabling the service.'
