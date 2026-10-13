#!/usr/bin/env bash
set -euo pipefail

ROOT=''
PURGE=0
while (($#)); do
  case "$1" in
    --root)
      (($# >= 2)) || { echo '--root requires a directory' >&2; exit 2; }
      ROOT="$2"
      shift 2
      ;;
    --purge) PURGE=1; shift ;;
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
  [[ "$(id -u)" -eq 0 ]] || { echo 'run uninstall.sh as root or provide --root for staging' >&2; exit 1; }
  systemctl stop sentinelip-sensor.service 2>/dev/null || true
  systemctl disable sentinelip-sensor.service 2>/dev/null || true
fi

rm -f -- "$ROOT/etc/systemd/system/sentinelip-sensor.service" \
  "$ROOT/usr/local/bin/sentinelip-sensor"
if [[ -d "$ROOT/opt/sentinelip-sensor" ]]; then
  rm -rf -- "$ROOT/opt/sentinelip-sensor/sensor" "$ROOT/opt/sentinelip-sensor/services"
  rmdir -- "$ROOT/opt/sentinelip-sensor" 2>/dev/null || true
fi
if ((PURGE == 1)); then
  rm -f -- "$ROOT/etc/sentinelip-sensor/config.json" "$ROOT/etc/sentinelip-sensor/grants.json" \
    "$ROOT/etc/sentinelip-sensor/config.example.json" "$ROOT/etc/sentinelip-sensor/grants.example.json"
fi
rmdir -- "$ROOT/etc/sentinelip-sensor" 2>/dev/null || true
rmdir -- "$ROOT/var/lib/sentinelip-sensor" 2>/dev/null || true
if ((STAGED == 0)); then
  systemctl daemon-reload
fi

if ((PURGE == 1)); then
  echo 'SentinelIP Sensor runtime removed; known config and grant files purged.'
else
  echo 'SentinelIP Sensor runtime removed; configuration and credentials were preserved.'
fi
