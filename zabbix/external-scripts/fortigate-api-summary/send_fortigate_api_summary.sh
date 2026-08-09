#!/bin/bash
set -euo pipefail

CONFIG_FILE="${FORTIGATE_SUMMARY_CONFIG:-/etc/sysconfig/404-donkey-fortigate-api-summary}"
COLLECTOR="${FORTIGATE_SUMMARY_COLLECTOR:-/usr/local/bin/fortigate_api_summary.py}"

if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "Configuration file is not readable: $CONFIG_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

: "${ZABBIX_SERVER:?ZABBIX_SERVER is required}"
: "${ZABBIX_HOST:?ZABBIX_HOST is required}"
: "${FORTIGATE_URL:?FORTIGATE_URL is required}"
: "${FORTIGATE_TOKEN:?FORTIGATE_TOKEN is required}"

TMP_JSON="$(mktemp /tmp/fortigate-api-summary.XXXXXX.json)"
trap 'rm -f "$TMP_JSON"' EXIT

"$COLLECTOR" > "$TMP_JSON"
python3 -m json.tool "$TMP_JSON" >/dev/null

zabbix_sender   -z "$ZABBIX_SERVER"   -s "$ZABBIX_HOST"   -k "fortigate.api.raw"   -o "$(tr -d '\n' < "$TMP_JSON")"
