#!/bin/bash
set -euo pipefail

CONFIG_FILE="${DONKEY_LOG_SUMMARY_CONFIG:-/etc/sysconfig/404-donkey-log-summary}"
if [[ -r "$CONFIG_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$CONFIG_FILE"
fi

: "${ZBX_SERVER:=127.0.0.1}"
: "${ZBX_HOST:=zabbix.kivela.work}"
: "${OLLAMA_URL:=http://192.168.0.111:11434/api/chat}"
: "${OLLAMA_MODEL:=qwen3.5:9b}"
: "${LOG_SUMMARY_SCRIPT:=/usr/local/libexec/404-donkey-not-found/log_summary.py}"

exec /usr/bin/python3 "$LOG_SUMMARY_SCRIPT" \
  --group all \
  --mode both \
  --ollama-url "$OLLAMA_URL" \
  --ollama-model "$OLLAMA_MODEL" \
  --send-zabbix \
  --zabbix-server "$ZBX_SERVER" \
  --zabbix-host "$ZBX_HOST"

