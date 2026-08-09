#!/bin/bash
set -euo pipefail

CONFIG=/etc/sysconfig/404-donkey-fortigate-soc-summary
if [[ ! -r "$CONFIG" ]]; then
    echo "Missing configuration: $CONFIG" >&2
    exit 2
fi

set -a
# shellcheck source=/dev/null
source "$CONFIG"
set +a

exec /usr/local/bin/send_fortigate_soc_summary.py
