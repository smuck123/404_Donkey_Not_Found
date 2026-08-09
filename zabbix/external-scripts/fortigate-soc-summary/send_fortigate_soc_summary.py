#!/usr/bin/env python3
"""Send one FortiGate SOC analysis window to Zabbix trapper items."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

from fortigate_soc_summary import collect


def quote(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )
    return f'"{escaped}"'


def main() -> int:
    server = os.getenv("ZABBIX_SERVER", "127.0.0.1").strip()
    host = os.getenv("ZABBIX_HOST", "fw1.kivela.work").strip()
    log_path = os.getenv("FORTIGATE_LOG", "/var/log/fw/fortigate.json").strip()
    maximum = int(os.getenv("FORTIGATE_SOC_LINES", "5000"))
    sender = shutil.which("zabbix_sender")
    if not sender:
        print("zabbix_sender is not installed", file=sys.stderr)
        return 2
    if not host:
        print("ZABBIX_HOST is required", file=sys.stderr)
        return 2

    payload = collect(log_path, max(100, min(maximum, 100000)))
    lines = []
    for key, value in payload["items"].items():
        if isinstance(value, (dict, list)):
            rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        else:
            rendered = str(value)
        lines.append(f"{quote(host)} {quote(key)} {quote(rendered)}")

    result = subprocess.run(
        [sender, "-z", server, "-i", "-"],
        input="\n".join(lines) + "\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
