#!/usr/bin/env python3
"""Collect a compact, read-only FortiGate API snapshot for Zabbix."""

import argparse
import json
import os
import ssl
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


TIMEOUT = 20
CONFIG_ENDPOINTS = {
    "interfaces": "/api/v2/cmdb/system/interface",
    "policies": "/api/v2/cmdb/firewall/policy",
    "routes": "/api/v2/cmdb/router/static",
    "vpn_phase1": "/api/v2/cmdb/vpn.ipsec/phase1-interface",
    "vpn_phase2": "/api/v2/cmdb/vpn.ipsec/phase2-interface",
}


def setting(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def ssl_context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    return ssl._create_unverified_context()


def api_get(
    base_url: str,
    token: str,
    vdom: str,
    verify_ssl: bool,
    path: str,
    params: dict[str, Any] | None = None,
) -> Any:
    query = dict(params or {})
    query.setdefault("vdom", vdom)
    url = f"{base_url.rstrip('/')}{path}?{urlencode(query)}"
    request = Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "404-Donkey-FortiGate-Zabbix/1.0",
        },
        method="GET",
    )
    try:
        with urlopen(
            request,
            timeout=TIMEOUT,
            context=ssl_context(verify_ssl),
        ) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(f"{path}: HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"{path}: connection failed: {exc.reason}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{path}: invalid JSON response") from exc


def rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    result = payload.get("results")
    if isinstance(result, list):
        return [row for row in result if isinstance(row, dict)]
    if isinstance(result, dict):
        for key in ("details", "results", "data"):
            nested = result.get(key)
            if isinstance(nested, list):
                return [row for row in nested if isinstance(row, dict)]
        return [result]
    return []


def resource_stat(payload: Any, resource: str) -> dict[str, Any]:
    results = payload.get("results", {}) if isinstance(payload, dict) else {}
    values = results.get(resource, []) if isinstance(results, dict) else []
    row = values[0] if isinstance(values, list) and values else {}
    current = row.get("current") if isinstance(row, dict) else None
    historical = row.get("historical", {}) if isinstance(row, dict) else {}
    interval = historical.get("1-min", {}) if isinstance(historical, dict) else {}
    samples = interval.get("values", []) if isinstance(interval, dict) else []
    numbers = []
    for sample in samples:
        if not isinstance(sample, list) or len(sample) < 2:
            continue
        try:
            numbers.append(float(sample[1]))
        except (TypeError, ValueError):
            continue
    return {
        "current": current,
        "samples": len(numbers),
        "minimum": min(numbers) if numbers else current,
        "average": round(sum(numbers) / len(numbers), 2) if numbers else current,
        "maximum": max(numbers) if numbers else current,
    }


def collect() -> dict[str, Any]:
    base_url = setting("FORTIGATE_URL")
    token = setting("FORTIGATE_TOKEN")
    vdom = setting("FORTIGATE_VDOM", "root") or "root"
    verify_ssl = setting("FORTIGATE_VERIFY_SSL", "true").lower() not in {
        "0", "false", "no", "off",
    }
    if not base_url or not token:
        raise RuntimeError("FORTIGATE_URL and FORTIGATE_TOKEN are required")

    errors: dict[str, str] = {}

    def get(name: str, path: str, params: dict[str, Any] | None = None) -> Any:
        try:
            return api_get(base_url, token, vdom, verify_ssl, path, params)
        except RuntimeError as exc:
            errors[name] = str(exc)
            return {}

    status = get("status", "/api/v2/monitor/system/status")
    configuration = {
        name: get(name, path)
        for name, path in CONFIG_ENDPOINTS.items()
    }
    resources = {
        resource: get(
            f"resource_{resource}",
            "/api/v2/monitor/system/resource/usage",
            {"resource": resource, "interval": "1-min"},
        )
        for resource in ("session", "setuprate", "cpu", "mem")
    }

    status_results = status.get("results", {}) if isinstance(status, dict) else {}
    if not isinstance(status_results, dict):
        status_results = {}

    interfaces = rows(configuration["interfaces"])
    policies = rows(configuration["policies"])
    routes = rows(configuration["routes"])
    phase1 = rows(configuration["vpn_phase1"])
    phase2 = rows(configuration["vpn_phase2"])

    interface_states = Counter(
        str(row.get("status", row.get("link", "unknown"))).lower()
        for row in interfaces
    )
    enabled_policies = sum(
        1
        for row in policies
        if str(row.get("status", "enable")).lower() in {
            "enable", "enabled", "1",
        }
    )

    return {
        "schema": "fortigate_api_summary_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "collection_status": "ok" if not errors else "partial",
        "errors": errors,
        "device": {
            "hostname": status_results.get("hostname"),
            "model": status_results.get("model"),
            "serial": status_results.get("serial") or (
                status.get("serial") if isinstance(status, dict) else None
            ),
            "version": status.get("version") if isinstance(status, dict) else None,
            "build": status.get("build") if isinstance(status, dict) else None,
        },
        "interfaces": {
            "total": len(interfaces),
            "up": interface_states.get("up", 0) + interface_states.get("1", 0),
            "down": sum(
                amount
                for state, amount in interface_states.items()
                if state not in {"up", "1"}
            ),
            "by_status": dict(interface_states),
            "down_names": [
                row.get("name")
                for row in interfaces
                if str(row.get("status", row.get("link", "unknown"))).lower()
                not in {"up", "1"}
            ],
        },
        "policies": {
            "total": len(policies),
            "enabled": enabled_policies,
            "disabled": len(policies) - enabled_policies,
        },
        "routes": {"static_total": len(routes)},
        "vpn": {
            "phase1_total": len(phase1),
            "phase2_total": len(phase2),
            "configuration_mismatch": int(len(phase1) != len(phase2)),
        },
        "performance": {
            resource: resource_stat(payload, resource)
            for resource, payload in resources.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON for manual diagnostics",
    )
    args = parser.parse_args()
    try:
        result = collect()
    except RuntimeError as exc:
        result = {
            "schema": "fortigate_api_summary_v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "collection_status": "failed",
            "errors": {"collector": str(exc)},
        }
    json.dump(
        result,
        sys.stdout,
        ensure_ascii=False,
        indent=2 if args.pretty else None,
        separators=None if args.pretty else (",", ":"),
    )
    sys.stdout.write("\n")
    return 0 if result["collection_status"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
