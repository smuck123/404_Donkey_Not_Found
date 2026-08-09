import asyncio
import os
from collections import Counter
from typing import Any

import httpx
from fastapi import APIRouter, Query


router = APIRouter(prefix="/fortigate", tags=["FortiGate read-only"])
TIMEOUT = httpx.Timeout(20.0, connect=5.0)
ALLOWED_PATHS = {
    "status": "/api/v2/monitor/system/status",
    "interfaces": "/api/v2/cmdb/system/interface",
    "policies": "/api/v2/cmdb/firewall/policy",
    "routes": "/api/v2/cmdb/router/static",
    "vpn_phase1": "/api/v2/cmdb/vpn.ipsec/phase1-interface",
    "vpn_phase2": "/api/v2/cmdb/vpn.ipsec/phase2-interface",
}


class FortiGateConfigurationError(RuntimeError):
    pass


class FortiGateAPIError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def _settings() -> tuple[str, str, str, bool, str]:
    base_url = (
        os.getenv("FORTIGATE_URL")
        or os.getenv("FORTIGATE_HOST")
        or ""
    ).strip().rstrip("/")
    token = os.getenv("FORTIGATE_TOKEN", "").strip()
    vdom = os.getenv("FORTIGATE_VDOM", "root").strip() or "root"
    verify_ssl = os.getenv("FORTIGATE_VERIFY_SSL", "true").lower() not in {
        "0", "false", "no", "off",
    }
    traffic_path = os.getenv(
        "FORTIGATE_TRAFFIC_PATH",
        "/api/v2/monitor/firewall/session",
    ).strip()

    if not base_url or not token:
        raise FortiGateConfigurationError(
            "FORTIGATE_URL and FORTIGATE_TOKEN must be configured"
        )
    if not traffic_path.startswith("/api/v2/monitor/"):
        raise FortiGateConfigurationError(
            "FORTIGATE_TRAFFIC_PATH must be a FortiGate monitor API path"
        )
    return base_url, token, vdom, verify_ssl, traffic_path


async def _request(path: str, params: dict[str, Any] | None = None) -> Any:
    base_url, token, vdom, verify_ssl, _ = _settings()
    request_params = dict(params or {})
    request_params.setdefault("vdom", vdom)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            verify=verify_ssl,
            follow_redirects=False,
        ) as client:
            response = await client.get(
                f"{base_url}{path}",
                headers=headers,
                params=request_params,
            )
    except httpx.RequestError as exc:
        raise FortiGateAPIError("Unable to reach the FortiGate API") from exc

    if response.status_code in {401, 403}:
        raise FortiGateAPIError(
            "FortiGate API authentication or authorization failed",
            response.status_code,
        )
    if response.status_code >= 400:
        raise FortiGateAPIError(
            f"FortiGate API returned HTTP {response.status_code}",
            502,
        )
    try:
        return response.json()
    except ValueError as exc:
        raise FortiGateAPIError("FortiGate API returned invalid JSON") from exc


def _rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    results = payload.get("results")
    if isinstance(results, list):
        return [row for row in results if isinstance(row, dict)]
    if isinstance(results, dict):
        for key in ("details", "results", "data"):
            nested = results.get(key)
            if isinstance(nested, list):
                return [row for row in nested if isinstance(row, dict)]
        return [results]
    data = payload.get("data")
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    return []


def _pick(row: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", [], {}):
            return value
    return default


def _integer(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


async def _named(name: str) -> Any:
    return await _request(ALLOWED_PATHS[name])


@router.get("/status", summary="Read current FortiGate system status")
async def fortigate_status() -> dict[str, Any]:
    payload = await _named("status")
    results = payload.get("results", {}) if isinstance(payload, dict) else {}
    if not isinstance(results, dict):
        results = {}
    return {
        "hostname": results.get("hostname"),
        "model": results.get("model"),
        "serial": results.get("serial") or (
            payload.get("serial") if isinstance(payload, dict) else None
        ),
        "version": payload.get("version") if isinstance(payload, dict) else None,
        "build": payload.get("build") if isinstance(payload, dict) else None,
        "status": payload.get("status") if isinstance(payload, dict) else None,
    }


@router.get("/summary", summary="Summarize current FortiGate configuration state")
async def fortigate_summary() -> dict[str, Any]:
    names = [
        "status", "interfaces", "policies", "routes", "vpn_phase1", "vpn_phase2"
    ]
    results = await asyncio.gather(
        *[_named(name) for name in names],
        return_exceptions=True,
    )
    values = dict(zip(names, results))

    errors = {
        name: str(value)
        for name, value in values.items()
        if isinstance(value, Exception)
    }
    status_payload = values.get("status")
    status_results = (
        status_payload.get("results", {})
        if isinstance(status_payload, dict)
        else {}
    )
    interfaces = _rows(values.get("interfaces"))
    policies = _rows(values.get("policies"))
    routes = _rows(values.get("routes"))
    phase1 = _rows(values.get("vpn_phase1"))
    phase2 = _rows(values.get("vpn_phase2"))

    interface_states = Counter(
        str(_pick(row, "status", "link", default="unknown")).lower()
        for row in interfaces
    )
    enabled_policies = sum(
        1 for row in policies
        if str(row.get("status", "enable")).lower() in {"enable", "enabled", "1"}
    )

    return {
        "read_only": True,
        "device": {
            "hostname": status_results.get("hostname"),
            "model": status_results.get("model"),
            "serial": status_results.get("serial") or (
                status_payload.get("serial")
                if isinstance(status_payload, dict)
                else None
            ),
            "version": (
                status_payload.get("version")
                if isinstance(status_payload, dict)
                else None
            ),
        },
        "interfaces": {
            "total": len(interfaces),
            "by_status": dict(interface_states),
            "down": [
                {
                    "name": _pick(row, "name", "interface"),
                    "alias": row.get("alias"),
                    "status": _pick(row, "status", "link", default="unknown"),
                }
                for row in interfaces
                if str(_pick(row, "status", "link", default="unknown")).lower()
                not in {"up", "1"}
            ][:20],
        },
        "firewall_policies": {
            "total": len(policies),
            "enabled": enabled_policies,
            "disabled": len(policies) - enabled_policies,
        },
        "static_routes": len(routes),
        "vpn": {
            "phase1_entries": len(phase1),
            "phase2_entries": len(phase2),
            "configuration_count_mismatch": len(phase1) != len(phase2),
        },
        "partial": bool(errors),
        "errors": errors,
    }


@router.get("/vpn-summary", summary="Summarize configured FortiGate IPsec VPNs")
async def fortigate_vpn_summary() -> dict[str, Any]:
    phase1_payload, phase2_payload = await asyncio.gather(
        _named("vpn_phase1"),
        _named("vpn_phase2"),
    )
    phase1 = _rows(phase1_payload)
    phase2 = _rows(phase2_payload)
    return {
        "phase1": [
            {
                "name": row.get("name"),
                "interface": row.get("interface"),
                "remote_gateway": _pick(row, "remote-gw", "remote_gw"),
                "status": row.get("status"),
            }
            for row in phase1
        ],
        "phase2": [
            {
                "name": row.get("name"),
                "phase1name": row.get("phase1name"),
                "status": row.get("status"),
            }
            for row in phase2
        ],
        "configuration_count_mismatch": len(phase1) != len(phase2),
    }


@router.get("/traffic-summary", summary="Summarize current FortiGate sessions")
async def fortigate_traffic_summary(
    count: int = Query(500, ge=1, le=5000),
    ip_version: str = Query("ipv4", pattern=r"^(ipv4|ipv6)$"),
) -> dict[str, Any]:
    _, _, _, _, traffic_path = _settings()
    payload = await _request(
        traffic_path,
        {"start": 0, "count": count, "ip_version": ip_version},
    )
    sessions = _rows(payload)[:count]

    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    services: Counter[str] = Counter()
    policies: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    total_bytes = 0
    shaper_drops = 0

    for row in sessions:
        source = str(_pick(row, "saddr", "src", "srcip", "src_ip", default="unknown"))
        destination = str(
            _pick(row, "daddr", "dst", "dstip", "dst_ip", default="unknown")
        )
        protocol = str(_pick(row, "proto", "protocol", default="unknown"))
        port = str(_pick(row, "dport", "dstport", "dst_port", default="unknown"))
        apps = row.get("apps")
        service = f"{protocol}/{port}"
        if isinstance(apps, list) and apps and isinstance(apps[0], dict):
            service = str(apps[0].get("name") or service)

        sources[source] += 1
        destinations[destination] += 1
        protocols[protocol] += 1
        services[service] += 1
        policies[str(_pick(row, "policyid", "policy_id", "policy", default="unknown"))] += 1
        total_bytes += _integer(row.get("sentbyte")) + _integer(row.get("rcvdbyte"))
        shaper_drops += _integer(row.get("tx_shaper_drops")) + _integer(
            row.get("rx_shaper_drops")
        )

    def top(counter: Counter[str]) -> list[dict[str, Any]]:
        return [{"value": value, "sessions": amount} for value, amount in counter.most_common(10)]

    return {
        "read_only": True,
        "sessions_analyzed": len(sessions),
        "total_bytes_observed": total_bytes,
        "shaper_drops_observed": shaper_drops,
        "top_sources": top(sources),
        "top_destinations": top(destinations),
        "top_services": top(services),
        "top_policies": top(policies),
        "top_protocols": top(protocols),
        "truncated": len(sessions) >= count,
    }
