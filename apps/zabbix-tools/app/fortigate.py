import asyncio
import os
import socket
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
    "resources": "/api/v2/monitor/system/resource/usage",
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


async def _resource_stat(resource: str, interval: str = "1-min") -> dict[str, Any]:
    payload = await _request(
        ALLOWED_PATHS["resources"],
        {"resource": resource, "interval": interval},
    )
    results = payload.get("results", {}) if isinstance(payload, dict) else {}
    rows = results.get(resource, []) if isinstance(results, dict) else []
    row = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else {}

    historical = row.get("historical", {})
    interval_data = (
        historical.get(interval, {})
        if isinstance(historical, dict)
        else {}
    )
    samples = interval_data.get("values", []) if isinstance(interval_data, dict) else []
    values = []
    newest_timestamp_ms = None
    for sample in samples:
        if not isinstance(sample, list) or len(sample) < 2:
            continue
        try:
            value = float(sample[1])
        except (TypeError, ValueError):
            continue
        values.append(value)
        if newest_timestamp_ms is None:
            try:
                newest_timestamp_ms = int(sample[0])
            except (TypeError, ValueError):
                pass

    current = row.get("current")
    return {
        "current": current,
        "samples": len(values),
        "minimum": min(values) if values else current,
        "average": round(sum(values) / len(values), 2) if values else current,
        "maximum": max(values) if values else current,
        "newest_timestamp_ms": newest_timestamp_ms,
    }


@router.get(
    "/performance-summary",
    summary="Summarize current FortiGate resources and short history",
)
async def fortigate_performance_summary() -> dict[str, Any]:
    resource_names = ("session", "setuprate", "cpu", "mem")
    values = await asyncio.gather(
        *[_resource_stat(resource) for resource in resource_names],
        return_exceptions=True,
    )

    data: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for resource, value in zip(resource_names, values):
        if isinstance(value, Exception):
            errors[resource] = str(value)
        else:
            data[resource] = value

    return {
        "read_only": True,
        "interval": "1-min",
        "units": {
            "session": "sessions",
            "setuprate": "sessions/second",
            "cpu": "percent",
            "mem": "percent",
        },
        "resources": data,
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
    _, _, _, _, configured_path = _settings()
    candidate_paths = list(dict.fromkeys([
        configured_path,
        "/api/v2/monitor/firewall/sessions",
        "/api/v2/monitor/firewall/session/select",
        "/api/v2/monitor/firewall/session",
    ]))
    payload: Any = None
    selected_path = ""
    endpoint_errors: dict[str, str] = {}
    for traffic_path in candidate_paths:
        try:
            payload = await _request(
                traffic_path,
                {
                    "start": 0,
                    "count": count,
                    "ip_version": ip_version,
                    "summary": "true",
                },
            )
            selected_path = traffic_path
            break
        except FortiGateAPIError as exc:
            endpoint_errors[traffic_path] = str(exc)
    if payload is None:
        raise FortiGateAPIError(
            "FortiGate session API is unavailable on all supported endpoints: "
            + "; ".join(f"{path}: {error}" for path, error in endpoint_errors.items())
        )
    sessions = _rows(payload)[:count]

    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    services: Counter[str] = Counter()
    policies: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    destination_ports: Counter[str] = Counter()
    source_countries: Counter[str] = Counter()
    destination_countries: Counter[str] = Counter()
    destination_dns: dict[str, str] = {}
    total_bytes = 0
    shaper_drops = 0

    for row in sessions:
        source = str(_pick(row, "saddr", "src", "srcip", "src_ip", default="unknown"))
        destination = str(
            _pick(row, "daddr", "dst", "dstip", "dst_ip", default="unknown")
        )
        source_country = str(_pick(
            row, "srccountry", "src_country", "source_country", default=""
        ))
        destination_country = str(_pick(
            row, "dstcountry", "dst_country", "destination_country", default=""
        ))
        reported_dns = str(_pick(
            row, "dstname", "dst_name", "hostname", "domain", default=""
        ))
        protocol = str(_pick(row, "proto", "protocol", default="unknown"))
        port = str(_pick(row, "dport", "dstport", "dst_port", default="unknown"))
        apps = row.get("apps")
        service = f"{protocol}/{port}"
        if isinstance(apps, list) and apps and isinstance(apps[0], dict):
            service = str(apps[0].get("name") or service)

        sources[source] += 1
        destinations[destination] += 1
        protocols[protocol] += 1
        destination_ports[port] += 1
        services[service] += 1
        if source_country and source_country.lower() not in {"unknown", "reserved"}:
            source_countries[source_country] += 1
        if destination_country and destination_country.lower() not in {"unknown", "reserved"}:
            destination_countries[destination_country] += 1
        if reported_dns:
            destination_dns[destination] = reported_dns
        policies[str(_pick(row, "policyid", "policy_id", "policy", default="unknown"))] += 1
        total_bytes += _integer(row.get("sentbyte")) + _integer(row.get("rcvdbyte"))
        shaper_drops += _integer(row.get("tx_shaper_drops")) + _integer(
            row.get("rx_shaper_drops")
        )

    def top(counter: Counter[str]) -> list[dict[str, Any]]:
        return [{"value": value, "sessions": amount} for value, amount in counter.most_common(10)]

    async def reverse_dns(ip: str) -> tuple[str, str]:
        if ip in destination_dns:
            return ip, destination_dns[ip]
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyaddr, ip),
                timeout=1.0,
            )
            return ip, str(result[0])
        except (OSError, TimeoutError, asyncio.TimeoutError):
            return ip, ""

    top_destination_rows = destinations.most_common(10)
    resolved = await asyncio.gather(
        *[reverse_dns(ip) for ip, _ in top_destination_rows]
    )
    resolved_by_ip = dict(resolved)
    top_destinations_resolved = [
        {
            "ip": ip,
            "dns": resolved_by_ip.get(ip) or None,
            "display": resolved_by_ip.get(ip) or ip,
            "sessions": amount,
        }
        for ip, amount in top_destination_rows
    ]

    def port_rows() -> list[dict[str, Any]]:
        rows = []
        for port, amount in destination_ports.most_common(10):
            service_name = None
            try:
                service_name = socket.getservbyport(int(port))
            except (OSError, ValueError):
                pass
            rows.append({
                "port": port,
                "service": service_name,
                "sessions": amount,
            })
        return rows

    return {
        "read_only": True,
        "api_path": selected_path,
        "endpoint_fallback_errors": endpoint_errors,
        "sessions_analyzed": len(sessions),
        "total_bytes_observed": total_bytes,
        "shaper_drops_observed": shaper_drops,
        "top_sources": top(sources),
        "top_destinations": top(destinations),
        "top_destinations_resolved": top_destinations_resolved,
        "top_destination_countries": top(destination_countries),
        "top_source_countries": top(source_countries),
        "country_data_available": bool(source_countries or destination_countries),
        "top_destination_ports": port_rows(),
        "top_services": top(services),
        "top_policies": top(policies),
        "top_protocols": top(protocols),
        "truncated": len(sessions) >= count,
    }


@router.get(
    "/live-details",
    operation_id="get_fortigate_live_details",
    summary="Get live FortiGate details by topic",
    description=(
        "Read current FortiGate API data for CPU, memory, sessions, interfaces, "
        "policies, routes, VPNs, or top live traffic. The topic may be cpu, "
        "memory, sessions, network, traffic, top, interfaces, policies, vpn, "
        "health, or all. This operation is read-only."
    ),
)
async def fortigate_live_details(
    topic: str = Query(
        "all",
        min_length=1,
        max_length=40,
        description="Requested live firewall detail, for example cpu or top traffic",
    ),
    count: int = Query(500, ge=1, le=5000),
) -> dict[str, Any]:
    normalized = topic.strip().lower()
    wants_traffic = any(
        word in normalized
        for word in ("traffic", "top", "session", "network", "source", "destination")
    )

    async def capture(awaitable: Any) -> dict[str, Any]:
        try:
            return {"available": True, "data": await awaitable}
        except Exception as exc:
            return {
                "available": False,
                "error": str(exc),
                "error_type": type(exc).__name__,
            }

    health_task = capture(fortigate_summary())
    performance_task = capture(fortigate_performance_summary())
    if wants_traffic:
        health, performance, traffic = await asyncio.gather(
            health_task,
            performance_task,
            capture(fortigate_traffic_summary(count=count, ip_version="ipv4")),
        )
    else:
        health, performance = await asyncio.gather(health_task, performance_task)
        traffic = {
            "available": False,
            "not_requested": True,
            "message": "Live session details were not requested for this topic.",
        }

    resources = (
        performance.get("data", {}).get("resources", {})
        if performance.get("available")
        else {}
    )
    selected: dict[str, Any] = {}
    if normalized in {"cpu", "processor"}:
        selected["cpu"] = resources.get("cpu")
    elif normalized in {"memory", "mem", "ram"}:
        selected["memory"] = resources.get("mem")
    elif normalized in {"session", "sessions"}:
        selected["sessions"] = resources.get("session")
        selected["session_setup_rate"] = resources.get("setuprate")
    elif normalized in {"interfaces", "interface", "network"}:
        selected["interfaces"] = (
            health.get("data", {}).get("interfaces")
            if health.get("available")
            else None
        )
    elif normalized in {"policies", "policy", "rules"}:
        selected["firewall_policies"] = (
            health.get("data", {}).get("firewall_policies")
            if health.get("available")
            else None
        )
    elif normalized in {"vpn", "vpns"}:
        selected["vpn"] = (
            health.get("data", {}).get("vpn")
            if health.get("available")
            else None
        )
    else:
        selected = {
            "health": health.get("data") if health.get("available") else None,
            "resources": resources,
        }

    available = health.get("available") or performance.get("available")
    if not available:
        overall_status = "unavailable"
    elif wants_traffic and not traffic.get("available"):
        overall_status = "partial"
    else:
        overall_status = "ok"
    return {
        "response_style": (
            "Answer the requested firewall detail first in at most five bullets. "
            "Report current, average, minimum, and maximum when present. For top "
            "traffic, list returned DNS names, IPs, countries, ports, services, "
            "policies, and protocols. If country or DNS data is absent, say so "
            "briefly. If session details are unavailable, still report live "
            "CPU, memory, session count, and firewall health. Never invent values."
        ),
        "topic": normalized,
        "read_only": True,
        "overall_status": overall_status,
        "selected": selected,
        "live_traffic": traffic if wants_traffic else None,
        "source_errors": {
            "health": health.get("error"),
            "performance": performance.get("error"),
            "traffic": traffic.get("error"),
        },
    }


@router.get(
    "/analyze",
    operation_id="analyze_fortigate",
    summary="Analyze a natural-language FortiGate question using live APIs",
    description=(
        "Interpret a firewall question, call only the relevant live read-only "
        "FortiGate APIs, and return compact facts and findings. Supports health, "
        "CPU, memory, sessions, interfaces, policies, routes, VPN, top traffic, "
        "DNS names, countries, ports, services, protocols, sources and destinations."
    ),
)
async def analyze_fortigate(
    question: str = Query(..., min_length=1, max_length=500),
    count: int = Query(500, ge=10, le=5000),
) -> dict[str, Any]:
    query = question.strip().lower()
    resource_words = {"cpu", "memory", "mem", "ram", "session", "sessions", "load", "performance"}
    traffic_words = {
        "traffic", "top", "country", "countries", "dns", "domain", "ip",
        "port", "service", "protocol", "source", "destination", "talker",
        "internet", "device",
    }
    config_words = {
        "health", "status", "interface", "interfaces", "policy", "policies",
        "rule", "rules", "route", "routes", "vpn", "device", "model", "version",
    }
    tokens = set(query.replace(",", " ").replace("?", " ").split())
    broad = (
        query in {"fw", "show fw", "firewall", "show firewall"}
        or any(word in query for word in ("summary", "summarize", "overall", "everything"))
    )
    wants_resources = broad or bool(tokens & resource_words)
    wants_traffic = broad or bool(tokens & traffic_words)
    wants_config = broad or bool(tokens & config_words)
    if not (wants_resources or wants_traffic or wants_config):
        wants_config = wants_resources = True

    async def capture(awaitable: Any) -> dict[str, Any]:
        try:
            return {"available": True, "data": await awaitable}
        except Exception as exc:
            return {
                "available": False,
                "error": str(exc),
                "error_type": type(exc).__name__,
            }

    tasks: dict[str, Any] = {}
    if wants_config:
        tasks["configuration"] = capture(fortigate_summary())
    if wants_resources:
        tasks["performance"] = capture(fortigate_performance_summary())
    if wants_traffic:
        tasks["traffic"] = capture(
            fortigate_traffic_summary(count=count, ip_version="ipv4")
        )
    if "policy" in query or "policies" in query or "rule" in query:
        tasks["policy_details"] = capture(_named("policies"))

    names = list(tasks)
    values = await asyncio.gather(*tasks.values())
    sections = dict(zip(names, values))
    facts: dict[str, Any] = {}
    findings: list[dict[str, str]] = []

    configuration = sections.get("configuration", {})
    if configuration.get("available"):
        config_data = configuration["data"]
        facts["device"] = config_data.get("device")
        facts["interfaces"] = config_data.get("interfaces")
        facts["firewall_policies"] = config_data.get("firewall_policies")
        facts["static_routes"] = config_data.get("static_routes")
        facts["vpn"] = config_data.get("vpn")
        down = config_data.get("interfaces", {}).get("down", [])
        if down:
            findings.append({
                "severity": "warning",
                "code": "interfaces_down",
                "message": "One or more firewall interfaces are down.",
            })
        if config_data.get("vpn", {}).get("configuration_count_mismatch"):
            findings.append({
                "severity": "warning",
                "code": "vpn_configuration_mismatch",
                "message": "IPsec phase 1 and phase 2 configuration counts differ.",
            })

    performance = sections.get("performance", {})
    if performance.get("available"):
        resources = performance["data"].get("resources", {})
        facts["performance"] = resources
        cpu = resources.get("cpu", {}).get("current")
        memory = resources.get("mem", {}).get("current")
        sessions = resources.get("session", {}).get("current")
        if isinstance(cpu, (int, float)) and cpu >= 80:
            findings.append({
                "severity": "warning",
                "code": "high_cpu",
                "message": f"Current firewall CPU utilization is {cpu}%.",
            })
        if isinstance(memory, (int, float)) and memory >= 85:
            findings.append({
                "severity": "warning",
                "code": "high_memory",
                "message": f"Current firewall memory utilization is {memory}%.",
            })
        if isinstance(sessions, (int, float)) and sessions >= 5000:
            findings.append({
                "severity": "warning",
                "code": "high_session_count",
                "message": f"Current firewall session count is {sessions}.",
            })

    traffic = sections.get("traffic", {})
    if traffic.get("available"):
        traffic_data = traffic["data"]
        facts["traffic"] = {
            key: traffic_data.get(key)
            for key in (
                "api_path", "sessions_analyzed", "total_bytes_observed",
                "shaper_drops_observed", "top_sources", "top_destinations_resolved",
                "top_destination_countries", "top_source_countries",
                "country_data_available", "top_destination_ports", "top_services",
                "top_policies", "top_protocols", "truncated",
            )
        }
        if _integer(traffic_data.get("shaper_drops_observed")) > 0:
            findings.append({
                "severity": "warning",
                "code": "traffic_shaper_drops",
                "message": "Traffic-shaper drops were observed in the sampled sessions.",
            })
        if traffic_data.get("truncated"):
            findings.append({
                "severity": "info",
                "code": "traffic_sample_truncated",
                "message": f"Traffic analysis is limited to {count} live sessions.",
            })

    policy_section = sections.get("policy_details", {})
    if policy_section.get("available"):
        policies = _rows(policy_section["data"])
        policy_stop_words = {
            "show", "list", "firewall", "fortigate", "policy", "policies",
            "rule", "rules", "details", "about", "what", "which", "status", "fw",
        }
        terms = [
            token for token in tokens
            if token.isdigit() or (len(token) >= 3 and token not in policy_stop_words)
        ]
        matched = []
        for policy in policies:
            policy_id = str(_pick(policy, "policyid", "id", default=""))
            policy_name = str(policy.get("name", ""))
            if not terms or any(
                term == policy_id or term in policy_name.lower()
                for term in terms
            ):
                matched.append({
                    "policyid": policy_id,
                    "name": policy_name,
                    "status": policy.get("status"),
                    "action": policy.get("action"),
                    "srcintf": policy.get("srcintf"),
                    "dstintf": policy.get("dstintf"),
                    "srcaddr": policy.get("srcaddr"),
                    "dstaddr": policy.get("dstaddr"),
                    "service": policy.get("service"),
                    "nat": policy.get("nat"),
                })
        facts["matching_policies"] = matched[:20]

    unavailable = {
        name: section.get("error")
        for name, section in sections.items()
        if not section.get("available")
    }
    available_count = sum(
        1 for section in sections.values() if section.get("available")
    )
    if available_count == len(sections):
        overall_status = "ok"
    elif available_count:
        overall_status = "partial"
    else:
        overall_status = "unavailable"

    return {
        "response_style": (
            "Answer the exact firewall question first. Default to at most six "
            "bullets. Prefer DNS names but retain IP addresses. Include countries, "
            "ports, services, policies, protocols, and data limits only when "
            "relevant. Separate warnings from normal facts. Never invent missing data."
        ),
        "question": question,
        "read_only": True,
        "overall_status": overall_status,
        "queried_sections": names,
        "facts": facts,
        "findings": findings,
        "unavailable_sections": unavailable,
    }
