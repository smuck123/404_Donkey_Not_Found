import json
import os
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.zabbix import ZabbixClient


router = APIRouter(tags=["host analysis"])
NUMERIC_VALUE_TYPES = {"0", "3"}


def iso_age_seconds(value: Any) -> int | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0, int((datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds()))
    except (TypeError, ValueError):
        return None


def item_age_seconds(item: dict[str, Any]) -> int | None:
    raw = str(item.get("lastclock", ""))
    return max(0, int(time.time()) - int(raw)) if raw.isdigit() and int(raw) > 0 else None


async def find_hosts(search: str, limit: int = 10) -> list[dict[str, Any]]:
    data = await ZabbixClient().call(
        "host.get",
        {
            "output": ["hostid", "host", "name", "status", "maintenance_status"],
            "search": {"host": search, "name": search},
            "searchByAny": True,
            "sortfield": "name",
            "limit": limit,
        },
    )
    return data if isinstance(data, list) else []


async def resolve_host(host: str) -> dict[str, Any]:
    if host.isdigit():
        data = await ZabbixClient().call(
            "host.get",
            {"hostids": [host], "output": ["hostid", "host", "name", "status", "maintenance_status"]},
        )
        rows = data if isinstance(data, list) else []
    else:
        rows = await find_hosts(host, 10)
    if not rows:
        raise HTTPException(status_code=404, detail="Host was not found")
    exact = [row for row in rows if host.lower() in {str(row.get("host", "")).lower(), str(row.get("name", "")).lower()}]
    return (exact or rows)[0]


def item_category(item: dict[str, Any]) -> str | None:
    blob = f'{item.get("name", "")} {item.get("key_", "")}'.lower()
    if "gpu." in blob or "gpu " in blob or "nvidia" in blob:
        return "gpu"
    if "cpu" in blob or "processor" in blob:
        return "cpu"
    if "memory" in blob or "vm.memory" in blob or "ram" in blob:
        return "memory"
    if "filesystem" in blob or "disk" in blob or "vfs.fs" in blob:
        return "disk"
    if "network" in blob or "net.if" in blob or "traffic" in blob:
        return "network"
    return None


async def numeric_stats(items: list[dict[str, Any]], hours: int) -> dict[str, dict[str, Any]]:
    selected = [row for row in items if str(row.get("value_type")) in NUMERIC_VALUE_TYPES]
    by_type: dict[str, list[str]] = defaultdict(list)
    for row in selected:
        by_type[str(row["value_type"])].append(str(row["itemid"]))

    samples: dict[str, list[tuple[int, float]]] = defaultdict(list)
    client = ZabbixClient()
    for value_type, itemids in by_type.items():
        data = await client.call(
            "history.get",
            {
                "output": ["itemid", "clock", "value"],
                "history": int(value_type),
                "itemids": itemids,
                "time_from": int(time.time()) - hours * 3600,
                "sortfield": "clock",
                "sortorder": "DESC",
                "limit": 20000,
            },
        )
        for sample in data if isinstance(data, list) else []:
            try:
                samples[str(sample["itemid"])].append((int(sample["clock"]), float(sample["value"])))
            except (KeyError, TypeError, ValueError):
                continue

    output: dict[str, dict[str, Any]] = {}
    for row in selected:
        values = samples.get(str(row["itemid"]), [])
        numbers = [value for _, value in values]
        output[str(row["itemid"])] = {
            "count": len(numbers),
            "latest": values[0][1] if values else None,
            "latest_clock": values[0][0] if values else None,
            "minimum": min(numbers) if numbers else None,
            "average": round(sum(numbers) / len(numbers), 3) if numbers else None,
            "maximum": max(numbers) if numbers else None,
        }
    return output


@router.get("/host-search", operation_id="search_zabbix_hosts")
async def host_search(
    query: str = Query(..., min_length=1, max_length=255),
    limit: int = Query(10, ge=1, le=100),
) -> dict[str, Any]:
    rows = await find_hosts(query, limit)
    return {"count": len(rows), "data": rows}


@router.get("/host-24h-summary", operation_id="get_zabbix_host_period_summary")
async def host_period_summary(
    host: str = Query(..., min_length=1, max_length=255),
    hours: int = Query(24, ge=1, le=168),
    items_per_category: int = Query(5, ge=1, le=20),
) -> dict[str, Any]:
    resolved = await resolve_host(host)
    hostid = str(resolved["hostid"])
    data = await ZabbixClient().call(
        "item.get",
        {
            "hostids": [hostid],
            "output": ["itemid", "name", "key_", "value_type", "status", "state", "lastvalue", "lastclock", "units"],
            "filter": {"status": 0},
            "sortfield": "name",
            "limit": 5000,
        },
    )
    items = data if isinstance(data, list) else []
    categorized: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        category = item_category(item)
        if category and len(categorized[category]) < items_per_category:
            categorized[category].append(item)

    selected = [item for category in ("cpu", "memory", "disk", "network") for item in categorized[category]]
    stats = await numeric_stats(selected, hours)
    categories: dict[str, list[dict[str, Any]]] = {}
    for category in ("cpu", "memory", "disk", "network"):
        categories[category] = [
            {**item, "stats": stats.get(str(item["itemid"]), {})}
            for item in categorized[category]
        ]

    problems = await ZabbixClient().call(
        "problem.get",
        {
            "hostids": [hostid],
            "output": ["eventid", "name", "severity", "clock", "acknowledged"],
            "time_from": int(time.time()) - hours * 3600,
            "recent": True,
            "sortfield": ["eventid"],
            "sortorder": "DESC",
            "limit": 50,
        },
    )
    return {
        "period_hours": hours,
        "host": resolved,
        "categories": categories,
        "recent_problems": problems if isinstance(problems, list) else [],
        "coverage": {category: len(categories[category]) for category in categories},
    }


@router.get("/gpu-summary", operation_id="get_zabbix_gpu_summary")
async def gpu_summary(
    host: str = Query(..., min_length=1, max_length=255),
    hours: int = Query(24, ge=1, le=168),
) -> dict[str, Any]:
    resolved = await resolve_host(host)
    data = await ZabbixClient().call(
        "item.get",
        {
            "hostids": [str(resolved["hostid"])],
            "output": ["itemid", "name", "key_", "value_type", "status", "state", "lastvalue", "lastclock", "units"],
            "search": {"key_": "gpu.", "name": "GPU"},
            "searchByAny": True,
            "limit": 500,
        },
    )
    items = data if isinstance(data, list) else []
    stats = await numeric_stats(items, hours)
    return {
        "period_hours": hours,
        "host": resolved,
        "count": len(items),
        "items": [{**item, "stats": stats.get(str(item["itemid"]), {})} for item in items],
    }


@router.get("/traffic-summary", operation_id="get_zabbix_json_traffic_summary")
async def traffic_summary(
    host: str = Query(..., min_length=1, max_length=255),
    item_key: str = Query(""),
) -> dict[str, Any]:
    resolved = await resolve_host(host)
    hostid = str(resolved["hostid"])
    client = ZabbixClient()

    params: dict[str, Any] = {
        "hostids": [hostid],
        "output": ["itemid", "name", "key_", "value_type", "lastvalue", "lastclock", "state"],
        "limit": 100,
    }
    configured_key = item_key or os.getenv("ZABBIX_TRAFFIC_ITEM_KEY", "")
    if configured_key:
        params["filter"] = {"key_": [configured_key]}
        params["limit"] = 1
    else:
        params["search"] = {"name": "traffic", "key_": "traffic"}
        params["searchByAny"] = True

    data = await client.call("item.get", params)
    candidates = data if isinstance(data, list) else []

    selected: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None
    preferred_keys = ("windows.traffic.out", "fortigate_summary.sh")
    candidates.sort(
        key=lambda row: (
            str(row.get("key_")) not in preferred_keys,
            not bool(row.get("lastvalue")),
        )
    )
    for item in candidates:
        try:
            decoded = json.loads(item.get("lastvalue", ""))
        except (TypeError, ValueError):
            continue
        if isinstance(decoded, dict):
            selected = item
            payload = decoded
            break

    if selected is None or payload is None:
        raise HTTPException(
            status_code=404,
            detail="No populated JSON traffic item was found for this host",
        )

    item_info = {
        key: selected.get(key)
        for key in ("itemid", "name", "key_", "value_type", "lastclock", "state")
    }

    entries = payload.get("data")
    if isinstance(entries, list):
        processes = Counter(str(row.get("process", "unknown")) for row in entries)
        remote_ips = Counter(str(row.get("r_ip", "unknown")) for row in entries)
        remote_ports = Counter(str(row.get("r_port", "unknown")) for row in entries)
        captured_at = payload.get("time")
        payload_age = iso_age_seconds(captured_at)
        return {
            "schema": "connection_list",
            "host": resolved,
            "item": item_info,
            "freshness": {
                "zabbix_item_age_seconds": item_age_seconds(selected),
                "payload_age_seconds": payload_age,
                "payload_stale": payload_age is not None and payload_age > 3600,
            },
            "captured_at": captured_at,
            "connections": len(entries),
            "top_processes": processes.most_common(10),
            "top_remote_ips": remote_ips.most_common(10),
            "top_remote_ports": remote_ports.most_common(10),
            "sample": entries[:15],
        }

    if any(key in payload for key in ("deny_per_min", "top_attackers", "top_ports", "traffic")):
        recent = payload.get("recent", [])
        recent_times = [row.get("time") for row in recent if isinstance(row, dict) and row.get("time")]
        newest_event_time = max(recent_times, default=None)
        payload_age = iso_age_seconds(newest_event_time)
        findings = []
        if payload_age is not None and payload_age > 3600:
            findings.append({
                "severity": "warning",
                "code": "stale_embedded_events",
                "message": "The Zabbix item is updating, but the newest embedded FortiGate event is older than one hour.",
            })
        return {
            "schema": "fortigate_aggregate",
            "host": resolved,
            "item": item_info,
            "freshness": {
                "zabbix_item_age_seconds": item_age_seconds(selected),
                "newest_embedded_event_time": newest_event_time,
                "embedded_event_age_seconds": payload_age,
                "embedded_events_stale": payload_age is not None and payload_age > 3600,
            },
            "findings": findings,
            "deny_per_min": payload.get("deny_per_min"),
            "accept": payload.get("accept"),
            "close": payload.get("close"),
            "traffic": payload.get("traffic", {}),
            "top_attackers": payload.get("top_attackers", [])[:10],
            "top_ports": payload.get("top_ports", [])[:10],
            "recent": recent[:15],
        }

    return {
        "schema": "generic_json",
        "host": resolved,
        "item": item_info,
        "data": payload,
    }


def _compact_json(value: Any, depth: int = 0) -> Any:
    """Bound nested SOC payloads so small local models receive useful context."""
    if depth >= 4:
        return value if not isinstance(value, (dict, list)) else "nested data omitted"
    if isinstance(value, list):
        return [_compact_json(row, depth + 1) for row in value[:10]]
    if isinstance(value, dict):
        return {
            str(key): _compact_json(item, depth + 1)
            for key, item in list(value.items())[:30]
        }
    return value


def _find_nested(value: Any, aliases: set[str], depth: int = 0) -> Any:
    if depth > 5:
        return None
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower().replace("-", "_").replace(" ", "_")
            if normalized in aliases and nested not in (None, "", [], {}):
                return nested
        for nested in value.values():
            found = _find_nested(nested, aliases, depth + 1)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(value, list):
        for nested in value[:20]:
            found = _find_nested(nested, aliases, depth + 1)
            if found not in (None, "", [], {}):
                return found
    return None


@router.get(
    "/internet-traffic-summary",
    operation_id="get_zabbix_internet_traffic_summary",
)
async def internet_traffic_summary(
    host: str = Query("fw1.kivela.work", min_length=1, max_length=255),
) -> dict[str, Any]:
    """Summarize Internet traffic from FortiGate SOC values already stored in Zabbix."""
    resolved = await resolve_host(host)
    keys = [
        "fortigate.soc.rich_summary",
        "fortigate.top_internal_to_external_destinations_enriched",
        "fortigate.top_external_attackers_enriched",
        "fortigate.grouped_destination_names",
        "fortigate.grouped_destination_owners",
        "fortigate.denied_port_heatmap",
        "fortigate.policy_summary",
        "fortigate.suspicious_country_scores",
        "fortigate.expected_vs_unexpected",
        "fortigate.total_events",
        "fortigate.parse_errors",
        "fortigate.ollama.summary",
    ]
    data = await ZabbixClient().call(
        "item.get",
        {
            "hostids": [str(resolved["hostid"])],
            "output": [
                "itemid", "name", "key_", "value_type", "lastvalue",
                "lastclock", "state", "status", "units",
            ],
            "filter": {"key_": keys, "status": 0},
            "sortfield": "key_",
            "limit": len(keys),
        },
    )
    rows = data if isinstance(data, list) else []
    decoded: dict[str, Any] = {}
    freshness: dict[str, Any] = {}
    for row in rows:
        key = str(row.get("key_", ""))
        raw = row.get("lastvalue")
        if raw in (None, "") or str(row.get("state", "0")) != "0":
            continue
        try:
            value = json.loads(str(raw))
        except (TypeError, ValueError):
            value = raw
        decoded[key] = value
        age = item_age_seconds(row)
        freshness[key] = {
            "lastclock": int(str(row.get("lastclock", "0")) or 0),
            "age_seconds": age,
            "fresh": age is not None and age <= 900,
        }

    rich = decoded.get("fortigate.soc.rich_summary", {})
    outbound = decoded.get(
        "fortigate.top_internal_to_external_destinations_enriched", []
    )
    inbound = decoded.get("fortigate.top_external_attackers_enriched", [])
    port_heatmap = decoded.get("fortigate.denied_port_heatmap", [])
    policy_summary = decoded.get("fortigate.policy_summary", [])
    country_scores = decoded.get("fortigate.suspicious_country_scores", [])

    top_destination_ips = _find_nested(
        rich,
        {
            "top_destination_ips", "destination_ips", "top_destinations",
            "external_destinations", "destinations",
        },
    )
    top_destination_countries = _find_nested(
        rich,
        {
            "top_destination_countries", "destination_countries",
            "top_countries", "countries",
        },
    )
    top_destination_services = _find_nested(
        rich,
        {
            "top_destination_services", "destination_services",
            "top_services", "services", "applications",
        },
    )
    top_destination_ports = _find_nested(
        rich,
        {
            "top_destination_ports", "destination_ports", "top_ports", "ports",
        },
    )
    direction_totals = _find_nested(
        rich,
        {"traffic", "traffic_direction", "direction_totals", "directions"},
    )

    if top_destination_ips in (None, "", [], {}):
        top_destination_ips = outbound
    if top_destination_countries in (None, "", [], {}):
        top_destination_countries = country_scores
    if top_destination_services in (None, "", [], {}):
        top_destination_services = policy_summary
    if top_destination_ports in (None, "", [], {}):
        top_destination_ports = port_heatmap

    available_ages = [
        value["age_seconds"]
        for value in freshness.values()
        if value.get("age_seconds") is not None
    ]
    newest_age = min(available_ages) if available_ages else None
    fresh = newest_age is not None and newest_age <= 900

    return {
        "response_style": (
            "Answer in at most six bullets. Separate traffic to the Internet "
            "(outbound) from traffic from the Internet (inbound). Include total "
            "events and top destination IP, country, service, and port when "
            "available. State data age. Do not call the live FortiGate session "
            "API and do not invent categories absent from the response."
        ),
        "source": "zabbix_collected_fortigate_soc",
        "live_session_api_required": False,
        "host": resolved,
        "fresh": fresh,
        "newest_data_age_seconds": newest_age,
        "total_events": decoded.get("fortigate.total_events"),
        "parse_errors": decoded.get("fortigate.parse_errors"),
        "direction_totals": _compact_json(direction_totals),
        "outbound": {
            "top_destinations": _compact_json(outbound),
            "top_destination_ips": _compact_json(top_destination_ips),
            "top_destination_countries": _compact_json(top_destination_countries),
            "top_destination_services": _compact_json(top_destination_services),
            "top_destination_ports": _compact_json(top_destination_ports),
            "grouped_destination_names": _compact_json(
                decoded.get("fortigate.grouped_destination_names", [])
            ),
            "grouped_destination_owners": _compact_json(
                decoded.get("fortigate.grouped_destination_owners", [])
            ),
        },
        "inbound": {
            "top_external_sources": _compact_json(inbound),
            "denied_port_heatmap": _compact_json(port_heatmap),
        },
        "expected_vs_unexpected": _compact_json(
            decoded.get("fortigate.expected_vs_unexpected", {})
        ),
        "ai_summary": decoded.get("fortigate.ollama.summary"),
        "freshness": freshness,
        "available_item_count": len(decoded),
        "missing_keys": [key for key in keys if key not in decoded],
    }


def split_host_names(value: str) -> list[str]:
    normalized = value.replace(" and ", ",").replace(";", ",")
    return [part.strip() for part in normalized.split(",") if part.strip()][:5]


def gpu_value(items: list[dict[str, Any]], key_fragment: str) -> dict[str, Any] | None:
    fragment = key_fragment.lower()
    matches = [
        item
        for item in items
        if fragment in str(item.get("key_", "")).lower()
        or fragment in str(item.get("name", "")).lower()
    ]
    if not matches:
        return None
    matches.sort(key=lambda item: int(str(item.get("lastclock", "0"))) if str(item.get("lastclock", "0")).isdigit() else 0, reverse=True)
    item = matches[0]
    raw_clock = str(item.get("lastclock", ""))
    age = max(0, int(time.time()) - int(raw_clock)) if raw_clock.isdigit() and int(raw_clock) > 0 else None
    value = item.get("lastvalue")
    return {
        "value": value if value not in ("", None) else None,
        "units": item.get("units", ""),
        "lastclock": int(raw_clock) if raw_clock.isdigit() else None,
        "age_seconds": age,
        "fresh": age is not None and age <= 300,
    }


@router.get("/gpu-brief", operation_id="get_zabbix_gpu_brief")
async def gpu_brief(
    hosts: str = Query(..., min_length=1, max_length=500),
) -> dict[str, Any]:
    """Return only current GPU utilization and temperature for up to five hosts."""
    requested = split_host_names(hosts)
    results = []
    for requested_host in requested:
        try:
            resolved = await resolve_host(requested_host)
            data = await ZabbixClient().call(
                "item.get",
                {
                    "hostids": [str(resolved["hostid"])],
                    "output": ["itemid", "name", "key_", "lastvalue", "lastclock", "units", "status", "state"],
                    "search": {"key_": "gpu.", "name": "GPU"},
                    "searchByAny": True,
                    "limit": 500,
                },
            )
            items = data if isinstance(data, list) else []
            utilization = gpu_value(items, "gpu.utilization")
            temperature = gpu_value(items, "gpu.temperature")
            if utilization is None:
                utilization = gpu_value(items, "gpu utilization")
            if temperature is None:
                temperature = gpu_value(items, "gpu temperature")
            if utilization is not None and not utilization.get("units"):
                utilization["units"] = "%"
            if temperature is not None and not temperature.get("units"):
                temperature["units"] = "°C"
            available = any(
                metric is not None
                and metric.get("value") is not None
                and metric.get("fresh") is True
                for metric in (utilization, temperature)
            )
            results.append({
                "requested_host": requested_host,
                "hostid": resolved.get("hostid"),
                "host": resolved.get("name") or resolved.get("host"),
                "data_available": available,
                "utilization": utilization,
                "temperature": temperature,
                "answer_hint": (
                    "Report utilization and temperature in one short bullet."
                    if available
                    else "Say exactly: No current GPU data available."
                ),
            })
        except HTTPException:
            results.append({
                "requested_host": requested_host,
                "host": None,
                "data_available": False,
                "utilization": None,
                "temperature": None,
                "answer_hint": "Say exactly: Host not found.",
            })
    return {
        "response_style": "One bullet per requested host. Maximum 60 words. Do not add recommendations.",
        "count": len(results),
        "data": results,
    }
