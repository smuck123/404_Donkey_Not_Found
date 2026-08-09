import json
import os
import time
from collections import Counter, defaultdict
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.zabbix import ZabbixClient


router = APIRouter(tags=["host analysis"])
NUMERIC_VALUE_TYPES = {"0", "3"}


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
        return {
            "schema": "connection_list",
            "host": resolved,
            "item": item_info,
            "captured_at": payload.get("time"),
            "connections": len(entries),
            "top_processes": processes.most_common(10),
            "top_remote_ips": remote_ips.most_common(10),
            "top_remote_ports": remote_ports.most_common(10),
            "sample": entries[:15],
        }

    if any(key in payload for key in ("deny_per_min", "top_attackers", "top_ports", "traffic")):
        return {
            "schema": "fortigate_aggregate",
            "host": resolved,
            "item": item_info,
            "deny_per_min": payload.get("deny_per_min"),
            "accept": payload.get("accept"),
            "close": payload.get("close"),
            "traffic": payload.get("traffic", {}),
            "top_attackers": payload.get("top_attackers", [])[:10],
            "top_ports": payload.get("top_ports", [])[:10],
            "recent": payload.get("recent", [])[:15],
        }

    return {
        "schema": "generic_json",
        "host": resolved,
        "item": item_info,
        "data": payload,
    }
