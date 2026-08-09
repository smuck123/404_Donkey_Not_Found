import asyncio
import time
from typing import Any

from fastapi import APIRouter, Query

from app.host_analysis import resolve_host
from app.zabbix import ZabbixClient


router = APIRouter(tags=["overview"])
SEVERITY_LABELS = {
    "0": "not_classified",
    "1": "information",
    "2": "warning",
    "3": "average",
    "4": "high",
    "5": "disaster",
}
AVAILABILITY_LABELS = {"0": "unknown", "1": "available", "2": "unavailable"}
METRIC_RULES: dict[str, tuple[str, ...]] = {
    "cpu_utilization": ("system.cpu.util", "cpu utilization", "cpu usage"),
    "memory_utilization": ("vm.memory.size[pused]", "memory utilization", "memory usage"),
    "disk_utilization": ("vfs.fs.size[/,pused]", "disk utilization", "disk space usage"),
    "network_availability": ("agent.ping", "icmpping", "availability"),
    "uptime": ("system.uptime", "uptime"),
    "gpu_utilization": ("gpu.utilization", "gpu utilization"),
    "gpu_temperature": ("gpu.temperature", "gpu temperature"),
}


def _clock(value: Any) -> int:
    raw = str(value or "")
    return int(raw) if raw.isdigit() else 0


def _item_score(item: dict[str, Any], patterns: tuple[str, ...]) -> tuple[int, int]:
    blob = f'{item.get("key_", "")} {item.get("name", "")}'.lower()
    match = max(
        (100 - index * 10 for index, pattern in enumerate(patterns) if pattern in blob),
        default=0,
    )
    healthy = 20 if str(item.get("status")) == "0" and str(item.get("state")) == "0" else 0
    populated = 10 if item.get("lastvalue") not in ("", None) else 0
    return match + healthy + populated, _clock(item.get("lastclock"))


def _representative(
    items: list[dict[str, Any]],
    patterns: tuple[str, ...],
    now: int,
) -> dict[str, Any] | None:
    candidates = [item for item in items if _item_score(item, patterns)[0] >= 100]
    if not candidates:
        return None
    item = max(candidates, key=lambda row: _item_score(row, patterns))
    lastclock = _clock(item.get("lastclock"))
    age = max(0, now - lastclock) if lastclock else None
    return {
        "itemid": item.get("itemid"),
        "name": item.get("name"),
        "key": item.get("key_"),
        "value": item.get("lastvalue") if item.get("lastvalue") not in ("", None) else None,
        "units": item.get("units") or "",
        "enabled": str(item.get("status")) == "0",
        "supported": str(item.get("state")) == "0",
        "lastclock": lastclock or None,
        "age_seconds": age,
        "fresh": age is not None and age <= 300,
    }


@router.get(
    "/overview",
    operation_id="get_zabbix_overview",
    summary="Get a compact general health overview for one Zabbix host",
    description=(
        "Resolve a host by technical name, visible name, or numeric ID and return "
        "normalized status, interface availability, active problems, and representative "
        "current metrics. Zabbix status 0 is normalized to enabled. Read-only."
    ),
)
async def overview(
    host: str = Query(..., min_length=1, max_length=255),
) -> dict[str, Any]:
    resolved = await resolve_host(host)
    hostid = str(resolved["hostid"])
    client = ZabbixClient()
    host_rows, problem_rows, item_rows = await asyncio.gather(
        client.call(
            "host.get",
            {
                "hostids": [hostid],
                "output": ["hostid", "host", "name", "status", "maintenance_status"],
                "selectInterfaces": ["type", "main", "ip", "dns", "available", "error"],
            },
        ),
        client.call(
            "problem.get",
            {
                "hostids": [hostid],
                "output": ["eventid", "name", "severity", "clock", "acknowledged"],
                "recent": False,
                "sortfield": ["eventid"],
                "sortorder": "DESC",
                "limit": 20,
            },
        ),
        client.call(
            "item.get",
            {
                "hostids": [hostid],
                "output": [
                    "itemid", "name", "key_", "value_type", "status", "state",
                    "lastvalue", "lastclock", "units",
                ],
                "filter": {"status": 0},
                "limit": 5000,
            },
        ),
    )

    host_row = host_rows[0] if isinstance(host_rows, list) and host_rows else resolved
    problems = problem_rows if isinstance(problem_rows, list) else []
    items = item_rows if isinstance(item_rows, list) else []
    now = int(time.time())
    raw_status = str(host_row.get("status", ""))
    enabled = raw_status == "0"

    interfaces = []
    for interface in host_row.get("interfaces", []):
        code = str(interface.get("available", "0"))
        interfaces.append({
            **interface,
            "availability_code": int(code) if code.isdigit() else code,
            "availability_label": AVAILABILITY_LABELS.get(code, "unknown"),
        })

    metrics = {
        name: metric
        for name, patterns in METRIC_RULES.items()
        if (metric := _representative(items, patterns, now)) is not None
    }
    normalized_problems = [
        {
            **problem,
            "severity_label": SEVERITY_LABELS.get(str(problem.get("severity", "0")), "unknown"),
            "age_seconds": max(0, now - _clock(problem.get("clock"))) if _clock(problem.get("clock")) else None,
        }
        for problem in problems
    ]

    return {
        "response_style": (
            "Lead with overall health. Use at most three bullets. Mention only active "
            "problems and available fresh metrics. Never treat raw status 0 as disabled."
        ),
        "host": {
            "hostid": hostid,
            "host": host_row.get("host"),
            "name": host_row.get("name"),
            "status_code": int(raw_status) if raw_status.isdigit() else raw_status,
            "status_label": "enabled" if enabled else "disabled",
            "enabled": enabled,
            "monitored": enabled,
            "in_maintenance": str(host_row.get("maintenance_status", "0")) == "1",
        },
        "interfaces": interfaces,
        "problems": {
            "active": len(normalized_problems),
            "highest_severity": (
                max((int(str(row.get("severity", "0"))) for row in problems), default=0)
            ),
            "data": normalized_problems,
        },
        "metrics": metrics,
        "data_quality": {
            "enabled_items": len(items),
            "fresh_metrics": sum(metric.get("fresh") is True for metric in metrics.values()),
            "stale_metrics": sum(metric.get("fresh") is False for metric in metrics.values()),
        },
    }
