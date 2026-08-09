import time
from typing import Any

from fastapi import APIRouter, Query

from app.zabbix import ZabbixAPIError, ZabbixClient


router = APIRouter(tags=["analysis"])


def _host_status(raw: Any) -> dict[str, Any]:
    code = str(raw)
    enabled = code == "0"
    return {
        "status_code": int(code) if code.isdigit() else code,
        "status_label": "enabled" if enabled else "disabled",
        "enabled": enabled,
        "monitored": enabled,
    }


@router.get("/host-summary", operation_id="get_zabbix_host_summary")
async def host_summary(hostid: str = Query(..., pattern=r"^\d+$")) -> dict[str, Any]:
    """Build a compact operational summary for one numeric Zabbix host ID."""
    client = ZabbixClient()
    hosts = await client.call(
        "host.get",
        {
            "hostids": [hostid],
            "output": ["hostid", "host", "name", "status", "maintenance_status"],
            "selectInterfaces": ["type", "main", "useip", "ip", "dns", "port", "available", "error"],
            "selectHostGroups": ["groupid", "name"],
            "selectParentTemplates": ["templateid", "name"],
        },
    )
    if not isinstance(hosts, list) or not hosts:
        raise ZabbixAPIError("Zabbix host was not found", status_code=404)

    problems = await client.call(
        "problem.get",
        {
            "hostids": [hostid],
            "output": ["eventid", "name", "severity", "clock", "acknowledged"],
            "recent": False,
            "sortfield": ["eventid"],
            "sortorder": "DESC",
            "limit": 100,
        },
    )
    items = await client.call(
        "item.get",
        {
            "hostids": [hostid],
            "output": ["itemid", "name", "key_", "status", "state", "lastclock", "lastvalue", "units"],
            "limit": 5000,
        },
    )

    host = hosts[0]
    item_rows = items if isinstance(items, list) else []
    problem_rows = problems if isinstance(problems, list) else []
    clocks = [int(row["lastclock"]) for row in item_rows if str(row.get("lastclock", "0")).isdigit()]
    newest_clock = max(clocks, default=0)
    severity_counts = {str(level): 0 for level in range(6)}
    for problem in problem_rows:
        severity_counts[str(problem.get("severity", "0"))] += 1

    return {
        "host": {**host, **_host_status(host.get("status"))},
        "availability": host.get("interfaces", []),
        "problems": {
            "total": len(problem_rows),
            "by_severity": severity_counts,
            "data": problem_rows[:20],
        },
        "items": {
            "total": len(item_rows),
            "enabled": sum(str(row.get("status")) == "0" for row in item_rows),
            "disabled": sum(str(row.get("status")) != "0" for row in item_rows),
            "unsupported": sum(str(row.get("state")) == "1" for row in item_rows),
            "newest_data_clock": newest_clock,
            "newest_data_age_seconds": max(0, int(time.time()) - newest_clock) if newest_clock else None,
        },
    }


@router.get("/triggers", operation_id="get_zabbix_triggers")
async def triggers(
    hostid: str = Query(..., pattern=r"^\d+$"),
    only_problems: bool = True,
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "hostids": [hostid],
        "output": ["triggerid", "description", "priority", "status", "value", "lastchange", "error"],
        "selectHosts": ["hostid", "host", "name"],
        "selectItems": ["itemid", "name", "key_", "value_type", "lastvalue", "units"],
        "sortfield": ["priority", "lastchange"],
        "sortorder": "DESC",
        "limit": limit,
    }
    if only_problems:
        params["filter"] = {"value": 1}
    data = await ZabbixClient().call("trigger.get", params)
    rows = data if isinstance(data, list) else []
    return {"count": len(rows), "data": rows}


@router.get("/trends", operation_id="get_zabbix_item_trends")
async def trends(
    itemid: str = Query(..., pattern=r"^\d+$"),
    time_from: int | None = Query(None, ge=0),
    time_till: int | None = Query(None, ge=0),
    limit: int = Query(168, ge=1, le=1000),
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "itemids": [itemid],
        "output": ["itemid", "clock", "num", "value_min", "value_avg", "value_max"],
        "limit": limit,
    }
    if time_from is not None:
        params["time_from"] = time_from
    if time_till is not None:
        params["time_till"] = time_till
    data = await ZabbixClient().call("trend.get", params)
    rows = data if isinstance(data, list) else []
    return {"count": len(rows), "data": rows}

