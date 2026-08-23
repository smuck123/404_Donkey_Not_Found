import asyncio
import json
import time
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.analytics import host_summary, router as analytics_router, trends, triggers
from app.documentation import documentation, router as documentation_router
from app.drafts import router as drafts_router
from app.overview import router as overview_router
from app.fortigate import (
    FortiGateAPIError,
    FortiGateConfigurationError,
    fortigate_live_details,
    fortigate_performance_summary,
    fortigate_summary,
    fortigate_traffic_summary,
    router as fortigate_router,
)
from app.host_analysis import (
    gpu_brief,
    gpu_summary,
    host_period_summary,
    host_search,
    internet_traffic_summary,
    router as host_analysis_router,
    traffic_summary,
)
from app.zabbix import ConfigurationError, ZabbixAPIError, ZabbixClient


app = FastAPI(title="Donkey Infrastructure Tools", version="0.6.0")
app.include_router(analytics_router)
app.include_router(documentation_router)
app.include_router(drafts_router)
app.include_router(fortigate_router)
app.include_router(host_analysis_router)
app.include_router(overview_router)


def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


@app.exception_handler(ConfigurationError)
async def configuration_error(_: Request, exc: ConfigurationError) -> JSONResponse:
    return error_response(503, "configuration_error", str(exc))


@app.exception_handler(ZabbixAPIError)
async def zabbix_error(_: Request, exc: ZabbixAPIError) -> JSONResponse:
    return error_response(exc.status_code, "zabbix_api_error", str(exc))


@app.exception_handler(FortiGateConfigurationError)
async def fortigate_configuration_error(
    _: Request, exc: FortiGateConfigurationError
) -> JSONResponse:
    return error_response(503, "fortigate_configuration_error", str(exc))


@app.exception_handler(FortiGateAPIError)
async def fortigate_api_error(_: Request, exc: FortiGateAPIError) -> JSONResponse:
    return error_response(exc.status_code, "fortigate_api_error", str(exc))


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "Invalid request parameters",
                "details": exc.errors(),
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    return error_response(exc.status_code, "http_error", str(exc.detail))


def result(data: list[dict[str, Any]]) -> dict[str, Any]:
    return {"count": len(data), "data": data}


def normalize_host(host: dict[str, Any]) -> dict[str, Any]:
    raw_status = str(host.get("status", ""))
    monitored = raw_status == "0"
    return {
        **host,
        "status_code": int(raw_status) if raw_status.isdigit() else raw_status,
        "status_label": "enabled" if monitored else "disabled",
        "monitored": monitored,
        "enabled": monitored,
    }


def normalize_item(item: dict[str, Any]) -> dict[str, Any]:
    raw_status = str(item.get("status", ""))
    enabled = raw_status == "0"
    return {
        **item,
        "status_code": int(raw_status) if raw_status.isdigit() else raw_status,
        "status_label": "enabled" if enabled else "disabled",
        "enabled": enabled,
    }


async def combined_internet_traffic_summary(host: str) -> dict[str, Any]:
    """Combine live FortiGate API data with optional Zabbix-collected traffic."""
    async def capture(awaitable: Any) -> dict[str, Any]:
        try:
            return {"available": True, "data": await awaitable}
        except Exception as exc:
            return {
                "available": False,
                "error": str(exc),
                "error_type": type(exc).__name__,
            }

    health, performance, live_sessions, zabbix_traffic = await asyncio.gather(
        capture(fortigate_summary()),
        capture(fortigate_performance_summary()),
        capture(fortigate_traffic_summary(count=500, ip_version="ipv4")),
        capture(internet_traffic_summary(host=host)),
    )

    live_available = health["available"] or performance["available"]
    zabbix_available = zabbix_traffic["available"]
    if live_available and zabbix_available:
        overall_status = "ok"
    elif live_available or zabbix_available:
        overall_status = "partial"
    else:
        overall_status = "unavailable"

    warnings: list[str] = []
    if not zabbix_available:
        warnings.append(
            "Zabbix-collected traffic is unavailable; live FortiGate API data is still valid."
        )
    if not live_sessions["available"]:
        warnings.append(
            "The FortiGate session-detail endpoint is unavailable; health and "
            "performance data may still be current."
        )
    if not live_available:
        warnings.append("Live FortiGate health and performance APIs are unavailable.")

    return {
        "response_style": (
            "Answer the user's traffic question first in at most six bullets. "
            "Use live FortiGate health and performance even when Zabbix is unavailable. "
            "Clearly distinguish live API data from Zabbix-collected traffic. "
            "Call the result partial, not unavailable, when either source works. "
            "Do not invent destinations, countries, services, or ports."
        ),
        "overall_status": overall_status,
        "read_only": True,
        "source_availability": {
            "live_fortigate_api": live_available,
            "live_session_details": live_sessions["available"],
            "zabbix_collected_traffic": zabbix_available,
        },
        "warnings": warnings,
        "live_fortigate": {
            "health": health,
            "performance": performance,
            "sessions": live_sessions,
        },
        "zabbix_collected_traffic": zabbix_traffic,
    }


@app.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get(
    "/openwebui/context",
    operation_id="get_complete_infrastructure_context",
    summary="Get a complete read-only infrastructure context for Open WebUI",
    description=(
        "Return a curated snapshot of Zabbix hosts and problems, live FortiGate "
        "health and performance, and recent inbound/outbound Internet traffic. "
        "Use this tool for broad infrastructure or firewall questions instead "
        "of calling many individual tools. This operation is read-only."
    ),
)
async def openwebui_context(
    firewall_host: str = Query(
        "fw1.kivela.work",
        min_length=1,
        max_length=255,
        description="Zabbix host containing the FortiGate SOC items",
    ),
    host_limit: int = Query(200, ge=1, le=1000),
    problem_limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    async def capture(name: str, awaitable: Any) -> tuple[str, Any]:
        try:
            return name, await awaitable
        except Exception as exc:
            return name, {"available": False, "error": str(exc)}

    collected = await asyncio.gather(
        capture("hosts", hosts(limit=host_limit)),
        capture("problems", problems(limit=problem_limit)),
        capture("fortigate_health", fortigate_summary()),
        capture("fortigate_performance", fortigate_performance_summary()),
        capture(
            "internet_traffic",
            combined_internet_traffic_summary(host=firewall_host),
        ),
    )
    sections = dict(collected)
    host_rows = sections.get("hosts", {}).get("data", [])
    problem_rows = sections.get("problems", {}).get("data", [])
    enabled = [row for row in host_rows if row.get("enabled") is True]
    disabled = [row for row in host_rows if row.get("enabled") is False]

    return {
        "response_style": (
            "Answer the user's exact question first. Default to at most eight "
            "bullets. Distinguish live FortiGate API values from the Zabbix SOC "
            "traffic window. Mention stale or unavailable sections. Do not list "
            "normal low-value details unless requested."
        ),
        "generated_at": int(time.time()),
        "read_only": True,
        "estate": {
            "hosts_total": len(host_rows),
            "hosts_enabled": len(enabled),
            "hosts_disabled": len(disabled),
            "active_or_recent_problems": len(problem_rows),
            "hosts": host_rows,
            "problems": problem_rows,
        },
        "fortigate": {
            "health": sections.get("fortigate_health"),
            "performance": sections.get("fortigate_performance"),
            "internet_traffic": sections.get("internet_traffic"),
        },
    }


@app.get(
    "/problems",
    operation_id="get_zabbix_problems",
    summary="Get current Zabbix problems",
    description=(
        "Read the newest current and recent monitoring problems from Zabbix. "
        "Use this tool when the user asks about alerts, outages, incidents, "
        "triggered problems, or current infrastructure health. This operation "
        "is read-only."
    ),
)
async def problems(limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    data = await ZabbixClient().call(
        "problem.get",
        {
            "output": "extend",
            "selectAcknowledges": "extend",
            "selectTags": "extend",
            "recent": True,
            "sortfield": ["eventid"],
            "sortorder": "DESC",
            "limit": limit,
        },
    )
    return result(data)


@app.get(
    "/hosts",
    operation_id="get_zabbix_hosts",
    summary="List monitored and disabled Zabbix hosts",
    description=(
        "Return Zabbix hosts with explicit enabled, monitored, and status_label "
        "fields. Zabbix raw status 0 means enabled/monitored and raw status 1 "
        "means disabled/unmonitored. Use the explicit fields instead of guessing "
        "from the raw status value. This operation is read-only."
    ),
)
async def hosts(limit: int = Query(100, ge=1, le=1000)) -> dict[str, Any]:
    data = await ZabbixClient().call(
        "host.get",
        {
            "output": ["hostid", "host", "name", "status"],
            "selectInterfaces": [
                "interfaceid",
                "ip",
                "dns",
                "port",
                "main",
                "type",
                "available",
                "error",
            ],
            "sortfield": "name",
            "limit": limit,
        },
    )
    return result([normalize_host(host) for host in data])


@app.get(
    "/items",
    operation_id="get_zabbix_items",
    summary="Find Zabbix items and numeric item IDs",
    description=(
        "Find Zabbix items before requesting history. Search by item name or key "
        "and optionally restrict results to a numeric host ID. The response "
        "contains itemid, key_, value_type, units, and recent value fields. Pass "
        "the returned numeric itemid and value_type to the history tool. This "
        "operation is read-only."
    ),
)
async def items(
    query: str | None = Query(
        None,
        min_length=1,
        max_length=255,
        description="Text contained in the item name or key, for example fgSysSesCount",
    ),
    hostid: str | None = Query(
        None,
        min_length=1,
        description="Optional numeric Zabbix host ID",
    ),
    include_templates: bool = Query(
        False,
        description="Include item definitions that belong to templates",
    ),
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "output": [
            "itemid",
            "hostid",
            "name",
            "key_",
            "value_type",
            "status",
            "state",
            "lastvalue",
            "lastclock",
            "units",
        ],
        "selectHosts": ["hostid", "host", "name", "status"],
        "templated": include_templates,
        "sortfield": "name",
        "limit": limit,
    }
    if hostid:
        params["hostids"] = [hostid]
    if query:
        params["search"] = {"name": query, "key_": query}
        params["searchByAny"] = True
        params["searchWildcardsEnabled"] = False

    data = await ZabbixClient().call("item.get", params)
    return result([normalize_item(item) for item in data])


@app.get(
    "/history",
    operation_id="get_zabbix_item_history",
    summary="Get recent Zabbix item history",
    description=(
        "Return recent values for one numeric Zabbix item ID. First use the item "
        "search tool to obtain itemid and value_type. Supply value_type as the "
        "history parameter. This operation is read-only."
    ),
)
async def history(
    itemid: str = Query(
        ...,
        min_length=1,
        pattern=r"^\d+$",
        description="Numeric itemid returned by the item search tool",
    ),
    history_type: int = Query(
        0,
        alias="history",
        ge=0,
        le=5,
        description="Zabbix value_type returned by item search",
    ),
    limit: int = Query(100, ge=1, le=1000),
) -> dict[str, Any]:
    data = await ZabbixClient().call(
        "history.get",
        {
            "output": "extend",
            "history": history_type,
            "itemids": [itemid],
            "sortfield": "clock",
            "sortorder": "DESC",
            "limit": limit,
        },
    )
    return result(data)


@app.get(
    "/fortigate/api-brief",
    operation_id="get_fortigate_api_brief",
    summary="Get validated FortiGate API values collected through Zabbix",
    description=(
        "Return a concise, read-only FortiGate health and inventory summary from "
        "fortigate.api.* Zabbix items. Measurements are returned only when the "
        "collection status is ok, preventing missing values from appearing as zero."
    ),
)
async def fortigate_api_brief(
    host: str = Query(
        "fw1.kivela.work",
        min_length=1,
        max_length=255,
        description="Zabbix technical or visible host name",
    ),
) -> dict[str, Any]:
    host_rows = await ZabbixClient().call(
        "host.get",
        {
            "output": ["hostid", "host", "name", "status"],
            "search": {"host": host, "name": host},
            "searchByAny": True,
            "searchWildcardsEnabled": False,
            "limit": 20,
        },
    )
    exact = [
        row for row in host_rows
        if host.casefold() in {
            str(row.get("host", "")).casefold(),
            str(row.get("name", "")).casefold(),
        }
    ]
    if not host_rows:
        raise HTTPException(status_code=404, detail="FortiGate Zabbix host was not found")
    selected = (exact or host_rows)[0]
    hostid = str(selected.get("hostid", ""))

    item_rows = await ZabbixClient().call(
        "item.get",
        {
            "output": [
                "itemid", "name", "key_", "value_type", "units", "state",
                "status", "lastvalue", "lastclock",
            ],
            "hostids": [hostid],
            "templated": False,
            "search": {"key_": "fortigate.api."},
            "searchWildcardsEnabled": False,
            "sortfield": "key_",
            "limit": 100,
        },
    )
    by_key = {str(row.get("key_", "")): row for row in item_rows}
    status_item = by_key.get("fortigate.api.collection_status", {})
    raw_item = by_key.get("fortigate.api.raw", {})
    collection_status = str(status_item.get("lastvalue", "")).strip().lower()
    lastclock = max(
        int(str(status_item.get("lastclock", "0")) or 0),
        int(str(raw_item.get("lastclock", "0")) or 0),
    )
    age_seconds = max(0, int(time.time()) - lastclock) if lastclock else None
    fresh = age_seconds is not None and age_seconds <= 900
    data_valid = collection_status == "ok" and fresh

    raw_payload: dict[str, Any] = {}
    try:
        parsed = json.loads(str(raw_item.get("lastvalue", "")))
        if isinstance(parsed, dict):
            raw_payload = parsed
    except (TypeError, ValueError, json.JSONDecodeError):
        pass

    def value(key: str) -> Any:
        row = by_key.get(key)
        if not row or str(row.get("state", "0")) != "0":
            return None
        if int(str(row.get("lastclock", "0")) or 0) <= 0:
            return None
        return row.get("lastvalue")

    inventory = {}
    metrics = {}
    if data_valid:
        inventory = {
            "hostname": value("fortigate.api.device.hostname"),
            "model": value("fortigate.api.device.model"),
            "serial": value("fortigate.api.device.serial"),
            "version": value("fortigate.api.device.version"),
            "build": value("fortigate.api.device.build"),
            "interfaces_total": value("fortigate.api.interfaces.total"),
            "interfaces_up": value("fortigate.api.interfaces.up"),
            "interfaces_down": value("fortigate.api.interfaces.down"),
            "down_interface_names": value("fortigate.api.interfaces.down_names"),
            "policies_total": value("fortigate.api.policies.total"),
            "policies_enabled": value("fortigate.api.policies.enabled"),
            "policies_disabled": value("fortigate.api.policies.disabled"),
            "static_routes": value("fortigate.api.routes.static_total"),
            "vpn_phase1": value("fortigate.api.vpn.phase1_total"),
            "vpn_phase2": value("fortigate.api.vpn.phase2_total"),
        }
        metrics = {
            "sessions": value("fortigate.api.performance.sessions"),
            "session_setup_rate": value("fortigate.api.performance.setuprate"),
            "cpu_percent": value("fortigate.api.performance.cpu"),
            "memory_percent": value("fortigate.api.performance.memory"),
        }

    warning = None
    if not fresh:
        warning = "FortiGate API data is missing or older than 15 minutes."
    elif collection_status != "ok":
        warning = (
            f"FortiGate API collection status is {collection_status or 'unknown'}; "
            "measurement values are withheld because they may be incomplete."
        )

    return {
        "response_style": (
            "Answer in at most three bullets. Report collection health first. "
            "Use inventory and metrics only when data_valid is true. Never "
            "interpret missing values as zero."
        ),
        "host": selected,
        "collection_status": collection_status or "unknown",
        "generated_at": raw_payload.get("generated_at"),
        "lastclock": lastclock,
        "age_seconds": age_seconds,
        "fresh": fresh,
        "data_valid": data_valid,
        "warning": warning,
        "errors": raw_payload.get("errors", {}),
        "inventory": inventory,
        "metrics": metrics,
    }


@app.get(
    "/read",
    operation_id="read_zabbix",
    summary="Stable read-only gateway for Zabbix data and documentation",
)
async def read_zabbix(
    action: str = Query(..., pattern=r"^(capabilities|hosts|problems|items|history|host_summary|host_search|host_24h_summary|gpu_brief|gpu_summary|traffic_summary|internet_traffic_summary|fortigate_live|fortigate_api_brief|triggers|trends|documentation)$"),
    query: str = "",
    hostid: str = "",
    itemid: str = "",
    history_type: int = Query(0, alias="history", ge=0, le=5),
    time_from: int | None = Query(None, ge=0),
    time_till: int | None = Query(None, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    hours: int = Query(24, ge=1, le=168),
    item_key: str = "",
) -> dict[str, Any]:
    """Dispatch only explicitly allowlisted read operations."""
    if action == "capabilities":
        return {
            "read_only": True,
            "actions": {
                "hosts": "List hosts.",
                "host_search": "Search hosts by technical or visible name using query.",
                "host_summary": "Operational inventory summary using numeric hostid.",
                "host_24h_summary": "CPU, memory, disk, network and recent-problem statistics; use query for host name or ID.",
                "gpu_brief": "Concise current GPU utilization and temperature for comma-separated host names in query.",
                "gpu_summary": "Detailed GPU values and period statistics; use query for host name or ID.",
                "traffic_summary": "Parse a JSON traffic item; use query for host name or ID and optional item_key.",
                "internet_traffic_summary": "Combine live FortiGate API status with inbound and outbound traffic collected in Zabbix.",
                "fortigate_live": "Read live FortiGate CPU, memory, sessions, interfaces, policies, VPN, or top traffic; put the requested topic in query.",
                "fortigate_api_brief": "Validated FortiGate API health, inventory and performance values collected through Zabbix.",
                "problems": "List current and recent problems.",
                "items": "Find items by query and optional hostid.",
                "history": "Read raw history using itemid and history value type.",
                "triggers": "Read problem triggers for numeric hostid.",
                "trends": "Read aggregated trends for numeric itemid.",
                "documentation": "Read an official Zabbix 8.0 manual path supplied in query.",
            },
        }
    if action == "host_search":
        if not query:
            raise HTTPException(status_code=422, detail="host_search requires query")
        return await host_search(query=query, limit=min(limit, 100))
    if action == "host_24h_summary":
        return await host_period_summary(host=query or hostid, hours=hours, items_per_category=min(20, max(1, limit // 20)))
    if action == "gpu_brief":
        if not query:
            raise HTTPException(status_code=422, detail="gpu_brief requires host names in query")
        return await gpu_brief(hosts=query)
    if action == "gpu_summary":
        return await gpu_summary(host=query or hostid, hours=hours)
    if action == "traffic_summary":
        return await traffic_summary(host=query or hostid, item_key=item_key)
    if action == "internet_traffic_summary":
        return await combined_internet_traffic_summary(host=query or "fw1.kivela.work")
    if action == "fortigate_live":
        return await fortigate_live_details(topic=query or "all", count=min(limit, 5000))
    if action == "fortigate_api_brief":
        return await fortigate_api_brief(host=query or "fw1.kivela.work")
    if action == "hosts":
        return await hosts(limit=min(limit, 1000))
    if action == "problems":
        return await problems(limit=min(limit, 500))
    if action == "items":
        return await items(query=query or None, hostid=hostid or None, limit=min(limit, 500))
    if action == "history":
        if not itemid.isdigit():
            raise HTTPException(status_code=422, detail="history requires a numeric itemid")
        return await history(itemid=itemid, history_type=history_type, limit=limit)
    if action == "host_summary":
        if not hostid.isdigit():
            raise HTTPException(status_code=422, detail="host_summary requires a numeric hostid")
        return await host_summary(hostid=hostid)
    if action == "triggers":
        if not hostid.isdigit():
            raise HTTPException(status_code=422, detail="triggers requires a numeric hostid")
        return await triggers(hostid=hostid, only_problems=True, limit=min(limit, 500))
    if action == "trends":
        if not itemid.isdigit():
            raise HTTPException(status_code=422, detail="trends requires a numeric itemid")
        return await trends(
            itemid=itemid,
            time_from=time_from,
            time_till=time_till,
            limit=limit,
        )
    if action == "documentation":
        return await documentation(path=query, max_chars=min(50000, max(1000, limit * 200)))
    raise HTTPException(status_code=422, detail="Unsupported read action")
