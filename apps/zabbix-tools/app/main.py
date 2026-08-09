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
    router as fortigate_router,
)
from app.host_analysis import (
    gpu_brief,
    gpu_summary,
    host_period_summary,
    host_search,
    router as host_analysis_router,
    traffic_summary,
)
from app.zabbix import ConfigurationError, ZabbixAPIError, ZabbixClient


app = FastAPI(title="Donkey Infrastructure Tools", version="0.5.0")
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


@app.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    return {"status": "ok"}


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
    "/read",
    operation_id="read_zabbix",
    summary="Stable read-only gateway for Zabbix data and documentation",
)
async def read_zabbix(
    action: str = Query(..., pattern=r"^(capabilities|hosts|problems|items|history|host_summary|host_search|host_24h_summary|gpu_brief|gpu_summary|traffic_summary|triggers|trends|documentation)$"),
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
