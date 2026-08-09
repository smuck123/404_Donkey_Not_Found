from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.analytics import router as analytics_router
from app.documentation import router as documentation_router
from app.drafts import router as drafts_router
from app.zabbix import ConfigurationError, ZabbixAPIError, ZabbixClient


app = FastAPI(title="Donkey Zabbix Tools", version="0.3.0")
app.include_router(analytics_router)
app.include_router(documentation_router)
app.include_router(drafts_router)


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
