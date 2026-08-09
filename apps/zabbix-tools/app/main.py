from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.zabbix import ConfigurationError, ZabbixAPIError, ZabbixClient


app = FastAPI(title="Donkey Zabbix Tools", version="0.1.0")


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
    summary="List monitored Zabbix hosts",
    description=(
        "Return hosts monitored by Zabbix, including host IDs, names, enabled "
        "status, and network interfaces. Use this tool to list, count, find, "
        "or identify monitored servers and devices. This operation is read-only."
    ),
)
async def hosts(limit: int = Query(100, ge=1, le=1000)) -> dict[str, Any]:
    data = await ZabbixClient().call(
        "host.get",
        {
            "output": ["hostid", "host", "name", "status"],
            "selectInterfaces": ["interfaceid", "ip", "dns", "port", "main", "type"],
            "sortfield": "name",
            "limit": limit,
        },
    )
    return result(data)


@app.get(
    "/history",
    operation_id="get_zabbix_item_history",
    summary="Get recent Zabbix item history",
    description=(
        "Return recent historical values for one Zabbix item ID. Use this tool "
        "only after an item ID and its value type are known. The history query "
        "parameter is the Zabbix value type from 0 through 5. This operation "
        "is read-only."
    ),
)
async def history(
    itemid: str = Query(..., min_length=1),
    history_type: int = Query(0, alias="history", ge=0, le=5),
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

