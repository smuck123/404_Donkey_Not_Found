import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP


BASE_URL = os.getenv("ZABBIX_TOOLS_URL", "http://127.0.0.1:8889").rstrip("/")
TIMEOUT = httpx.Timeout(15.0, connect=3.0)
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8001"))

# FastMCP 1.x configures its bind address when the server is created.
# FastMCP.run() only selects the transport and does not accept host/port.
mcp = FastMCP(
    "Donkey Zabbix Read Only",
    instructions=(
        "Read-only Zabbix tools. Prefer get_host_overview for general health questions. "
        "Use get_gpu_brief for current GPU questions and get_host_24h_summary for period summaries. "
        "Never infer enabled/disabled state from raw numeric codes."
    ),
    host=MCP_HOST,
    port=MCP_PORT,
    json_response=True,
)


async def _get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        response = await client.get(f"{BASE_URL}{path}", params=params)
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict):
        raise ValueError("Zabbix tools returned an unexpected response")
    return data


async def _read(action: str, **params: Any) -> dict[str, Any]:
    return await _get("/read", {"action": action, **params})


@mcp.tool()
async def list_hosts(limit: int = 100) -> dict[str, Any]:
    """List Zabbix hosts with normalized enabled and monitored fields."""
    return await _get("/hosts", {"limit": max(1, min(limit, 500))})


@mcp.tool()
async def search_hosts(query: str, limit: int = 20) -> dict[str, Any]:
    """Find a Zabbix host by technical name or visible name."""
    return await _read("host_search", query=query, limit=max(1, min(limit, 100)))


@mcp.tool()
async def get_host_overview(host: str) -> dict[str, Any]:
    """Get a compact current health overview by host name or numeric host ID."""
    return await _get("/overview", {"host": host})


@mcp.tool()
async def get_host_24h_summary(host: str, hours: int = 24) -> dict[str, Any]:
    """Summarize CPU, memory, disk, network and recent problems for a host."""
    return await _read(
        "host_24h_summary",
        query=host,
        hours=max(1, min(hours, 168)),
    )


@mcp.tool()
async def get_active_problems(host: str = "", limit: int = 50) -> dict[str, Any]:
    """Get active problems globally, or the compact active-problem list for one host."""
    if host:
        overview = await _get("/overview", {"host": host})
        return {"host": overview.get("host"), "problems": overview.get("problems")}
    return await _get("/problems", {"limit": max(1, min(limit, 200))})


@mcp.tool()
async def find_items(query: str, host: str = "", limit: int = 50) -> dict[str, Any]:
    """Find item IDs, keys, units, types, and latest values by name or key fragment."""
    hostid = ""
    if host:
        matches = await _get("/host-search", {"query": host, "limit": 10})
        rows = matches.get("data", [])
        if not rows:
            return {"count": 0, "data": [], "message": "Host was not found"}
        exact = [
            row for row in rows
            if host.lower() in {
                str(row.get("host", "")).lower(),
                str(row.get("name", "")).lower(),
            }
        ]
        hostid = str((exact or rows)[0]["hostid"])
    return await _get(
        "/items",
        {"query": query, "hostid": hostid, "limit": max(1, min(limit, 200))},
    )


@mcp.tool()
async def get_item_history(
    itemid: str,
    history_type: int = 0,
    limit: int = 20,
) -> dict[str, Any]:
    """Read recent values for a numeric item ID returned by find_items."""
    if not itemid.isdigit():
        raise ValueError("itemid must be numeric")
    return await _get(
        "/history",
        {
            "itemid": itemid,
            "history": max(0, min(history_type, 5)),
            "limit": max(1, min(limit, 200)),
        },
    )


@mcp.tool()
async def get_gpu_brief(hosts: str) -> dict[str, Any]:
    """Get concise current GPU utilization and temperature for comma-separated hosts."""
    return await _read("gpu_brief", query=hosts)


@mcp.tool()
async def get_gpu_summary(host: str, hours: int = 24) -> dict[str, Any]:
    """Get detailed current and historical GPU statistics for one host."""
    return await _read(
        "gpu_summary",
        query=host,
        hours=max(1, min(hours, 168)),
    )


@mcp.tool()
async def get_traffic_summary(host: str, item_key: str = "") -> dict[str, Any]:
    """Get the parsed FortiGate traffic summary JSON for a host."""
    return await _read(
        "traffic_summary",
        query=host,
        item_key=item_key,
    )


@mcp.tool()
async def get_host_triggers(hostid: str, limit: int = 100) -> dict[str, Any]:
    """Get problem triggers for a numeric Zabbix host ID."""
    if not hostid.isdigit():
        raise ValueError("hostid must be numeric")
    return await _read(
        "triggers",
        hostid=hostid,
        limit=max(1, min(limit, 500)),
    )


@mcp.tool()
async def get_item_trends(
    itemid: str,
    time_from: int = 0,
    time_till: int = 0,
    limit: int = 100,
) -> dict[str, Any]:
    """Get aggregated Zabbix trends for a numeric item ID."""
    if not itemid.isdigit():
        raise ValueError("itemid must be numeric")
    params: dict[str, Any] = {
        "itemid": itemid,
        "limit": max(1, min(limit, 1000)),
    }
    if time_from > 0:
        params["time_from"] = time_from
    if time_till > 0:
        params["time_till"] = time_till
    return await _read("trends", **params)


@mcp.tool()
async def read_zabbix_documentation(path: str, max_chars: int = 12000) -> dict[str, Any]:
    """Read an allowlisted page from the official Zabbix 8.0 documentation."""
    return await _read(
        "documentation",
        query=path,
        limit=max(5, min(max_chars // 200, 250)),
    )


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
