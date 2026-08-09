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


@mcp.tool()
async def list_hosts(limit: int = 100) -> dict[str, Any]:
    """List Zabbix hosts with normalized enabled and monitored fields."""
    return await _get("/hosts", {"limit": max(1, min(limit, 500))})


@mcp.tool()
async def get_host_overview(host: str) -> dict[str, Any]:
    """Get a compact general health overview by host name or numeric host ID."""
    return await _get("/overview", {"host": host})


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


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
