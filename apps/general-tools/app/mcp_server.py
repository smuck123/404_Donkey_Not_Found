import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP


BASE_URL = os.getenv("GENERAL_TOOLS_URL", "http://127.0.0.1:8893").rstrip("/")
TIMEOUT = httpx.Timeout(15.0, connect=3.0)
mcp = FastMCP(
    "404 Donkey General Tools",
    instructions="Read-only general tools. Use get_top_news for current headlines.",
    host=os.getenv("MCP_HOST", "0.0.0.0"),
    port=int(os.getenv("MCP_PORT", "8001")),
    json_response=True,
)


@mcp.tool()
async def get_top_news(category: str = "top", limit: int = 8) -> dict[str, Any]:
    """Get current RSS headlines. Category: top, finland, world, or technology."""
    normalized = category.strip().lower()
    if normalized == "tech":
        normalized = "technology"
    if normalized not in {"top", "finland", "world", "technology"}:
        raise ValueError("category must be top, finland, world, or technology")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        response = await client.get(
            f"{BASE_URL}/news",
            params={"category": normalized, "limit": max(1, min(limit, 20))},
        )
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict):
        raise ValueError("General tools returned an unexpected response")
    return data


if __name__ == "__main__":
    mcp.run(transport="streamable-http")

