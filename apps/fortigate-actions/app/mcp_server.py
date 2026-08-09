import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP


BASE_URL = os.getenv("FORTIGATE_ACTIONS_URL", "http://127.0.0.1:8891").rstrip("/")
ACTION_KEY = os.getenv("FORTIGATE_ACTION_KEY", "")
mcp = FastMCP(
    "404 Donkey FortiGate Approved Actions",
    instructions=(
        "Only propose or confirm an IP action when explicitly requested. "
        "Never confirm in the same turn as a proposal. Confirm only when the "
        "human's newest message contains the exact confirmation code."
    ), host="0.0.0.0", port=8001, json_response=True,
)


async def request(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=3.0)) as client:
        response = await client.request(method, f"{BASE_URL}{path}", json=body, headers={"X-Action-Key": ACTION_KEY})
        response.raise_for_status()
        return response.json()


@mcp.tool()
async def propose_ip_action(action: str, ip: str, direction: str, reason: str, requested_by: str) -> dict[str, Any]:
    """Preview a public-IP block or unblock. This never changes the firewall."""
    return await request("POST", "/actions/preview", {"action": action, "ip": ip, "direction": direction, "reason": reason, "requested_by": requested_by})


@mcp.tool()
async def confirm_ip_action(proposal_id: str, confirmation_code: str, approved_by: str) -> dict[str, Any]:
    """Execute a previously previewed action only after a human supplies its code in a later message."""
    return await request("POST", "/actions/confirm", {"proposal_id": proposal_id, "confirmation_code": confirmation_code, "approved_by": approved_by})


@mcp.tool()
async def propose_user_action(
    action: str,
    subject: str,
    reason: str,
    requested_by: str,
) -> dict[str, Any]:
    """Preview block, unblock, slow, or restore for the fixed Big or Bee aliases. This never changes the firewall."""
    return await request(
        "POST",
        "/user-actions/preview",
        {
            "action": action,
            "subject": subject,
            "reason": reason,
            "requested_by": requested_by,
        },
    )


@mcp.tool()
async def confirm_user_action(
    proposal_id: str,
    confirmation_code: str,
    approved_by: str,
) -> dict[str, Any]:
    """Execute a previously previewed Big or Bee action only after the human supplies its exact code in a later message."""
    return await request(
        "POST",
        "/user-actions/confirm",
        {
            "proposal_id": proposal_id,
            "confirmation_code": confirmation_code,
            "approved_by": approved_by,
        },
    )


@mcp.tool()
async def list_user_actions(limit: int = 50) -> dict[str, Any]:
    """List recent pending, completed, expired, and failed Big or Bee actions."""
    return await request(
        "GET", f"/user-actions?limit={max(1, min(limit, 200))}"
    )


@mcp.tool()
async def list_ip_actions(limit: int = 50) -> dict[str, Any]:
    """List recent pending, completed, expired, and failed firewall actions."""
    return await request("GET", f"/actions?limit={max(1, min(limit, 200))}")


if __name__ == "__main__":
    mcp.run(transport="streamable-http")

