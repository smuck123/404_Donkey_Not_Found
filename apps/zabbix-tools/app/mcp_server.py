import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP


BASE_URL = os.getenv("ZABBIX_TOOLS_URL", "http://127.0.0.1:8889").rstrip("/")
TIMEOUT = httpx.Timeout(15.0, connect=3.0)
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8001"))
DEFAULT_FIREWALL_ZABBIX_HOST = os.getenv("FORTIGATE_ZABBIX_HOST", "himabot").strip()
DEFAULT_TRAFFIC_ITEM_KEY = os.getenv(
    "ZABBIX_TRAFFIC_ITEM_KEY", "fortigate_summary.sh"
).strip()

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
async def get_traffic_summary(host: str = "", item_key: str = "") -> dict[str, Any]:
    """Get collected FortiGate traffic; defaults to the configured firewall host."""
    selected_host = host.strip() or DEFAULT_FIREWALL_ZABBIX_HOST
    selected_key = item_key.strip() or DEFAULT_TRAFFIC_ITEM_KEY
    if not selected_host:
        raise ValueError("A FortiGate Zabbix host must be configured")
    return await _read(
        "traffic_summary",
        query=selected_host,
        item_key=selected_key,
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


async def _estate_summary(limit: int = 500) -> dict[str, Any]:
    hosts_result = await _get("/hosts", {"limit": max(1, min(limit, 1000))})
    problems_result = await _get("/problems", {"limit": 200})
    hosts = hosts_result.get("data", [])
    problems = problems_result.get("data", [])

    enabled = [host for host in hosts if host.get("enabled") is True]
    disabled = [host for host in hosts if host.get("enabled") is False]
    unavailable = []
    for host in enabled:
        interfaces = host.get("interfaces", []) or []
        if interfaces and all(str(interface.get("available", "")) == "2" for interface in interfaces):
            unavailable.append({
                "hostid": host.get("hostid"),
                "host": host.get("host"),
                "name": host.get("name"),
                "interface_errors": [
                    interface.get("error")
                    for interface in interfaces
                    if interface.get("error")
                ],
            })

    severity_counts = Counter(str(problem.get("severity", "0")) for problem in problems)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts": {
            "total": len(hosts),
            "enabled": len(enabled),
            "disabled": len(disabled),
            "unavailable": len(unavailable),
            "unavailable_hosts": unavailable[:20],
        },
        "problems": {
            "total": len(problems),
            "by_severity": dict(sorted(severity_counts.items())),
            "top": problems[:10],
        },
    }


@mcp.tool()
async def get_fortigate_summary() -> dict[str, Any]:
    """Get current read-only FortiGate device, interface, policy, route and VPN summary."""
    return await _get("/fortigate/summary")


@mcp.tool()
async def get_fortigate_performance() -> dict[str, Any]:
    """Get live FortiGate sessions, setup rate, CPU and memory with short statistics."""
    return await _get("/fortigate/performance-summary")


@mcp.tool()
async def get_fortigate_traffic(count: int = 500) -> dict[str, Any]:
    """Summarize current FortiGate sessions, top talkers, services and policies."""
    return await _get(
        "/fortigate/traffic-summary",
        {"count": max(1, min(count, 5000)), "ip_version": "ipv4"},
    )


@mcp.tool()
async def get_fortigate_vpn_summary() -> dict[str, Any]:
    """Get the current read-only FortiGate IPsec configuration summary."""
    return await _get("/fortigate/vpn-summary")


@mcp.tool()
async def get_estate_summary(limit: int = 500) -> dict[str, Any]:
    """Summarize total, enabled, disabled and unavailable hosts plus active problems."""
    return await _estate_summary(limit)


@mcp.tool()
async def get_morning_report(
    hosts: str = "",
    hours: int = 24,
    firewall_host: str = "",
) -> dict[str, Any]:
    """Collect a concise morning report, with optional FortiGate traffic data."""
    requested_hosts = [
        value.strip()
        for value in hosts.split(",")
        if value.strip()
    ][:20]
    period_hours = max(1, min(hours, 168))
    estate = await _estate_summary()

    host_reports = []
    for host in requested_hosts:
        report: dict[str, Any] = {"requested_host": host}
        try:
            report["overview"] = await _get("/overview", {"host": host})
            host_info = report["overview"].get("host", {})
            hostid = str(host_info.get("hostid", ""))
            if hostid.isdigit():
                log_items = await _get(
                    "/items",
                    {"query": "log.summary", "hostid": hostid, "limit": 10},
                )
                report["log_summaries"] = log_items.get("data", [])
            report["period"] = await _read(
                "host_24h_summary",
                query=host,
                hours=period_hours,
            )
        except (httpx.HTTPError, ValueError) as exc:
            report["error"] = str(exc)
        host_reports.append(report)

    gpu = None
    if requested_hosts:
        try:
            gpu = await _read("gpu_brief", query=",".join(requested_hosts))
        except (httpx.HTTPError, ValueError) as exc:
            gpu = {"error": str(exc)}

    traffic = None
    if firewall_host.strip():
        traffic = {}
        try:
            traffic["configuration"] = await _get("/fortigate/summary")
            traffic["performance"] = await _get("/fortigate/performance-summary")
        except (httpx.HTTPError, ValueError) as exc:
            traffic["direct_api_error"] = str(exc)
        try:
            traffic["historical_log_summary"] = await _read(
                "traffic_summary",
                query=firewall_host.strip(),
            )
        except (httpx.HTTPError, ValueError) as exc:
            traffic["historical_summary_error"] = str(exc)

    return {
        "response_style": (
            "Morning report. Start with overall status. Use at most 8 bullets. "
            "Prioritize new or active problems, unavailable hosts, stale data, "
            "and meaningful 24-hour changes. Do not list normal low-value details."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_hours": period_hours,
        "estate": estate,
        "hosts": host_reports,
        "gpu": gpu,
        "traffic": traffic,
    }


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
